use crate::app::auth::AuthApp;
use crate::error::{CliError, Result};
use crate::infra::crypto::VaultCrypto;
use crate::infra::db::{MetadataDb, VaultDb};
use reqwest::{Client, Method};

pub struct ApiApp<'a> {
    metadata_db: &'a MetadataDb,
    vault_db: &'a VaultDb,
    crypto: &'a VaultCrypto,
    auth_app: &'a AuthApp<'a>,
    client: Client,
}

impl<'a> ApiApp<'a> {
    pub fn new(
        metadata_db: &'a MetadataDb,
        vault_db: &'a VaultDb,
        crypto: &'a VaultCrypto,
        auth_app: &'a AuthApp<'a>,
    ) -> Self {
        Self {
            metadata_db,
            vault_db,
            crypto,
            auth_app,
            client: Client::new(),
        }
    }

    pub async fn call(
        &self,
        provider_id: &str,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        let provider = self
            .metadata_db
            .get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        let mut session = self
            .metadata_db
            .get_latest_session(provider_id)?
            .ok_or_else(|| CliError::AuthRequired)?;

        if provider.auth_type == crate::domain::provider::AuthType::OauthPkce {
            if let Some(exp) = session.expires_at {
                if chrono::Utc::now()
                    + chrono::Duration::try_seconds(30).unwrap_or(chrono::Duration::zero())
                    >= exp
                {
                    tracing::info!("Token expired or expiring soon. Refreshing...");
                    if let Err(e) = self.auth_app.refresh_oauth_token(provider_id).await {
                        tracing::error!("Failed to refresh token: {}", e);
                        return Err(CliError::AuthExpired);
                    } else {
                        session = self
                            .metadata_db
                            .get_latest_session(provider_id)?
                            .ok_or_else(|| CliError::AuthRequired)?;
                    }
                }
            }
        }

        let (cipher_text, nonce) = self
            .vault_db
            .get_secret(&session.secret_id)?
            .ok_or_else(|| CliError::VaultError("Secret not found".into()))?;

        let secret_bytes = self.crypto.decrypt(&cipher_text, &nonce)?;
        let secret_str = String::from_utf8(secret_bytes)
            .map_err(|_| CliError::VaultError("Invalid UTF-8 in secret".into()))?;

        let access_token = if provider.auth_type == crate::domain::provider::AuthType::OauthPkce {
            let json: serde_json::Value = serde_json::from_str(&secret_str)
                .map_err(|e| CliError::VaultError(format!("Malformed OAuth secret: {}", e)))?;
            json.get("access_token")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string()
        } else {
            secret_str
        };

        let url = if path.starts_with('/') {
            format!("{}{}", provider.base_url.trim_end_matches('/'), path)
        } else {
            format!("{}/{}", provider.base_url.trim_end_matches('/'), path)
        };

        let req_method = match method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            _ => return Err(CliError::Internal(format!("Unsupported method {}", method))),
        };

        let mut req = self.client.request(req_method, &url);

        // Provider configuration should ideally specify whether to use Bearer Auth, Basic Auth, or custom headers.
        // For simplicity in this implementation, we default to Bearer token if not explicitly specified.
        req = req.header("Authorization", format!("Bearer {}", access_token));

        if let Some(json_body) = body {
            req = req.json(&json_body);
        }

        let res = req
            .send()
            .await
            .map_err(|e| CliError::Internal(format!("API request failed: {}", e)))?;

        let status = res.status();
        let body_text = res
            .text()
            .await
            .map_err(|e| CliError::Internal(format!("Failed to read response body: {}", e)))?;

        if !status.is_success() {
            return Err(CliError::Internal(format!(
                "API Error ({}): {}",
                status, body_text
            )));
        }

        let json_value: serde_json::Value =
            serde_json::from_str(&body_text).unwrap_or(serde_json::Value::String(body_text));

        Ok(json_value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::auth::AuthApp;
    use crate::domain::provider::{AuthType, ProviderConfig};
    use crate::domain::session::SessionRecord;
    use crate::infra::db::{MetadataDb, VaultDb};
    use chrono::{Duration, Utc};
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn setup() -> (MetadataDb, VaultDb, VaultCrypto) {
        let metadata = MetadataDb::new(Connection::open_in_memory().expect("metadata conn"))
            .expect("metadata init");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault conn"))
            .expect("vault init");
        let dir = tempdir().expect("temp dir");
        let crypto = VaultCrypto::load_or_create(&dir.path().join("vault.key")).expect("crypto init");
        (metadata, vault, crypto)
    }

    fn api_key_provider(id: &str, base_url: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: base_url.to_string(),
            auth_type: AuthType::ApiKey,
            scopes: vec!["read".to_string()],
            client_id: None,
            auth_url: None,
            token_url: None,
        }
    }

    fn oauth_provider(id: &str, base_url: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: base_url.to_string(),
            auth_type: AuthType::OauthPkce,
            scopes: vec!["scope:read".to_string()],
            client_id: Some("client-1".to_string()),
            auth_url: Some("https://id.example.com/auth".to_string()),
            token_url: Some("https://id.example.com/token".to_string()),
        }
    }

    fn insert_session_with_secret(
        metadata: &MetadataDb,
        vault: &VaultDb,
        crypto: &VaultCrypto,
        provider_id: &str,
        secret_id: &str,
        secret_payload: &[u8],
        expires_at: Option<chrono::DateTime<Utc>>,
    ) {
        let (cipher, nonce) = crypto.encrypt(secret_payload).expect("encrypt secret");
        vault
            .insert_secret(secret_id, "token", &cipher, &nonce)
            .expect("insert secret");
        let session = SessionRecord {
            session_id: format!("sess-{secret_id}"),
            provider_id: provider_id.to_string(),
            scopes: vec!["read".to_string()],
            expires_at,
            secret_id: secret_id.to_string(),
        };
        metadata.insert_session(&session).expect("insert session");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_fails_when_provider_is_missing() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);

        let err = app
            .call("missing", "GET", "/v1/data", None)
            .await
            .expect_err("missing provider should fail");
        assert!(matches!(err, CliError::ProviderNotFound(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_fails_when_session_is_missing() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", "http://127.0.0.1:9"))
            .expect("insert provider");
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);

        let err = app
            .call("p1", "GET", "/v1/data", None)
            .await
            .expect_err("missing session should fail");
        assert!(matches!(err, CliError::AuthRequired));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_fails_for_unsupported_http_method() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", "http://127.0.0.1:9"))
            .expect("insert provider");
        insert_session_with_secret(
            &metadata,
            &vault,
            &crypto,
            "p1",
            "sec1",
            b"api-key",
            None,
        );

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let err = app
            .call("p1", "TRACE", "/v1/data", None)
            .await
            .expect_err("unsupported method should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_sends_bearer_token_and_returns_json() {
        use axum::{extract::Request, http::StatusCode, response::IntoResponse, routing::post, Json, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");

        let app_router = Router::new().route(
            "/v1/data",
            post(|req: Request| async move {
                let auth = req
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let body = axum::body::to_bytes(req.into_body(), usize::MAX)
                    .await
                    .expect("body bytes");
                let body_value: serde_json::Value = serde_json::from_slice(&body).expect("json body");
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "auth": auth,
                        "body": body_value
                    })),
                )
                    .into_response()
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, app_router).await;
        });

        let (metadata, vault, crypto) = setup();
        let base_url = format!("http://{addr}");
        metadata
            .insert_provider(&api_key_provider("p1", &base_url))
            .expect("insert provider");
        insert_session_with_secret(
            &metadata,
            &vault,
            &crypto,
            "p1",
            "sec1",
            b"api-key-123",
            None,
        );

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let res = app
            .call("p1", "POST", "/v1/data", Some(serde_json::json!({ "x": 1 })))
            .await
            .expect("api call");
        server_task.abort();

        assert_eq!(
            res.get("auth").and_then(|v| v.as_str()),
            Some("Bearer api-key-123")
        );
        assert_eq!(res.get("body").and_then(|v| v.get("x")).and_then(|v| v.as_i64()), Some(1));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_with_non_json_response_returns_string() {
        use axum::{http::StatusCode, routing::get, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let app_router = Router::new().route("/status", get(|| async { (StatusCode::OK, "ok") }));
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, app_router).await;
        });

        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", &format!("http://{addr}")))
            .expect("insert provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"api-key", None);

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let res = app
            .call("p1", "GET", "status", None)
            .await
            .expect("api call");
        server_task.abort();

        assert_eq!(res, serde_json::Value::String("ok".to_string()));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_returns_error_for_non_success_http_status() {
        use axum::{http::StatusCode, routing::get, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("local addr");
        let app_router = Router::new().route("/v1/fail", get(|| async { (StatusCode::BAD_REQUEST, "bad-request") }));
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, app_router).await;
        });

        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", &format!("http://{addr}")))
            .expect("insert provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"api-key", None);

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let err = app
            .call("p1", "GET", "/v1/fail", None)
            .await
            .expect_err("expected non-success status");
        server_task.abort();

        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_fails_when_secret_is_not_valid_utf8_for_api_key() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", "http://127.0.0.1:9"))
            .expect("insert provider");
        insert_session_with_secret(
            &metadata,
            &vault,
            &crypto,
            "p1",
            "sec1",
            &[0xff, 0xfe, 0xfd],
            None,
        );

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let err = app
            .call("p1", "GET", "/v1/data", None)
            .await
            .expect_err("invalid utf8 should fail");
        assert!(matches!(err, CliError::VaultError(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_fails_when_oauth_secret_is_malformed_json() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&oauth_provider("oauth", "http://127.0.0.1:9"))
            .expect("insert provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "oauth", "sec1", b"not-json", None);

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let err = app
            .call("oauth", "GET", "/v1/data", None)
            .await
            .expect_err("malformed oauth secret should fail");
        assert!(matches!(err, CliError::VaultError(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_returns_auth_expired_when_refresh_fails() {
        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth", "http://127.0.0.1:9");
        provider.client_id = None;
        metadata.insert_provider(&provider).expect("insert provider");

        let payload = serde_json::json!({
            "access_token": "a",
            "refresh_token": "r"
        })
        .to_string();
        insert_session_with_secret(
            &metadata,
            &vault,
            &crypto,
            "oauth",
            "sec1",
            payload.as_bytes(),
            Some(Utc::now() - Duration::seconds(5)),
        );

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let err = app
            .call("oauth", "GET", "/v1/data", None)
            .await
            .expect_err("refresh failure should map to AuthExpired");
        assert!(matches!(err, CliError::AuthExpired));
    }
}
