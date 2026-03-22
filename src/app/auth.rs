use crate::domain::provider::AuthType;
use crate::domain::session::SessionRecord;
use crate::error::{CliError, Result};
use crate::infra::crypto::VaultCrypto;
use crate::infra::db::{MetadataDb, VaultDb};
use chrono::Utc;
use rpassword;
use uuid::Uuid;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;

pub struct AuthApp<'a> {
    metadata_db: &'a MetadataDb,
    vault_db: &'a VaultDb,
    crypto: &'a VaultCrypto,
    client: Client,
    refresh_lock: tokio::sync::Mutex<()>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

impl<'a> AuthApp<'a> {
    pub fn new(
        metadata_db: &'a MetadataDb,
        vault_db: &'a VaultDb,
        crypto: &'a VaultCrypto,
    ) -> Self {
        Self {
            metadata_db,
            vault_db,
            crypto,
            client: Client::new(),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn login_api_key(&self, provider_id: &str, api_key: Option<&str>) -> Result<()> {
        let provider = self
            .metadata_db
            .get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        if provider.auth_type != AuthType::ApiKey {
            return Err(CliError::Internal(
                "Provider does not support API Key auth".into(),
            ));
        }

        let key = match api_key {
            Some(k) => k.to_string(),
            None => {
                println!("Enter API Key for {}: ", provider_id);
                rpassword::read_password()
                    .map_err(|e| CliError::Internal(format!("Failed to read password: {}", e)))?
            }
        };

        let secret_id = format!("apikey_{}_{}", provider_id, Uuid::new_v4());
        let (cipher_text, nonce) = self.crypto.encrypt(key.as_bytes())?;

        self.vault_db
            .insert_secret(&secret_id, "api_key", &cipher_text, &nonce)?;

        let session = SessionRecord {
            session_id: format!("sess_{}", Uuid::new_v4()),
            provider_id: provider_id.to_string(),
            scopes: provider.scopes.clone(),
            expires_at: None,
            secret_id,
        };
        self.metadata_db.insert_session(&session)?;

        Ok(())
    }

    pub async fn login_oauth_pkce(&self, provider_id: &str) -> Result<()> {
        let provider = self
            .metadata_db
            .get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        if provider.auth_type != AuthType::OauthPkce {
            return Err(CliError::Internal(
                "Provider does not support OAuth PKCE".into(),
            ));
        }

        let client_id = provider
            .client_id
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing client_id".into()))?;
        let auth_url = provider
            .auth_url
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing auth_url".into()))?;
        let token_url = provider
            .token_url
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing token_url".into()))?;

        // 1. Generate PKCE & state
        let (code_verifier, code_challenge, expected_state) = self.generate_pkce_params();

        // 2. Build Authorize URL
        let redirect_uri = "http://127.0.0.1:8080/callback"; // Default for pre-registration
        let authorize_url = self.build_authorize_url(
            auth_url,
            client_id,
            redirect_uri,
            &provider.scopes,
            &expected_state,
            &code_challenge,
        )?;

        println!("Open this URL in your browser:\n{}\n", authorize_url);

        // 3. Start callback server and wait for code
        let (code_str, state_str) = self.start_callback_server().await?;

        if state_str != expected_state {
            return Err(CliError::Internal("CSRF token mismatch".into()));
        }

        // 4. Exchange code for token
        let token_result = self
            .exchange_code_for_token(
                token_url,
                client_id,
                &code_str,
                redirect_uri,
                &code_verifier,
            )
            .await?;

        // 5. Store secrets and session
        self.store_oauth_session(provider_id, &token_result, &provider.scopes)?;

        Ok(())
    }

    fn generate_pkce_params(&self) -> (String, String, String) {
        let mut state_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut state_bytes);
        let state = URL_SAFE_NO_PAD.encode(state_bytes);

        let mut verifier_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut verifier_bytes);
        let verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        (verifier, challenge, state)
    }

    fn build_authorize_url(
        &self,
        auth_url: &str,
        client_id: &str,
        redirect_uri: &str,
        scopes: &[String],
        state: &str,
        challenge: &str,
    ) -> Result<url::Url> {
        let mut url = url::Url::parse(auth_url).map_err(|e| CliError::Internal(e.to_string()))?;
        let scopes_str = scopes.join(" ");
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes_str)
            .append_pair("state", state)
            .append_pair("code_challenge", challenge)
            .append_pair("code_challenge_method", "S256");
        Ok(url)
    }

    async fn start_callback_server(&self) -> Result<(String, String)> {
        type CallbackTx = std::sync::Arc<
            tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<(String, String)>>>,
        >;

        let (tx, rx) = tokio::sync::oneshot::channel::<(String, String)>();
        let tx: CallbackTx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

        use axum::{extract::Query, extract::State, response::Html, routing::get, Router};
        let app = Router::new().route("/callback", get(move |Query(params): Query<HashMap<String, String>>, State(tx): State<CallbackTx>| {
            async move {
                let code = params.get("code").cloned().unwrap_or_default();
                let state = params.get("state").cloned().unwrap_or_default();
                if let Some(chan) = tx.lock().await.take() {
                    let _ = chan.send((code, state));
                }
                Html("<html><body>Authentication successful! You can close this window.</body></html>")
            }
        })).with_state(tx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|e| CliError::Internal(format!("Failed to bind to local port: {}", e)))?;
        let addr = listener
            .local_addr()
            .map_err(|e| CliError::Internal(e.to_string()))?;
        let dynamic_redirect_uri = format!("http://{}/callback", addr);

        println!("Waiting for callback on {} ...", dynamic_redirect_uri);
        println!("Note: If your provider requires a fixed redirect URI, ensure http://127.0.0.1:8080/callback is registered.");

        tokio::select! {
            result = rx => {
                result.map_err(|_| CliError::Internal("Failed to receive callback".into()))
            }
            _ = axum::serve(listener, app) => {
                Err(CliError::Internal("Server exited unexpectedly".into()))
            }
        }
    }

    async fn exchange_code_for_token(
        &self,
        token_url: &str,
        client_id: &str,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
    ) -> Result<TokenResponse> {
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);
        params.insert("client_id", client_id);
        params.insert("code_verifier", verifier);

        let res = self
            .client
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| CliError::Internal(format!("Token exchange request failed: {}", e)))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(CliError::Internal(format!(
                "Token exchange failed: {}",
                err_text
            )));
        }

        res.json()
            .await
            .map_err(|e| CliError::Internal(format!("Failed to parse token response: {}", e)))
    }

    fn store_oauth_session(
        &self,
        provider_id: &str,
        token_result: &TokenResponse,
        scopes: &[String],
    ) -> Result<()> {
        let payload = serde_json::json!({
            "access_token": token_result.access_token,
            "refresh_token": token_result.refresh_token
        });

        let secret_str = payload.to_string();
        let secret_id = format!("oauth_{}_{}", provider_id, Uuid::new_v4());
        let (cipher_text, nonce) = self.crypto.encrypt(secret_str.as_bytes())?;

        self.vault_db
            .insert_secret(&secret_id, "oauth_token", &cipher_text, &nonce)?;

        let expires_in_sec = token_result.expires_in.unwrap_or(0);
        let expires_at = if expires_in_sec > 0 {
            Some(
                Utc::now()
                    + chrono::Duration::try_seconds(expires_in_sec as i64)
                        .unwrap_or(chrono::Duration::zero()),
            )
        } else {
            None
        };

        let session = SessionRecord {
            session_id: format!("sess_{}", Uuid::new_v4()),
            provider_id: provider_id.to_string(),
            scopes: scopes.to_vec(),
            expires_at,
            secret_id,
        };
        self.metadata_db.insert_session(&session)?;

        Ok(())
    }

    pub async fn refresh_oauth_token(&self, provider_id: &str) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;

        let provider = self
            .metadata_db
            .get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        if provider.auth_type != AuthType::OauthPkce {
            return Err(CliError::Internal(
                "Provider does not support OAuth PKCE".into(),
            ));
        }

        let session = self
            .metadata_db
            .get_latest_session(provider_id)?
            .ok_or_else(|| CliError::AuthRequired)?;

        // DBに記録されている最新のExpiresを見て、すでに他の呼び出しによって更新済みであればスキップ
        if let Some(exp) = session.expires_at {
            if chrono::Utc::now()
                + chrono::Duration::try_seconds(30).unwrap_or(chrono::Duration::zero())
                < exp
            {
                tracing::info!("Token was already refreshed by another parallel request.");
                return Ok(());
            }
        }

        let (cipher_text, nonce) = self
            .vault_db
            .get_secret(&session.secret_id)?
            .ok_or_else(|| CliError::VaultError("Secret not found".into()))?;

        let secret_bytes = self.crypto.decrypt(&cipher_text, &nonce)?;
        let secret_json: serde_json::Value = serde_json::from_slice(&secret_bytes)
            .map_err(|_| CliError::VaultError("Invalid JSON in secret".into()))?;

        let refresh_token_str = secret_json
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::Internal("No refresh_token found in vault".into()))?;

        let client_id = provider
            .client_id
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing client_id".into()))?;
        let token_url = provider
            .token_url
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing token_url".into()))?;

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token_str);
        params.insert("client_id", client_id);

        let res = self
            .client
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| CliError::Internal(format!("Token refresh request failed: {}", e)))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(CliError::Internal(format!(
                "Token refresh failed: {}",
                err_text
            )));
        }

        let token_result: TokenResponse = res
            .json()
            .await
            .map_err(|e| CliError::Internal(format!("Failed to parse token response: {}", e)))?;

        let access_token = token_result.access_token;
        // Fallback to old refresh token if new one is not returned
        let base_refresh = refresh_token_str.to_string();
        let final_refresh_token = token_result.refresh_token.unwrap_or(base_refresh);

        let payload = serde_json::json!({
            "access_token": access_token,
            "refresh_token": final_refresh_token
        });

        let secret_str = payload.to_string();
        let (new_cipher, new_nonce) = self.crypto.encrypt(secret_str.as_bytes())?;

        self.vault_db
            .insert_secret(&session.secret_id, "oauth_token", &new_cipher, &new_nonce)?;

        let expires_in_sec = token_result.expires_in.unwrap_or(0);
        let expires_at = if expires_in_sec > 0 {
            Some(
                Utc::now()
                    + chrono::Duration::try_seconds(expires_in_sec as i64)
                        .unwrap_or(chrono::Duration::zero()),
            )
        } else {
            None
        };

        let mut updated_session = session;
        updated_session.expires_at = expires_at;
        self.metadata_db.insert_session(&updated_session)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::{AuthType, ProviderConfig};
    use crate::infra::db::{MetadataDb, VaultDb};
    use chrono::Duration;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn setup() -> (MetadataDb, VaultDb, VaultCrypto) {
        let metadata = MetadataDb::new(Connection::open_in_memory().expect("metadata conn"))
            .expect("metadata db init");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault conn"))
            .expect("vault db init");
        let dir = tempdir().expect("temp dir");
        let crypto = VaultCrypto::load_or_create(&dir.path().join("vault.key"))
            .expect("crypto init");
        (metadata, vault, crypto)
    }

    fn api_key_provider(id: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: "https://api.example.com".to_string(),
            auth_type: AuthType::ApiKey,
            scopes: vec!["read".to_string(), "write".to_string()],
            client_id: None,
            auth_url: None,
            token_url: None,
        }
    }

    fn oauth_provider(id: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: "https://api.example.com".to_string(),
            auth_type: AuthType::OauthPkce,
            scopes: vec!["scope:read".to_string()],
            client_id: Some("client-1".to_string()),
            auth_url: Some("https://id.example.com/oauth/authorize".to_string()),
            token_url: Some("https://id.example.com/oauth/token".to_string()),
        }
    }

    #[test]
    fn login_api_key_requires_existing_provider() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app.login_api_key("missing", Some("abc")).expect_err("provider should be missing");
        match err {
            CliError::ProviderNotFound(id) => assert_eq!(id, "missing"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn login_api_key_rejects_oauth_provider() {
        let (metadata, vault, crypto) = setup();
        metadata.insert_provider(&oauth_provider("oauth")).expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app.login_api_key("oauth", Some("abc")).expect_err("auth type should mismatch");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[test]
    fn login_api_key_persists_encrypted_secret_and_session() {
        let (metadata, vault, crypto) = setup();
        metadata.insert_provider(&api_key_provider("p1")).expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        app.login_api_key("p1", Some("secret-123")).expect("login");

        let session = metadata
            .get_latest_session("p1")
            .expect("read latest session")
            .expect("session exists");
        assert_eq!(session.provider_id, "p1");
        assert_eq!(session.scopes, vec!["read".to_string(), "write".to_string()]);
        assert!(session.secret_id.starts_with("apikey_p1_"));

        let (cipher, nonce) = vault
            .get_secret(&session.secret_id)
            .expect("vault read")
            .expect("secret exists");
        let decrypted = crypto.decrypt(&cipher, &nonce).expect("decrypt");
        assert_eq!(decrypted, b"secret-123");
    }

    #[test]
    fn generate_pkce_params_builds_valid_sha256_challenge() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let (verifier, challenge, state) = app.generate_pkce_params();
        assert!(!verifier.is_empty());
        assert!(!challenge.is_empty());
        assert!(!state.is_empty());

        let mut hasher = Sha256::new();
        hasher.update(verifier.as_bytes());
        let expected = URL_SAFE_NO_PAD.encode(hasher.finalize());
        assert_eq!(challenge, expected);
    }

    #[test]
    fn build_authorize_url_contains_all_required_query_params() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let url = app
            .build_authorize_url(
                "https://id.example.com/authorize",
                "client123",
                "http://127.0.0.1:8080/callback",
                &["scope-a".to_string(), "scope-b".to_string()],
                "state123",
                "challenge123",
            )
            .expect("url build");

        let query: std::collections::HashMap<String, String> = url.query_pairs().into_owned().collect();
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(query.get("client_id").map(String::as_str), Some("client123"));
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:8080/callback")
        );
        assert_eq!(query.get("scope").map(String::as_str), Some("scope-a scope-b"));
        assert_eq!(query.get("state").map(String::as_str), Some("state123"));
        assert_eq!(query.get("code_challenge").map(String::as_str), Some("challenge123"));
        assert_eq!(query.get("code_challenge_method").map(String::as_str), Some("S256"));
    }

    #[test]
    fn build_authorize_url_rejects_invalid_auth_url() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .build_authorize_url("://invalid", "client", "http://localhost", &[], "s", "c")
            .expect_err("invalid URL must fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[test]
    fn store_oauth_session_persists_token_secret_and_expiry() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);
        let token = TokenResponse {
            access_token: "access-1".to_string(),
            refresh_token: Some("refresh-1".to_string()),
            expires_in: Some(600),
        };

        app.store_oauth_session("oauth", &token, &["scope:x".to_string()])
            .expect("store oauth session");

        let session = metadata
            .get_latest_session("oauth")
            .expect("latest session")
            .expect("session exists");
        assert_eq!(session.provider_id, "oauth");
        assert_eq!(session.scopes, vec!["scope:x".to_string()]);
        assert!(session.expires_at.is_some());

        let (cipher, nonce) = vault
            .get_secret(&session.secret_id)
            .expect("vault read")
            .expect("secret exists");
        let plaintext = crypto.decrypt(&cipher, &nonce).expect("decrypt");
        let value: serde_json::Value =
            serde_json::from_slice(&plaintext).expect("token payload should be valid JSON");
        assert_eq!(value.get("access_token").and_then(|v| v.as_str()), Some("access-1"));
        assert_eq!(value.get("refresh_token").and_then(|v| v.as_str()), Some("refresh-1"));
    }

    #[test]
    fn store_oauth_session_without_expiry_stores_none_expires_at() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);
        let token = TokenResponse {
            access_token: "access-1".to_string(),
            refresh_token: Some("refresh-1".to_string()),
            expires_in: None,
        };

        app.store_oauth_session("oauth", &token, &["scope:x".to_string()])
            .expect("store oauth session");

        let session = metadata
            .get_latest_session("oauth")
            .expect("latest session")
            .expect("session exists");
        assert!(session.expires_at.is_none());
        assert!(vault
            .get_secret(&session.secret_id)
            .expect("vault read")
            .is_some());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn login_oauth_pkce_requires_client_id() {
        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth");
        provider.client_id = None;
        metadata.insert_provider(&provider).expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .login_oauth_pkce("oauth")
            .await
            .expect_err("missing client_id should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn login_oauth_pkce_requires_auth_url() {
        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth");
        provider.auth_url = None;
        metadata.insert_provider(&provider).expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .login_oauth_pkce("oauth")
            .await
            .expect_err("missing auth_url should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn login_oauth_pkce_requires_token_url() {
        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth");
        provider.token_url = None;
        metadata.insert_provider(&provider).expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .login_oauth_pkce("oauth")
            .await
            .expect_err("missing token_url should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_fails_for_missing_provider() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .refresh_oauth_token("missing")
            .await
            .expect_err("provider should be missing");
        assert!(matches!(err, CliError::ProviderNotFound(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_rejects_non_oauth_provider() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1"))
            .expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .refresh_oauth_token("p1")
            .await
            .expect_err("non-oauth provider should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_requires_existing_session() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&oauth_provider("oauth"))
            .expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .refresh_oauth_token("oauth")
            .await
            .expect_err("session should be required");
        assert!(matches!(err, CliError::AuthRequired));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_fails_on_invalid_secret_json() {
        let (metadata, vault, crypto) = setup();
        let provider = oauth_provider("oauth");
        metadata.insert_provider(&provider).expect("insert provider");

        let (cipher, nonce) = crypto.encrypt(b"not-json").expect("encrypt");
        vault
            .insert_secret("secret1", "oauth_token", &cipher, &nonce)
            .expect("insert secret");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            scopes: provider.scopes.clone(),
            expires_at: Some(Utc::now() - Duration::seconds(10)),
            secret_id: "secret1".to_string(),
        };
        metadata.insert_session(&session).expect("insert session");

        let app = AuthApp::new(&metadata, &vault, &crypto);
        let err = app
            .refresh_oauth_token("oauth")
            .await
            .expect_err("invalid JSON should fail");
        assert!(matches!(err, CliError::VaultError(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_fails_when_refresh_token_is_missing() {
        let (metadata, vault, crypto) = setup();
        let provider = oauth_provider("oauth");
        metadata.insert_provider(&provider).expect("insert provider");

        let payload = serde_json::json!({ "access_token": "a-only" }).to_string();
        let (cipher, nonce) = crypto.encrypt(payload.as_bytes()).expect("encrypt");
        vault
            .insert_secret("secret1", "oauth_token", &cipher, &nonce)
            .expect("insert secret");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            scopes: provider.scopes.clone(),
            expires_at: Some(Utc::now() - Duration::seconds(10)),
            secret_id: "secret1".to_string(),
        };
        metadata.insert_session(&session).expect("insert session");

        let app = AuthApp::new(&metadata, &vault, &crypto);
        let err = app
            .refresh_oauth_token("oauth")
            .await
            .expect_err("missing refresh token should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_fails_when_client_id_is_missing() {
        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth");
        provider.client_id = None;
        metadata.insert_provider(&provider).expect("insert provider");

        let payload = serde_json::json!({
            "access_token": "a",
            "refresh_token": "r"
        })
        .to_string();
        let (cipher, nonce) = crypto.encrypt(payload.as_bytes()).expect("encrypt");
        vault
            .insert_secret("secret1", "oauth_token", &cipher, &nonce)
            .expect("insert secret");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            scopes: provider.scopes.clone(),
            expires_at: Some(Utc::now() - Duration::seconds(10)),
            secret_id: "secret1".to_string(),
        };
        metadata.insert_session(&session).expect("insert session");

        let app = AuthApp::new(&metadata, &vault, &crypto);
        let err = app
            .refresh_oauth_token("oauth")
            .await
            .expect_err("missing client_id should fail");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_oauth_token_returns_early_when_token_not_expiring() {
        let (metadata, vault, crypto) = setup();
        let provider = oauth_provider("oauth");
        metadata.insert_provider(&provider).expect("insert provider");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            scopes: provider.scopes.clone(),
            expires_at: Some(Utc::now() + Duration::minutes(10)),
            secret_id: "missing-secret-ok".to_string(),
        };
        metadata.insert_session(&session).expect("insert session");

        let app = AuthApp::new(&metadata, &vault, &crypto);
        let result = app.refresh_oauth_token("oauth").await;
        assert!(result.is_ok());
    }
}
