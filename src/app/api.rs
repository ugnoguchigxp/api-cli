use crate::app::auth::AuthApp;
use crate::domain::provider::CredentialPlacement;
use crate::error::{CliError, Result};
use crate::infra::crypto::VaultCrypto;
use crate::infra::db::{MetadataDb, VaultDb};
use reqwest::{
    header::{HeaderName, HeaderValue},
    Client, ClientBuilder, Method, Response,
};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 1024 * 1024;
pub const DEFAULT_MAX_ERROR_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct ApiRequestOptions {
    pub timeout: Duration,
    pub max_response_bytes: usize,
    pub headers: Vec<(String, String)>,
    pub principal_id: String,
    pub tenant_id: String,
}

impl Default for ApiRequestOptions {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_REQUEST_TIMEOUT,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            headers: Vec::new(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
        }
    }
}

#[derive(Clone)]
pub struct ApiApp {
    metadata_db: MetadataDb,
    vault_db: VaultDb,
    crypto: VaultCrypto,
    auth_app: AuthApp,
    public_client: Client,
    private_client: Client,
}

impl ApiApp {
    #[cfg(test)]
    pub fn new(
        metadata_db: &MetadataDb,
        vault_db: &VaultDb,
        crypto: &VaultCrypto,
        auth_app: &AuthApp,
    ) -> Self {
        Self::try_new(metadata_db, vault_db, crypto, auth_app)
            .expect("static HTTP client configuration must be valid")
    }

    pub fn try_new(
        metadata_db: &MetadataDb,
        vault_db: &VaultDb,
        crypto: &VaultCrypto,
        auth_app: &AuthApp,
    ) -> Result<Self> {
        let public_client = build_api_client(false)?;
        let private_client = build_api_client(true)?;
        Ok(Self {
            metadata_db: metadata_db.clone(),
            vault_db: vault_db.clone(),
            crypto: crypto.clone(),
            auth_app: auth_app.clone(),
            public_client,
            private_client,
        })
    }

    pub async fn call(
        &self,
        provider_id: &str,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> Result<serde_json::Value> {
        self.call_with_limits(
            provider_id,
            method,
            path,
            body,
            DEFAULT_REQUEST_TIMEOUT,
            DEFAULT_MAX_RESPONSE_BYTES,
        )
        .await
    }

    pub fn provider_is_authenticated_for(
        &self,
        provider_id: &str,
        principal_id: &str,
        tenant_id: &str,
        required_scopes: &[String],
    ) -> Result<bool> {
        let Some(session) =
            self.metadata_db
                .get_latest_session_for(provider_id, principal_id, tenant_id)?
        else {
            return Ok(false);
        };
        Ok(self.metadata_db.get_provider(provider_id)?.is_some()
            && required_scopes
                .iter()
                .all(|scope| session.scopes.contains(scope)))
    }

    pub async fn call_with_limits(
        &self,
        provider_id: &str,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        timeout: Duration,
        max_response_bytes: usize,
    ) -> Result<serde_json::Value> {
        self.call_with_options(
            provider_id,
            method,
            path,
            body,
            ApiRequestOptions {
                timeout,
                max_response_bytes,
                headers: Vec::new(),
                ..ApiRequestOptions::default()
            },
        )
        .await
    }

    pub async fn call_with_options(
        &self,
        provider_id: &str,
        method: &str,
        path: &str,
        body: Option<serde_json::Value>,
        options: ApiRequestOptions,
    ) -> Result<serde_json::Value> {
        let provider = self
            .metadata_db
            .get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        let mut session = self
            .metadata_db
            .get_latest_session_for(provider_id, &options.principal_id, &options.tenant_id)?
            .ok_or_else(|| CliError::AuthRequired)?;

        if provider.auth_type == crate::domain::provider::AuthType::OauthPkce {
            if let Some(exp) = session.expires_at {
                if chrono::Utc::now()
                    + chrono::Duration::try_seconds(30).unwrap_or(chrono::Duration::zero())
                    >= exp
                {
                    tracing::info!("Token expired or expiring soon. Refreshing...");
                    let refresh_result = self
                        .auth_app
                        .refresh_oauth_token_for(
                            provider_id,
                            &options.principal_id,
                            &options.tenant_id,
                        )
                        .await;
                    session = self
                        .metadata_db
                        .get_latest_session_for(
                            provider_id,
                            &options.principal_id,
                            &options.tenant_id,
                        )?
                        .ok_or_else(|| CliError::AuthRequired)?;
                    if let Err(error) = refresh_result {
                        let refreshed_elsewhere = session.expires_at.is_some_and(|expires_at| {
                            chrono::Utc::now()
                                + chrono::Duration::try_seconds(30)
                                    .unwrap_or(chrono::Duration::zero())
                                < expires_at
                        });
                        if !refreshed_elsewhere {
                            tracing::error!("Failed to refresh token: {}", error);
                            return Err(CliError::AuthExpired);
                        }
                        tracing::info!(
                            "Another process refreshed the OAuth session while this refresh failed"
                        );
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
                .filter(|token| !token.is_empty())
                .ok_or_else(|| CliError::VaultError("OAuth access_token is missing".into()))?
                .to_string()
        } else {
            secret_str
        };
        if access_token.is_empty() {
            return Err(CliError::VaultError("Stored credential is empty".into()));
        }

        let url_text = if path.starts_with('/') {
            format!("{}{}", provider.base_url.trim_end_matches('/'), path)
        } else {
            format!("{}/{}", provider.base_url.trim_end_matches('/'), path)
        };
        let base_url = url::Url::parse(&provider.base_url)
            .map_err(|error| CliError::BlockedUrl(format!("invalid provider base URL: {error}")))?;
        if base_url.query().is_some() || base_url.fragment().is_some() {
            return Err(CliError::BlockedUrl(
                "provider base URL cannot contain a query or fragment".into(),
            ));
        }
        validate_outbound_url(&base_url, provider.allow_private_network).await?;
        let url = url::Url::parse(&url_text)
            .map_err(|error| CliError::BlockedUrl(format!("invalid request URL: {error}")))?;
        validate_outbound_url(&url, provider.allow_private_network).await?;
        if !same_origin(&base_url, &url) {
            return Err(CliError::BlockedUrl(
                "request path changed the provider origin".into(),
            ));
        }

        let req_method = match method.to_uppercase().as_str() {
            "GET" => Method::GET,
            "POST" => Method::POST,
            "PUT" => Method::PUT,
            "DELETE" => Method::DELETE,
            "PATCH" => Method::PATCH,
            _ => return Err(CliError::Internal(format!("Unsupported method {}", method))),
        };

        let client = if provider.allow_private_network {
            &self.private_client
        } else {
            &self.public_client
        };
        let mut req = client.request(req_method, url).timeout(options.timeout);

        req = match &provider.credential_placement {
            CredentialPlacement::Bearer => {
                let value =
                    HeaderValue::from_str(&format!("Bearer {access_token}")).map_err(|_| {
                        CliError::VaultError(
                            "Stored credential cannot be encoded as a header".into(),
                        )
                    })?;
                req.header(reqwest::header::AUTHORIZATION, value)
            }
            CredentialPlacement::Header { name } => {
                let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                    CliError::Internal(format!("Invalid API key header name: {error}"))
                })?;
                if crate::app::action::is_forbidden_request_header(&header_name) {
                    return Err(CliError::InvalidProvider(format!(
                        "credential header is forbidden: {header_name}"
                    )));
                }
                let value = HeaderValue::from_str(&access_token).map_err(|_| {
                    CliError::VaultError("Stored credential cannot be encoded as a header".into())
                })?;
                req.header(header_name, value)
            }
        };
        for (name, value) in options.headers {
            let header_name = HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
                CliError::InvalidAction(format!("invalid executor header name: {error}"))
            })?;
            if crate::app::action::is_forbidden_request_header(&header_name) {
                return Err(CliError::InvalidAction(format!(
                    "executor cannot override sensitive header {header_name}"
                )));
            }
            if matches!(
                &provider.credential_placement,
                CredentialPlacement::Header { name }
                    if header_name.as_str().eq_ignore_ascii_case(name)
            ) {
                return Err(CliError::InvalidAction(format!(
                    "executor cannot override credential header {header_name}"
                )));
            }
            let header_value = HeaderValue::from_str(&value).map_err(|error| {
                CliError::InvalidAction(format!("invalid executor header value: {error}"))
            })?;
            req = req.header(header_name, header_value);
        }

        if let Some(json_body) = body {
            req = req.json(&json_body);
        }

        let res = req.send().await.map_err(|error| {
            if error.is_timeout() {
                CliError::RequestTimeout {
                    timeout_ms: options.timeout.as_millis() as u64,
                }
            } else {
                tracing::warn!("Upstream request failed before a response was received");
                CliError::UpstreamResultUnknown
            }
        })?;

        let status = res.status();
        let body_limit = if status.is_success() {
            options.max_response_bytes
        } else {
            options.max_response_bytes.min(DEFAULT_MAX_ERROR_BYTES)
        };
        let body_bytes = read_limited_response(res, body_limit).await?;

        if !status.is_success() {
            tracing::warn!(
                status = status.as_u16(),
                response_bytes = body_bytes.len(),
                "Upstream API returned an error response"
            );
            return Err(CliError::UpstreamError {
                status: status.as_u16(),
            });
        }

        let body_text =
            String::from_utf8(body_bytes).map_err(|_| CliError::UpstreamResultUnknown)?;
        let json_value: serde_json::Value =
            serde_json::from_str(&body_text).unwrap_or(serde_json::Value::String(body_text));

        Ok(json_value)
    }
}

fn build_api_client(allow_private_network: bool) -> Result<Client> {
    let builder = configure_dns(Client::builder(), allow_private_network)
        .connect_timeout(DEFAULT_CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::custom(|attempt| {
            if attempt.previous().len() >= 3 {
                return attempt.error("redirect limit exceeded");
            }
            let Some(first) = attempt.previous().first() else {
                return attempt.follow();
            };
            if same_origin(first, attempt.url()) {
                attempt.follow()
            } else {
                attempt.stop()
            }
        }));
    builder
        .build()
        .map_err(|error| CliError::Internal(format!("Failed to create HTTP client: {error}")))
}

pub(crate) fn configure_dns(builder: ClientBuilder, allow_private_network: bool) -> ClientBuilder {
    if allow_private_network {
        builder
    } else {
        builder.dns_resolver2(PublicDnsResolver)
    }
}

#[derive(Clone, Copy, Debug)]
struct PublicDnsResolver;

impl reqwest::dns::Resolve for PublicDnsResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_string();
        Box::pin(async move {
            let addresses = tokio::net::lookup_host((host.as_str(), 0))
                .await
                .map_err(|error| {
                    Box::new(error) as Box<dyn std::error::Error + Send + Sync + 'static>
                })?
                .collect::<Vec<SocketAddr>>();
            if addresses.is_empty() {
                return Err(Box::new(std::io::Error::other("DNS returned no addresses"))
                    as Box<dyn std::error::Error + Send + Sync + 'static>);
            }
            if addresses
                .iter()
                .any(|address| is_non_public_ip(address.ip()))
            {
                return Err(
                    Box::new(std::io::Error::other("DNS returned a non-public address"))
                        as Box<dyn std::error::Error + Send + Sync + 'static>,
                );
            }
            Ok(Box::new(addresses.into_iter()) as reqwest::dns::Addrs)
        })
    }
}

pub(crate) async fn read_limited_response(mut response: Response, limit: usize) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|content_length| content_length > limit as u64)
    {
        return Err(CliError::ResponseTooLarge { limit_bytes: limit });
    }

    let mut body =
        Vec::with_capacity(response.content_length().unwrap_or(0).min(limit as u64) as usize);
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|_| CliError::UpstreamResultUnknown)?
    {
        if body.len().saturating_add(chunk.len()) > limit {
            return Err(CliError::ResponseTooLarge { limit_bytes: limit });
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn same_origin(left: &url::Url, right: &url::Url) -> bool {
    left.scheme() == right.scheme()
        && left.host_str() == right.host_str()
        && left.port_or_known_default() == right.port_or_known_default()
}

pub(crate) async fn validate_outbound_url(
    url: &url::Url,
    allow_private_network: bool,
) -> Result<()> {
    let host = url
        .host_str()
        .ok_or_else(|| CliError::BlockedUrl("URL does not contain a host".into()))?;
    let is_loopback = host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<IpAddr>()
            .map(|address| address.is_loopback())
            .unwrap_or(false);

    if url.scheme() != "https" && !(url.scheme() == "http" && is_loopback) {
        return Err(CliError::BlockedUrl(format!(
            "only HTTPS is allowed except for loopback development URLs: {url}"
        )));
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(CliError::BlockedUrl(
            "embedded URL credentials are not allowed".into(),
        ));
    }
    if url.fragment().is_some() {
        return Err(CliError::BlockedUrl(
            "URL fragments are not allowed for outbound requests".into(),
        ));
    }
    if !allow_private_network {
        let port = url.port_or_known_default().ok_or_else(|| {
            CliError::BlockedUrl("URL scheme does not have a known default port".into())
        })?;
        let addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| CliError::BlockedUrl(format!("DNS lookup failed: {error}")))?;
        for address in addresses {
            if is_non_public_ip(address.ip()) {
                return Err(CliError::BlockedUrl(format!(
                    "provider resolved to a non-public address {}; explicitly allow private network egress on this provider if intended",
                    address.ip()
                )));
            }
        }
    }
    Ok(())
}

fn is_non_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => {
            let [a, b, c, _] = address.octets();
            a == 0
                || a == 10
                || (a == 100 && (64..=127).contains(&b))
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 0 && c == 0)
                || (a == 192 && b == 0 && c == 2)
                || (a == 192 && b == 88 && c == 99)
                || (a == 192 && b == 168)
                || (a == 198 && (b == 18 || b == 19))
                || (a == 198 && b == 51 && c == 100)
                || (a == 203 && b == 0 && c == 113)
                || a >= 224
        }
        IpAddr::V6(address) => {
            if let Some(embedded) = address.to_ipv4() {
                return is_non_public_ip(IpAddr::V4(embedded));
            }
            let segments = address.segments();
            address.is_loopback()
                || address.is_unspecified()
                || address.is_multicast()
                || address.is_unique_local()
                || address.is_unicast_link_local()
                || (segments[0] == 0x0064
                    && segments[1] == 0xff9b
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0
                    && segments[5] == 0)
                || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001)
                || (segments[0] == 0
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0
                    && segments[4] == 0xffff
                    && segments[5] == 0)
                || (segments[0] == 0x0100
                    && segments[1] == 0
                    && segments[2] == 0
                    && segments[3] == 0)
                || (segments[0] == 0x2001 && segments[1] < 0x0200)
                || (segments[0] == 0x2001 && segments[1] == 0x0db8)
                || (segments[0] & 0xffc0) == 0xfec0
                || segments[0] == 0x2002
                || (segments[0] & 0xfff0) == 0x3ff0
                || segments[0] == 0x5f00
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::auth::AuthApp;
    use crate::domain::provider::{AuthType, CredentialPlacement, ProviderConfig};
    use crate::domain::session::SessionRecord;
    use crate::infra::db::{MetadataDb, VaultDb};
    use chrono::{Duration, Utc};
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn setup() -> (MetadataDb, VaultDb, VaultCrypto) {
        let metadata = MetadataDb::new(Connection::open_in_memory().expect("metadata conn"))
            .expect("metadata init");
        let vault =
            VaultDb::new(Connection::open_in_memory().expect("vault conn")).expect("vault init");
        let dir = tempdir().expect("temp dir");
        let crypto =
            VaultCrypto::load_or_create(&dir.path().join("vault.key")).expect("crypto init");
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
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: true,
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
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: true,
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
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
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
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"api-key", None);

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
        use axum::{
            extract::Request, http::StatusCode, response::IntoResponse, routing::post, Json, Router,
        };

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
                let body_value: serde_json::Value =
                    serde_json::from_slice(&body).expect("json body");
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
            .call(
                "p1",
                "POST",
                "/v1/data",
                Some(serde_json::json!({ "x": 1 })),
            )
            .await
            .expect("api call");
        server_task.abort();

        assert_eq!(
            res.get("auth").and_then(|v| v.as_str()),
            Some("Bearer api-key-123")
        );
        assert_eq!(
            res.get("body")
                .and_then(|v| v.get("x"))
                .and_then(|v| v.as_i64()),
            Some(1)
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_supports_custom_api_key_header() {
        use axum::{extract::Request, routing::get, Json, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let router = Router::new().route(
            "/data",
            get(|request: Request| async move {
                Json(serde_json::json!({
                    "key": request.headers().get("x-api-key").and_then(|value| value.to_str().ok())
                }))
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let (metadata, vault, crypto) = setup();
        let mut provider = api_key_provider("p1", &format!("http://{addr}"));
        provider.credential_placement = CredentialPlacement::Header {
            name: "x-api-key".into(),
        };
        metadata
            .insert_provider(&provider)
            .expect("insert provider");
        insert_session_with_secret(
            &metadata,
            &vault,
            &crypto,
            "p1",
            "sec1",
            b"header-secret",
            None,
        );
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let output = app.call("p1", "GET", "/data", None).await.expect("call");
        server_task.abort();
        assert_eq!(output["key"], "header-secret");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn call_revalidates_stored_credential_header_configuration() {
        let (metadata, vault, crypto) = setup();
        let mut provider = api_key_provider("p1", "http://127.0.0.1:9");
        provider.credential_placement = CredentialPlacement::Header {
            name: "host".into(),
        };
        metadata.insert_provider(&provider).expect("provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "secret", b"key", None);
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);

        assert!(matches!(
            app.call("p1", "GET", "/", None).await,
            Err(CliError::InvalidProvider(_))
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oversized_chunked_response_is_stopped_at_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let server_task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut request = [0_u8; 2048];
            let _ = stream.read(&mut request).await;
            stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n8\r\n:\"value\"\r\n1\r\n}\r\n0\r\n\r\n",
                )
                .await
                .expect("write response");
        });

        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", &format!("http://{addr}")))
            .expect("provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"key", None);
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let error = app
            .call_with_limits(
                "p1",
                "GET",
                "/",
                None,
                Duration::seconds(1).to_std().expect("duration"),
                5,
            )
            .await
            .expect_err("response must exceed limit");
        server_task.abort();
        assert!(matches!(
            error,
            CliError::ResponseTooLarge { limit_bytes: 5 }
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn request_timeout_is_typed() {
        use axum::{routing::get, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("address");
        let router = Router::new().route(
            "/slow",
            get(|| async {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                "ok"
            }),
        );
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", &format!("http://{addr}")))
            .expect("provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"key", None);
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let error = app
            .call_with_limits(
                "p1",
                "GET",
                "/slow",
                None,
                std::time::Duration::from_millis(5),
                1024,
            )
            .await
            .expect_err("timeout");
        server_task.abort();
        assert!(matches!(error, CliError::RequestTimeout { timeout_ms: 5 }));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn cross_origin_redirect_is_not_followed() {
        use axum::{response::Redirect, routing::get, Router};
        use std::sync::{
            atomic::{AtomicUsize, Ordering},
            Arc,
        };

        let destination_hits = Arc::new(AtomicUsize::new(0));
        let destination_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind destination");
        let destination_address = destination_listener.local_addr().expect("address");
        let hits = destination_hits.clone();
        let destination = Router::new().route(
            "/secret",
            get(move || {
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    "secret"
                }
            }),
        );
        let destination_task = tokio::spawn(async move {
            let _ = axum::serve(destination_listener, destination).await;
        });

        let source_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind source");
        let source_address = source_listener.local_addr().expect("address");
        let source = Router::new().route(
            "/redirect",
            get(move || async move {
                Redirect::temporary(&format!("http://{destination_address}/secret"))
            }),
        );
        let source_task = tokio::spawn(async move {
            let _ = axum::serve(source_listener, source).await;
        });

        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1", &format!("http://{source_address}")))
            .expect("provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"key", None);
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let error = app
            .call("p1", "GET", "/redirect", None)
            .await
            .expect_err("redirect response is not success");
        assert!(matches!(error, CliError::UpstreamError { status: 307 }));
        assert_eq!(destination_hits.load(Ordering::SeqCst), 0);
        source_task.abort();
        destination_task.abort();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn private_network_requires_explicit_provider_permission() {
        let (metadata, vault, crypto) = setup();
        let mut provider = api_key_provider("p1", "http://127.0.0.1:9");
        provider.allow_private_network = false;
        metadata
            .insert_provider(&provider)
            .expect("insert provider");
        insert_session_with_secret(&metadata, &vault, &crypto, "p1", "sec1", b"key", None);
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let error = app
            .call("p1", "GET", "/", None)
            .await
            .expect_err("private egress must be blocked");
        assert!(matches!(error, CliError::BlockedUrl(_)));
    }

    #[test]
    fn special_purpose_addresses_are_not_treated_as_public() {
        for address in [
            "100.64.0.1",
            "192.0.2.1",
            "198.18.0.1",
            "203.0.113.1",
            "240.0.0.1",
            "::192.168.1.1",
            "::ffff:127.0.0.1",
            "::ffff:0:192.168.1.1",
            "64:ff9b::192.168.1.1",
            "64:ff9b:1::192.168.1.1",
            "2001:db8::1",
            "fe80::1",
        ] {
            assert!(
                is_non_public_ip(address.parse().expect("IP address")),
                "{address} must be blocked"
            );
        }
        assert!(!is_non_public_ip("8.8.8.8".parse().expect("public IPv4")));
        assert!(!is_non_public_ip(
            "2606:4700:4700::1111".parse().expect("public IPv6")
        ));
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
        let app_router = Router::new().route(
            "/v1/fail",
            get(|| async { (StatusCode::BAD_REQUEST, "bad-request") }),
        );
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

        assert!(matches!(err, CliError::UpstreamError { status: 400 }));
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
        insert_session_with_secret(
            &metadata,
            &vault,
            &crypto,
            "oauth",
            "sec1",
            b"not-json",
            None,
        );

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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");

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
