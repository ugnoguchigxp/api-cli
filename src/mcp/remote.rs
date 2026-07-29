use super::McpServer;
use crate::app::action::{ActionApp, ExecutionIdentity};
use crate::error::{CliError, Result};
use axum::extract::{Request, State};
use axum::http::{
    header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, WWW_AUTHENTICATE},
    HeaderName, HeaderValue, Method, StatusCode,
};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::Router;
use reqwest::Client;
use rmcp::transport::streamable_http_server::{
    session::{local::LocalSessionManager, SessionManager},
    StreamableHttpServerConfig, StreamableHttpService,
};
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::limit::RequestBodyLimitLayer;

const MCP_SESSION_ID: &str = "mcp-session-id";
const SESSION_BINDING_TTL: Duration = Duration::from_secs(10 * 60);

#[derive(Clone)]
pub struct RemoteMcpConfig {
    pub listen: SocketAddr,
    pub introspection_url: String,
    pub audience: String,
    pub client_id: String,
    pub client_secret: String,
    pub allowed_hosts: Vec<String>,
    pub allowed_origins: Vec<String>,
    pub max_concurrency: usize,
    pub max_sessions: usize,
    pub max_request_bytes: usize,
    pub allow_insecure_http: bool,
}

#[derive(Clone)]
struct AuthState {
    client: Client,
    introspection_url: String,
    audience: String,
    client_id: String,
    client_secret: String,
    semaphore: Arc<tokio::sync::Semaphore>,
    session_manager: Arc<LocalSessionManager>,
    session_bindings: Arc<tokio::sync::Mutex<HashMap<String, BoundSession>>>,
    max_sessions: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SessionSubject {
    principal_id: String,
    tenant_id: String,
    client_id: String,
}

impl From<&ExecutionIdentity> for SessionSubject {
    fn from(identity: &ExecutionIdentity) -> Self {
        Self {
            principal_id: identity.principal_id.clone(),
            tenant_id: identity.tenant_id.clone(),
            client_id: identity.client_id.clone(),
        }
    }
}

#[derive(Clone, Debug)]
struct BoundSession {
    subject: SessionSubject,
    last_seen: Instant,
}

#[derive(Debug, Deserialize)]
struct IntrospectionResponse {
    active: bool,
    sub: Option<String>,
    scope: Option<String>,
    aud: Option<Audience>,
    tenant_id: Option<String>,
    client_id: Option<String>,
    azp: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

impl Audience {
    fn contains(&self, expected: &str) -> bool {
        match self {
            Self::One(value) => value == expected,
            Self::Many(values) => values.iter().any(|value| value == expected),
        }
    }
}

pub async fn run(action_app: &ActionApp, config: RemoteMcpConfig) -> Result<()> {
    validate_config(&config)?;
    let introspection_url = url::Url::parse(&config.introspection_url)
        .map_err(|error| CliError::BlockedUrl(format!("invalid introspection URL: {error}")))?;
    let allow_private_introspection = is_loopback_url(&introspection_url);
    let session_manager = Arc::new(LocalSessionManager::default());
    let auth_state = AuthState {
        client: crate::app::api::configure_dns(Client::builder(), allow_private_introspection)
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(10))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|error| CliError::Internal(error.to_string()))?,
        introspection_url: config.introspection_url.clone(),
        audience: config.audience,
        client_id: config.client_id,
        client_secret: config.client_secret,
        semaphore: Arc::new(tokio::sync::Semaphore::new(config.max_concurrency)),
        session_manager: session_manager.clone(),
        session_bindings: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
        max_sessions: config.max_sessions,
    };
    let handler = McpServer::new_remote(action_app);
    let service: StreamableHttpService<McpServer, LocalSessionManager> = StreamableHttpService::new(
        move || Ok(handler.clone()),
        session_manager,
        StreamableHttpServerConfig::default()
            .with_allowed_hosts(config.allowed_hosts.clone())
            .with_allowed_origins(config.allowed_origins.clone())
            .with_json_response(true),
    );
    let allowed_origins = config
        .allowed_origins
        .iter()
        .map(|origin| {
            HeaderValue::from_str(origin)
                .map_err(|error| CliError::Internal(format!("invalid allowed origin: {error}")))
        })
        .collect::<Result<Vec<_>>>()?;
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::list(allowed_origins))
        .allow_methods([Method::GET, Method::POST, Method::DELETE])
        .allow_headers([
            AUTHORIZATION,
            ACCEPT,
            CONTENT_TYPE,
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("mcp-session-id"),
        ])
        .expose_headers([
            HeaderName::from_static("mcp-session-id"),
            HeaderName::from_static("mcp-protocol-version"),
            HeaderName::from_static("x-request-id"),
        ]);
    let router = Router::new()
        .nest_service("/mcp", service)
        .layer(middleware::from_fn_with_state(
            auth_state,
            authenticate_request,
        ))
        .layer(RequestBodyLimitLayer::new(config.max_request_bytes))
        .layer(cors);
    let listener = tokio::net::TcpListener::bind(config.listen).await?;
    tracing::info!("Remote MCP listening on http://{}/mcp", config.listen);
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(CliError::IoError)
}

fn validate_config(config: &RemoteMcpConfig) -> Result<()> {
    let url = url::Url::parse(&config.introspection_url)
        .map_err(|error| CliError::BlockedUrl(format!("invalid introspection URL: {error}")))?;
    if url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(CliError::BlockedUrl(
            "OAuth introspection URL requires a host and cannot contain credentials or a fragment"
                .into(),
        ));
    }
    let loopback = is_loopback_url(&url);
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(CliError::BlockedUrl(
            "OAuth introspection must use HTTPS except on loopback".into(),
        ));
    }
    if config.audience.is_empty()
        || config.audience.trim() != config.audience
        || config.client_id.is_empty()
        || config.client_id.trim() != config.client_id
        || config.client_secret.is_empty()
        || config.allowed_hosts.is_empty()
        || config.max_concurrency == 0
        || config.max_sessions == 0
        || config.max_request_bytes == 0
        || config.max_request_bytes > 16 * 1024 * 1024
    {
        return Err(CliError::Internal(
            "audience, introspection client credentials, allowed hosts, and positive limits are required"
                .into(),
        ));
    }
    let mut hosts = BTreeSet::new();
    for host in &config.allowed_hosts {
        if host.is_empty()
            || host.trim() != host
            || host.chars().any(char::is_control)
            || !hosts.insert(host)
        {
            return Err(CliError::Internal(
                "allowed hosts must be non-empty, unique, and contain no control characters".into(),
            ));
        }
    }
    let mut origins = BTreeSet::new();
    for origin in &config.allowed_origins {
        if !origins.insert(origin) {
            return Err(CliError::Internal("allowed origins must be unique".into()));
        }
        let origin_url = url::Url::parse(origin)
            .map_err(|error| CliError::Internal(format!("invalid allowed origin: {error}")))?;
        if !matches!(origin_url.scheme(), "http" | "https")
            || origin_url.host_str().is_none()
            || !origin_url.username().is_empty()
            || origin_url.password().is_some()
            || origin_url.path() != "/"
            || origin_url.query().is_some()
            || origin_url.fragment().is_some()
        {
            return Err(CliError::Internal(format!(
                "allowed origin must be an HTTP(S) origin without path, query, credentials, or fragment: {origin}"
            )));
        }
    }
    if !config.listen.ip().is_loopback() && config.allowed_origins.is_empty() {
        return Err(CliError::Internal(
            "non-loopback Remote MCP requires at least one --allowed-origin".into(),
        ));
    }
    if !config.listen.ip().is_loopback() && !config.allow_insecure_http {
        return Err(CliError::Internal(
            "non-loopback cleartext HTTP requires --allow-insecure-http; prefer a loopback TLS reverse proxy"
                .into(),
        ));
    }
    Ok(())
}

fn is_loopback_url(url: &url::Url) -> bool {
    url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<std::net::IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    })
}

async fn authenticate_request(
    State(state): State<AuthState>,
    mut request: Request,
    next: Next,
) -> Response {
    let permit = match state.semaphore.clone().try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return (StatusCode::TOO_MANY_REQUESTS, "Too many requests").into_response(),
    };
    let request_id = uuid::Uuid::new_v4().to_string();
    match introspect(&state, request.headers().get(AUTHORIZATION)).await {
        Ok(identity) => {
            let subject = SessionSubject::from(&identity);
            let incoming_session = match request.headers().get(MCP_SESSION_ID) {
                Some(value) => match value.to_str() {
                    Ok(value) if !value.is_empty() && value.len() <= 256 => Some(value.to_string()),
                    _ => {
                        return unauthorized_response(
                            "Remote MCP request has an invalid session identifier",
                        );
                    }
                },
                None => None,
            };
            if let Some(session_id) = incoming_session.as_deref() {
                let mut bindings = state.session_bindings.lock().await;
                bindings.retain(|_, binding| binding.last_seen.elapsed() <= SESSION_BINDING_TTL);
                match bindings.get_mut(session_id) {
                    Some(binding) if binding.subject == subject => {
                        binding.last_seen = Instant::now();
                    }
                    _ => {
                        return unauthorized_response(
                            "Remote MCP session is not bound to this authenticated subject",
                        );
                    }
                }
            } else {
                let mut bindings = state.session_bindings.lock().await;
                bindings.retain(|_, binding| binding.last_seen.elapsed() <= SESSION_BINDING_TTL);
                if bindings.len() >= state.max_sessions
                    || state.session_manager.sessions.read().await.len() >= state.max_sessions
                {
                    return (StatusCode::TOO_MANY_REQUESTS, "Too many MCP sessions")
                        .into_response();
                }
            }
            let method = request.method().clone();
            request.extensions_mut().insert(identity);
            let mut response = next.run(request).await;
            if method == Method::DELETE && response.status().is_success() {
                if let Some(session_id) = incoming_session.as_deref() {
                    state.session_bindings.lock().await.remove(session_id);
                }
            } else if incoming_session.is_none() {
                if let Some(session_id) = response
                    .headers()
                    .get(MCP_SESSION_ID)
                    .and_then(|value| value.to_str().ok())
                {
                    let mut bindings = state.session_bindings.lock().await;
                    bindings
                        .retain(|_, binding| binding.last_seen.elapsed() <= SESSION_BINDING_TTL);
                    if bindings.len() >= state.max_sessions {
                        let session_id = session_id.to_string().into();
                        drop(bindings);
                        let _ = state.session_manager.close_session(&session_id).await;
                        return (StatusCode::TOO_MANY_REQUESTS, "Too many MCP sessions")
                            .into_response();
                    }
                    bindings.insert(
                        session_id.to_string(),
                        BoundSession {
                            subject,
                            last_seen: Instant::now(),
                        },
                    );
                }
            }
            if let Ok(value) = HeaderValue::from_str(&request_id) {
                response
                    .headers_mut()
                    .insert(HeaderName::from_static("x-request-id"), value);
            }
            drop(permit);
            response
        }
        Err(message) => unauthorized_response(message),
    }
}

fn unauthorized_response(message: &str) -> Response {
    tracing::warn!("Remote MCP authentication rejected: {message}");
    let mut response = (StatusCode::UNAUTHORIZED, "Unauthorized").into_response();
    response.headers_mut().insert(
        WWW_AUTHENTICATE,
        HeaderValue::from_static("Bearer error=\"invalid_token\""),
    );
    response
}

async fn introspect(
    state: &AuthState,
    authorization: Option<&HeaderValue>,
) -> std::result::Result<ExecutionIdentity, &'static str> {
    let authorization = authorization
        .and_then(|value| value.to_str().ok())
        .ok_or("missing Authorization header")?;
    let (scheme, token) = authorization
        .split_once(' ')
        .filter(|(scheme, token)| {
            scheme.eq_ignore_ascii_case("bearer")
                && !token.is_empty()
                && token.len() <= 16 * 1024
                && !token.chars().any(char::is_whitespace)
        })
        .ok_or("invalid bearer scheme")?;
    debug_assert!(scheme.eq_ignore_ascii_case("bearer"));
    let response = state
        .client
        .post(&state.introspection_url)
        .basic_auth(&state.client_id, Some(&state.client_secret))
        .form(&[("token", token), ("token_type_hint", "access_token")])
        .send()
        .await
        .map_err(|_| "introspection request failed")?;
    if !response.status().is_success() {
        return Err("introspection endpoint rejected the request");
    }
    let bytes = crate::app::api::read_limited_response(response, 64 * 1024)
        .await
        .map_err(|_| "invalid introspection response size")?;
    let response: IntrospectionResponse =
        serde_json::from_slice(&bytes).map_err(|_| "invalid introspection response")?;
    if !response.active {
        return Err("inactive token");
    }
    if !response
        .aud
        .as_ref()
        .is_some_and(|audience| audience.contains(&state.audience))
    {
        return Err("token audience mismatch");
    }
    let principal_id = response
        .sub
        .filter(|value| valid_identity_claim(value))
        .ok_or("token subject is missing")?;
    let tenant_id = response
        .tenant_id
        .filter(|value| valid_identity_claim(value))
        .ok_or("token tenant is missing")?;
    let client_id = response
        .client_id
        .or(response.azp)
        .filter(|value| valid_identity_claim(value))
        .ok_or("authorized client is missing")?;
    let scope = response.scope.unwrap_or_default();
    let scope_values = scope.split_ascii_whitespace().collect::<Vec<_>>();
    if scope_values.len() > 256
        || scope_values.iter().any(|scope| {
            scope.is_empty() || scope.len() > 256 || scope.chars().any(char::is_control)
        })
    {
        return Err("token scope set is invalid");
    }
    let scopes = scope_values
        .into_iter()
        .map(str::to_string)
        .collect::<BTreeSet<_>>();
    Ok(ExecutionIdentity {
        principal_id,
        tenant_id,
        client_id,
        scopes,
    })
}

fn valid_identity_claim(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

use axum::response::IntoResponse;

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> RemoteMcpConfig {
        RemoteMcpConfig {
            listen: "127.0.0.1:0".parse().expect("address"),
            introspection_url: "https://id.example.com/introspect".into(),
            audience: "https://broker.example.com/mcp".into(),
            client_id: "broker".into(),
            client_secret: "secret".into(),
            allowed_hosts: vec!["broker.example.com".into()],
            allowed_origins: vec![],
            max_concurrency: 64,
            max_sessions: 1024,
            max_request_bytes: 1024 * 1024,
            allow_insecure_http: false,
        }
    }

    #[test]
    fn rejects_non_loopback_deployment_without_origin_allowlist() {
        let mut config = config();
        config.listen = "0.0.0.0:8080".parse().expect("address");
        assert!(validate_config(&config).is_err());
    }

    #[test]
    fn non_loopback_cleartext_listener_requires_explicit_opt_in() {
        let mut config = config();
        config.listen = "0.0.0.0:8080".parse().expect("address");
        config.allowed_origins = vec!["https://app.example.com".into()];
        assert!(validate_config(&config).is_err());
        config.allow_insecure_http = true;
        validate_config(&config).expect("explicit opt-in");
    }

    #[test]
    fn audience_requires_exact_member_match() {
        let audience = Audience::Many(vec!["api".into(), "broker".into()]);
        assert!(audience.contains("broker"));
        assert!(!audience.contains("bro"));
    }

    #[tokio::test]
    async fn introspection_binds_subject_tenant_audience_and_scopes() {
        use axum::{routing::post, Json};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let router = Router::new().route(
            "/introspect",
            post(|| async {
                Json(serde_json::json!({
                    "active": true,
                    "sub": "user-1",
                    "tenant_id": "tenant-1",
                    "client_id": "mcp-client-1",
                    "aud": ["other", "broker"],
                    "scope": "customer:read customer:search"
                }))
            }),
        );
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let state = AuthState {
            client: Client::new(),
            introspection_url: format!("http://{address}/introspect"),
            audience: "broker".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            session_manager: Arc::new(LocalSessionManager::default()),
            session_bindings: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            max_sessions: 8,
        };
        let identity = introspect(
            &state,
            Some(&HeaderValue::from_static("bearer access-token")),
        )
        .await
        .expect("introspection");
        task.abort();
        assert_eq!(identity.principal_id, "user-1");
        assert_eq!(identity.tenant_id, "tenant-1");
        assert_eq!(identity.client_id, "mcp-client-1");
        assert!(identity.scopes.contains("customer:read"));
        assert!(!identity.scopes.contains("customer:write"));
    }

    #[tokio::test]
    async fn mcp_session_is_bound_to_the_authenticated_subject() {
        use axum::{extract::Form, routing::post, Json};

        let introspection_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind introspection");
        let introspection_address = introspection_listener.local_addr().expect("address");
        let introspection_router = Router::new().route(
            "/introspect",
            post(|Form(form): Form<HashMap<String, String>>| async move {
                let subject = match form.get("token").map(String::as_str) {
                    Some("token-a") => "user-a",
                    Some("token-b") => "user-b",
                    _ => "unknown",
                };
                Json(serde_json::json!({
                    "active": true,
                    "sub": subject,
                    "tenant_id": "tenant-1",
                    "client_id": "mcp-client",
                    "aud": "broker",
                    "scope": "customer:read"
                }))
            }),
        );
        let introspection_task = tokio::spawn(async move {
            let _ = axum::serve(introspection_listener, introspection_router).await;
        });

        let session_manager = Arc::new(LocalSessionManager::default());
        let auth_state = AuthState {
            client: Client::new(),
            introspection_url: format!("http://{introspection_address}/introspect"),
            audience: "broker".into(),
            client_id: "client".into(),
            client_secret: "secret".into(),
            semaphore: Arc::new(tokio::sync::Semaphore::new(4)),
            session_manager,
            session_bindings: Arc::new(tokio::sync::Mutex::new(HashMap::new())),
            max_sessions: 8,
        };
        let broker_router = Router::new()
            .route(
                "/",
                post(|_body: String| async {
                    let mut response = StatusCode::OK.into_response();
                    response.headers_mut().insert(
                        HeaderName::from_static(MCP_SESSION_ID),
                        HeaderValue::from_static("session-a"),
                    );
                    response
                }),
            )
            .layer(middleware::from_fn_with_state(
                auth_state,
                authenticate_request,
            ))
            .layer(RequestBodyLimitLayer::new(1024));
        let broker_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind broker");
        let broker_address = broker_listener.local_addr().expect("address");
        let broker_task = tokio::spawn(async move {
            let _ = axum::serve(broker_listener, broker_router).await;
        });

        let client = Client::new();
        let first = client
            .post(format!("http://{broker_address}/"))
            .bearer_auth("token-a")
            .send()
            .await
            .expect("first request");
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(
            first
                .headers()
                .get(MCP_SESSION_ID)
                .and_then(|value| value.to_str().ok()),
            Some("session-a")
        );

        let hijack = client
            .post(format!("http://{broker_address}/"))
            .bearer_auth("token-b")
            .header(MCP_SESSION_ID, "session-a")
            .send()
            .await
            .expect("hijack request");
        assert_eq!(hijack.status(), StatusCode::UNAUTHORIZED);

        let oversized = client
            .post(format!("http://{broker_address}/"))
            .bearer_auth("token-a")
            .body("x".repeat(1025))
            .send()
            .await
            .expect("oversized request");
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);

        broker_task.abort();
        introspection_task.abort();
    }
}
