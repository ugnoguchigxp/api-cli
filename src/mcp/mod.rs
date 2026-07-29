use crate::app::action::{ActionApp, ExecutionIdentity};
use crate::domain::action::RiskLevel;
use crate::error::{CliError, Result};
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ElicitRequest, ElicitRequestParams,
    ErrorData, Implementation, InputRequest, InputRequests, InputRequiredResult, ListToolsResult,
    PaginatedRequestParams, ProtocolVersion, ServerCapabilities, ServerInfo, Tool, ToolAnnotations,
};
use rmcp::service::RequestContext;
use rmcp::{RoleServer, ServerHandler, ServiceExt};
use serde_json::{json, Value};
use std::sync::Arc;

pub mod remote;

#[derive(Clone)]
pub struct McpServer {
    action_app: ActionApp,
    remote: bool,
}

impl McpServer {
    pub fn new(action_app: &ActionApp) -> Self {
        Self {
            action_app: action_app.clone(),
            remote: false,
        }
    }

    pub fn new_remote(action_app: &ActionApp) -> Self {
        Self {
            action_app: action_app.clone(),
            remote: true,
        }
    }

    pub async fn run(self) -> Result<()> {
        tracing::info!("Starting MCP server over stdio");
        self.serve(rmcp::transport::stdio())
            .await
            .map_err(|error| CliError::Internal(format!("MCP initialization failed: {error}")))?
            .waiting()
            .await
            .map_err(|error| CliError::Internal(format!("MCP server failed: {error}")))?;
        Ok(())
    }

    fn tools(&self, identity: &ExecutionIdentity) -> Result<Vec<Tool>> {
        self.action_app
            .registry()
            .list()
            .into_iter()
            .filter(|action| !self.remote || action.spec.risk.is_read_only())
            .map(|action| Ok((action, self.action_app.is_available(identity, action)?)))
            .filter_map(|result: Result<_>| match result {
                Ok((action, true)) => Some(Ok(action)),
                Ok((_, false)) => None,
                Err(error) => Some(Err(error)),
            })
            .filter_map(|action| {
                let action = match action {
                    Ok(action) => action,
                    Err(error) => return Some(Err(error)),
                };
                let Value::Object(input_schema) = action.spec.input_schema.clone() else {
                    return None;
                };
                let annotations = ToolAnnotations::new()
                    .read_only(action.spec.risk == RiskLevel::Read)
                    .destructive(matches!(
                        action.spec.risk,
                        RiskLevel::Destructive | RiskLevel::Privileged
                    ))
                    .idempotent(
                        action.spec.risk == RiskLevel::Read
                            || action.spec.constraints.idempotency_header.is_some(),
                    )
                    .open_world(true);
                let mut tool = Tool::new(
                    action.metadata.name.clone(),
                    action.metadata.description.clone(),
                    input_schema,
                )
                .with_annotations(annotations);
                if let Some(Value::Object(output_schema)) = action.spec.output_schema.clone() {
                    tool = tool.with_raw_output_schema(Arc::new(output_schema));
                }
                Some(Ok(tool))
            })
            .collect()
    }

    async fn invoke(
        &self,
        request: CallToolRequestParams,
        identity: ExecutionIdentity,
    ) -> CallToolResponse {
        let name = request.name.to_string();
        let Some(action) = self.action_app.registry().get(&name) else {
            return tool_error(CliError::ActionNotFound(name), self.remote);
        };
        let input = Value::Object(request.arguments.clone().unwrap_or_default());
        if self.remote && !action.spec.risk.is_read_only() {
            return tool_error(CliError::AuthorizationDenied(
                "remote write Actions require a separately configured server-side approval service"
                    .into(),
            ), self.remote);
        }
        if action.spec.risk.is_read_only()
            && (request.request_state.is_some() || request.input_responses.is_some())
        {
            return tool_error(CliError::InvalidApproval, self.remote);
        }

        if !action.spec.risk.is_read_only() && request.request_state.is_none() {
            let ticket = match self.action_app.prepare(&identity, &name, &input) {
                Ok(ticket) => ticket,
                Err(error) => return tool_error(error, self.remote),
            };
            let requested_schema = match serde_json::from_value(json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "confirmed": {
                        "type": "boolean",
                        "description": "Confirm this exact action invocation"
                    }
                },
                "required": ["confirmed"]
            })) {
                Ok(schema) => schema,
                Err(error) => {
                    return tool_error(
                        CliError::Internal(format!("approval schema failed: {error}")),
                        self.remote,
                    );
                }
            };
            let mut requests = InputRequests::new();
            requests.insert(
                "approval".into(),
                InputRequest::Elicitation(ElicitRequest::new(
                    ElicitRequestParams::FormElicitationParams {
                        meta: None,
                        message: format!(
                            "Approve action '{}' ({:?}) against provider '{}'? The approval is one-time and bound to the complete arguments (the display preview may be truncated):\n{}",
                            action.metadata.name,
                            action.spec.risk,
                            action.spec.executor.provider,
                            approval_preview(&input),
                        ),
                        requested_schema,
                    },
                )),
            );
            return InputRequiredResult::new(Some(requests), Some(ticket)).into();
        }

        let ticket = request.request_state.as_deref();
        if let Some(ticket) = ticket {
            let confirmed = request
                .input_responses
                .as_ref()
                .and_then(|responses| responses.get("approval"))
                .is_some_and(|response| {
                    response.get("action").and_then(Value::as_str) == Some("accept")
                        && response
                            .pointer("/content/confirmed")
                            .and_then(Value::as_bool)
                            == Some(true)
                });
            if !confirmed {
                let _ = self.action_app.deny(&identity, ticket);
                return tool_error(CliError::InvalidApproval, self.remote);
            }
            if let Err(error) = self.action_app.approve(&identity, ticket) {
                return tool_error(error, self.remote);
            }
        }

        match self
            .action_app
            .run_for(&identity, &name, input, ticket)
            .await
        {
            Ok(output) => CallToolResult::structured(output).into(),
            Err(error) => tool_error(error, self.remote),
        }
    }
}

fn approval_preview(input: &Value) -> String {
    const MAX_CHARS: usize = 4096;
    let rendered = serde_json::to_string_pretty(input).unwrap_or_else(|_| "{}".into());
    let mut characters = rendered.chars();
    let preview = characters.by_ref().take(MAX_CHARS).collect::<String>();
    if characters.next().is_some() {
        format!("{preview}\n… (truncated; approval remains bound to the complete arguments)")
    } else {
        preview
    }
}

fn identity_from_context(
    context: &RequestContext<RoleServer>,
    remote: bool,
) -> std::result::Result<ExecutionIdentity, ErrorData> {
    if !remote {
        return Ok(ExecutionIdentity::local_mcp());
    }
    context
        .extensions
        .get::<axum::http::request::Parts>()
        .and_then(|parts| parts.extensions.get::<ExecutionIdentity>())
        .cloned()
        .ok_or_else(|| ErrorData::invalid_request("authenticated identity is missing", None))
}

fn tool_error(error: CliError, remote: bool) -> CallToolResponse {
    let message = if remote
        && matches!(
            &error,
            CliError::DatabaseError(_)
                | CliError::VaultError(_)
                | CliError::IoError(_)
                | CliError::BlockedUrl(_)
                | CliError::Internal(_)
        ) {
        "The broker could not complete the operation".into()
    } else {
        error.to_string()
    };
    CallToolResult::structured_error(json!({
        "error": {
            "type": error_type(&error),
            "message": message
        }
    }))
    .into()
}

fn error_type(error: &CliError) -> &'static str {
    match error {
        CliError::ActionNotFound(_) => "action_not_found",
        CliError::SchemaValidation { .. } => "schema_validation",
        CliError::AuthorizationDenied(_) => "authorization_denied",
        CliError::ApprovalRequired { .. } => "approval_required",
        CliError::InvalidApproval => "invalid_approval",
        CliError::AuthRequired | CliError::AuthExpired => "authentication",
        CliError::RequestTimeout { .. } => "timeout",
        CliError::ResponseTooLarge { .. } => "response_too_large",
        CliError::UpstreamError { .. } => "upstream_error",
        CliError::UpstreamResultUnknown => "upstream_result_unknown",
        CliError::BlockedUrl(_) => "blocked_url",
        _ => "execution_failed",
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("api-cli", env!("CARGO_PKG_VERSION")));
        info.protocol_version = ProtocolVersion::V_2026_07_28;
        info.instructions = Some(
            "Only explicitly enabled ActionDefinitions are exposed. Generic HTTP calls are unavailable."
                .into(),
        );
        info
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<ListToolsResult, ErrorData> {
        let identity = identity_from_context(&context, self.remote)?;
        let remote = self.remote;
        Ok(ListToolsResult {
            tools: self.tools(&identity).map_err(|error| {
                ErrorData::internal_error(
                    if remote {
                        "failed to enumerate authorized tools".into()
                    } else {
                        error.to_string()
                    },
                    None,
                )
            })?,
            ..Default::default()
        })
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> std::result::Result<CallToolResponse, ErrorData> {
        let identity = identity_from_context(&context, self.remote)?;
        Ok(self.invoke(request, identity).await)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::action::ActionRegistry;
    use crate::app::api::ApiApp;
    use crate::app::auth::AuthApp;
    use crate::domain::action::{
        ActionConstraints, ActionDefinition, ActionMetadata, ActionSpec, ApprovalMode,
        HttpExecutorDefinition,
    };
    use crate::domain::provider::{AuthType, CredentialPlacement, ProviderConfig};
    use crate::infra::crypto::VaultCrypto;
    use crate::infra::db::{MetadataDb, VaultDb};
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn setup() -> McpServer {
        setup_action("customer.get", "GET", RiskLevel::Read, ApprovalMode::Never)
    }

    fn setup_action(
        name: &str,
        method: &str,
        risk: RiskLevel,
        approval: ApprovalMode,
    ) -> McpServer {
        let metadata =
            MetadataDb::new(Connection::open_in_memory().expect("metadata")).expect("db");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault")).expect("db");
        let directory = tempdir().expect("tempdir");
        let crypto = VaultCrypto::load_or_create(&directory.path().join("key")).expect("crypto");
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        metadata
            .insert_provider(&ProviderConfig {
                id: "crm".into(),
                base_url: "https://api.example.com".into(),
                auth_type: AuthType::ApiKey,
                scopes: vec![],
                client_id: None,
                auth_url: None,
                token_url: None,
                credential_placement: CredentialPlacement::Bearer,
                oauth_redirect_port: None,
                allow_private_network: false,
            })
            .expect("provider");
        auth.login_api_key("crm", Some("secret"))
            .expect("API key login");
        let api = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let definition = ActionDefinition {
            api_version: "apicli.dev/v1alpha1".into(),
            kind: "Action".into(),
            metadata: ActionMetadata {
                name: name.into(),
                version: 1,
                description: "Get customer".into(),
                enabled: true,
            },
            spec: ActionSpec {
                input_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {}
                }),
                output_schema: Some(json!({"type": "object"})),
                executor: HttpExecutorDefinition {
                    kind: "openapi".into(),
                    provider: "crm".into(),
                    operation_id: "getCustomer".into(),
                    method: method.into(),
                    path: "/customers".into(),
                    parameters: Default::default(),
                },
                risk,
                approval,
                broker_scopes: vec![],
                upstream_scopes: vec![],
                constraints: ActionConstraints::default(),
            },
        };
        let registry = ActionRegistry::from_actions(vec![definition]).expect("registry");
        let app = ActionApp::new(registry, &api, &metadata);
        McpServer::new(&app)
    }

    #[test]
    fn exposes_action_tools_and_never_generic_api_call() {
        let server = setup();
        let tools = server
            .tools(&ExecutionIdentity::local())
            .expect("list tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "customer.get");
        assert!(!tools.iter().any(|tool| tool.name == "api_call"));
    }

    #[test]
    fn advertises_current_mcp_and_tool_capability() {
        let info = setup().get_info();
        assert_eq!(info.protocol_version, ProtocolVersion::V_2026_07_28);
        assert!(info.capabilities.tools.is_some());
    }

    #[test]
    fn remote_identity_cannot_use_another_users_upstream_credential() {
        let mut server = setup();
        server.remote = true;
        let identity = ExecutionIdentity {
            principal_id: "remote-user".into(),
            tenant_id: "tenant-1".into(),
            client_id: "client-1".into(),
            scopes: std::collections::BTreeSet::from(["*".into()]),
        };
        assert!(server.tools(&identity).expect("list tools").is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn write_tool_returns_mrtr_input_required_with_opaque_ticket() {
        let server = setup_action(
            "customer.update",
            "PATCH",
            RiskLevel::ReversibleWrite,
            ApprovalMode::Always,
        );
        let response = server
            .invoke(
                CallToolRequestParams::new("customer.update")
                    .with_arguments(serde_json::Map::new()),
                ExecutionIdentity::local_mcp(),
            )
            .await;
        match response {
            CallToolResponse::InputRequired(result) => {
                assert!(result
                    .request_state
                    .as_deref()
                    .is_some_and(|state| !state.is_empty()));
                assert!(result
                    .input_requests
                    .as_ref()
                    .is_some_and(|requests| requests.contains_key("approval")));
            }
            other => panic!("expected input_required, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn read_tool_rejects_unexpected_mrtr_state() {
        let server = setup();
        let response = server
            .invoke(
                CallToolRequestParams::new("customer.get")
                    .with_arguments(serde_json::Map::new())
                    .with_request_state("unrelated-approval-ticket"),
                ExecutionIdentity::local_mcp(),
            )
            .await;
        match response {
            CallToolResponse::Complete(result) => {
                assert_eq!(
                    result
                        .structured_content
                        .as_ref()
                        .and_then(|value| value.pointer("/error/type"))
                        .and_then(Value::as_str),
                    Some("invalid_approval")
                );
            }
            other => panic!("expected complete error response, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rmcp_client_completes_handshake_and_lists_tools() {
        let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);
        let server = setup();
        let server_task = tokio::spawn(async move {
            server
                .serve(server_transport)
                .await
                .expect("serve")
                .waiting()
                .await
                .expect("server completion");
        });
        let client = ().serve(client_transport).await.expect("client handshake");
        let tools = client.list_all_tools().await.expect("list tools");
        assert_eq!(tools.len(), 1);
        assert_eq!(tools[0].name, "customer.get");
        client.cancel().await.expect("cancel");
        server_task.await.expect("join");
    }
}
