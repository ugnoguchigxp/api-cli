use crate::app::api::ApiApp;
use crate::app::approval::ApprovalCache;
use crate::app::provider::ProviderApp;
use crate::error::Result;
use serde::{Deserialize, Serialize};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<serde_json::Value>,
}

pub struct McpServer<'a> {
    api_app: &'a ApiApp<'a>,
    provider_app: &'a ProviderApp<'a>,
    approval_cache: ApprovalCache,
}

impl<'a> McpServer<'a> {
    pub fn new(api_app: &'a ApiApp<'a>, provider_app: &'a ProviderApp<'a>) -> Self {
        Self {
            api_app,
            provider_app,
            approval_cache: ApprovalCache::new(),
        }
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin).lines();
        let mut stdout = io::stdout();

        tracing::info!("Starting MCP server via tokio stdio...");

        while let Some(line) = reader
            .next_line()
            .await
            .map_err(|e| crate::error::CliError::Internal(e.to_string()))?
        {
            if line.trim().is_empty() {
                continue;
            }

            match serde_json::from_str::<JsonRpcRequest>(&line) {
                Ok(req) => {
                    let result = self.handle_request(&req).await;
                    let response = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: req.id,
                        result: result.as_ref().ok().cloned(),
                        error: result.err().map(|e| {
                            serde_json::json!({
                                "code": -32000,
                                "message": e.to_string()
                            })
                        }),
                    };

                    let res_str = serde_json::to_string(&response).map_err(|e| {
                        crate::error::CliError::Internal(format!(
                            "Failed to serialize response: {}",
                            e
                        ))
                    })?;
                    stdout
                        .write_all(format!("{}\n", res_str).as_bytes())
                        .await
                        .unwrap_or_default();
                    stdout.flush().await.unwrap_or_default();
                }
                Err(e) => {
                    let err_res = JsonRpcResponse {
                        jsonrpc: "2.0".to_string(),
                        id: None,
                        result: None,
                        error: Some(serde_json::json!({
                            "code": -32700,
                            "message": format!("Parse error: {}", e)
                        })),
                    };
                    let err_str = serde_json::to_string(&err_res).map_err(|e| {
                        crate::error::CliError::Internal(format!(
                            "Failed to serialize error: {}",
                            e
                        ))
                    })?;
                    stdout
                        .write_all(format!("{}\n", err_str).as_bytes())
                        .await
                        .unwrap_or_default();
                    stdout.flush().await.unwrap_or_default();
                }
            }
        }

        Ok(())
    }

    async fn handle_request(&self, req: &JsonRpcRequest) -> Result<serde_json::Value> {
        match req.method.as_str() {
            "list_providers" => {
                let providers = self.provider_app.list_providers()?;
                Ok(serde_json::to_value(providers).map_err(|e| {
                    crate::error::CliError::Internal(format!("Serialization error: {}", e))
                })?)
            }
            "api_call" => {
                let params = req.params.as_ref().ok_or_else(|| {
                    crate::error::CliError::Internal("Missing params for api_call".into())
                })?;

                let provider_id = params
                    .get("provider_id")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| {
                        crate::error::CliError::Internal("Missing provider_id".into())
                    })?;
                let method = params
                    .get("method")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| crate::error::CliError::Internal("Missing method".into()))?;
                let path = params
                    .get("path")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| crate::error::CliError::Internal("Missing path".into()))?;
                let body = params.get("body").cloned();

                // Approval check
                if !self.approval_cache.is_approved(provider_id, method, path) {
                    // For stdio MCP, we can't easily prompt.
                    // As a temporary measure, we require manual approval via CLI or a separate mechanism.
                    // Here we just return an error asking for approval.
                    return Err(crate::error::CliError::Internal(
                        format!("Action required: This API call ({}: {} {}) requires manual approval. Please run 'api-cli mcp approve {} {} {}' to proceed.", 
                        provider_id, method, path, provider_id, method, path)
                    ));
                }

                let res = self.api_app.call(provider_id, method, path, body).await?;
                Ok(res)
            }
            _ => Err(crate::error::CliError::Internal(format!(
                "Method not found: {}",
                req.method
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::auth::AuthApp;
    use crate::domain::provider::{AuthType, ProviderConfig};
    use crate::infra::crypto::VaultCrypto;
    use crate::infra::db::{MetadataDb, VaultDb};
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn setup() -> (MetadataDb, VaultDb, VaultCrypto) {
        let metadata = MetadataDb::new(Connection::open_in_memory().expect("metadata conn"))
            .expect("metadata init");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault conn"))
            .expect("vault init");
        let dir = tempdir().expect("tempdir");
        let crypto = VaultCrypto::load_or_create(&dir.path().join("vault.key")).expect("crypto init");
        (metadata, vault, crypto)
    }

    fn sample_provider(id: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: "https://api.example.com".to_string(),
            auth_type: AuthType::ApiKey,
            scopes: vec!["read".to_string()],
            client_id: None,
            auth_url: None,
            token_url: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_list_providers_returns_registered_providers() {
        let (metadata, vault, crypto) = setup();
        metadata.insert_provider(&sample_provider("p1")).expect("insert provider");

        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "list_providers".to_string(),
            params: None,
        };

        let value = server.handle_request(&req).await.expect("list providers");
        let providers: Vec<ProviderConfig> = serde_json::from_value(value).expect("deserialize providers");
        assert_eq!(providers.len(), 1);
        assert_eq!(providers[0].id, "p1");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_api_call_requires_params() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "api_call".to_string(),
            params: None,
        };

        let err = server.handle_request(&req).await.expect_err("missing params should fail");
        assert!(matches!(err, crate::error::CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_api_call_requires_manual_approval() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "api_call".to_string(),
            params: Some(serde_json::json!({
                "provider_id": "p1",
                "method": "GET",
                "path": "/v1/resource"
            })),
        };

        let err = server
            .handle_request(&req)
            .await
            .expect_err("approval should be required");
        assert!(matches!(err, crate::error::CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_api_call_requires_provider_id() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "api_call".to_string(),
            params: Some(serde_json::json!({
                "method": "GET",
                "path": "/v1/resource"
            })),
        };

        let err = server.handle_request(&req).await.expect_err("missing provider_id");
        assert!(matches!(err, crate::error::CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_api_call_requires_method() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "api_call".to_string(),
            params: Some(serde_json::json!({
                "provider_id": "p1",
                "path": "/v1/resource"
            })),
        };

        let err = server.handle_request(&req).await.expect_err("missing method");
        assert!(matches!(err, crate::error::CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_api_call_requires_path() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "api_call".to_string(),
            params: Some(serde_json::json!({
                "provider_id": "p1",
                "method": "GET"
            })),
        };

        let err = server.handle_request(&req).await.expect_err("missing path");
        assert!(matches!(err, crate::error::CliError::Internal(_)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn handle_request_returns_method_not_found_for_unknown_method() {
        let (metadata, vault, crypto) = setup();
        let auth = AuthApp::new(&metadata, &vault, &crypto);
        let api_app = ApiApp::new(&metadata, &vault, &crypto, &auth);
        let provider_app = ProviderApp::new(&metadata);
        let server = McpServer::new(&api_app, &provider_app);

        let req = JsonRpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(serde_json::json!(1)),
            method: "unknown_method".to_string(),
            params: None,
        };

        let err = server.handle_request(&req).await.expect_err("unknown method should fail");
        assert!(matches!(err, crate::error::CliError::Internal(_)));
    }
}
