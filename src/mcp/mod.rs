use crate::app::api::ApiApp;
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
}

impl<'a> McpServer<'a> {
    pub fn new(api_app: &'a ApiApp<'a>, provider_app: &'a ProviderApp<'a>) -> Self {
        Self { api_app, provider_app }
    }

    pub async fn run(&self) -> Result<()> {
        let stdin = io::stdin();
        let mut reader = BufReader::new(stdin).lines();
        let mut stdout = io::stdout();

        tracing::info!("Starting MCP server via tokio stdio...");

        while let Some(line) = reader.next_line().await.map_err(|e| crate::error::CliError::Internal(e.to_string()))? {
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
                        error: result.err().map(|e| serde_json::json!({
                            "code": -32000,
                            "message": e.to_string()
                        })),
                    };

                    let res_str = serde_json::to_string(&response).unwrap();
                    stdout.write_all(format!("{}\n", res_str).as_bytes()).await.unwrap_or_default();
                    stdout.flush().await.unwrap_or_default();
                }
                Err(e) => {
                    let err_res = serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": null,
                        "error": {
                            "code": -32700,
                            "message": format!("Parse error: {}", e)
                        }
                    });
                    let err_str = serde_json::to_string(&err_res).unwrap();
                    stdout.write_all(format!("{}\n", err_str).as_bytes()).await.unwrap_or_default();
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
                Ok(serde_json::to_value(providers).unwrap())
            }
            "api_call" => {
                let params = req.params.as_ref()
                    .ok_or_else(|| crate::error::CliError::Internal("Missing params for api_call".into()))?;
                    
                let provider_id = params.get("provider_id").and_then(|v| v.as_str())
                    .ok_or_else(|| crate::error::CliError::Internal("Missing provider_id".into()))?;
                let method = params.get("method").and_then(|v| v.as_str())
                    .ok_or_else(|| crate::error::CliError::Internal("Missing method".into()))?;
                let path = params.get("path").and_then(|v| v.as_str())
                    .ok_or_else(|| crate::error::CliError::Internal("Missing path".into()))?;
                let body = params.get("body").cloned();
                
                // User approval prompt should ideally happen here, 
                // but since it's stdio we need a separate channel or desktop GUI for prompt. 
                // For MCP v1, we bypass interactive prompt or require it to be pre-approved.
                let res = self.api_app.call(provider_id, method, path, body).await?;
                Ok(res)
            }
            _ => {
                Err(crate::error::CliError::Internal(format!("Method not found: {}", req.method)))
            }
        }
    }
}
