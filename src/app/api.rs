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
    pub fn new(metadata_db: &'a MetadataDb, vault_db: &'a VaultDb, crypto: &'a VaultCrypto, auth_app: &'a AuthApp<'a>) -> Self {
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
        let provider = self.metadata_db.get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        let mut session = self.metadata_db.get_latest_session(provider_id)?
            .ok_or_else(|| CliError::AuthRequired)?;

        if provider.auth_type == crate::domain::provider::AuthType::OauthPkce {
            if let Some(exp) = session.expires_at {
                if chrono::Utc::now() + chrono::Duration::try_seconds(30).unwrap_or(chrono::Duration::zero()) >= exp {
                    tracing::info!("Token expired or expiring soon. Refreshing...");
                    if let Err(e) = self.auth_app.refresh_oauth_token(provider_id).await {
                        tracing::warn!("Failed to refresh token automatically: {}", e);
                    } else {
                        session = self.metadata_db.get_latest_session(provider_id)?
                            .ok_or_else(|| CliError::AuthRequired)?;
                    }
                }
            }
        }

        let (cipher_text, nonce) = self.vault_db.get_secret(&session.secret_id)?
            .ok_or_else(|| CliError::VaultError("Secret not found".into()))?;

        let secret_bytes = self.crypto.decrypt(&cipher_text, &nonce)?;
        let secret_str = String::from_utf8(secret_bytes)
            .map_err(|_| CliError::VaultError("Invalid UTF-8 in secret".into()))?;

        let access_token = if provider.auth_type == crate::domain::provider::AuthType::OauthPkce {
            let json: serde_json::Value = serde_json::from_str(&secret_str).unwrap_or_default();
            json.get("access_token").and_then(|v| v.as_str()).unwrap_or("").to_string()
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

        let res = req.send().await
            .map_err(|e| CliError::Internal(format!("API request failed: {}", e)))?;

        let status = res.status();
        let body_text = res.text().await
            .map_err(|e| CliError::Internal(format!("Failed to read response body: {}", e)))?;

        if !status.is_success() {
            return Err(CliError::Internal(format!("API Error ({}): {}", status, body_text)));
        }

        let json_value: serde_json::Value = serde_json::from_str(&body_text)
            .unwrap_or_else(|_| serde_json::Value::String(body_text));

        Ok(json_value)
    }
}
