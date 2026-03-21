use crate::domain::provider::AuthType;
use crate::domain::session::SessionRecord;
use crate::error::{CliError, Result};
use crate::infra::crypto::VaultCrypto;
use crate::infra::db::{MetadataDb, VaultDb};
use chrono::Utc;

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
    refresh_lock: tokio::sync::Mutex<()>,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

impl<'a> AuthApp<'a> {
    pub fn new(metadata_db: &'a MetadataDb, vault_db: &'a VaultDb, crypto: &'a VaultCrypto) -> Self {
        Self { metadata_db, vault_db, crypto, refresh_lock: tokio::sync::Mutex::new(()) }
    }

    pub fn login_api_key(&self, provider_id: &str, api_key: &str) -> Result<()> {
        let provider = self.metadata_db.get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        if provider.auth_type != AuthType::ApiKey {
            return Err(CliError::Internal("Provider does not support API Key auth".into()));
        }

        let secret_id = format!("apikey_{}_{}", provider_id, Utc::now().timestamp());
        let (cipher_text, nonce) = self.crypto.encrypt(api_key.as_bytes())?;
        
        self.vault_db.insert_secret(&secret_id, "api_key", &cipher_text, &nonce)?;

        let session = SessionRecord {
            session_id: format!("sess_{}", Utc::now().timestamp()),
            provider_id: provider_id.to_string(),
            scopes: provider.scopes.clone(),
            expires_at: None,
            secret_id,
        };
        self.metadata_db.insert_session(&session)?;

        Ok(())
    }

    pub async fn login_oauth_pkce(&self, provider_id: &str) -> Result<()> {
        let provider = self.metadata_db.get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;
            
        if provider.auth_type != AuthType::OauthPkce {
            return Err(CliError::Internal("Provider does not support OAuth PKCE".into()));
        }

        let client_id = provider.client_id.as_ref().ok_or_else(|| CliError::Internal("Missing client_id".into()))?;
        let auth_url = provider.auth_url.as_ref().ok_or_else(|| CliError::Internal("Missing auth_url".into()))?;
        let token_url = provider.token_url.as_ref().ok_or_else(|| CliError::Internal("Missing token_url".into()))?;

        // 1. Generate state
        let mut state_bytes = [0u8; 16];
        OsRng.fill_bytes(&mut state_bytes);
        let expected_state = URL_SAFE_NO_PAD.encode(state_bytes);

        // 2. Generate PKCE verifier
        let mut verifier_bytes = [0u8; 32];
        OsRng.fill_bytes(&mut verifier_bytes);
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);

        // 3. Generate PKCE challenge
        let mut hasher = Sha256::new();
        hasher.update(code_verifier.as_bytes());
        let code_challenge = URL_SAFE_NO_PAD.encode(hasher.finalize());

        let redirect_uri = "http://127.0.0.1:8080/callback";
        let scopes = provider.scopes.join(" ");

        let mut authorize_url = url::Url::parse(auth_url).map_err(|e| CliError::Internal(e.to_string()))?;
        authorize_url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &scopes)
            .append_pair("state", &expected_state)
            .append_pair("code_challenge", &code_challenge)
            .append_pair("code_challenge_method", "S256");

        println!("Open this URL in your browser:\n{}\n", authorize_url);
        println!("Waiting for callback on {} ...", redirect_uri);

        // Axum server setup
        let (tx, rx) = tokio::sync::oneshot::channel::<(String, String)>();
        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

        use axum::{extract::Query, response::Html, routing::get, Router};
        let app = Router::new().route("/callback", get(move |Query(params): Query<HashMap<String, String>>| {
            let tx = tx.clone();
            async move {
                let code = params.get("code").cloned().unwrap_or_default();
                let state = params.get("state").cloned().unwrap_or_default();
                if let Some(chan) = tx.lock().await.take() {
                    let _ = chan.send((code, state));
                }
                Html("<html><body>Authentication successful! You can close this window.</body></html>")
            }
        }));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await
            .map_err(|e| CliError::Internal(format!("Failed to bind to 8080: {}", e)))?;
            
        let (code_str, state_str) = tokio::select! {
            result = rx => {
                result.map_err(|_| CliError::Internal("Failed to receive callback".into()))?
            }
            _ = axum::serve(listener, app) => {
                return Err(CliError::Internal("Server exited unexpectedly".into()));
            }
        };

        if state_str != expected_state {
            return Err(CliError::Internal("CSRF token mismatch".into()));
        }

        // Exchange code for token
        let client = Client::new();
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", &code_str);
        params.insert("redirect_uri", redirect_uri);
        params.insert("client_id", client_id);
        params.insert("code_verifier", &code_verifier);

        let res = client.post(token_url).form(&params).send().await
            .map_err(|e| CliError::Internal(format!("Token exchange request failed: {}", e)))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(CliError::Internal(format!("Token exchange failed: {}", err_text)));
        }

        let token_result: TokenResponse = res.json().await
            .map_err(|e| CliError::Internal(format!("Failed to parse token response: {}", e)))?;

        let access_token = token_result.access_token;
        let payload = serde_json::json!({
            "access_token": access_token,
            "refresh_token": token_result.refresh_token
        });
        
        let secret_str = payload.to_string();
        let secret_id = format!("oauth_{}_{}", provider_id, Utc::now().timestamp());
        let (cipher_text, nonce) = self.crypto.encrypt(secret_str.as_bytes())?;
        
        self.vault_db.insert_secret(&secret_id, "oauth_token", &cipher_text, &nonce)?;

        let expires_in_sec = token_result.expires_in.unwrap_or(0);
        let expires_at = if expires_in_sec > 0 {
            Some(Utc::now() + chrono::Duration::try_seconds(expires_in_sec as i64).unwrap_or(chrono::Duration::zero()))
        } else {
            None
        };

        let session = SessionRecord {
            session_id: format!("sess_{}", Utc::now().timestamp()),
            provider_id: provider_id.to_string(),
            scopes: provider.scopes.clone(),
            expires_at,
            secret_id,
        };
        self.metadata_db.insert_session(&session)?;

        Ok(())
    }

    pub async fn refresh_oauth_token(&self, provider_id: &str) -> Result<()> {
        let _guard = self.refresh_lock.lock().await;
        
        let provider = self.metadata_db.get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;
            
        if provider.auth_type != AuthType::OauthPkce {
            return Err(CliError::Internal("Provider does not support OAuth PKCE".into()));
        }

        let session = self.metadata_db.get_latest_session(provider_id)?
            .ok_or_else(|| CliError::AuthRequired)?;

        // DBに記録されている最新のExpiresを見て、すでに他の呼び出しによって更新済みであればスキップ
        if let Some(exp) = session.expires_at {
            if chrono::Utc::now() + chrono::Duration::try_seconds(30).unwrap_or(chrono::Duration::zero()) < exp {
                tracing::info!("Token was already refreshed by another parallel request.");
                return Ok(());
            }
        }

        let (cipher_text, nonce) = self.vault_db.get_secret(&session.secret_id)?
            .ok_or_else(|| CliError::VaultError("Secret not found".into()))?;

        let secret_bytes = self.crypto.decrypt(&cipher_text, &nonce)?;
        let secret_json: serde_json::Value = serde_json::from_slice(&secret_bytes)
            .map_err(|_| CliError::VaultError("Invalid JSON in secret".into()))?;
            
        let refresh_token_str = secret_json.get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or_else(|| CliError::Internal("No refresh_token found in vault".into()))?;

        let client_id = provider.client_id.as_ref().ok_or_else(|| CliError::Internal("Missing client_id".into()))?;
        let token_url = provider.token_url.as_ref().ok_or_else(|| CliError::Internal("Missing token_url".into()))?;

        let client = Client::new();
        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token_str);
        params.insert("client_id", client_id);

        let res = client.post(token_url).form(&params).send().await
            .map_err(|e| CliError::Internal(format!("Token refresh request failed: {}", e)))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(CliError::Internal(format!("Token refresh failed: {}", err_text)));
        }

        let token_result: TokenResponse = res.json().await
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
        
        self.vault_db.insert_secret(&session.secret_id, "oauth_token", &new_cipher, &new_nonce)?;

        let expires_in_sec = token_result.expires_in.unwrap_or(0);
        let expires_at = if expires_in_sec > 0 {
            Some(Utc::now() + chrono::Duration::try_seconds(expires_in_sec as i64).unwrap_or(chrono::Duration::zero()))
        } else {
            None
        };

        let mut updated_session = session;
        updated_session.expires_at = expires_at;
        self.metadata_db.insert_session(&updated_session)?;

        Ok(())
    }
}
