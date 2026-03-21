use crate::domain::provider::AuthType;
use crate::domain::session::SessionRecord;
use crate::error::{CliError, Result};
use crate::infra::crypto::VaultCrypto;
use crate::infra::db::{MetadataDb, VaultDb};
use chrono::Utc;
use uuid::Uuid;
use rpassword;

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
    pub fn new(metadata_db: &'a MetadataDb, vault_db: &'a VaultDb, crypto: &'a VaultCrypto) -> Self {
        Self {
            metadata_db,
            vault_db,
            crypto,
            client: Client::new(),
            refresh_lock: tokio::sync::Mutex::new(()),
        }
    }

    pub fn login_api_key(&self, provider_id: &str, api_key: Option<&str>) -> Result<()> {
        let provider = self.metadata_db.get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;

        if provider.auth_type != AuthType::ApiKey {
            return Err(CliError::Internal("Provider does not support API Key auth".into()));
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
        
        self.vault_db.insert_secret(&secret_id, "api_key", &cipher_text, &nonce)?;

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
        let provider = self.metadata_db.get_provider(provider_id)?
            .ok_or_else(|| CliError::ProviderNotFound(provider_id.to_string()))?;
            
        if provider.auth_type != AuthType::OauthPkce {
            return Err(CliError::Internal("Provider does not support OAuth PKCE".into()));
        }

        let client_id = provider.client_id.as_ref().ok_or_else(|| CliError::Internal("Missing client_id".into()))?;
        let auth_url = provider.auth_url.as_ref().ok_or_else(|| CliError::Internal("Missing auth_url".into()))?;
        let token_url = provider.token_url.as_ref().ok_or_else(|| CliError::Internal("Missing token_url".into()))?;

        // 1. Generate PKCE & state
        let (code_verifier, code_challenge, expected_state) = self.generate_pkce_params();

        // 2. Build Authorize URL
        let redirect_uri = "http://127.0.0.1:8080/callback"; // Default for pre-registration
        let authorize_url = self.build_authorize_url(auth_url, client_id, redirect_uri, &provider.scopes, &expected_state, &code_challenge)?;
        
        println!("Open this URL in your browser:\n{}\n", authorize_url);

        // 3. Start callback server and wait for code
        let (code_str, state_str) = self.start_callback_server().await?;

        if state_str != expected_state {
            return Err(CliError::Internal("CSRF token mismatch".into()));
        }

        // 4. Exchange code for token
        let token_result = self.exchange_code_for_token(token_url, client_id, &code_str, redirect_uri, &code_verifier).await?;

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

    fn build_authorize_url(&self, auth_url: &str, client_id: &str, redirect_uri: &str, scopes: &[String], state: &str, challenge: &str) -> Result<url::Url> {
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
        let (tx, rx) = tokio::sync::oneshot::channel::<(String, String)>();
        let tx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

        use axum::{extract::Query, response::Html, routing::get, Router, extract::State};
        let app = Router::new().route("/callback", get(move |Query(params): Query<HashMap<String, String>>, State(tx): State<std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<(String, String)>>>>>| {
            async move {
                let code = params.get("code").cloned().unwrap_or_default();
                let state = params.get("state").cloned().unwrap_or_default();
                if let Some(chan) = tx.lock().await.take() {
                    let _ = chan.send((code, state));
                }
                Html("<html><body>Authentication successful! You can close this window.</body></html>")
            }
        })).with_state(tx);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await
            .map_err(|e| CliError::Internal(format!("Failed to bind to local port: {}", e)))?;
        let addr = listener.local_addr().map_err(|e| CliError::Internal(e.to_string()))?;
        let dynamic_redirect_uri = format!("http://{}/callback", addr);

        println!("Waiting for callback on {} ...", dynamic_redirect_uri);
        println!("Note: If your provider requires a fixed redirect URI, ensure {} is registered.", "http://127.0.0.1:8080/callback");
            
        tokio::select! {
            result = rx => {
                result.map_err(|_| CliError::Internal("Failed to receive callback".into()))
            }
            _ = axum::serve(listener, app) => {
                Err(CliError::Internal("Server exited unexpectedly".into()))
            }
        }
    }

    async fn exchange_code_for_token(&self, token_url: &str, client_id: &str, code: &str, redirect_uri: &str, verifier: &str) -> Result<TokenResponse> {
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);
        params.insert("client_id", client_id);
        params.insert("code_verifier", verifier);

        let res = self.client.post(token_url).form(&params).send().await
            .map_err(|e| CliError::Internal(format!("Token exchange request failed: {}", e)))?;

        if !res.status().is_success() {
            let err_text = res.text().await.unwrap_or_default();
            return Err(CliError::Internal(format!("Token exchange failed: {}", err_text)));
        }

        res.json().await.map_err(|e| CliError::Internal(format!("Failed to parse token response: {}", e)))
    }

    fn store_oauth_session(&self, provider_id: &str, token_result: &TokenResponse, scopes: &[String]) -> Result<()> {
        let payload = serde_json::json!({
            "access_token": token_result.access_token,
            "refresh_token": token_result.refresh_token
        });
        
        let secret_str = payload.to_string();
        let secret_id = format!("oauth_{}_{}", provider_id, Uuid::new_v4());
        let (cipher_text, nonce) = self.crypto.encrypt(secret_str.as_bytes())?;
        
        self.vault_db.insert_secret(&secret_id, "oauth_token", &cipher_text, &nonce)?;

        let expires_in_sec = token_result.expires_in.unwrap_or(0);
        let expires_at = if expires_in_sec > 0 {
            Some(Utc::now() + chrono::Duration::try_seconds(expires_in_sec as i64).unwrap_or(chrono::Duration::zero()))
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

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token_str);
        params.insert("client_id", client_id);

        let res = self.client.post(token_url).form(&params).send().await
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
