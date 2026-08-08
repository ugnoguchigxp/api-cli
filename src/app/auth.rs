use crate::domain::provider::AuthType;
use crate::domain::session::SessionRecord;
use crate::error::{CliError, Result};
use crate::infra::crypto::VaultCrypto;
use crate::infra::db::{MetadataDb, VaultDb};
use chrono::Utc;
use rpassword;
use uuid::Uuid;

const MAX_CREDENTIAL_BYTES: usize = 64 * 1024;

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore};
use reqwest::Client;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::time::Duration;

const OAUTH_CALLBACK_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Clone)]
pub struct AuthApp {
    metadata_db: MetadataDb,
    vault_db: VaultDb,
    crypto: VaultCrypto,
    public_client: Client,
    private_client: Client,
    refresh_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
}

#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
    scope: Option<String>,
    token_type: Option<String>,
}

#[derive(Debug)]
struct OAuthCallback {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

impl AuthApp {
    #[cfg(test)]
    pub fn new(metadata_db: &MetadataDb, vault_db: &VaultDb, crypto: &VaultCrypto) -> Self {
        Self::try_new(metadata_db, vault_db, crypto)
            .expect("static OAuth HTTP client configuration must be valid")
    }

    pub fn try_new(
        metadata_db: &MetadataDb,
        vault_db: &VaultDb,
        crypto: &VaultCrypto,
    ) -> Result<Self> {
        let build_client = |allow_private_network| {
            crate::app::api::configure_dns(Client::builder(), allow_private_network)
                .connect_timeout(crate::app::api::DEFAULT_CONNECT_TIMEOUT)
                .timeout(crate::app::api::DEFAULT_REQUEST_TIMEOUT)
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .map_err(|error| {
                    CliError::Internal(format!("Failed to create OAuth HTTP client: {error}"))
                })
        };
        let public_client = build_client(false)?;
        let private_client = build_client(true)?;
        Ok(Self {
            metadata_db: metadata_db.clone(),
            vault_db: vault_db.clone(),
            crypto: crypto.clone(),
            public_client,
            private_client,
            refresh_lock: std::sync::Arc::new(tokio::sync::Mutex::new(())),
        })
    }

    pub fn login_api_key(&self, provider_id: &str, api_key: Option<&str>) -> Result<()> {
        self.login_api_key_for(provider_id, api_key, "local-user", "local")
    }

    pub fn login_api_key_for(
        &self,
        provider_id: &str,
        api_key: Option<&str>,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<()> {
        validate_credential_subject(principal_id, tenant_id)?;
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
        if key.is_empty() {
            return Err(CliError::AuthRequired);
        }
        if key.len() > MAX_CREDENTIAL_BYTES {
            return Err(CliError::InvalidInput(format!(
                "API key exceeds the {MAX_CREDENTIAL_BYTES} byte limit"
            )));
        }

        let secret_id = format!("apikey_{}_{}", provider_id, Uuid::new_v4());
        let (cipher_text, nonce) = self.crypto.encrypt(key.as_bytes())?;

        let session = SessionRecord {
            session_id: format!("sess_{}", Uuid::new_v4()),
            provider_id: provider_id.to_string(),
            principal_id: principal_id.into(),
            tenant_id: tenant_id.into(),
            scopes: provider.scopes.clone(),
            expires_at: None,
            secret_id,
        };
        self.persist_new_session(&session, "api_key", &cipher_text, &nonce)?;

        Ok(())
    }

    pub async fn login_oauth_pkce(&self, provider_id: &str) -> Result<()> {
        self.login_oauth_pkce_for(provider_id, "local-user", "local")
            .await
    }

    pub async fn login_oauth_pkce_for(
        &self,
        provider_id: &str,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<()> {
        self.login_oauth_pkce_for_with_authorizer(
            provider_id,
            principal_id,
            tenant_id,
            |authorize_url| {
                eprintln!("Open this URL in your browser:\n{}\n", authorize_url);
            },
        )
        .await
    }

    #[cfg(test)]
    async fn login_oauth_pkce_with_authorizer<F>(
        &self,
        provider_id: &str,
        authorize: F,
    ) -> Result<()>
    where
        F: FnOnce(url::Url),
    {
        self.login_oauth_pkce_for_with_authorizer(provider_id, "local-user", "local", authorize)
            .await
    }

    async fn login_oauth_pkce_for_with_authorizer<F>(
        &self,
        provider_id: &str,
        principal_id: &str,
        tenant_id: &str,
        authorize: F,
    ) -> Result<()>
    where
        F: FnOnce(url::Url),
    {
        validate_credential_subject(principal_id, tenant_id)?;
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
        let parsed_auth_url = url::Url::parse(auth_url)
            .map_err(|error| CliError::BlockedUrl(format!("invalid authorization URL: {error}")))?;
        crate::app::api::validate_outbound_url(&parsed_auth_url, provider.allow_private_network)
            .await?;
        let parsed_token_url = url::Url::parse(token_url)
            .map_err(|error| CliError::BlockedUrl(format!("invalid token URL: {error}")))?;
        crate::app::api::validate_outbound_url(&parsed_token_url, provider.allow_private_network)
            .await?;

        // Bind first so the exact same redirect URI is used for both authorization
        // and token exchange.
        let listener =
            tokio::net::TcpListener::bind(("127.0.0.1", provider.oauth_redirect_port.unwrap_or(0)))
                .await
                .map_err(|e| {
                    CliError::Internal(format!("Failed to bind OAuth callback listener: {e}"))
                })?;
        let callback_addr = listener
            .local_addr()
            .map_err(|e| CliError::Internal(format!("Failed to read callback address: {e}")))?;
        let redirect_uri = format!("http://{callback_addr}/callback");

        // 1. Generate PKCE & state
        let (code_verifier, code_challenge, expected_state) = self.generate_pkce_params();

        // 2. Build Authorize URL
        let authorize_url = self.build_authorize_url(
            auth_url,
            client_id,
            &redirect_uri,
            &provider.scopes,
            &expected_state,
            &code_challenge,
        )?;

        authorize(authorize_url);

        // 3. Start callback server and wait for code
        let callback = self
            .start_callback_server(listener, &expected_state)
            .await?;
        let code_str = validate_oauth_callback(callback, &expected_state)?;

        // 4. Exchange code for token
        let token_result = self
            .exchange_code_for_token(
                token_url,
                client_id,
                &code_str,
                &redirect_uri,
                &code_verifier,
                provider.allow_private_network,
            )
            .await?;

        // 5. Store secrets and session
        self.store_oauth_session_for(
            provider_id,
            &token_result,
            &provider.scopes,
            principal_id,
            tenant_id,
        )?;

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
        const RESERVED: [&str; 7] = [
            "response_type",
            "client_id",
            "redirect_uri",
            "scope",
            "state",
            "code_challenge",
            "code_challenge_method",
        ];
        let existing = url
            .query_pairs()
            .filter(|(key, _)| !RESERVED.contains(&key.as_ref()))
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect::<Vec<_>>();
        url.set_query(None);
        url.query_pairs_mut().extend_pairs(existing);
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

    async fn start_callback_server(
        &self,
        listener: tokio::net::TcpListener,
        expected_state: &str,
    ) -> Result<OAuthCallback> {
        type CallbackTx =
            std::sync::Arc<tokio::sync::Mutex<Option<tokio::sync::oneshot::Sender<OAuthCallback>>>>;
        #[derive(Clone)]
        struct CallbackState {
            tx: CallbackTx,
            expected_state: String,
        }

        let (tx, rx) = tokio::sync::oneshot::channel::<OAuthCallback>();
        let tx: CallbackTx = std::sync::Arc::new(tokio::sync::Mutex::new(Some(tx)));

        use axum::{extract::Query, extract::State, response::Html, routing::get, Router};
        let app = Router::new()
            .route(
                "/callback",
                get(
                    move |Query(params): Query<HashMap<String, String>>,
                          State(state): State<CallbackState>| async move {
                        let callback = OAuthCallback {
                            code: params.get("code").cloned(),
                            state: params.get("state").cloned(),
                            error: params.get("error").cloned(),
                            error_description: params.get("error_description").cloned(),
                        };
                        let valid_state =
                            callback.state.as_deref() == Some(state.expected_state.as_str());
                        let succeeded = callback.error.is_none() && callback.code.is_some();
                        if valid_state {
                            if let Some(chan) = state.tx.lock().await.take() {
                                let _ = chan.send(callback);
                            }
                        }
                        if valid_state && succeeded {
                            Html(
                                "<html><body>Authentication successful. You can close this window.</body></html>",
                            )
                        } else {
                            Html(
                                "<html><body>Authentication failed. Return to the terminal for details.</body></html>",
                            )
                        }
                    },
                ),
            )
            .with_state(CallbackState {
                tx,
                expected_state: expected_state.into(),
            });

        let addr = listener
            .local_addr()
            .map_err(|e| CliError::Internal(e.to_string()))?;
        eprintln!("Waiting for callback on http://{addr}/callback ...");

        tokio::select! {
            result = rx => {
                result.map_err(|_| CliError::Internal("Failed to receive OAuth callback".into()))
            }
            result = axum::serve(listener, app) => {
                match result {
                    Ok(()) => Err(CliError::Internal("OAuth callback server exited unexpectedly".into())),
                    Err(error) => Err(CliError::Internal(format!("OAuth callback server failed: {error}"))),
                }
            }
            _ = tokio::time::sleep(OAUTH_CALLBACK_TIMEOUT) => {
                Err(CliError::RequestTimeout {
                    timeout_ms: OAUTH_CALLBACK_TIMEOUT.as_millis() as u64,
                })
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
        allow_private_network: bool,
    ) -> Result<TokenResponse> {
        let mut params = HashMap::new();
        params.insert("grant_type", "authorization_code");
        params.insert("code", code);
        params.insert("redirect_uri", redirect_uri);
        params.insert("client_id", client_id);
        params.insert("code_verifier", verifier);

        let response = self
            .client(allow_private_network)
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| CliError::Internal(format!("Token exchange request failed: {}", e)))?;

        parse_token_response(response, "Token exchange").await
    }

    #[cfg(test)]
    fn store_oauth_session(
        &self,
        provider_id: &str,
        token_result: &TokenResponse,
        scopes: &[String],
    ) -> Result<()> {
        self.store_oauth_session_for(provider_id, token_result, scopes, "local-user", "local")
    }

    fn store_oauth_session_for(
        &self,
        provider_id: &str,
        token_result: &TokenResponse,
        scopes: &[String],
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<()> {
        if token_result.access_token.is_empty() {
            return Err(CliError::Internal(
                "Token response contains an empty access_token".into(),
            ));
        }
        let payload = serde_json::json!({
            "access_token": token_result.access_token,
            "refresh_token": token_result.refresh_token
        });

        let secret_str = payload.to_string();
        let secret_id = format!("oauth_{}_{}", provider_id, Uuid::new_v4());
        let (cipher_text, nonce) = self.crypto.encrypt(secret_str.as_bytes())?;

        let expires_at = token_expiry(token_result.expires_in)?;
        let granted_scopes = match token_result.scope.as_deref() {
            Some(scope) => parse_scope(scope)?,
            None => scopes.to_vec(),
        };

        let session = SessionRecord {
            session_id: format!("sess_{}", Uuid::new_v4()),
            provider_id: provider_id.to_string(),
            principal_id: principal_id.into(),
            tenant_id: tenant_id.into(),
            scopes: granted_scopes,
            expires_at,
            secret_id,
        };
        self.persist_new_session(&session, "oauth_token", &cipher_text, &nonce)?;

        Ok(())
    }

    #[cfg(test)]
    pub async fn refresh_oauth_token(&self, provider_id: &str) -> Result<()> {
        self.refresh_oauth_token_for(provider_id, "local-user", "local")
            .await
    }

    pub async fn refresh_oauth_token_for(
        &self,
        provider_id: &str,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<()> {
        validate_credential_subject(principal_id, tenant_id)?;
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
            .get_latest_session_for(provider_id, principal_id, tenant_id)?
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
            .filter(|token| !token.is_empty())
            .ok_or_else(|| CliError::Internal("No refresh_token found in vault".into()))?;

        let client_id = provider
            .client_id
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing client_id".into()))?;
        let token_url = provider
            .token_url
            .as_ref()
            .ok_or_else(|| CliError::Internal("Missing token_url".into()))?;
        let parsed_token_url = url::Url::parse(token_url)
            .map_err(|error| CliError::BlockedUrl(format!("invalid token URL: {error}")))?;
        crate::app::api::validate_outbound_url(&parsed_token_url, provider.allow_private_network)
            .await?;

        let mut params = HashMap::new();
        params.insert("grant_type", "refresh_token");
        params.insert("refresh_token", refresh_token_str);
        params.insert("client_id", client_id);

        let response = self
            .client(provider.allow_private_network)
            .post(token_url)
            .form(&params)
            .send()
            .await
            .map_err(|e| CliError::Internal(format!("Token refresh request failed: {}", e)))?;

        let token_result = parse_token_response(response, "Token refresh").await?;
        let access_token = token_result.access_token;
        // Fallback to old refresh token if new one is not returned
        let base_refresh = refresh_token_str.to_string();
        let final_refresh_token = token_result
            .refresh_token
            .filter(|token| !token.is_empty())
            .unwrap_or(base_refresh);
        let expires_at = token_expiry(token_result.expires_in)?;
        let granted_scopes = token_result.scope.as_deref().map(parse_scope).transpose()?;

        let payload = serde_json::json!({
            "access_token": access_token,
            "refresh_token": final_refresh_token
        });

        let secret_str = payload.to_string();
        let new_secret_id = format!("oauth_{}_{}", provider_id, Uuid::new_v4());
        let (new_cipher, new_nonce) = self.crypto.encrypt(secret_str.as_bytes())?;

        self.vault_db
            .insert_secret(&new_secret_id, "oauth_token", &new_cipher, &new_nonce)?;

        let old_secret_id = session.secret_id.clone();
        let mut updated_session = session;
        updated_session.expires_at = expires_at;
        updated_session.secret_id = new_secret_id.clone();
        if let Some(scopes) = granted_scopes {
            updated_session.scopes = scopes;
        }
        let replaced = match self
            .metadata_db
            .update_session_if_secret_is_current(&updated_session, &old_secret_id)
        {
            Ok(replaced) => replaced,
            Err(error) => {
                if let Err(cleanup_error) = self.vault_db.delete_secret(&new_secret_id) {
                    tracing::warn!(error = %cleanup_error, "Failed to remove an unreferenced refreshed credential");
                }
                return Err(error);
            }
        };
        if !replaced {
            if let Err(error) = self.vault_db.delete_secret(&new_secret_id) {
                tracing::warn!(error = %error, "Failed to remove a credential from a lost refresh race");
            }
            let refreshed_elsewhere = self
                .metadata_db
                .get_latest_session_for(provider_id, principal_id, tenant_id)?
                .is_some_and(|current| current.secret_id != old_secret_id);
            return if refreshed_elsewhere {
                Ok(())
            } else {
                Err(CliError::AuthExpired)
            };
        }
        if let Err(error) = self.vault_db.delete_secret(&old_secret_id) {
            tracing::warn!(error = %error, "Failed to remove a superseded OAuth credential");
        }

        Ok(())
    }

    fn persist_new_session(
        &self,
        session: &SessionRecord,
        kind: &str,
        cipher_text: &[u8],
        nonce: &[u8],
    ) -> Result<()> {
        self.vault_db
            .insert_secret(&session.secret_id, kind, cipher_text, nonce)?;
        let superseded = match self.metadata_db.replace_session_for_subject(session) {
            Ok(secret_ids) => secret_ids,
            Err(error) => {
                if let Err(cleanup_error) = self.vault_db.delete_secret(&session.secret_id) {
                    tracing::warn!(error = %cleanup_error, "Failed to remove an unreferenced credential");
                }
                return Err(error);
            }
        };
        for secret_id in superseded {
            if let Err(error) = self.vault_db.delete_secret(&secret_id) {
                tracing::warn!(error = %error, "Failed to remove a superseded credential");
            }
        }
        Ok(())
    }

    fn client(&self, allow_private_network: bool) -> &Client {
        if allow_private_network {
            &self.private_client
        } else {
            &self.public_client
        }
    }
}

fn validate_credential_subject(principal_id: &str, tenant_id: &str) -> Result<()> {
    for (field, value) in [("principal_id", principal_id), ("tenant_id", tenant_id)] {
        if value.is_empty()
            || value.len() > 256
            || value.trim() != value
            || value.chars().any(char::is_control)
        {
            return Err(CliError::InvalidInput(format!(
                "{field} must be 1..=256 characters without surrounding whitespace or control characters"
            )));
        }
    }
    Ok(())
}

async fn parse_token_response(
    response: reqwest::Response,
    operation: &str,
) -> Result<TokenResponse> {
    let status = response.status();
    let bytes =
        crate::app::api::read_limited_response(response, crate::app::api::DEFAULT_MAX_ERROR_BYTES)
            .await?;
    if !status.is_success() {
        return Err(CliError::Internal(format!(
            "{operation} failed with HTTP {}",
            status.as_u16()
        )));
    }
    let token: TokenResponse = serde_json::from_slice(&bytes)
        .map_err(|error| CliError::Internal(format!("Failed to parse token response: {error}")))?;
    if token.access_token.is_empty() {
        return Err(CliError::Internal(
            "Token response contains an empty access_token".into(),
        ));
    }
    if token
        .token_type
        .as_deref()
        .is_some_and(|token_type| !token_type.eq_ignore_ascii_case("bearer"))
    {
        return Err(CliError::Internal(
            "Token response uses an unsupported token_type".into(),
        ));
    }
    Ok(token)
}

fn token_expiry(expires_in: Option<u64>) -> Result<Option<chrono::DateTime<Utc>>> {
    let Some(expires_in) = expires_in else {
        return Ok(None);
    };
    let seconds = i64::try_from(expires_in)
        .map_err(|_| CliError::Internal("expires_in exceeds the supported range".into()))?;
    let duration = chrono::Duration::try_seconds(seconds)
        .ok_or_else(|| CliError::Internal("expires_in exceeds the supported range".into()))?;
    Utc::now()
        .checked_add_signed(duration)
        .map(Some)
        .ok_or_else(|| CliError::Internal("token expiry exceeds the supported range".into()))
}

fn parse_scope(scope: &str) -> Result<Vec<String>> {
    let mut scopes = scope
        .split_ascii_whitespace()
        .map(str::to_string)
        .collect::<Vec<_>>();
    if scopes.len() > 256
        || scopes
            .iter()
            .any(|scope| scope.len() > 256 || scope.chars().any(char::is_whitespace))
    {
        return Err(CliError::Internal(
            "OAuth token scope set is malformed or exceeds supported limits".into(),
        ));
    }
    scopes.sort();
    scopes.dedup();
    Ok(scopes)
}

fn validate_oauth_callback(callback: OAuthCallback, expected_state: &str) -> Result<String> {
    if let Some(error) = callback.error {
        let error = sanitize_oauth_error(&error);
        let description = sanitize_oauth_error(callback.error_description.as_deref().unwrap_or(""));
        return Err(CliError::Internal(format!(
            "OAuth authorization failed: {error} {description}"
        )));
    }
    let code = callback
        .code
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Internal("OAuth callback did not include a code".into()))?;
    let state = callback
        .state
        .filter(|value| !value.is_empty())
        .ok_or_else(|| CliError::Internal("OAuth callback did not include state".into()))?;
    if state != expected_state {
        return Err(CliError::Internal("CSRF token mismatch".into()));
    }
    Ok(code)
}

fn sanitize_oauth_error(value: &str) -> String {
    value
        .chars()
        .filter(|character| !character.is_control())
        .take(512)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::{AuthType, CredentialPlacement, ProviderConfig};
    use crate::infra::db::{MetadataDb, VaultDb};
    use chrono::Duration;
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn setup() -> (MetadataDb, VaultDb, VaultCrypto) {
        let metadata = MetadataDb::new(Connection::open_in_memory().expect("metadata conn"))
            .expect("metadata db init");
        let vault =
            VaultDb::new(Connection::open_in_memory().expect("vault conn")).expect("vault db init");
        let dir = tempdir().expect("temp dir");
        let crypto =
            VaultCrypto::load_or_create(&dir.path().join("vault.key")).expect("crypto init");
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
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
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
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        }
    }

    #[test]
    fn login_api_key_requires_existing_provider() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .login_api_key("missing", Some("abc"))
            .expect_err("provider should be missing");
        match err {
            CliError::ProviderNotFound(id) => assert_eq!(id, "missing"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn login_api_key_rejects_oversized_credentials() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1"))
            .expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        assert!(matches!(
            app.login_api_key("p1", Some(&"x".repeat(MAX_CREDENTIAL_BYTES + 1))),
            Err(CliError::InvalidInput(_))
        ));
        assert!(metadata
            .get_latest_session("p1")
            .expect("session lookup")
            .is_none());
        assert!(!vault.has_secrets().expect("vault lookup"));
    }

    #[test]
    fn login_api_key_rejects_oauth_provider() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&oauth_provider("oauth"))
            .expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        let err = app
            .login_api_key("oauth", Some("abc"))
            .expect_err("auth type should mismatch");
        assert!(matches!(err, CliError::Internal(_)));
    }

    #[test]
    fn login_api_key_persists_encrypted_secret_and_session() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1"))
            .expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);

        app.login_api_key("p1", Some("secret-123")).expect("login");

        let session = metadata
            .get_latest_session("p1")
            .expect("read latest session")
            .expect("session exists");
        assert_eq!(session.provider_id, "p1");
        assert_eq!(
            session.scopes,
            vec!["read".to_string(), "write".to_string()]
        );
        assert!(session.secret_id.starts_with("apikey_p1_"));

        let (cipher, nonce) = vault
            .get_secret(&session.secret_id)
            .expect("vault read")
            .expect("secret exists");
        let decrypted = crypto.decrypt(&cipher, &nonce).expect("decrypt");
        assert_eq!(decrypted, b"secret-123");

        let old_session_id = session.session_id;
        let old_secret_id = session.secret_id;
        app.login_api_key("p1", Some("replacement"))
            .expect("replace login");
        assert!(metadata
            .get_session(&old_session_id)
            .expect("old session lookup")
            .is_none());
        assert!(vault
            .get_secret(&old_secret_id)
            .expect("old secret lookup")
            .is_none());
        let replacement = metadata
            .get_latest_session("p1")
            .expect("replacement lookup")
            .expect("replacement session");
        let (cipher, nonce) = vault
            .get_secret(&replacement.secret_id)
            .expect("replacement vault read")
            .expect("replacement secret");
        assert_eq!(
            crypto
                .decrypt(&cipher, &nonce)
                .expect("decrypt replacement"),
            b"replacement"
        );
    }

    #[test]
    fn api_key_can_be_preprovisioned_for_an_exact_remote_subject() {
        let (metadata, vault, crypto) = setup();
        metadata
            .insert_provider(&api_key_provider("p1"))
            .expect("provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);
        app.login_api_key_for("p1", Some("secret"), "remote-user", "tenant-1")
            .expect("remote login");

        assert!(metadata
            .get_latest_session_for("p1", "remote-user", "tenant-1")
            .expect("lookup")
            .is_some());
        assert!(metadata
            .get_latest_session_for("p1", "remote-user", "tenant-2")
            .expect("cross-tenant lookup")
            .is_none());
        assert!(matches!(
            app.login_api_key_for("p1", Some("secret"), " remote-user", "tenant-1"),
            Err(CliError::InvalidInput(_))
        ));
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

        let query: std::collections::HashMap<String, String> =
            url.query_pairs().into_owned().collect();
        assert_eq!(query.get("response_type").map(String::as_str), Some("code"));
        assert_eq!(
            query.get("client_id").map(String::as_str),
            Some("client123")
        );
        assert_eq!(
            query.get("redirect_uri").map(String::as_str),
            Some("http://127.0.0.1:8080/callback")
        );
        assert_eq!(
            query.get("scope").map(String::as_str),
            Some("scope-a scope-b")
        );
        assert_eq!(query.get("state").map(String::as_str), Some("state123"));
        assert_eq!(
            query.get("code_challenge").map(String::as_str),
            Some("challenge123")
        );
        assert_eq!(
            query.get("code_challenge_method").map(String::as_str),
            Some("S256")
        );
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
    fn oauth_callback_rejects_errors_missing_values_and_state_mismatch() {
        assert!(validate_oauth_callback(
            OAuthCallback {
                code: Some("code".into()),
                state: Some("state".into()),
                error: Some("access_denied".into()),
                error_description: Some("denied".into()),
            },
            "state",
        )
        .is_err());
        assert!(validate_oauth_callback(
            OAuthCallback {
                code: None,
                state: Some("state".into()),
                error: None,
                error_description: None,
            },
            "state",
        )
        .is_err());
        assert!(validate_oauth_callback(
            OAuthCallback {
                code: Some("code".into()),
                state: None,
                error: None,
                error_description: None,
            },
            "state",
        )
        .is_err());
        assert!(validate_oauth_callback(
            OAuthCallback {
                code: Some("code".into()),
                state: Some("other".into()),
                error: None,
                error_description: None,
            },
            "state",
        )
        .is_err());
    }

    #[test]
    fn oauth_limits_scopes_and_treats_zero_expiry_as_expired() {
        let before = Utc::now();
        let expiry = token_expiry(Some(0))
            .expect("zero expiry")
            .expect("explicit zero has an expiry");
        assert!(expiry >= before && expiry <= Utc::now());
        assert!(token_expiry(None).expect("missing expiry").is_none());

        assert_eq!(
            parse_scope("write read read").expect("valid scopes"),
            vec!["read".to_string(), "write".to_string()]
        );
        let excessive = (0..257)
            .map(|index| format!("scope:{index}"))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_scope(&excessive).is_err());
        assert!(parse_scope(&format!("scope:{}", "x".repeat(257))).is_err());
    }

    #[test]
    fn oauth_error_text_is_safe_for_terminal_output() {
        let error = validate_oauth_callback(
            OAuthCallback {
                code: None,
                state: Some("state".into()),
                error: Some("denied\u{1b}[31m".into()),
                error_description: Some("line\nbreak".into()),
            },
            "state",
        )
        .expect_err("OAuth error must fail")
        .to_string();
        assert!(!error.contains('\u{1b}'));
        assert!(!error.contains('\n'));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn oauth_pkce_uses_identical_dynamic_redirect_uri_for_authorize_and_token() {
        use axum::{
            extract::{Form, Query, State},
            response::Redirect,
            routing::{get, post},
            Json, Router,
        };
        use std::sync::Arc;

        #[derive(Clone, Default)]
        struct Captured {
            authorize_redirect: Arc<tokio::sync::Mutex<Option<String>>>,
            token_redirect: Arc<tokio::sync::Mutex<Option<String>>>,
            verifier: Arc<tokio::sync::Mutex<Option<String>>>,
        }

        let captured = Captured::default();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock oauth");
        let address = listener.local_addr().expect("mock oauth address");
        let router = Router::new()
            .route(
                "/authorize",
                get(
                    |Query(params): Query<HashMap<String, String>>,
                     State(captured): State<Captured>| async move {
                        let redirect_uri =
                            params.get("redirect_uri").cloned().expect("redirect_uri");
                        *captured.authorize_redirect.lock().await = Some(redirect_uri.clone());
                        let mut callback = url::Url::parse(&redirect_uri).expect("callback URL");
                        callback
                            .query_pairs_mut()
                            .append_pair("code", "authorization-code")
                            .append_pair(
                                "state",
                                params.get("state").expect("authorization state"),
                            );
                        Redirect::temporary(callback.as_str())
                    },
                ),
            )
            .route(
                "/token",
                post(
                    |State(captured): State<Captured>,
                     Form(params): Form<HashMap<String, String>>| async move {
                        *captured.token_redirect.lock().await = params.get("redirect_uri").cloned();
                        *captured.verifier.lock().await = params.get("code_verifier").cloned();
                        Json(serde_json::json!({
                            "access_token": "access-token",
                            "refresh_token": "refresh-token",
                            "expires_in": 3600
                        }))
                    },
                ),
            )
            .with_state(captured.clone());
        let server_task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth");
        provider.auth_url = Some(format!("http://{address}/authorize"));
        provider.token_url = Some(format!("http://{address}/token"));
        provider.allow_private_network = true;
        metadata
            .insert_provider(&provider)
            .expect("insert provider");
        let app = AuthApp::new(&metadata, &vault, &crypto);
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            app.login_oauth_pkce_with_authorizer("oauth", |authorize_url| {
                tokio::spawn(async move {
                    reqwest::get(authorize_url)
                        .await
                        .expect("open authorization URL");
                });
            }),
        )
        .await
        .expect("OAuth test timeout")
        .expect("OAuth login");
        server_task.abort();

        let authorize_redirect = captured
            .authorize_redirect
            .lock()
            .await
            .clone()
            .expect("authorize redirect");
        let token_redirect = captured
            .token_redirect
            .lock()
            .await
            .clone()
            .expect("token redirect");
        assert_eq!(authorize_redirect, token_redirect);
        assert!(authorize_redirect.starts_with("http://127.0.0.1:"));
        assert!(captured
            .verifier
            .lock()
            .await
            .as_ref()
            .is_some_and(|verifier| !verifier.is_empty()));
        assert!(metadata
            .get_latest_session("oauth")
            .expect("session lookup")
            .is_some());
    }

    #[test]
    fn store_oauth_session_persists_token_secret_and_expiry() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);
        let token = TokenResponse {
            access_token: "access-1".to_string(),
            refresh_token: Some("refresh-1".to_string()),
            expires_in: Some(600),
            scope: None,
            token_type: Some("Bearer".into()),
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
        assert_eq!(
            value.get("access_token").and_then(|v| v.as_str()),
            Some("access-1")
        );
        assert_eq!(
            value.get("refresh_token").and_then(|v| v.as_str()),
            Some("refresh-1")
        );
    }

    #[test]
    fn store_oauth_session_without_expiry_stores_none_expires_at() {
        let (metadata, vault, crypto) = setup();
        let app = AuthApp::new(&metadata, &vault, &crypto);
        let token = TokenResponse {
            access_token: "access-1".to_string(),
            refresh_token: Some("refresh-1".to_string()),
            expires_in: None,
            scope: None,
            token_type: Some("Bearer".into()),
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");

        let (cipher, nonce) = crypto.encrypt(b"not-json").expect("encrypt");
        vault
            .insert_secret("secret1", "oauth_token", &cipher, &nonce)
            .expect("insert secret");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");

        let payload = serde_json::json!({ "access_token": "a-only" }).to_string();
        let (cipher, nonce) = crypto.encrypt(payload.as_bytes()).expect("encrypt");
        vault
            .insert_secret("secret1", "oauth_token", &cipher, &nonce)
            .expect("insert secret");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");

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
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
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
        metadata
            .insert_provider(&provider)
            .expect("insert provider");

        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: provider.id.clone(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: provider.scopes.clone(),
            expires_at: Some(Utc::now() + Duration::minutes(10)),
            secret_id: "missing-secret-ok".to_string(),
        };
        metadata.insert_session(&session).expect("insert session");

        let app = AuthApp::new(&metadata, &vault, &crypto);
        let result = app.refresh_oauth_token("oauth").await;
        assert!(result.is_ok());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refresh_is_bound_to_the_requested_principal_and_tenant() {
        use axum::{extract::Form, routing::post, Json, Router};
        use serde_json::Value;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind token endpoint");
        let address = listener.local_addr().expect("token endpoint");
        let router = Router::new().route(
            "/token",
            post(|Form(form): Form<HashMap<String, String>>| async move {
                assert_eq!(
                    form.get("refresh_token").map(String::as_str),
                    Some("remote-refresh")
                );
                Json(serde_json::json!({
                    "access_token": "remote-access-new",
                    "refresh_token": "remote-refresh-new",
                    "expires_in": 600,
                    "scope": "scope:remote",
                    "token_type": "Bearer"
                }))
            }),
        );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });

        let (metadata, vault, crypto) = setup();
        let mut provider = oauth_provider("oauth");
        provider.token_url = Some(format!("http://{address}/token"));
        provider.allow_private_network = true;
        metadata.insert_provider(&provider).expect("provider");

        for (session_id, principal, tenant, secret_id, refresh) in [
            (
                "local-session",
                "local-user",
                "local",
                "local-secret",
                "local-refresh",
            ),
            (
                "remote-session",
                "remote-user",
                "tenant-1",
                "remote-secret",
                "remote-refresh",
            ),
        ] {
            let payload = serde_json::json!({
                "access_token": format!("{principal}-old"),
                "refresh_token": refresh
            })
            .to_string();
            let (cipher, nonce) = crypto.encrypt(payload.as_bytes()).expect("encrypt");
            vault
                .insert_secret(secret_id, "oauth_token", &cipher, &nonce)
                .expect("secret");
            metadata
                .insert_session(&SessionRecord {
                    session_id: session_id.into(),
                    provider_id: "oauth".into(),
                    principal_id: principal.into(),
                    tenant_id: tenant.into(),
                    scopes: vec!["scope:old".into()],
                    expires_at: Some(Utc::now() - Duration::seconds(10)),
                    secret_id: secret_id.into(),
                })
                .expect("session");
        }

        let app = AuthApp::new(&metadata, &vault, &crypto);
        app.refresh_oauth_token_for("oauth", "remote-user", "tenant-1")
            .await
            .expect("remote refresh");
        server.abort();

        let remote = metadata
            .get_latest_session_for("oauth", "remote-user", "tenant-1")
            .expect("remote lookup")
            .expect("remote session");
        assert_eq!(remote.scopes, vec!["scope:remote"]);
        assert_ne!(remote.secret_id, "remote-secret");
        assert!(vault
            .get_secret("remote-secret")
            .expect("superseded remote secret lookup")
            .is_none());
        let (cipher, nonce) = vault
            .get_secret(&remote.secret_id)
            .expect("remote secret")
            .expect("remote secret exists");
        let remote_secret: Value =
            serde_json::from_slice(&crypto.decrypt(&cipher, &nonce).expect("decrypt remote"))
                .expect("remote JSON");
        assert_eq!(remote_secret["access_token"], "remote-access-new");

        let (cipher, nonce) = vault
            .get_secret("local-secret")
            .expect("local secret")
            .expect("local secret exists");
        let local_secret: Value =
            serde_json::from_slice(&crypto.decrypt(&cipher, &nonce).expect("decrypt local"))
                .expect("local JSON");
        assert_eq!(local_secret["access_token"], "local-user-old");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn token_responses_are_bounded_and_error_bodies_are_not_exposed() {
        use axum::{http::StatusCode, routing::get, Router};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let address = listener.local_addr().expect("address");
        let router = Router::new()
            .route("/large", get(|| async { "x".repeat(70 * 1024) }))
            .route(
                "/error",
                get(|| async { (StatusCode::BAD_REQUEST, "upstream-sensitive-details") }),
            );
        let server = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        let client = Client::new();

        let large = client
            .get(format!("http://{address}/large"))
            .send()
            .await
            .expect("large response");
        assert!(matches!(
            parse_token_response(large, "Token exchange").await,
            Err(CliError::ResponseTooLarge { .. })
        ));

        let error_response = client
            .get(format!("http://{address}/error"))
            .send()
            .await
            .expect("error response");
        let error = parse_token_response(error_response, "Token exchange")
            .await
            .expect_err("error response");
        assert!(!error.to_string().contains("upstream-sensitive-details"));
        assert!(error.to_string().contains("HTTP 400"));
        server.abort();
    }
}
