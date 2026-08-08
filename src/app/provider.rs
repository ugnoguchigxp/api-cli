use crate::domain::provider::{AuthType, CredentialPlacement, ProviderConfig};
use crate::error::{CliError, Result};
use crate::infra::db::{MetadataDb, VaultDb};

#[derive(Clone)]
pub struct ProviderApp {
    db: MetadataDb,
    vault_db: VaultDb,
}

impl ProviderApp {
    pub fn new(db: &MetadataDb, vault_db: &VaultDb) -> Self {
        Self {
            db: db.clone(),
            vault_db: vault_db.clone(),
        }
    }

    pub fn add_provider(&self, config: ProviderConfig) -> Result<()> {
        validate_provider(&config)?;
        if !self.db.create_provider(&config)? {
            return Err(CliError::ProviderAlreadyExists(config.id));
        }
        Ok(())
    }

    pub fn list_providers(&self) -> Result<Vec<ProviderConfig>> {
        self.db.list_providers()
    }

    #[allow(dead_code)]
    pub fn get_provider(&self, id: &str) -> Result<Option<ProviderConfig>> {
        self.db.get_provider(id)
    }

    pub fn remove_provider(&self, id: &str) -> Result<()> {
        let mut first_error = None;
        for secret_id in self.db.delete_provider(id)? {
            if let Err(error) = self.vault_db.delete_secret(&secret_id) {
                tracing::warn!(secret_id, %error, "Failed to delete a revoked provider credential");
                first_error.get_or_insert(error);
            }
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        Ok(())
    }
}

fn validate_provider(config: &ProviderConfig) -> Result<()> {
    if config.id.is_empty()
        || config.id.len() > 128
        || !config
            .id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(CliError::InvalidProvider(format!(
            "invalid provider ID {}",
            config.id
        )));
    }
    let base_url =
        validate_configured_url(&config.base_url, "provider", config.allow_private_network)?;
    if base_url.query().is_some() || base_url.fragment().is_some() {
        return Err(CliError::BlockedUrl(
            "provider base URL cannot contain a query or fragment".into(),
        ));
    }
    if let CredentialPlacement::Header { name } = &config.credential_placement {
        let header = reqwest::header::HeaderName::from_bytes(name.as_bytes()).map_err(|error| {
            CliError::InvalidProvider(format!("invalid API key header: {error}"))
        })?;
        if crate::app::action::is_forbidden_request_header(&header) {
            return Err(CliError::InvalidProvider(format!(
                "sensitive API key header is forbidden: {name}"
            )));
        }
    }
    if config.auth_type == AuthType::OauthPkce
        && (config.client_id.as_deref().unwrap_or_default().is_empty()
            || config.auth_url.as_deref().unwrap_or_default().is_empty()
            || config.token_url.as_deref().unwrap_or_default().is_empty())
    {
        return Err(CliError::InvalidProvider(
            "OAuth PKCE provider requires client-id, auth-url, and token-url".into(),
        ));
    }
    match config.auth_type {
        AuthType::OauthPkce => {
            if !matches!(config.credential_placement, CredentialPlacement::Bearer) {
                return Err(CliError::InvalidProvider(
                    "OAuth PKCE credentials must use Bearer placement".into(),
                ));
            }
            validate_configured_url(
                config.auth_url.as_deref().unwrap_or_default(),
                "OAuth authorization",
                config.allow_private_network,
            )?;
            let client_id = config.client_id.as_deref().unwrap_or_default();
            if client_id.len() > 256
                || client_id.trim() != client_id
                || client_id.chars().any(char::is_control)
            {
                return Err(CliError::InvalidProvider(
                    "OAuth client_id must be 1..=256 bytes without surrounding whitespace or control characters"
                        .into(),
                ));
            }
            validate_configured_url(
                config.token_url.as_deref().unwrap_or_default(),
                "OAuth token",
                config.allow_private_network,
            )?;
            if config.oauth_redirect_port == Some(0) {
                return Err(CliError::InvalidProvider(
                    "oauth_redirect_port must be non-zero when specified".into(),
                ));
            }
        }
        AuthType::ApiKey => {
            if config.client_id.is_some()
                || config.auth_url.is_some()
                || config.token_url.is_some()
                || config.oauth_redirect_port.is_some()
            {
                return Err(CliError::InvalidProvider(
                    "API Key provider cannot contain OAuth settings".into(),
                ));
            }
        }
    }
    let mut scopes = std::collections::BTreeSet::new();
    if config.scopes.len() > 256 {
        return Err(CliError::InvalidProvider(
            "provider cannot declare more than 256 scopes".into(),
        ));
    }
    for scope in &config.scopes {
        if scope.is_empty()
            || scope.trim() != scope
            || scope.len() > 256
            || scope.chars().any(char::is_whitespace)
            || !scopes.insert(scope)
        {
            return Err(CliError::InvalidProvider(
                "scopes must be non-empty, unique, and contain no whitespace".into(),
            ));
        }
    }
    Ok(())
}

fn validate_configured_url(
    value: &str,
    label: &str,
    allow_private_network: bool,
) -> Result<url::Url> {
    if value.len() > 16 * 1024 {
        return Err(CliError::BlockedUrl(format!(
            "{label} URL exceeds 16384 bytes"
        )));
    }
    let parsed = url::Url::parse(value)
        .map_err(|error| CliError::BlockedUrl(format!("invalid {label} URL: {error}")))?;
    if parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.fragment().is_some()
    {
        return Err(CliError::BlockedUrl(format!(
            "{label} URL requires a host and cannot contain credentials or a fragment"
        )));
    }
    let loopback = parsed.host_str().is_some_and(|host| {
        host.parse::<std::net::IpAddr>()
            .is_ok_and(|address| address.is_loopback())
    });
    if parsed.scheme() != "https"
        && !(parsed.scheme() == "http" && loopback && allow_private_network)
    {
        return Err(CliError::BlockedUrl(format!(
            "{label} URL must use HTTPS; loopback HTTP requires --allow-private-network"
        )));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::{AuthType, CredentialPlacement};
    use crate::infra::db::{MetadataDb, VaultDb};
    use rusqlite::Connection;

    fn sample_provider(id: &str) -> ProviderConfig {
        ProviderConfig {
            id: id.to_string(),
            base_url: "https://example.com".to_string(),
            auth_type: AuthType::ApiKey,
            scopes: vec!["read".to_string()],
            client_id: None,
            auth_url: None,
            token_url: None,
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        }
    }

    #[test]
    fn add_get_list_remove_provider() {
        let conn = Connection::open_in_memory().expect("in-memory metadata db");
        let db = MetadataDb::new(conn).expect("metadata db init");
        let vault =
            VaultDb::new(Connection::open_in_memory().expect("in-memory vault db")).expect("vault");
        let app = ProviderApp::new(&db, &vault);
        let config = sample_provider("p1");

        app.add_provider(config).expect("insert provider");

        let found = app.get_provider("p1").expect("get provider");
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "p1");

        let list = app.list_providers().expect("list providers");
        assert_eq!(list.len(), 1);

        app.remove_provider("p1").expect("remove provider");
        assert!(app
            .get_provider("p1")
            .expect("get provider after remove")
            .is_none());
    }

    #[test]
    fn duplicate_provider_cannot_redirect_an_existing_credential() {
        let db = MetadataDb::new(Connection::open_in_memory().expect("metadata")).expect("db");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault")).expect("vault");
        let app = ProviderApp::new(&db, &vault);
        app.add_provider(sample_provider("p1")).expect("first add");

        let mut redirected = sample_provider("p1");
        redirected.base_url = "https://attacker.example".into();
        let error = app
            .add_provider(redirected)
            .expect_err("duplicate provider must fail");
        assert!(matches!(error, CliError::ProviderAlreadyExists(id) if id == "p1"));
        assert_eq!(
            app.get_provider("p1")
                .expect("provider")
                .expect("existing provider")
                .base_url,
            "https://example.com"
        );
    }

    #[test]
    fn cleartext_provider_requires_a_literal_loopback_address() {
        let mut provider = sample_provider("p1");
        provider.base_url = "http://localhost:8080".into();
        provider.allow_private_network = true;
        assert!(matches!(
            validate_provider(&provider),
            Err(CliError::BlockedUrl(_))
        ));

        provider.base_url = "http://127.0.0.1:8080".into();
        validate_provider(&provider).expect("literal loopback development provider");
    }

    #[test]
    fn removing_provider_deletes_credential_sessions_and_vault_records() {
        use crate::app::auth::AuthApp;
        use crate::infra::crypto::VaultCrypto;
        use tempfile::tempdir;

        let db = MetadataDb::new(Connection::open_in_memory().expect("metadata")).expect("db");
        let vault = VaultDb::new(Connection::open_in_memory().expect("vault")).expect("vault");
        let directory = tempdir().expect("tempdir");
        let crypto = VaultCrypto::load_or_create(&directory.path().join("key")).expect("vault key");
        let app = ProviderApp::new(&db, &vault);
        app.add_provider(sample_provider("p1")).expect("provider");
        AuthApp::new(&db, &vault, &crypto)
            .login_api_key("p1", Some("secret"))
            .expect("login");
        let secret_id = db
            .get_latest_session("p1")
            .expect("session lookup")
            .expect("session")
            .secret_id;

        app.remove_provider("p1").expect("remove");
        assert!(db
            .get_latest_session("p1")
            .expect("session lookup")
            .is_none());
        assert!(vault
            .get_secret(&secret_id)
            .expect("vault lookup")
            .is_none());
    }
}
