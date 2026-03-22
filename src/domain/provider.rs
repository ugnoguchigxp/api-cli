use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AuthType {
    OauthPkce,
    ApiKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderConfig {
    pub id: String,
    pub base_url: String,
    pub auth_type: AuthType,
    pub scopes: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_url: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{AuthType, ProviderConfig};

    #[test]
    fn auth_type_uses_kebab_case_serde_format() {
        let oauth = serde_json::to_string(&AuthType::OauthPkce).expect("serialize oauth");
        let api_key = serde_json::to_string(&AuthType::ApiKey).expect("serialize api key");
        assert_eq!(oauth, "\"oauth-pkce\"");
        assert_eq!(api_key, "\"api-key\"");

        let parsed: AuthType = serde_json::from_str("\"oauth-pkce\"").expect("deserialize oauth");
        assert_eq!(parsed, AuthType::OauthPkce);
    }

    #[test]
    fn provider_config_skips_none_optional_fields() {
        let provider = ProviderConfig {
            id: "p1".to_string(),
            base_url: "https://api.example.com".to_string(),
            auth_type: AuthType::ApiKey,
            scopes: vec!["read".to_string()],
            client_id: None,
            auth_url: None,
            token_url: None,
        };

        let value = serde_json::to_value(provider).expect("serialize provider");
        assert!(value.get("client_id").is_none());
        assert!(value.get("auth_url").is_none());
        assert!(value.get("token_url").is_none());
    }
}
