use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub provider_id: String,
    #[serde(default = "default_principal_id")]
    pub principal_id: String,
    #[serde(default = "default_tenant_id")]
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub secret_id: String,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthenticationStatus {
    Active,
    Expiring,
    Expired,
}

impl AuthenticationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Expiring => "expiring",
            Self::Expired => "expired",
        }
    }
}

impl SessionRecord {
    pub fn authentication_status_at(&self, now: DateTime<Utc>) -> AuthenticationStatus {
        match self.expires_at {
            Some(expires_at) if expires_at <= now => AuthenticationStatus::Expired,
            Some(expires_at) if expires_at <= now + chrono::Duration::minutes(5) => {
                AuthenticationStatus::Expiring
            }
            _ => AuthenticationStatus::Active,
        }
    }
}

fn default_principal_id() -> String {
    "local-user".into()
}

fn default_tenant_id() -> String {
    "local".into()
}

#[cfg(test)]
mod tests {
    use super::{AuthenticationStatus, SessionRecord};
    use chrono::{Duration, Utc};

    #[test]
    fn session_record_roundtrip_json() {
        let now = Utc::now();
        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: "p1".to_string(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: vec!["read".to_string()],
            expires_at: Some(now),
            secret_id: "sec-1".to_string(),
        };

        let json = serde_json::to_string(&session).expect("serialize session");
        let restored: SessionRecord = serde_json::from_str(&json).expect("deserialize session");
        assert_eq!(restored.session_id, "sess-1");
        assert_eq!(restored.provider_id, "p1");
        assert_eq!(restored.secret_id, "sec-1");
        assert_eq!(restored.scopes, vec!["read".to_string()]);
        assert_eq!(restored.expires_at, Some(now));
    }

    #[test]
    fn authentication_status_distinguishes_active_expiring_and_expired() {
        let now = Utc::now();
        let mut session = SessionRecord {
            session_id: "sess-1".into(),
            provider_id: "p1".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: vec![],
            expires_at: None,
            secret_id: "secret-1".into(),
        };
        assert_eq!(
            session.authentication_status_at(now),
            AuthenticationStatus::Active
        );
        session.expires_at = Some(now + Duration::minutes(4));
        assert_eq!(
            session.authentication_status_at(now),
            AuthenticationStatus::Expiring
        );
        session.expires_at = Some(now - Duration::seconds(1));
        assert_eq!(
            session.authentication_status_at(now),
            AuthenticationStatus::Expired
        );
    }
}
