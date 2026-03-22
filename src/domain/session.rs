use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub provider_id: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub secret_id: String,
}

#[cfg(test)]
mod tests {
    use super::SessionRecord;
    use chrono::Utc;

    #[test]
    fn session_record_roundtrip_json() {
        let now = Utc::now();
        let session = SessionRecord {
            session_id: "sess-1".to_string(),
            provider_id: "p1".to_string(),
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
}
