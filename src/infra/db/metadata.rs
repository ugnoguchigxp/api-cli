use rusqlite::{params, Connection};
use crate::domain::provider::ProviderConfig;
use crate::domain::session::SessionRecord;
use crate::error::Result;

pub struct MetadataDb {
    conn: Connection,
}

impl MetadataDb {
    pub fn new(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE IF NOT EXISTS providers (
                 id TEXT PRIMARY KEY,
                 config_json TEXT,
                 created_at TEXT,
                 updated_at TEXT
             );
             CREATE TABLE IF NOT EXISTS sessions (
                 session_id TEXT PRIMARY KEY,
                 provider_id TEXT,
                 config_json TEXT,
                 expires_at TEXT,
                 created_at TEXT,
                 updated_at TEXT
             );
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT
             );"
        )?;
        Ok(Self { conn })
    }

    pub fn insert_provider(&self, provider: &ProviderConfig) -> Result<()> {
        tokio::task::block_in_place(|| {
            let json = serde_json::to_string(provider)
                .map_err(|e| crate::error::CliError::Internal(format!("Failed to serialize provider: {}", e)))?;
            let now = chrono::Utc::now().to_rfc3339();
            self.conn.execute(
                "INSERT INTO providers (id, config_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json, updated_at=excluded.updated_at",
                params![provider.id, json, now],
            )?;
            Ok(())
        })
    }

    pub fn get_provider(&self, id: &str) -> Result<Option<ProviderConfig>> {
        tokio::task::block_in_place(|| {
            let mut stmt = self.conn.prepare("SELECT config_json FROM providers WHERE id = ?1")?;
            let mut rows = stmt.query(params![id])?;
            if let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                let provider = serde_json::from_str(&json)
                    .map_err(|e| crate::error::CliError::Internal(format!("Failed to deserialize provider: {}", e)))?;
                Ok(Some(provider))
            } else {
                Ok(None)
            }
        })
    }

    pub fn list_providers(&self) -> Result<Vec<ProviderConfig>> {
        tokio::task::block_in_place(|| {
            let mut stmt = self.conn.prepare("SELECT config_json FROM providers ORDER BY id")?;
            let items = stmt.query_map([], |row| {
                let json: String = row.get(0)?;
                let provider: ProviderConfig = serde_json::from_str(&json)
                    .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e)))?;
                Ok(provider)
            })?;
            
            let mut providers = Vec::new();
            for item in items {
                providers.push(item?);
            }
            Ok(providers)
        })
    }

    pub fn delete_provider(&self, id: &str) -> Result<()> {
        tokio::task::block_in_place(|| {
            self.conn.execute("DELETE FROM providers WHERE id = ?1", params![id])?;
            Ok(())
        })
    }

    pub fn insert_session(&self, session: &SessionRecord) -> Result<()> {
        tokio::task::block_in_place(|| {
            let json = serde_json::to_string(session)
                .map_err(|e| crate::error::CliError::Internal(format!("Failed to serialize session: {}", e)))?;
            let expires_at = session.expires_at.map(|d| d.to_rfc3339());
            let now = chrono::Utc::now().to_rfc3339();
            
            self.conn.execute(
                "INSERT INTO sessions (session_id, provider_id, config_json, expires_at, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(session_id) DO UPDATE SET config_json=excluded.config_json, expires_at=excluded.expires_at, updated_at=excluded.updated_at",
                params![session.session_id, session.provider_id, json, expires_at, now],
            )?;
            Ok(())
        })
    }

    #[allow(dead_code)]
    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
         tokio::task::block_in_place(|| {
             let mut stmt = self.conn.prepare("SELECT config_json FROM sessions WHERE session_id = ?1")?;
             let mut rows = stmt.query(params![session_id])?;
             if let Some(row) = rows.next()? {
                 let json: String = row.get(0)?;
                 let session = serde_json::from_str(&json)
                    .map_err(|e| crate::error::CliError::Internal(format!("Failed to deserialize session: {}", e)))?;
                 Ok(Some(session))
             } else {
                 Ok(None)
             }
         })
    }

    pub fn get_latest_session(&self, provider_id: &str) -> Result<Option<SessionRecord>> {
        tokio::task::block_in_place(|| {
            // sessionsテーブルからプロバイダーに紐づく最新のセッションを取得
            let mut stmt = self.conn.prepare("SELECT config_json FROM sessions WHERE provider_id = ?1 ORDER BY created_at DESC LIMIT 1")?;
            let mut rows = stmt.query(params![provider_id])?;
            if let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                let session = serde_json::from_str(&json)
                    .map_err(|e| crate::error::CliError::Internal(format!("Failed to deserialize session: {}", e)))?;
                Ok(Some(session))
            } else {
                Ok(None)
            }
        })
    }

    #[allow(dead_code)]
    pub fn delete_session(&self, session_id: &str) -> Result<()> {
         tokio::task::block_in_place(|| {
             self.conn.execute("DELETE FROM sessions WHERE session_id = ?1", params![session_id])?;
             Ok(())
         })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::AuthType;

    fn setup_db() -> MetadataDb {
        let conn = Connection::open_in_memory().unwrap();
        MetadataDb::new(conn).unwrap()
    }

    #[test]
    fn test_provider_crud() {
        let db = setup_db();
        let provider = ProviderConfig {
            id: "test-p".into(),
            base_url: "https://example.com".into(),
            auth_type: AuthType::ApiKey,
            client_id: None,
            auth_url: None,
            token_url: None,
            scopes: vec!["read".into()],
        };

        db.insert_provider(&provider).unwrap();
        let fetched = db.get_provider("test-p").unwrap().unwrap();
        assert_eq!(fetched.id, "test-p");
        assert_eq!(fetched.scopes, vec!["read".to_string()]);

        let list = db.list_providers().unwrap();
        assert_eq!(list.len(), 1);

        db.delete_provider("test-p").unwrap();
        assert!(db.get_provider("test-p").unwrap().is_none());
    }

    #[test]
    fn test_session_latest() {
        let db = setup_db();
        let s1 = SessionRecord {
            session_id: "s1".into(),
            provider_id: "p1".into(),
            scopes: vec![],
            expires_at: None,
            secret_id: "sec1".into(),
        };
        let s2 = SessionRecord {
            session_id: "s2".into(),
            provider_id: "p1".into(),
            scopes: vec![],
            expires_at: None,
            secret_id: "sec2".into(),
        };

        db.insert_session(&s1).unwrap();
        // Wait a bit or manually ensure timestamp order if needed, 
        // but normally successive inserts have increasing timestamps in our impl
        std::thread::sleep(std::time::Duration::from_millis(10));
        db.insert_session(&s2).unwrap();

        let latest = db.get_latest_session("p1").unwrap().unwrap();
        assert_eq!(latest.session_id, "s2");
    }
}
