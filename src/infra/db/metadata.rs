use crate::domain::provider::ProviderConfig;
use crate::domain::session::SessionRecord;
use crate::error::{CliError, Result};
use crate::infra::db::run_db;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex, MutexGuard};

const LATEST_SCHEMA_VERSION: i64 = 4;

#[derive(Clone, Debug)]
pub struct ApprovalTicketRecord {
    pub ticket_id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub action_name: String,
    pub action_version: u32,
    pub definition_hash: String,
    pub provider_id: String,
    pub arguments_hash: String,
    pub policy_version: String,
    pub expires_at: String,
}

#[derive(Clone, Debug)]
pub struct AuditEventRecord {
    pub event_id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub client_id: String,
    pub approval_ticket_id: Option<String>,
    pub action_name: String,
    pub action_version: u32,
    pub definition_hash: String,
    pub provider_id: String,
    pub arguments_hash: String,
    pub risk: String,
    pub outcome: String,
    pub error_code: Option<String>,
}

pub struct ApprovalTicketBinding<'a> {
    pub ticket_id: &'a str,
    pub principal_id: &'a str,
    pub tenant_id: &'a str,
    pub client_id: &'a str,
    pub action_name: &'a str,
    pub action_version: u32,
    pub definition_hash: &'a str,
    pub provider_id: &'a str,
    pub arguments_hash: &'a str,
    pub policy_version: &'a str,
}

#[derive(Clone, Debug)]
pub struct MetadataDb {
    conn: Arc<Mutex<Connection>>,
}

impl MetadataDb {
    pub fn new(mut conn: Connection) -> Result<Self> {
        Self::migrate(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA busy_timeout = 5000;
             PRAGMA foreign_keys = ON;
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );",
        )?;

        let current: i64 = conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?;
        if current > LATEST_SCHEMA_VERSION {
            return Err(CliError::UnsupportedSchemaVersion {
                database: "metadata",
                found: current,
                supported: LATEST_SCHEMA_VERSION,
            });
        }

        if current < 1 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS providers (
                     id TEXT PRIMARY KEY,
                     config_json TEXT NOT NULL,
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 );
                 CREATE TABLE IF NOT EXISTS sessions (
                     session_id TEXT PRIMARY KEY,
                     provider_id TEXT NOT NULL,
                     config_json TEXT NOT NULL,
                     expires_at TEXT,
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 );
                 CREATE INDEX IF NOT EXISTS idx_sessions_provider_created
                     ON sessions(provider_id, created_at DESC);",
            )?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![1_i64, chrono::Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
        }
        if current < 2 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TABLE approval_tickets (
                     ticket_id TEXT PRIMARY KEY,
                     principal_id TEXT NOT NULL,
                     tenant_id TEXT NOT NULL,
                     client_id TEXT NOT NULL,
                     action_name TEXT NOT NULL,
                     action_version INTEGER NOT NULL,
                     definition_hash TEXT NOT NULL,
                     provider_id TEXT NOT NULL,
                     arguments_hash TEXT NOT NULL,
                     policy_version TEXT NOT NULL,
                     status TEXT NOT NULL CHECK(status IN (
                         'pending', 'approved', 'executing', 'succeeded',
                         'failed', 'unknown', 'denied', 'expired'
                     )),
                     expires_at TEXT NOT NULL,
                     created_at TEXT NOT NULL,
                     approved_at TEXT,
                     consumed_at TEXT
                 );
                 CREATE INDEX idx_approval_tickets_expiry
                     ON approval_tickets(status, expires_at);
                 CREATE TABLE audit_events (
                     sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                     event_id TEXT NOT NULL UNIQUE,
                     principal_id TEXT NOT NULL,
                     tenant_id TEXT NOT NULL,
                     client_id TEXT NOT NULL,
                     action_name TEXT NOT NULL,
                     action_version INTEGER NOT NULL,
                     definition_hash TEXT NOT NULL,
                     provider_id TEXT NOT NULL,
                     arguments_hash TEXT NOT NULL,
                     risk TEXT NOT NULL,
                     outcome TEXT NOT NULL,
                     error_code TEXT,
                     created_at TEXT NOT NULL
                 );
                 CREATE INDEX idx_audit_events_created
                     ON audit_events(created_at);",
            )?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![2_i64, chrono::Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
        }
        if current < 3 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "ALTER TABLE sessions
                     ADD COLUMN principal_id TEXT NOT NULL DEFAULT 'local-user';
                 ALTER TABLE sessions
                     ADD COLUMN tenant_id TEXT NOT NULL DEFAULT 'local';
                 UPDATE sessions
                    SET principal_id = COALESCE(
                            NULLIF(json_extract(config_json, '$.principal_id'), ''),
                            'local-user'
                        ),
                        tenant_id = COALESCE(
                            NULLIF(json_extract(config_json, '$.tenant_id'), ''),
                            'local'
                        );
                 CREATE INDEX idx_sessions_subject_provider_created
                     ON sessions(
                         principal_id,
                         tenant_id,
                         provider_id,
                         created_at DESC
                     );",
            )?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![3_i64, chrono::Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
        }
        if current < 4 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "ALTER TABLE audit_events
                     ADD COLUMN approval_ticket_id TEXT;
                 CREATE INDEX idx_audit_events_approval_ticket
                     ON audit_events(approval_ticket_id)
                     WHERE approval_ticket_id IS NOT NULL;",
            )?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![4_i64, chrono::Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| CliError::Internal("Metadata database lock poisoned".into()))
    }

    #[cfg(test)]
    pub fn schema_version(&self) -> Result<i64> {
        run_db(|| {
            self.connection()?
                .query_row(
                    "SELECT COALESCE(MAX(version), 0) FROM schema_version",
                    [],
                    |row| row.get(0),
                )
                .map_err(Into::into)
        })
    }

    #[cfg(test)]
    pub fn approval_status(&self, ticket_id: &str) -> Result<Option<String>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt =
                conn.prepare("SELECT status FROM approval_tickets WHERE ticket_id = ?1")?;
            let mut rows = stmt.query(params![ticket_id])?;
            Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
        })
    }

    #[cfg(test)]
    pub fn audit_approval_ticket_ids(&self) -> Result<Vec<Option<String>>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt =
                conn.prepare("SELECT approval_ticket_id FROM audit_events ORDER BY sequence")?;
            let rows = stmt.query_map([], |row| row.get(0))?;
            rows.collect::<std::result::Result<Vec<_>, _>>()
                .map_err(Into::into)
        })
    }

    #[cfg(test)]
    pub fn insert_provider(&self, provider: &ProviderConfig) -> Result<()> {
        run_db(|| {
            let json = serde_json::to_string(provider).map_err(|e| {
                crate::error::CliError::Internal(format!("Failed to serialize provider: {}", e))
            })?;
            let now = chrono::Utc::now().to_rfc3339();
            self.connection()?.execute(
                "INSERT INTO providers (id, config_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(id) DO UPDATE SET config_json=excluded.config_json, updated_at=excluded.updated_at",
                params![provider.id, json, now],
            )?;
            Ok(())
        })
    }

    pub fn create_provider(&self, provider: &ProviderConfig) -> Result<bool> {
        run_db(|| {
            let json = serde_json::to_string(provider).map_err(|error| {
                CliError::Internal(format!("Failed to serialize provider: {error}"))
            })?;
            let now = chrono::Utc::now().to_rfc3339();
            let changed = self.connection()?.execute(
                "INSERT INTO providers (id, config_json, created_at, updated_at)
                 VALUES (?1, ?2, ?3, ?3)
                 ON CONFLICT(id) DO NOTHING",
                params![provider.id, json, now],
            )?;
            Ok(changed == 1)
        })
    }

    pub fn get_provider(&self, id: &str) -> Result<Option<ProviderConfig>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt = conn.prepare("SELECT config_json FROM providers WHERE id = ?1")?;
            let mut rows = stmt.query(params![id])?;
            if let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                let provider = serde_json::from_str(&json).map_err(|e| {
                    crate::error::CliError::Internal(format!(
                        "Failed to deserialize provider: {}",
                        e
                    ))
                })?;
                Ok(Some(provider))
            } else {
                Ok(None)
            }
        })
    }

    pub fn list_providers(&self) -> Result<Vec<ProviderConfig>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt = conn.prepare("SELECT config_json FROM providers ORDER BY id")?;
            let items = stmt.query_map([], |row| {
                let json: String = row.get(0)?;
                let provider: ProviderConfig = serde_json::from_str(&json).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Text,
                        Box::new(e),
                    )
                })?;
                Ok(provider)
            })?;

            let mut providers = Vec::new();
            for item in items {
                providers.push(item?);
            }
            Ok(providers)
        })
    }

    pub fn delete_provider(&self, id: &str) -> Result<Vec<String>> {
        run_db(|| {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let mut secret_ids = Vec::new();
            {
                let mut stmt =
                    tx.prepare("SELECT config_json FROM sessions WHERE provider_id = ?1")?;
                let rows = stmt.query_map(params![id], |row| row.get::<_, String>(0))?;
                for row in rows {
                    let json = row?;
                    match serde_json::from_str::<SessionRecord>(&json) {
                        Ok(session) => secret_ids.push(session.secret_id),
                        Err(error) => tracing::warn!(
                            provider_id = id,
                            error = %error,
                            "Removing a provider with an unreadable session; its orphaned vault record cannot be identified"
                        ),
                    }
                }
            }
            tx.execute(
                "UPDATE approval_tickets
                    SET status = 'denied'
                  WHERE provider_id = ?1 AND status IN ('pending', 'approved')",
                params![id],
            )?;
            tx.execute("DELETE FROM sessions WHERE provider_id = ?1", params![id])?;
            tx.execute("DELETE FROM providers WHERE id = ?1", params![id])?;
            tx.commit()?;
            Ok(secret_ids)
        })
    }

    pub fn insert_session(&self, session: &SessionRecord) -> Result<()> {
        run_db(|| {
            let json = serde_json::to_string(session).map_err(|e| {
                crate::error::CliError::Internal(format!("Failed to serialize session: {}", e))
            })?;
            let expires_at = session.expires_at.map(|d| d.to_rfc3339());
            let now = chrono::Utc::now().to_rfc3339();

            self.connection()?.execute(
                "INSERT INTO sessions (
                     session_id, provider_id, principal_id, tenant_id, config_json,
                     expires_at, created_at, updated_at
                 )
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7)
                 ON CONFLICT(session_id) DO UPDATE SET
                     provider_id=excluded.provider_id,
                     principal_id=excluded.principal_id,
                     tenant_id=excluded.tenant_id,
                     config_json=excluded.config_json,
                     expires_at=excluded.expires_at,
                     updated_at=excluded.updated_at",
                params![
                    session.session_id,
                    session.provider_id,
                    session.principal_id,
                    session.tenant_id,
                    json,
                    expires_at,
                    now
                ],
            )?;
            Ok(())
        })
    }

    #[allow(dead_code)]
    pub fn get_session(&self, session_id: &str) -> Result<Option<SessionRecord>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt =
                conn.prepare("SELECT config_json FROM sessions WHERE session_id = ?1")?;
            let mut rows = stmt.query(params![session_id])?;
            if let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                let session = serde_json::from_str(&json).map_err(|e| {
                    crate::error::CliError::Internal(format!(
                        "Failed to deserialize session: {}",
                        e
                    ))
                })?;
                Ok(Some(session))
            } else {
                Ok(None)
            }
        })
    }

    pub fn get_latest_session(&self, provider_id: &str) -> Result<Option<SessionRecord>> {
        self.get_latest_session_for(provider_id, "local-user", "local")
    }

    pub fn get_latest_session_for(
        &self,
        provider_id: &str,
        principal_id: &str,
        tenant_id: &str,
    ) -> Result<Option<SessionRecord>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt = conn.prepare(
                "SELECT config_json FROM sessions
                 WHERE provider_id = ?1 AND principal_id = ?2 AND tenant_id = ?3
                 ORDER BY created_at DESC, rowid DESC
                 LIMIT 1",
            )?;
            let mut rows = stmt.query(params![provider_id, principal_id, tenant_id])?;
            if let Some(row) = rows.next()? {
                let json: String = row.get(0)?;
                let session: SessionRecord = serde_json::from_str(&json).map_err(|e| {
                    crate::error::CliError::Internal(format!(
                        "Failed to deserialize session: {}",
                        e
                    ))
                })?;
                Ok(Some(session))
            } else {
                Ok(None)
            }
        })
    }

    #[allow(dead_code)]
    pub fn delete_session(&self, session_id: &str) -> Result<()> {
        run_db(|| {
            self.connection()?.execute(
                "DELETE FROM sessions WHERE session_id = ?1",
                params![session_id],
            )?;
            Ok(())
        })
    }

    pub fn create_approval_ticket(&self, ticket: &ApprovalTicketRecord) -> Result<()> {
        run_db(|| {
            self.connection()?.execute(
                "INSERT INTO approval_tickets (
                     ticket_id, principal_id, tenant_id, client_id, action_name,
                     action_version, definition_hash, provider_id, arguments_hash,
                     policy_version, status, expires_at, created_at
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10,
                     'pending', ?11, ?12
                 )",
                params![
                    ticket.ticket_id,
                    ticket.principal_id,
                    ticket.tenant_id,
                    ticket.client_id,
                    ticket.action_name,
                    ticket.action_version,
                    ticket.definition_hash,
                    ticket.provider_id,
                    ticket.arguments_hash,
                    ticket.policy_version,
                    ticket.expires_at,
                    chrono::Utc::now().to_rfc3339(),
                ],
            )?;
            Ok(())
        })
    }

    pub fn approve_ticket(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<bool> {
        run_db(|| {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let now = chrono::Utc::now().to_rfc3339();
            tx.execute(
                "UPDATE approval_tickets
                    SET status = 'expired'
                  WHERE status IN ('pending', 'approved') AND expires_at <= ?1",
                params![now],
            )?;
            let changed = tx.execute(
                "UPDATE approval_tickets
                 SET status = 'approved', approved_at = ?1
                 WHERE ticket_id = ?2 AND principal_id = ?3 AND tenant_id = ?4
                   AND client_id = ?5
                   AND status = 'pending' AND expires_at > ?1",
                params![now, ticket_id, principal_id, tenant_id, client_id],
            )?;
            tx.commit()?;
            Ok(changed == 1)
        })
    }

    pub fn consume_ticket(&self, binding: &ApprovalTicketBinding<'_>) -> Result<bool> {
        run_db(|| {
            let mut conn = self.connection()?;
            let tx = conn.transaction()?;
            let now = chrono::Utc::now().to_rfc3339();
            tx.execute(
                "UPDATE approval_tickets
                    SET status = 'expired'
                  WHERE status IN ('pending', 'approved') AND expires_at <= ?1",
                params![now],
            )?;
            let changed = tx.execute(
                "UPDATE approval_tickets
                 SET status = 'executing', consumed_at = ?1
                 WHERE ticket_id = ?2 AND principal_id = ?3 AND tenant_id = ?4
                   AND client_id = ?5 AND action_name = ?6 AND action_version = ?7
                   AND definition_hash = ?8 AND provider_id = ?9
                   AND arguments_hash = ?10 AND policy_version = ?11
                   AND status = 'approved' AND expires_at > ?1",
                params![
                    now,
                    binding.ticket_id,
                    binding.principal_id,
                    binding.tenant_id,
                    binding.client_id,
                    binding.action_name,
                    binding.action_version,
                    binding.definition_hash,
                    binding.provider_id,
                    binding.arguments_hash,
                    binding.policy_version
                ],
            )?;
            tx.commit()?;
            Ok(changed == 1)
        })
    }

    pub fn deny_ticket(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
    ) -> Result<bool> {
        run_db(|| {
            let changed = self.connection()?.execute(
                "UPDATE approval_tickets
                    SET status = 'denied'
                  WHERE ticket_id = ?1 AND principal_id = ?2 AND tenant_id = ?3
                    AND client_id = ?4 AND status = 'pending'",
                params![ticket_id, principal_id, tenant_id, client_id],
            )?;
            Ok(changed == 1)
        })
    }

    pub fn finish_ticket(
        &self,
        ticket_id: &str,
        principal_id: &str,
        tenant_id: &str,
        client_id: &str,
        outcome: &str,
    ) -> Result<bool> {
        if !matches!(outcome, "succeeded" | "failed" | "unknown") {
            return Err(CliError::Internal(format!(
                "invalid approval outcome {outcome}"
            )));
        }
        run_db(|| {
            let changed = self.connection()?.execute(
                "UPDATE approval_tickets SET status = ?1
                 WHERE ticket_id = ?2 AND principal_id = ?3 AND tenant_id = ?4
                   AND client_id = ?5 AND status = 'executing'",
                params![outcome, ticket_id, principal_id, tenant_id, client_id],
            )?;
            Ok(changed == 1)
        })
    }

    pub fn insert_audit_event(&self, event: &AuditEventRecord) -> Result<()> {
        run_db(|| {
            self.connection()?.execute(
                "INSERT INTO audit_events (
                     event_id, principal_id, tenant_id, client_id, approval_ticket_id, action_name,
                     action_version, definition_hash, provider_id, arguments_hash,
                     risk, outcome, error_code, created_at
                 ) VALUES (
                     ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14
                 )",
                params![
                    event.event_id,
                    event.principal_id,
                    event.tenant_id,
                    event.client_id,
                    event.approval_ticket_id,
                    event.action_name,
                    event.action_version,
                    event.definition_hash,
                    event.provider_id,
                    event.arguments_hash,
                    event.risk,
                    event.outcome,
                    event.error_code,
                    chrono::Utc::now().to_rfc3339(),
                ],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::provider::{AuthType, CredentialPlacement};
    use chrono::Utc;

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
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
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
    fn migration_records_latest_schema_version() {
        let db = setup_db();
        assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn migrates_v2_session_subjects_into_indexed_columns() {
        let conn = Connection::open_in_memory().expect("connection");
        conn.execute_batch(
            "CREATE TABLE schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );
             INSERT INTO schema_version(version, applied_at) VALUES (2, 'now');
             CREATE TABLE sessions (
                 session_id TEXT PRIMARY KEY,
                 provider_id TEXT NOT NULL,
                 config_json TEXT NOT NULL,
                 expires_at TEXT,
                 created_at TEXT NOT NULL,
                 updated_at TEXT NOT NULL
             );
             CREATE TABLE audit_events (
                 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                 event_id TEXT NOT NULL UNIQUE,
                 principal_id TEXT NOT NULL,
                 tenant_id TEXT NOT NULL,
                 client_id TEXT NOT NULL,
                 action_name TEXT NOT NULL,
                 action_version INTEGER NOT NULL,
                 definition_hash TEXT NOT NULL,
                 provider_id TEXT NOT NULL,
                 arguments_hash TEXT NOT NULL,
                 risk TEXT NOT NULL,
                 outcome TEXT NOT NULL,
                 error_code TEXT,
                 created_at TEXT NOT NULL
             );",
        )
        .expect("v2 schema");
        let session = SessionRecord {
            session_id: "remote-session".into(),
            provider_id: "crm".into(),
            principal_id: "user-1".into(),
            tenant_id: "tenant-1".into(),
            scopes: vec!["read".into()],
            expires_at: None,
            secret_id: "secret-1".into(),
        };
        conn.execute(
            "INSERT INTO sessions (
                 session_id, provider_id, config_json, created_at, updated_at
             ) VALUES (?1, ?2, ?3, 'now', 'now')",
            params![
                session.session_id,
                session.provider_id,
                serde_json::to_string(&session).expect("session JSON")
            ],
        )
        .expect("session");

        let db = MetadataDb::new(conn).expect("migrate");
        assert_eq!(db.schema_version().expect("version"), 4);
        assert_eq!(
            db.get_latest_session_for("crm", "user-1", "tenant-1")
                .expect("lookup")
                .expect("session")
                .session_id,
            "remote-session"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_db_api_does_not_panic_on_current_thread_runtime() {
        let db = setup_db();
        let provider = ProviderConfig {
            id: "current-thread".into(),
            base_url: "https://example.com".into(),
            auth_type: AuthType::ApiKey,
            client_id: None,
            auth_url: None,
            token_url: None,
            scopes: vec![],
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        };
        db.insert_provider(&provider).expect("insert provider");
        assert!(db
            .get_provider("current-thread")
            .expect("get provider")
            .is_some());
    }

    #[test]
    fn rejects_database_from_newer_schema_version() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE schema_version (
                version INTEGER PRIMARY KEY,
                applied_at TEXT NOT NULL
             );
             INSERT INTO schema_version(version, applied_at)
             VALUES (999, 'now');",
        )
        .unwrap();

        let err = MetadataDb::new(conn).expect_err("newer schema must be rejected");
        assert!(matches!(err, CliError::UnsupportedSchemaVersion { .. }));
    }

    #[test]
    fn test_session_latest() {
        let db = setup_db();
        let s1 = SessionRecord {
            session_id: "s1".into(),
            provider_id: "p1".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: vec![],
            expires_at: None,
            secret_id: "sec1".into(),
        };
        let s2 = SessionRecord {
            session_id: "s2".into(),
            provider_id: "p1".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
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

    #[test]
    fn session_lookup_is_isolated_by_principal_and_tenant() {
        let db = setup_db();
        let remote = SessionRecord {
            session_id: "remote".into(),
            provider_id: "p1".into(),
            principal_id: "user-1".into(),
            tenant_id: "tenant-1".into(),
            scopes: vec!["read".into()],
            expires_at: None,
            secret_id: "remote-secret".into(),
        };
        db.insert_session(&remote).expect("insert session");
        assert!(db
            .get_latest_session_for("p1", "user-1", "tenant-1")
            .expect("lookup")
            .is_some());
        assert!(db
            .get_latest_session_for("p1", "user-2", "tenant-1")
            .expect("lookup")
            .is_none());
        assert!(db
            .get_latest_session_for("p1", "user-1", "tenant-2")
            .expect("lookup")
            .is_none());
    }

    #[test]
    fn test_get_provider_returns_none_for_missing() {
        let db = setup_db();
        assert!(db.get_provider("missing").unwrap().is_none());
    }

    #[test]
    fn test_list_providers_is_sorted_by_id() {
        let db = setup_db();
        let p1 = ProviderConfig {
            id: "zeta".into(),
            base_url: "https://z.example.com".into(),
            auth_type: AuthType::ApiKey,
            client_id: None,
            auth_url: None,
            token_url: None,
            scopes: vec![],
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        };
        let p2 = ProviderConfig {
            id: "alpha".into(),
            base_url: "https://a.example.com".into(),
            auth_type: AuthType::ApiKey,
            client_id: None,
            auth_url: None,
            token_url: None,
            scopes: vec![],
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        };
        db.insert_provider(&p1).unwrap();
        db.insert_provider(&p2).unwrap();

        let list = db.list_providers().unwrap();
        let ids: Vec<String> = list.into_iter().map(|p| p.id).collect();
        assert_eq!(ids, vec!["alpha".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn test_insert_provider_upserts_by_id() {
        let db = setup_db();
        let mut provider = ProviderConfig {
            id: "dup".into(),
            base_url: "https://v1.example.com".into(),
            auth_type: AuthType::ApiKey,
            client_id: None,
            auth_url: None,
            token_url: None,
            scopes: vec!["read".into()],
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        };
        db.insert_provider(&provider).unwrap();

        provider.base_url = "https://v2.example.com".into();
        provider.scopes = vec!["write".into()];
        db.insert_provider(&provider).unwrap();

        let got = db.get_provider("dup").unwrap().unwrap();
        assert_eq!(got.base_url, "https://v2.example.com");
        assert_eq!(got.scopes, vec!["write".to_string()]);
    }

    #[test]
    fn test_get_and_delete_session() {
        let db = setup_db();
        let s1 = SessionRecord {
            session_id: "s1".into(),
            provider_id: "p1".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: vec!["read".into()],
            expires_at: Some(Utc::now()),
            secret_id: "sec1".into(),
        };
        db.insert_session(&s1).unwrap();

        let fetched = db.get_session("s1").unwrap().unwrap();
        assert_eq!(fetched.secret_id, "sec1");

        db.delete_session("s1").unwrap();
        assert!(db.get_session("s1").unwrap().is_none());
    }

    #[test]
    fn test_get_latest_session_returns_none_when_no_session() {
        let db = setup_db();
        assert!(db.get_latest_session("missing").unwrap().is_none());
    }

    #[test]
    fn test_insert_session_upserts_by_session_id() {
        let db = setup_db();
        let mut s1 = SessionRecord {
            session_id: "sess".into(),
            provider_id: "p1".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: vec!["read".into()],
            expires_at: None,
            secret_id: "sec1".into(),
        };
        db.insert_session(&s1).unwrap();

        s1.secret_id = "sec2".into();
        s1.expires_at = Some(Utc::now());
        s1.provider_id = "p2".into();
        s1.principal_id = "user-2".into();
        s1.tenant_id = "tenant-2".into();
        db.insert_session(&s1).unwrap();

        let fetched = db.get_session("sess").unwrap().unwrap();
        assert_eq!(fetched.secret_id, "sec2");
        assert!(fetched.expires_at.is_some());
        assert!(db
            .get_latest_session_for("p1", "local-user", "local")
            .expect("old lookup")
            .is_none());
        assert!(db
            .get_latest_session_for("p2", "user-2", "tenant-2")
            .expect("new lookup")
            .is_some());
    }

    #[test]
    fn deleting_provider_revokes_sessions_and_pending_approvals() {
        let db = setup_db();
        let provider = ProviderConfig {
            id: "crm".into(),
            base_url: "https://example.com".into(),
            auth_type: AuthType::ApiKey,
            client_id: None,
            auth_url: None,
            token_url: None,
            scopes: vec![],
            credential_placement: CredentialPlacement::Bearer,
            oauth_redirect_port: None,
            allow_private_network: false,
        };
        db.insert_provider(&provider).expect("provider");
        db.insert_session(&SessionRecord {
            session_id: "session-1".into(),
            provider_id: "crm".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            scopes: vec![],
            expires_at: None,
            secret_id: "secret-1".into(),
        })
        .expect("session");
        db.create_approval_ticket(&ApprovalTicketRecord {
            ticket_id: "ticket-1".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            client_id: "local-cli".into(),
            action_name: "customer.update".into(),
            action_version: 1,
            definition_hash: "definition".into(),
            provider_id: "crm".into(),
            arguments_hash: "arguments".into(),
            policy_version: "v1".into(),
            expires_at: (Utc::now() + chrono::Duration::minutes(5)).to_rfc3339(),
        })
        .expect("ticket");

        assert_eq!(
            db.delete_provider("crm").expect("delete provider"),
            vec!["secret-1".to_string()]
        );
        assert!(db.get_latest_session("crm").expect("lookup").is_none());
        assert_eq!(
            db.approval_status("ticket-1").expect("status"),
            Some("denied".into())
        );
    }

    #[test]
    fn expired_approval_is_persistently_marked_expired() {
        let db = setup_db();
        db.create_approval_ticket(&ApprovalTicketRecord {
            ticket_id: "expired-ticket".into(),
            principal_id: "local-user".into(),
            tenant_id: "local".into(),
            client_id: "local-cli".into(),
            action_name: "customer.update".into(),
            action_version: 1,
            definition_hash: "definition".into(),
            provider_id: "crm".into(),
            arguments_hash: "arguments".into(),
            policy_version: "v1".into(),
            expires_at: (Utc::now() - chrono::Duration::seconds(1)).to_rfc3339(),
        })
        .expect("ticket");

        assert!(!db
            .approve_ticket("expired-ticket", "local-user", "local", "local-cli")
            .expect("approve"));
        assert_eq!(
            db.approval_status("expired-ticket").expect("status"),
            Some("expired".into())
        );
    }
}
