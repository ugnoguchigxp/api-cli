use crate::error::{CliError, Result};
use crate::infra::db::run_db;
use chrono::Utc;
use rusqlite::{params, Connection};
use std::sync::{Arc, Mutex, MutexGuard};

const LATEST_SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub struct VaultDb {
    conn: Arc<Mutex<Connection>>,
}

impl VaultDb {
    pub fn new(mut conn: Connection) -> Result<Self> {
        Self::migrate(&mut conn)?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
        })
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             PRAGMA busy_timeout = 5000;
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
                database: "vault",
                found: current,
                supported: LATEST_SCHEMA_VERSION,
            });
        }
        if current < 1 {
            let tx = conn.transaction()?;
            tx.execute_batch(
                "CREATE TABLE IF NOT EXISTS secrets (
                     secret_id TEXT PRIMARY KEY,
                     kind TEXT NOT NULL,
                     cipher_text BLOB NOT NULL,
                     nonce BLOB NOT NULL,
                     created_at TEXT NOT NULL,
                     updated_at TEXT NOT NULL
                 );",
            )?;
            tx.execute(
                "INSERT INTO schema_version (version, applied_at) VALUES (?1, ?2)",
                params![1_i64, Utc::now().to_rfc3339()],
            )?;
            tx.commit()?;
        }
        Ok(())
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.conn
            .lock()
            .map_err(|_| CliError::Internal("Vault database lock poisoned".into()))
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

    pub fn insert_secret(
        &self,
        secret_id: &str,
        kind: &str,
        cipher_text: &[u8],
        nonce: &[u8],
    ) -> Result<()> {
        run_db(|| {
            let now = Utc::now().to_rfc3339();
            self.connection()?.execute(
                "INSERT INTO secrets (secret_id, kind, cipher_text, nonce, created_at, updated_at) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(secret_id) DO UPDATE SET
                 kind=excluded.kind,
                 cipher_text=excluded.cipher_text,
                 nonce=excluded.nonce,
                 updated_at=excluded.updated_at",
                params![secret_id, kind, cipher_text, nonce, now],
            )?;
            Ok(())
        })
    }

    pub fn get_secret(&self, secret_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        run_db(|| {
            let conn = self.connection()?;
            let mut stmt =
                conn.prepare("SELECT cipher_text, nonce FROM secrets WHERE secret_id = ?1")?;
            let mut rows = stmt.query(params![secret_id])?;

            if let Some(row) = rows.next()? {
                let cipher_text: Vec<u8> = row.get(0)?;
                let nonce: Vec<u8> = row.get(1)?;
                Ok(Some((cipher_text, nonce)))
            } else {
                Ok(None)
            }
        })
    }

    pub fn delete_secret(&self, secret_id: &str) -> Result<()> {
        run_db(|| {
            self.connection()?.execute(
                "DELETE FROM secrets WHERE secret_id = ?1",
                params![secret_id],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{CliError, VaultDb, LATEST_SCHEMA_VERSION};
    use rusqlite::Connection;

    fn setup_db() -> VaultDb {
        let conn = Connection::open_in_memory().expect("open in-memory db");
        VaultDb::new(conn).expect("init vault db")
    }

    #[test]
    fn insert_and_get_secret_roundtrip() {
        let db = setup_db();
        db.insert_secret("s1", "api_key", b"cipher", b"nonce")
            .expect("insert secret");

        let found = db.get_secret("s1").expect("get secret");
        assert_eq!(found, Some((b"cipher".to_vec(), b"nonce".to_vec())));
    }

    #[test]
    fn insert_secret_updates_existing_record() {
        let db = setup_db();
        db.insert_secret("s1", "oauth_token", b"old", b"oldn")
            .expect("insert initial");
        db.insert_secret("s1", "oauth_token", b"new", b"newn")
            .expect("upsert");

        let found = db
            .get_secret("s1")
            .expect("get secret")
            .expect("secret exists");
        assert_eq!(found, (b"new".to_vec(), b"newn".to_vec()));
    }

    #[test]
    fn get_secret_returns_none_for_missing_id() {
        let db = setup_db();
        assert!(db.get_secret("missing").expect("get missing").is_none());
    }

    #[test]
    fn delete_secret_removes_record() {
        let db = setup_db();
        db.insert_secret("s1", "api_key", b"cipher", b"nonce")
            .expect("insert secret");
        db.delete_secret("s1").expect("delete secret");

        assert!(db.get_secret("s1").expect("get after delete").is_none());
    }

    #[test]
    fn migration_records_latest_schema_version() {
        let db = setup_db();
        assert_eq!(db.schema_version().unwrap(), LATEST_SCHEMA_VERSION);
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

        let err = VaultDb::new(conn).expect_err("newer schema must be rejected");
        assert!(matches!(err, CliError::UnsupportedSchemaVersion { .. }));
    }
}
