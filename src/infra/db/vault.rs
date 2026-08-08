use crate::error::{CliError, Result};
use crate::infra::db::{enable_wal, run_db, DbConnection, SqlitePool};
use chrono::Utc;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::{params, Connection, TransactionBehavior};
use std::path::Path;
use std::sync::{Arc, Mutex};

const LATEST_SCHEMA_VERSION: i64 = 1;

#[derive(Clone, Debug)]
pub struct VaultDb {
    connections: VaultConnections,
}

#[derive(Clone, Debug)]
enum VaultConnections {
    Single(Arc<Mutex<Connection>>),
    Pool(SqlitePool),
}

impl VaultDb {
    pub fn new(mut conn: Connection) -> Result<Self> {
        Self::migrate(&mut conn)?;
        Ok(Self {
            connections: VaultConnections::Single(Arc::new(Mutex::new(conn))),
        })
    }

    pub fn open(path: &Path) -> Result<Self> {
        let manager = SqliteConnectionManager::file(path)
            .with_init(|connection| connection.execute_batch("PRAGMA busy_timeout = 5000;"));
        let pool = r2d2::Pool::builder()
            .max_size(4)
            .connection_timeout(std::time::Duration::from_secs(5))
            .build(manager)
            .map_err(|error| CliError::Internal(format!("vault database pool: {error}")))?;
        {
            let mut connection = pool
                .get()
                .map_err(|error| CliError::Internal(format!("vault database pool: {error}")))?;
            Self::migrate(&mut connection)?;
        }
        Ok(Self {
            connections: VaultConnections::Pool(pool),
        })
    }

    fn migrate(conn: &mut Connection) -> Result<()> {
        conn.execute_batch(
            "PRAGMA busy_timeout = 5000;
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT NOT NULL
             );",
        )?;
        enable_wal(conn)?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let current: i64 = tx.query_row(
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
        }
        tx.commit()?;
        Ok(())
    }

    fn connection(&self) -> Result<DbConnection<'_>> {
        match &self.connections {
            VaultConnections::Single(connection) => connection
                .lock()
                .map(DbConnection::Single)
                .map_err(|_| CliError::Internal("Vault database lock poisoned".into())),
            VaultConnections::Pool(pool) => pool
                .get()
                .map(DbConnection::Pooled)
                .map_err(|error| CliError::Internal(format!("vault database pool: {error}"))),
        }
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

    pub fn has_secrets(&self) -> Result<bool> {
        run_db(|| {
            self.connection()?
                .query_row("SELECT EXISTS(SELECT 1 FROM secrets LIMIT 1)", [], |row| {
                    row.get(0)
                })
                .map_err(Into::into)
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
        assert!(!db.has_secrets().expect("empty vault"));
        db.insert_secret("s1", "api_key", b"cipher", b"nonce")
            .expect("insert secret");
        assert!(db.has_secrets().expect("nonempty vault"));

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

    #[test]
    fn file_database_pool_supports_concurrent_secret_writers() {
        let directory = tempfile::tempdir().expect("temp directory");
        let db = VaultDb::open(&directory.path().join("vault.db")).expect("open pool");
        let handles = (0..8)
            .map(|index| {
                let db = db.clone();
                std::thread::spawn(move || {
                    let secret_id = format!("secret-{index}");
                    db.insert_secret(
                        &secret_id,
                        "api_key",
                        format!("cipher-{index}").as_bytes(),
                        b"123456789012",
                    )
                    .expect("insert secret");
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle.join().expect("writer thread");
        }
        for index in 0..8 {
            assert!(db
                .get_secret(&format!("secret-{index}"))
                .expect("read secret")
                .is_some());
        }
    }

    #[test]
    fn concurrent_database_open_serializes_migrations() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = std::sync::Arc::new(directory.path().join("vault.db"));
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(8));
        let handles = (0..8)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    VaultDb::open(path.as_ref()).expect("concurrent database open")
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            let db = handle.join().expect("open thread");
            assert_eq!(
                db.schema_version().expect("schema version"),
                LATEST_SCHEMA_VERSION
            );
        }
    }
}
