use crate::error::Result;
use chrono::Utc;
use rusqlite::{params, Connection};

pub struct VaultDb {
    conn: Connection,
}

impl VaultDb {
    pub fn new(conn: Connection) -> Result<Self> {
        conn.execute_batch(
            "PRAGMA journal_mode = DELETE;
             CREATE TABLE IF NOT EXISTS secrets (
                 secret_id TEXT PRIMARY KEY,
                 kind TEXT,
                 cipher_text BLOB,
                 nonce BLOB,
                 created_at TEXT,
                 updated_at TEXT
             );
             CREATE TABLE IF NOT EXISTS schema_version (
                 version INTEGER PRIMARY KEY,
                 applied_at TEXT
             );",
        )?;
        Ok(Self { conn })
    }

    pub fn insert_secret(
        &self,
        secret_id: &str,
        kind: &str,
        cipher_text: &[u8],
        nonce: &[u8],
    ) -> Result<()> {
        tokio::task::block_in_place(|| {
            let now = Utc::now().to_rfc3339();
            self.conn.execute(
                "INSERT INTO secrets (secret_id, kind, cipher_text, nonce, created_at, updated_at) 
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5)
                 ON CONFLICT(secret_id) DO UPDATE SET
                 cipher_text=excluded.cipher_text,
                 nonce=excluded.nonce,
                 updated_at=excluded.updated_at",
                params![secret_id, kind, cipher_text, nonce, now],
            )?;
            Ok(())
        })
    }

    pub fn get_secret(&self, secret_id: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        tokio::task::block_in_place(|| {
            let mut stmt = self
                .conn
                .prepare("SELECT cipher_text, nonce FROM secrets WHERE secret_id = ?1")?;
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

    #[allow(dead_code)]
pub fn delete_secret(&self, secret_id: &str) -> Result<()> {
        tokio::task::block_in_place(|| {
            self.conn.execute(
                "DELETE FROM secrets WHERE secret_id = ?1",
                params![secret_id],
            )?;
            Ok(())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::VaultDb;
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
}
