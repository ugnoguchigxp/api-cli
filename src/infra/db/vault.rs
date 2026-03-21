use rusqlite::{params, Connection};
use chrono::Utc;
use crate::error::Result;

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
             );"
        )?;
        Ok(Self { conn })
    }

    pub fn insert_secret(&self, secret_id: &str, kind: &str, cipher_text: &[u8], nonce: &[u8]) -> Result<()> {
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
            let mut stmt = self.conn.prepare("SELECT cipher_text, nonce FROM secrets WHERE secret_id = ?1")?;
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
        tokio::task::block_in_place(|| {
            self.conn.execute("DELETE FROM secrets WHERE secret_id = ?1", params![secret_id])?;
            Ok(())
        })
    }
}
