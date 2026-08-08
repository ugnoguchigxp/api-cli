pub mod metadata;
pub mod vault;

pub use metadata::MetadataDb;
pub use vault::VaultDb;

use r2d2::PooledConnection;
use r2d2_sqlite::SqliteConnectionManager;
use rusqlite::Connection;
use std::ops::{Deref, DerefMut};
use std::sync::MutexGuard;

type SqlitePool = r2d2::Pool<SqliteConnectionManager>;

enum DbConnection<'a> {
    Single(MutexGuard<'a, Connection>),
    Pooled(PooledConnection<SqliteConnectionManager>),
}

impl Deref for DbConnection<'_> {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        match self {
            Self::Single(connection) => connection,
            Self::Pooled(connection) => connection,
        }
    }
}

impl DerefMut for DbConnection<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        match self {
            Self::Single(connection) => connection,
            Self::Pooled(connection) => connection,
        }
    }
}

fn run_db<T>(operation: impl FnOnce() -> crate::error::Result<T>) -> crate::error::Result<T> {
    if tokio::runtime::Handle::try_current().is_ok_and(|handle| {
        matches!(
            handle.runtime_flavor(),
            tokio::runtime::RuntimeFlavor::MultiThread
        )
    }) {
        tokio::task::block_in_place(operation)
    } else {
        operation()
    }
}

/// Switching a newly-created database into WAL mode requires an exclusive
/// lock and, unlike ordinary statements, may return `SQLITE_BUSY` immediately
/// while another process is doing the same initialization. Retry only those
/// transient lock errors within the same five-second window used by the pools.
fn enable_wal(connection: &Connection) -> crate::error::Result<()> {
    const RETRIES: usize = 100;
    const RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(50);

    for attempt in 0..=RETRIES {
        match connection.execute_batch("PRAGMA journal_mode = WAL;") {
            Ok(()) => return Ok(()),
            Err(rusqlite::Error::SqliteFailure(error, _))
                if matches!(
                    error.code,
                    rusqlite::ErrorCode::DatabaseBusy | rusqlite::ErrorCode::DatabaseLocked
                ) && attempt < RETRIES =>
            {
                std::thread::sleep(RETRY_DELAY);
            }
            Err(error) => return Err(error.into()),
        }
    }
    unreachable!("the retry loop always returns on its final attempt")
}
