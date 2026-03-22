use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Authentication required")]
    AuthRequired,

    #[error("Token expired")]
    AuthExpired,

    #[error("Missing vault key")]
    #[allow(dead_code)]
    VaultKeyMissing,

    #[error("Vault error: {0}")]
    VaultError(String),

    #[error("Provider not found: {0}")]
    ProviderNotFound(String),

    #[error("Provider already exists: {0}")]
    #[allow(dead_code)]
    ProviderAlreadyExists(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CliError>;

#[cfg(test)]
mod tests {
    use super::CliError;

    #[test]
    fn display_messages_are_human_readable() {
        assert_eq!(CliError::AuthRequired.to_string(), "Authentication required");
        assert_eq!(CliError::AuthExpired.to_string(), "Token expired");
        assert_eq!(
            CliError::ProviderNotFound("x".to_string()).to_string(),
            "Provider not found: x"
        );
    }

    #[test]
    fn io_error_converts_via_from() {
        let io_err = std::io::Error::other("boom");
        let cli_err: CliError = io_err.into();
        assert!(matches!(cli_err, CliError::IoError(_)));
    }

    #[test]
    fn database_error_converts_via_from() {
        let db_err = rusqlite::Connection::open("/definitely/missing/dir/db.sqlite")
            .expect_err("must fail");
        let cli_err: CliError = db_err.into();
        assert!(matches!(cli_err, CliError::DatabaseError(_)));
    }
}
