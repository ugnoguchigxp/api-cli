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
    ProviderAlreadyExists(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] rusqlite::Error),

    #[error(
        "Unsupported {database} database schema version {found}; this binary supports up to {supported}"
    )]
    UnsupportedSchemaVersion {
        database: &'static str,
        found: i64,
        supported: i64,
    },

    #[error("Request timed out after {timeout_ms} ms")]
    RequestTimeout { timeout_ms: u64 },

    #[error("Response exceeded the {limit_bytes} byte limit")]
    ResponseTooLarge { limit_bytes: usize },

    #[error("Upstream API returned HTTP {status}")]
    UpstreamError { status: u16 },

    #[error("Upstream API result is unknown; do not retry automatically")]
    UpstreamResultUnknown,

    #[error("Blocked outbound URL: {0}")]
    BlockedUrl(String),

    #[error("Invalid action: {0}")]
    InvalidAction(String),

    #[error("Invalid provider: {0}")]
    InvalidProvider(String),

    #[error("Action not found: {0}")]
    ActionNotFound(String),

    #[error("{target} schema validation failed: {message}")]
    SchemaValidation { target: String, message: String },

    #[error("Approval required for action {action}; ticket: {ticket}")]
    ApprovalRequired { action: String, ticket: String },

    #[error("Approval ticket is invalid, expired, already used, or bound to different inputs")]
    InvalidApproval,

    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),

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
        assert_eq!(
            CliError::AuthRequired.to_string(),
            "Authentication required"
        );
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
        let db_err =
            rusqlite::Connection::open("/definitely/missing/dir/db.sqlite").expect_err("must fail");
        let cli_err: CliError = db_err.into();
        assert!(matches!(cli_err, CliError::DatabaseError(_)));
    }
}
