use thiserror::Error;

#[derive(Debug, Error)]
pub enum CliError {
    #[error("Authentication required")]
    AuthRequired,

    #[error("Token expired")]
    AuthExpired,

    #[error("Missing vault key")]
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

    #[error("Request exceeded the {limit_bytes} byte limit")]
    RequestTooLarge { limit_bytes: usize },

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

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Action not found: {0}")]
    ActionNotFound(String),

    #[error("Audit event not found: {0}")]
    AuditEventNotFound(String),

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

impl CliError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::AuthRequired => "auth_required",
            Self::AuthExpired => "auth_expired",
            Self::VaultKeyMissing => "vault_key_missing",
            Self::VaultError(_) => "vault_error",
            Self::ProviderNotFound(_) => "provider_not_found",
            Self::ProviderAlreadyExists(_) => "provider_already_exists",
            Self::DatabaseError(_) => "database_error",
            Self::UnsupportedSchemaVersion { .. } => "unsupported_schema_version",
            Self::RequestTimeout { .. } => "request_timeout",
            Self::ResponseTooLarge { .. } => "response_too_large",
            Self::RequestTooLarge { .. } => "request_too_large",
            Self::UpstreamError { .. } => "upstream_error",
            Self::UpstreamResultUnknown => "upstream_result_unknown",
            Self::BlockedUrl(_) => "blocked_url",
            Self::InvalidAction(_) => "invalid_action",
            Self::InvalidProvider(_) => "invalid_provider",
            Self::InvalidInput(_) => "invalid_input",
            Self::ActionNotFound(_) => "action_not_found",
            Self::AuditEventNotFound(_) => "audit_event_not_found",
            Self::SchemaValidation { .. } => "schema_validation",
            Self::ApprovalRequired { .. } => "approval_required",
            Self::InvalidApproval => "invalid_approval",
            Self::AuthorizationDenied(_) => "authorization_denied",
            Self::IoError(_) => "io_error",
            Self::Internal(_) => "internal",
        }
    }
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
        assert_eq!(
            CliError::ProviderNotFound("x".to_string()).code(),
            "provider_not_found"
        );
    }

    #[test]
    fn every_error_variant_has_a_stable_machine_code() {
        let cases = [
            (CliError::AuthRequired, "auth_required"),
            (CliError::AuthExpired, "auth_expired"),
            (CliError::VaultKeyMissing, "vault_key_missing"),
            (CliError::VaultError("x".into()), "vault_error"),
            (CliError::ProviderNotFound("x".into()), "provider_not_found"),
            (
                CliError::ProviderAlreadyExists("x".into()),
                "provider_already_exists",
            ),
            (
                CliError::DatabaseError(rusqlite::Error::InvalidQuery),
                "database_error",
            ),
            (
                CliError::UnsupportedSchemaVersion {
                    database: "metadata",
                    found: 2,
                    supported: 1,
                },
                "unsupported_schema_version",
            ),
            (
                CliError::RequestTimeout { timeout_ms: 1 },
                "request_timeout",
            ),
            (
                CliError::ResponseTooLarge { limit_bytes: 1 },
                "response_too_large",
            ),
            (
                CliError::RequestTooLarge { limit_bytes: 1 },
                "request_too_large",
            ),
            (CliError::UpstreamError { status: 500 }, "upstream_error"),
            (CliError::UpstreamResultUnknown, "upstream_result_unknown"),
            (CliError::BlockedUrl("x".into()), "blocked_url"),
            (CliError::InvalidAction("x".into()), "invalid_action"),
            (CliError::InvalidProvider("x".into()), "invalid_provider"),
            (CliError::InvalidInput("x".into()), "invalid_input"),
            (CliError::ActionNotFound("x".into()), "action_not_found"),
            (
                CliError::AuditEventNotFound("x".into()),
                "audit_event_not_found",
            ),
            (
                CliError::SchemaValidation {
                    target: "input".into(),
                    message: "x".into(),
                },
                "schema_validation",
            ),
            (
                CliError::ApprovalRequired {
                    action: "x".into(),
                    ticket: "y".into(),
                },
                "approval_required",
            ),
            (CliError::InvalidApproval, "invalid_approval"),
            (
                CliError::AuthorizationDenied("x".into()),
                "authorization_denied",
            ),
            (CliError::IoError(std::io::Error::other("x")), "io_error"),
            (CliError::Internal("x".into()), "internal"),
        ];

        for (error, expected) in cases {
            assert_eq!(error.code(), expected);
        }
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
