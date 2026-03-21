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

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, CliError>;
