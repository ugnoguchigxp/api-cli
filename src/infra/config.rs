use std::path::PathBuf;
use crate::error::{CliError, Result};
use directories::ProjectDirs;
use std::fs;

pub fn get_api_cli_dir() -> Result<PathBuf> {
    let proj_dirs = ProjectDirs::from("com", "api-cli", "api-cli")
        .ok_or_else(|| CliError::Internal("Could not determine project directories".to_string()))?;
    let dir = proj_dirs.config_dir().to_path_buf();
    if !dir.exists() {
        fs::create_dir_all(&dir)?;
    }
    Ok(dir)
}

pub fn get_metadata_db_path() -> Result<PathBuf> {
    Ok(get_api_cli_dir()?.join("metadata.db"))
}

pub fn get_vault_db_path() -> Result<PathBuf> {
    Ok(get_api_cli_dir()?.join("vault.db"))
}

pub fn get_vault_key_path() -> Result<PathBuf> {
    Ok(get_api_cli_dir()?.join("vault.key"))
}

pub fn get_runtime_sock_path() -> Result<PathBuf> {
    let runtime_dir = get_api_cli_dir()?.join("runtime");
    if !runtime_dir.exists() {
        fs::create_dir_all(&runtime_dir)?;
    }
    Ok(runtime_dir.join("mcp.sock"))
}
