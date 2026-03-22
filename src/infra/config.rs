use crate::error::{CliError, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;

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

#[allow(dead_code)]
pub fn get_runtime_sock_path() -> Result<PathBuf> {
    let runtime_dir = get_api_cli_dir()?.join("runtime");
    if !runtime_dir.exists() {
        fs::create_dir_all(&runtime_dir)?;
    }
    Ok(runtime_dir.join("mcp.sock"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::sync::{Mutex, OnceLock};
    use tempfile::tempdir;

    static ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    struct EnvGuard {
        home: Option<OsString>,
        xdg_config_home: Option<OsString>,
    }

    impl EnvGuard {
        fn set(home: &std::path::Path) -> Self {
            let prev = Self {
                home: std::env::var_os("HOME"),
                xdg_config_home: std::env::var_os("XDG_CONFIG_HOME"),
            };
            std::env::set_var("HOME", home);
            std::env::set_var("XDG_CONFIG_HOME", home);
            prev
        }
    }

    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.home {
                Some(v) => std::env::set_var("HOME", v),
                None => std::env::remove_var("HOME"),
            }
            match &self.xdg_config_home {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    #[test]
    fn api_cli_dir_is_created_under_home() {
        let _lock = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock");
        let temp_home = tempdir().expect("temp dir");
        let _guard = EnvGuard::set(temp_home.path());

        let dir = get_api_cli_dir().expect("get api-cli dir");
        assert!(dir.exists());
        assert!(dir.starts_with(temp_home.path()));
    }

    #[test]
    fn db_key_and_runtime_paths_are_derived_from_api_cli_dir() {
        let _lock = ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("env lock");
        let temp_home = tempdir().expect("temp dir");
        let _guard = EnvGuard::set(temp_home.path());

        let base = get_api_cli_dir().expect("base dir");
        let metadata = get_metadata_db_path().expect("metadata path");
        let vault = get_vault_db_path().expect("vault path");
        let key = get_vault_key_path().expect("key path");
        let sock = get_runtime_sock_path().expect("runtime sock path");

        assert_eq!(metadata, base.join("metadata.db"));
        assert_eq!(vault, base.join("vault.db"));
        assert_eq!(key, base.join("vault.key"));
        assert_eq!(sock, base.join("runtime").join("mcp.sock"));
        assert!(base.join("runtime").exists());
    }
}
