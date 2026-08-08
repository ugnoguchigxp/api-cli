use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use fs2::FileExt;
use rand::{rngs::OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{CliError, Result};

#[derive(Clone)]
pub struct VaultCrypto {
    key: Key<Aes256Gcm>,
}

impl VaultCrypto {
    /// Uses the platform credential store for new installations and keeps the
    /// secure file backend as a compatibility and headless-environment fallback.
    pub fn load_or_create_preferred(key_path: &Path) -> Result<Self> {
        Self::load_or_create_preferred_for_vault(key_path, false)
    }

    /// Loads the preferred key backend while refusing to mint a replacement
    /// key when the vault already contains encrypted records.
    pub fn load_or_create_preferred_for_vault(
        key_path: &Path,
        vault_has_secrets: bool,
    ) -> Result<Self> {
        let _initialization_lock = acquire_initialization_lock(key_path)?;
        let marker_path = keyring_marker_path(key_path);
        if marker_path.exists() {
            validate_keyring_marker(&marker_path)?;
            return Self::load_or_create_keyring(key_path, false)?.ok_or_else(|| {
                CliError::VaultError(
                    "OS credential store is unavailable or the vault key entry is missing; refusing to generate a replacement key"
                        .into(),
                )
            });
        }
        if key_path.exists() {
            return Self::load_or_create(key_path);
        }

        let force_file = match std::env::var_os("API_CLI_VAULT_KEY_BACKEND") {
            None => false,
            Some(value) if value == "file" => true,
            Some(_) => {
                return Err(CliError::InvalidInput(
                    "API_CLI_VAULT_KEY_BACKEND only accepts 'file'".into(),
                ))
            }
        };
        if force_file {
            if vault_has_secrets {
                return Err(CliError::VaultKeyMissing);
            }
            return Self::load_or_create(key_path);
        }

        match Self::load_or_create_keyring(key_path, !vault_has_secrets)? {
            Some(crypto) => {
                store_keyring_marker(&marker_path)?;
                Ok(crypto)
            }
            None if vault_has_secrets => Err(CliError::VaultKeyMissing),
            None => {
                tracing::warn!(
                    "OS credential store is unavailable; using the permission-restricted vault key file"
                );
                Self::load_or_create(key_path)
            }
        }
    }

    fn load_or_create_keyring(key_path: &Path, create: bool) -> Result<Option<Self>> {
        let account = keyring_account(key_path);
        let entry = match keyring::v1::Entry::new("dev.apicli.vault", &account) {
            Ok(entry) => entry,
            Err(_) => return Ok(None),
        };
        match entry.get_secret() {
            Ok(key_bytes) => Self::from_key_bytes(&key_bytes).map(Some),
            Err(keyring::v1::Error::NoEntry) if create => {
                let mut key_bytes = [0_u8; 32];
                OsRng.fill_bytes(&mut key_bytes);
                if entry.set_secret(&key_bytes).is_err() {
                    return Ok(None);
                }
                Ok(Some(Self::from_key_bytes(&key_bytes)?))
            }
            Err(_) => Ok(None),
        }
    }

    /// Loads the vault key from the given path, or creates one if it doesn't exist
    pub fn load_or_create(key_path: &Path) -> Result<Self> {
        if key_path.exists() {
            let metadata = fs::symlink_metadata(key_path)?;
            if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
                return Err(CliError::VaultError(
                    "Vault key must be a regular file, not a symlink".into(),
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if metadata.permissions().mode() & 0o077 != 0 {
                    fs::set_permissions(key_path, fs::Permissions::from_mode(0o600))?;
                }
            }
            let key_bytes = fs::read(key_path)?;
            if key_bytes.len() != 32 {
                return Err(CliError::VaultError(format!(
                    "Vault key has invalid length {}; refusing to replace it",
                    key_bytes.len()
                )));
            }
            Self::from_key_bytes(&key_bytes)
        } else {
            // Generate a 32-byte key
            let mut key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut key_bytes);

            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }

            #[cfg(unix)]
            let mut key_file = {
                use std::os::unix::fs::OpenOptionsExt;
                fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(key_path)?
            };
            #[cfg(not(unix))]
            let mut key_file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(key_path)?;
            key_file.write_all(&key_bytes)?;
            key_file.sync_all()?;

            Self::from_key_bytes(&key_bytes)
        }
    }

    fn from_key_bytes(key_bytes: &[u8]) -> Result<Self> {
        if key_bytes.len() != 32 {
            return Err(CliError::VaultError(format!(
                "Vault key has invalid length {}; refusing to replace it",
                key_bytes.len()
            )));
        }
        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        Ok(Self { key: *key })
    }

    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let cipher = Aes256Gcm::new(&self.key);

        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| CliError::VaultError(format!("Encryption failed: {}", e)))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    pub fn decrypt(&self, ciphertext: &[u8], nonce: &[u8]) -> Result<Vec<u8>> {
        if nonce.len() != 12 {
            return Err(CliError::VaultError(format!(
                "Invalid AES-GCM nonce length: {}",
                nonce.len()
            )));
        }
        let cipher = Aes256Gcm::new(&self.key);
        let nonce = Nonce::from_slice(nonce);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| CliError::VaultError(format!("Decryption failed: {}", e)))?;

        Ok(plaintext)
    }
}

fn keyring_account(key_path: &Path) -> String {
    let digest = Sha256::digest(key_path.as_os_str().as_encoded_bytes());
    format!("vault-{}", hex::encode(&digest[..16]))
}

fn keyring_marker_path(key_path: &Path) -> std::path::PathBuf {
    key_path.with_extension("keyring")
}

fn acquire_initialization_lock(key_path: &Path) -> Result<fs::File> {
    let lock_path = key_path.with_extension("lock");
    if let Some(parent) = lock_path.parent() {
        fs::create_dir_all(parent)?;
    }
    if lock_path.exists() {
        let metadata = fs::symlink_metadata(&lock_path)?;
        if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
            return Err(CliError::VaultError(
                "Vault initialization lock must be a regular file, not a symlink".into(),
            ));
        }
    }
    #[cfg(unix)]
    let lock = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)?
    };
    #[cfg(not(unix))]
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    lock.lock_exclusive()
        .map_err(|error| CliError::VaultError(format!("Vault initialization lock: {error}")))?;
    Ok(lock)
}

fn validate_keyring_marker(marker_path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(marker_path)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(CliError::VaultError(
            "Vault keyring marker must be a regular file, not a symlink".into(),
        ));
    }
    if fs::read(marker_path)? != b"keyring-v1\n" {
        return Err(CliError::VaultError(
            "Vault keyring marker has an unsupported format".into(),
        ));
    }
    Ok(())
}

fn store_keyring_marker(marker_path: &Path) -> Result<()> {
    if let Some(parent) = marker_path.parent() {
        fs::create_dir_all(parent)?;
    }
    #[cfg(unix)]
    let mut marker = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(marker_path)?
    };
    #[cfg(not(unix))]
    let mut marker = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(marker_path)?;
    marker.write_all(b"keyring-v1\n")?;
    marker.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use tempfile::tempdir;

    struct EnvRestore(Option<OsString>);

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            match self.0.take() {
                Some(value) => std::env::set_var("API_CLI_VAULT_KEY_BACKEND", value),
                None => std::env::remove_var("API_CLI_VAULT_KEY_BACKEND"),
            }
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");
        let crypto = VaultCrypto::load_or_create(&key_path)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(fs::metadata(&key_path)?.permissions().mode() & 0o777, 0o600);
        }

        let plaintext = b"hello world secret";
        let (ciphertext, nonce) = crypto.encrypt(plaintext)?;

        assert_ne!(plaintext.to_vec(), ciphertext);

        let decrypted = crypto.decrypt(&ciphertext, &nonce)?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }

    #[test]
    fn test_load_existing_key() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");

        let crypto1 = VaultCrypto::load_or_create(&key_path)?;
        let plaintext = b"persistent secret";
        let (ciphertext, nonce) = crypto1.encrypt(plaintext)?;

        // Re-load
        let crypto2 = VaultCrypto::load_or_create(&key_path)?;
        let decrypted = crypto2.decrypt(&ciphertext, &nonce)?;
        assert_eq!(plaintext.to_vec(), decrypted);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn existing_key_permissions_are_tightened_and_symlinks_are_rejected() -> Result<()> {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempdir()?;
        let key_path = dir.path().join("vault.key");
        fs::write(&key_path, [7_u8; 32])?;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o644))?;
        VaultCrypto::load_or_create(&key_path)?;
        assert_eq!(fs::metadata(&key_path)?.permissions().mode() & 0o777, 0o600);

        let symlink_path = dir.path().join("linked.key");
        symlink(&key_path, &symlink_path)?;
        assert!(matches!(
            VaultCrypto::load_or_create(&symlink_path),
            Err(CliError::VaultError(_))
        ));
        Ok(())
    }

    #[test]
    fn test_reject_existing_key_with_invalid_length() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");
        fs::write(&key_path, b"too-short")?;

        let error = match VaultCrypto::load_or_create(&key_path) {
            Ok(_) => panic!("invalid key must fail"),
            Err(error) => error,
        };
        assert!(matches!(error, CliError::VaultError(_)));
        assert_eq!(fs::read(&key_path)?, b"too-short");
        Ok(())
    }

    #[test]
    fn keyring_account_is_stable_and_does_not_disclose_the_path() {
        let path = Path::new("/Users/alice/private/api-cli/vault.key");
        let account = keyring_account(path);
        assert_eq!(account, keyring_account(path));
        assert!(account.starts_with("vault-"));
        assert!(!account.contains("alice"));
    }

    #[test]
    fn keyring_marker_must_be_regular_and_versioned() -> Result<()> {
        let directory = tempdir()?;
        let marker = directory.path().join("vault.keyring");
        fs::write(&marker, b"unknown\n")?;
        assert!(matches!(
            validate_keyring_marker(&marker),
            Err(CliError::VaultError(_))
        ));
        fs::write(&marker, b"keyring-v1\n")?;
        validate_keyring_marker(&marker)?;
        Ok(())
    }

    #[test]
    fn nonempty_vault_never_gets_a_replacement_file_key() {
        let directory = tempdir().expect("temp directory");
        let key_path = directory.path().join("vault.key");
        let previous = std::env::var_os("API_CLI_VAULT_KEY_BACKEND");
        let _restore = EnvRestore(previous);
        std::env::set_var("API_CLI_VAULT_KEY_BACKEND", "file");

        assert!(matches!(
            VaultCrypto::load_or_create_preferred_for_vault(&key_path, true),
            Err(CliError::VaultKeyMissing)
        ));
        assert!(!key_path.exists());
    }

    #[test]
    fn test_decrypt_fails_when_nonce_is_tampered() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");
        let crypto = VaultCrypto::load_or_create(&key_path)?;

        let (ciphertext, mut nonce) = crypto.encrypt(b"secret")?;
        nonce[0] ^= 0b0000_0001;

        let err = crypto
            .decrypt(&ciphertext, &nonce)
            .expect_err("decrypt should fail");
        assert!(matches!(err, CliError::VaultError(_)));
        Ok(())
    }

    #[test]
    fn test_decrypt_fails_when_ciphertext_is_tampered() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");
        let crypto = VaultCrypto::load_or_create(&key_path)?;

        let (mut ciphertext, nonce) = crypto.encrypt(b"secret")?;
        ciphertext[0] ^= 0b0000_0001;

        let err = crypto
            .decrypt(&ciphertext, &nonce)
            .expect_err("decrypt should fail");
        assert!(matches!(err, CliError::VaultError(_)));
        Ok(())
    }
}
