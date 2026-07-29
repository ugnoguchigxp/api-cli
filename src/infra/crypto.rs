use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::io::Write;
use std::path::Path;

use crate::error::{CliError, Result};

#[derive(Clone)]
pub struct VaultCrypto {
    key: Key<Aes256Gcm>,
}

impl VaultCrypto {
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
            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            Ok(Self { key: *key })
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

            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            Ok(Self { key: *key })
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
