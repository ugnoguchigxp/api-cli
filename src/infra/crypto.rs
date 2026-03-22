use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use rand::{rngs::OsRng, RngCore};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use crate::error::{CliError, Result};

pub struct VaultCrypto {
    key: Key<Aes256Gcm>,
}

impl VaultCrypto {
    /// Loads the vault key from the given path, or creates one if it doesn't exist
    pub fn load_or_create(key_path: &Path) -> Result<Self> {
        if key_path.exists() && fs::metadata(key_path)?.len() == 32 {
            let key_bytes = fs::read(key_path)?;
            let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
            Ok(Self { key: *key })
        } else {
            // Generate a 32-byte key
            let mut key_bytes = [0u8; 32];
            OsRng.fill_bytes(&mut key_bytes);

            if let Some(parent) = key_path.parent() {
                fs::create_dir_all(parent)?;
            }

            fs::write(key_path, key_bytes)?;

            // Set permissions to 0600 on Unix
            #[cfg(unix)]
            {
                let mut perms = fs::metadata(key_path)?.permissions();
                perms.set_mode(0o600);
                fs::set_permissions(key_path, perms)?;
            }

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

    #[test]
    fn test_recreate_when_existing_key_has_invalid_length() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");
        fs::write(&key_path, b"too-short")?;

        let crypto = VaultCrypto::load_or_create(&key_path)?;
        assert_eq!(fs::metadata(&key_path)?.len(), 32);

        let (ciphertext, nonce) = crypto.encrypt(b"ok")?;
        let decrypted = crypto.decrypt(&ciphertext, &nonce)?;
        assert_eq!(decrypted, b"ok");
        Ok(())
    }

    #[test]
    fn test_decrypt_fails_when_nonce_is_tampered() -> Result<()> {
        let dir = tempdir().unwrap();
        let key_path = dir.path().join("vault.key");
        let crypto = VaultCrypto::load_or_create(&key_path)?;

        let (ciphertext, mut nonce) = crypto.encrypt(b"secret")?;
        nonce[0] ^= 0b0000_0001;

        let err = crypto.decrypt(&ciphertext, &nonce).expect_err("decrypt should fail");
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

        let err = crypto.decrypt(&ciphertext, &nonce).expect_err("decrypt should fail");
        assert!(matches!(err, CliError::VaultError(_)));
        Ok(())
    }
}
