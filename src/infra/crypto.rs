use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce, Key,
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
        if key_path.exists() {
            let key_bytes = fs::read(key_path)?;
            if key_bytes.len() != 32 {
                return Err(CliError::VaultError("Invalid key length".to_string()));
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

            fs::write(key_path, &key_bytes)?;
            
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
