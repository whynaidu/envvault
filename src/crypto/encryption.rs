//! AES-256-GCM authenticated encryption.
//!
//! Each call to `encrypt` generates a fresh random 12-byte nonce and
//! prepends it to the ciphertext.  `decrypt` splits the nonce back out
//! before decrypting.
//!
//! Layout of the returned byte buffer:
//!   [ 12-byte nonce | ciphertext + 16-byte auth tag ]

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{AeadCore, Aes256Gcm, Nonce};

use crate::errors::{EnvVaultError, Result};

/// Size of the AES-256-GCM nonce in bytes.
const NONCE_LEN: usize = 12;

/// Encrypt `plaintext` with a 32-byte `key`.
///
/// Returns the nonce prepended to the ciphertext (nonce || ciphertext).
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    // Build the cipher from the raw key bytes.
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| EnvVaultError::EncryptionFailed(format!("invalid key length: {e}")))?;

    // Generate a random 12-byte nonce.
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    // Encrypt and authenticate the plaintext.
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| EnvVaultError::EncryptionFailed(format!("encryption error: {e}")))?;

    // Prepend the nonce so the caller only needs to store one blob.
    let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt data that was produced by `encrypt`.
///
/// Expects the first 12 bytes to be the nonce, followed by the ciphertext.
pub fn decrypt(key: &[u8], ciphertext_with_nonce: &[u8]) -> Result<Vec<u8>> {
    // Make sure we have at least a nonce worth of bytes.
    if ciphertext_with_nonce.len() < NONCE_LEN {
        return Err(EnvVaultError::DecryptionFailed);
    }

    // Split nonce from ciphertext.
    let (nonce_bytes, ciphertext) = ciphertext_with_nonce.split_at(NONCE_LEN);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Build the cipher from the raw key bytes.
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| EnvVaultError::DecryptionFailed)?;

    // Decrypt and verify the auth tag.
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| EnvVaultError::DecryptionFailed)?;

    Ok(plaintext)
}
