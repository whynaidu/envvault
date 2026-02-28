//! Key derivation helpers using HKDF-SHA256.
//!
//! From a single master key we derive:
//! - A unique **per-secret** encryption key for each secret name.
//! - A dedicated **HMAC key** for vault integrity checks.
//!
//! HKDF (RFC 5869) uses the master key as input keying material (IKM)
//! and a context string (`info`) to produce independent sub-keys.

use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroize;

use crate::errors::{EnvVaultError, Result};

/// Length of derived sub-keys (256 bits).
const KEY_LEN: usize = 32;

/// Derive a per-secret encryption key from the master key.
///
/// Each secret name produces a different key so that compromising one
/// encrypted value does not reveal others.
///
/// `info` is set to `"envvault-secret:<secret_name>"` to bind the
/// derived key to a specific secret.
pub fn derive_secret_key(master_key: &[u8], secret_name: &str) -> Result<[u8; KEY_LEN]> {
    let info = format!("envvault-secret:{secret_name}");
    hkdf_derive(master_key, info.as_bytes())
}

/// Derive an HMAC key from the master key.
///
/// This key is used to compute an HMAC over the vault file so we can
/// detect tampering before attempting decryption.
pub fn derive_hmac_key(master_key: &[u8]) -> Result<[u8; KEY_LEN]> {
    hkdf_derive(master_key, b"envvault-hmac-key")
}

/// Internal helper: run HKDF-SHA256 expand with the given `info`.
///
/// We skip the `extract` step and use the master key directly as the
/// pseudo-random key (PRK), because the master key already has high
/// entropy (it came from Argon2id).
fn hkdf_derive(ikm: &[u8], info: &[u8]) -> Result<[u8; KEY_LEN]> {
    // `salt` is None — HKDF will use a zero-filled salt internally.
    let hk = Hkdf::<Sha256>::new(None, ikm);

    let mut okm = [0u8; KEY_LEN];
    hk.expand(info, &mut okm)
        .map_err(|e| EnvVaultError::KeyDerivationFailed(format!("HKDF expand failed: {e}")))?;

    Ok(okm)
}

/// A wrapper around a 32-byte master key that automatically zeroes
/// its memory when dropped.
///
/// Use this to hold the master key in memory so it cannot linger
/// after it is no longer needed.
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct MasterKey {
    bytes: [u8; KEY_LEN],
}

impl MasterKey {
    /// Create a new `MasterKey` from raw bytes.
    pub fn new(bytes: [u8; KEY_LEN]) -> Self {
        Self { bytes }
    }

    /// Access the raw key bytes (e.g. to pass to HKDF or encryption).
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.bytes
    }

    /// Derive a per-secret encryption key from this master key.
    pub fn derive_secret_key(&self, secret_name: &str) -> Result<[u8; KEY_LEN]> {
        derive_secret_key(&self.bytes, secret_name)
    }

    /// Derive an HMAC key from this master key.
    pub fn derive_hmac_key(&self) -> Result<[u8; KEY_LEN]> {
        derive_hmac_key(&self.bytes)
    }
}
