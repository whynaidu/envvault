//! Password-based key derivation using Argon2id.
//!
//! Argon2id is a memory-hard KDF that protects against brute-force and
//! GPU-based attacks.  Parameters are configurable via `Argon2Params`
//! (loaded from `.envvault.toml` or sensible defaults).

use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::errors::{EnvVaultError, Result};

/// Length of the salt in bytes (256 bits).
const SALT_LEN: usize = 32;

/// Length of the derived key in bytes (256 bits, for AES-256).
const KEY_LEN: usize = 32;

/// Configurable Argon2id parameters.
///
/// These map 1:1 to the fields in `Settings` so the CLI can pass
/// whatever the user configured in `.envvault.toml`.
#[derive(Debug, Clone, Copy)]
pub struct Argon2Params {
    /// Memory cost in KiB (default: 65 536 = 64 MB).
    pub memory_kib: u32,
    /// Number of iterations (default: 3).
    pub iterations: u32,
    /// Parallelism lanes (default: 4).
    pub parallelism: u32,
}

impl Default for Argon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Derive a 32-byte master key from a password and salt using Argon2id.
///
/// Uses the default Argon2id parameters (64 MB, 3 iterations, 4 lanes).
/// Prefer `derive_master_key_with_params` when you have a `Settings`.
pub fn derive_master_key(password: &[u8], salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    derive_master_key_with_params(password, salt, &Argon2Params::default())
}

/// Minimum safe memory cost in KiB (8 MB).
const MIN_MEMORY_KIB: u32 = 8_192;

/// Derive a 32-byte master key with explicit Argon2id parameters.
///
/// The same password + salt + params will always produce the same key.
/// Enforces minimum Argon2 parameters to prevent dangerously weak KDF settings.
pub fn derive_master_key_with_params(
    password: &[u8],
    salt: &[u8],
    argon2_params: &Argon2Params,
) -> Result<[u8; KEY_LEN]> {
    if argon2_params.memory_kib < MIN_MEMORY_KIB {
        return Err(EnvVaultError::KeyDerivationFailed(format!(
            "Argon2 memory_kib must be at least {MIN_MEMORY_KIB} (got {})",
            argon2_params.memory_kib
        )));
    }
    if argon2_params.iterations < 1 {
        return Err(EnvVaultError::KeyDerivationFailed(
            "Argon2 iterations must be at least 1".into(),
        ));
    }
    if argon2_params.parallelism < 1 {
        return Err(EnvVaultError::KeyDerivationFailed(
            "Argon2 parallelism must be at least 1".into(),
        ));
    }

    let params = Params::new(
        argon2_params.memory_kib,
        argon2_params.iterations,
        argon2_params.parallelism,
        Some(KEY_LEN),
    )
    .map_err(|e| EnvVaultError::KeyDerivationFailed(format!("invalid Argon2 params: {e}")))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut key = [0u8; KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut key)
        .map_err(|e| EnvVaultError::KeyDerivationFailed(format!("Argon2id hashing failed: {e}")))?;

    Ok(key)
}

/// Generate a cryptographically random 32-byte salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    salt
}
