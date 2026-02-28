//! Cryptographic primitives for EnvVault.
//!
//! This module provides:
//! - AES-256-GCM encryption and decryption (`encryption`)
//! - Argon2id password-based key derivation (`kdf`)
//! - HKDF-based per-secret key and HMAC key derivation (`keys`)

pub mod encryption;
pub mod kdf;
pub mod keyfile;
pub mod keys;

// Re-export the most commonly used items so callers can write:
//   use crate::crypto::{encrypt, decrypt, derive_master_key, ...};
pub use encryption::{decrypt, encrypt};
pub use kdf::{derive_master_key, derive_master_key_with_params, generate_salt, Argon2Params};
pub use keyfile::{combine_password_keyfile, generate_keyfile, hash_keyfile, load_keyfile};
pub use keys::{derive_hmac_key, derive_secret_key};
