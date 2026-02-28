//! Secret and SecretMetadata types stored inside a vault.
//!
//! Each secret holds its name, the encrypted value (as raw bytes),
//! and creation/update timestamps.  The `encrypted_value` field uses
//! custom serde helpers so it serializes as a base64 string in JSON
//! rather than a raw byte array.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

// Re-use the base64 serde helpers from format.rs (no duplication).
use super::format::{base64_decode, base64_encode};

/// A single encrypted secret stored in the vault.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    /// The name of the secret (e.g. "DATABASE_URL").
    pub name: String,

    /// The encrypted value bytes (nonce + ciphertext).
    /// Serialized as a base64 string in JSON for readability.
    #[serde(serialize_with = "base64_encode", deserialize_with = "base64_decode")]
    pub encrypted_value: Vec<u8>,

    /// When this secret was first created.
    pub created_at: DateTime<Utc>,

    /// When this secret was last updated.
    pub updated_at: DateTime<Utc>,
}

/// Lightweight metadata about a secret (no encrypted value).
///
/// Returned by `VaultStore::list_secrets` so callers can display
/// secret names and timestamps without touching any ciphertext.
#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
