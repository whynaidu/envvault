//! Secret and SecretMetadata types stored inside a vault.
//!
//! Each secret holds its name, the encrypted value (as raw bytes),
//! creation/update timestamps, and optional metadata (description and
//! tags) introduced in vault format v2. The `encrypted_value` field
//! uses custom serde helpers so it serializes as a base64 string in
//! JSON rather than a raw byte array.

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

    /// Optional human-readable description (vault format v2+).
    ///
    /// Absent in v1 vaults; defaults to `None` on read and is omitted
    /// from JSON when not set, keeping v1/v2 round-trip symmetric for
    /// secrets that have no description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Optional tags for classification and filtering (vault format v2+).
    ///
    /// Each entry is a free-form string, typically in `key:value` form
    /// (e.g., `provider:stripe`, `tier:prod`). Absent in v1 vaults.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Optional expiration timestamp (vault format v2+).
    ///
    /// When set and the current time is past this value, the secret
    /// is considered expired. `list --expired` surfaces these, and
    /// `run` emits a warning when injecting an expired secret.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<DateTime<Utc>>,
}

impl Secret {
    /// Returns `true` if the secret has an expiration and it is in the past.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => exp <= Utc::now(),
            None => false,
        }
    }
}

/// Lightweight metadata about a secret (no encrypted value).
///
/// Returned by `VaultStore::list_secrets` so callers can display
/// secret names, timestamps, and v2 metadata without touching any
/// ciphertext.
#[derive(Debug, Clone)]
pub struct SecretMetadata {
    pub name: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub description: Option<String>,
    pub tags: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl SecretMetadata {
    /// Returns `true` if the secret has an expiration and it is in the past.
    pub fn is_expired(&self) -> bool {
        match self.expires_at {
            Some(exp) => exp <= Utc::now(),
            None => false,
        }
    }
}
