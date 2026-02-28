//! Binary vault file format and HMAC integrity verification.
//!
//! A `.vault` file has this layout:
//!
//! ```text
//! [EVLT: 4 bytes][version: 1 byte][header_len: 4 bytes LE][header JSON][secrets JSON][HMAC-SHA256: 32 bytes]
//! ```
//!
//! - **Magic** (`EVLT`): identifies the file as an EnvVault vault.
//! - **Version**: format version (currently `1`).
//! - **Header length**: little-endian u32 telling us where the header
//!   JSON ends and the secrets JSON begins.
//! - **Header JSON**: serialized `VaultHeader`.
//! - **Secrets JSON**: serialized `Vec<Secret>`.
//! - **HMAC-SHA256**: 32-byte tag computed over header + secrets bytes.

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use super::secret::Secret;
use crate::errors::{EnvVaultError, Result};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Magic bytes at the start of every vault file.
const MAGIC: &[u8; 4] = b"EVLT";

/// Current binary format version.
pub const CURRENT_VERSION: u8 = 1;

/// Size of the HMAC tag appended to the file (SHA-256 = 32 bytes).
const HMAC_LEN: usize = 32;

/// Fixed-size prefix: 4 (magic) + 1 (version) + 4 (header_len).
const PREFIX_LEN: usize = 9;

// ---------------------------------------------------------------------------
// VaultHeader
// ---------------------------------------------------------------------------

/// Argon2 parameters stored in the vault header so the exact same
/// KDF settings are used when re-opening.  Backward-compatible:
/// if missing, defaults are used (m=64MB, t=3, p=4).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct StoredArgon2Params {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

impl Default for StoredArgon2Params {
    fn default() -> Self {
        Self {
            memory_kib: 65_536,
            iterations: 3,
            parallelism: 4,
        }
    }
}

/// Metadata stored at the beginning of a vault file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VaultHeader {
    /// Format version.
    pub version: u8,

    /// The salt used for Argon2id key derivation (base64 in JSON).
    #[serde(serialize_with = "base64_encode", deserialize_with = "base64_decode")]
    pub salt: Vec<u8>,

    /// When this vault was first created.
    pub created_at: DateTime<Utc>,

    /// Environment name (e.g. "dev", "staging", "prod").
    pub environment: String,

    /// Argon2 params used at vault creation (stored so open uses the same).
    /// Optional for backward compatibility with v0.1.0 vaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub argon2_params: Option<StoredArgon2Params>,

    /// SHA-256 hash of the keyfile (base64), if one was used at creation.
    /// Presence of this field means a keyfile is required to open the vault.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Write a vault file to disk **atomically**.
///
/// 1. Serialize header and secrets to JSON.
/// 2. Compute HMAC over header + secrets bytes.
/// 3. Write to a temp file in the same directory.
/// 4. Rename temp file over the target path.
///
/// The rename ensures readers never see a half-written file.
pub fn write_vault(
    path: &Path,
    header: &VaultHeader,
    secrets: &[Secret],
    hmac_key: &[u8],
) -> Result<()> {
    let header_bytes = serde_json::to_vec(header)
        .map_err(|e| EnvVaultError::SerializationError(format!("header: {e}")))?;
    let secrets_bytes = serde_json::to_vec(secrets)
        .map_err(|e| EnvVaultError::SerializationError(format!("secrets: {e}")))?;

    let hmac_tag = compute_hmac(hmac_key, &header_bytes, &secrets_bytes)?;

    // Build the binary blob.
    let header_len = u32::try_from(header_bytes.len()).map_err(|_| {
        EnvVaultError::SerializationError(format!(
            "header length {} exceeds u32::MAX",
            header_bytes.len()
        ))
    })?;
    let total = PREFIX_LEN + header_bytes.len() + secrets_bytes.len() + HMAC_LEN;
    let mut buf = Vec::with_capacity(total);

    buf.extend_from_slice(MAGIC); // 4 bytes
    buf.push(CURRENT_VERSION); // 1 byte
    buf.extend_from_slice(&header_len.to_le_bytes()); // 4 bytes LE
    buf.extend_from_slice(&header_bytes); // header JSON
    buf.extend_from_slice(&secrets_bytes); // secrets JSON
    buf.extend_from_slice(&hmac_tag); // 32 bytes

    // Atomic write: write to a temp file, then rename.
    // The temp file is in the same directory so rename is guaranteed
    // to be atomic on the same filesystem.
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp_path = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));

    fs::write(&tmp_path, &buf)?;
    fs::rename(&tmp_path, path)?;

    Ok(())
}

/// Raw data read from a vault file on disk.
///
/// Keeps the original bytes so the HMAC can be verified over the
/// exact bytes that were written — no re-serialization needed.
pub struct RawVault {
    pub header: VaultHeader,
    pub secrets: Vec<Secret>,
    /// The raw header JSON bytes exactly as stored on disk.
    pub header_bytes: Vec<u8>,
    /// The raw secrets JSON bytes exactly as stored on disk.
    pub secrets_bytes: Vec<u8>,
    /// The HMAC tag stored at the end of the file.
    pub stored_hmac: Vec<u8>,
}

/// Read a vault file from disk and return its parts **with raw bytes**.
///
/// The caller should verify the HMAC over `header_bytes` and
/// `secrets_bytes` (the original bytes from disk) before trusting
/// the deserialized data.
pub fn read_vault(path: &Path) -> Result<RawVault> {
    if !path.exists() {
        return Err(EnvVaultError::VaultNotFound(path.to_path_buf()));
    }

    let data = fs::read(path)?;

    // Minimum size: prefix + HMAC.
    let min_size = PREFIX_LEN + HMAC_LEN;
    if data.len() < min_size {
        return Err(EnvVaultError::InvalidVaultFormat(
            "file too small to be a valid vault".into(),
        ));
    }

    // --- Parse the fixed-size prefix ---

    if &data[0..4] != MAGIC {
        return Err(EnvVaultError::InvalidVaultFormat(
            "missing EVLT magic bytes".into(),
        ));
    }

    let version = data[4];
    if version != CURRENT_VERSION {
        return Err(EnvVaultError::InvalidVaultFormat(format!(
            "unsupported version {version}, expected {CURRENT_VERSION}"
        )));
    }

    let header_len_u32 = u32::from_le_bytes(
        data[5..9]
            .try_into()
            .map_err(|_| EnvVaultError::InvalidVaultFormat("bad header length".into()))?,
    );
    let header_len = usize::try_from(header_len_u32).map_err(|_| {
        EnvVaultError::InvalidVaultFormat(format!(
            "header length {header_len_u32} exceeds platform address space"
        ))
    })?;

    let header_end = PREFIX_LEN + header_len;
    if header_end + HMAC_LEN > data.len() {
        return Err(EnvVaultError::InvalidVaultFormat(
            "header length exceeds file size".into(),
        ));
    }

    // --- Extract the three variable-length sections as raw bytes ---

    let header_bytes = data[PREFIX_LEN..header_end].to_vec();
    let secrets_end = data.len() - HMAC_LEN;
    let secrets_bytes = data[header_end..secrets_end].to_vec();
    let stored_hmac = data[secrets_end..].to_vec();

    // --- Deserialize from the raw bytes ---

    let header: VaultHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| EnvVaultError::InvalidVaultFormat(format!("header JSON: {e}")))?;

    let secrets: Vec<Secret> = serde_json::from_slice(&secrets_bytes)
        .map_err(|e| EnvVaultError::InvalidVaultFormat(format!("secrets JSON: {e}")))?;

    Ok(RawVault {
        header,
        secrets,
        header_bytes,
        secrets_bytes,
        stored_hmac,
    })
}

/// Compute HMAC-SHA256 over header + secrets bytes.
pub fn compute_hmac(hmac_key: &[u8], header_bytes: &[u8], secrets_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
        .map_err(|e| EnvVaultError::HmacError(format!("invalid HMAC key: {e}")))?;

    mac.update(header_bytes);
    mac.update(secrets_bytes);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Verify that the HMAC matches using constant-time comparison.
///
/// Uses `hmac::Mac::verify_slice` which is guaranteed constant-time,
/// preventing timing side-channel attacks.
pub fn verify_hmac(
    hmac_key: &[u8],
    header_bytes: &[u8],
    secrets_bytes: &[u8],
    expected_hmac: &[u8],
) -> Result<()> {
    let mut mac = Hmac::<Sha256>::new_from_slice(hmac_key)
        .map_err(|e| EnvVaultError::HmacError(format!("invalid HMAC key: {e}")))?;

    mac.update(header_bytes);
    mac.update(secrets_bytes);

    mac.verify_slice(expected_hmac)
        .map_err(|_| EnvVaultError::HmacMismatch)
}

// ---------------------------------------------------------------------------
// Serde helpers for base64-encoded Vec<u8> fields
// ---------------------------------------------------------------------------

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;

pub(crate) fn base64_encode<S>(data: &[u8], serializer: S) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let encoded = BASE64.encode(data);
    serializer.serialize_str(&encoded)
}

pub(crate) fn base64_decode<'de, D>(deserializer: D) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let s = String::deserialize(deserializer)?;
    BASE64.decode(&s).map_err(serde::de::Error::custom)
}
