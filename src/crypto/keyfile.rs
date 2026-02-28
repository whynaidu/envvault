//! Keyfile-based authentication for EnvVault.
//!
//! A keyfile is a 32-byte random file that acts as a second factor.
//! When a vault is created with a keyfile, both the password and the
//! keyfile are required to derive the master key.
//!
//! The combination is: `HMAC-SHA256(keyfile_bytes, password_bytes)`.
//! This combined value is then fed into Argon2id as the "password".

use std::fs;
use std::path::Path;

use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;

use crate::errors::{EnvVaultError, Result};

/// Expected length of a keyfile in bytes (256 bits).
const KEYFILE_LEN: usize = 32;

/// Generate a new random keyfile and write it to `path`.
///
/// The file is written with restrictive permissions (owner-only read).
/// Returns the raw keyfile bytes so the caller can use them immediately.
pub fn generate_keyfile(path: &Path) -> Result<Vec<u8>> {
    if path.exists() {
        return Err(EnvVaultError::KeyfileError(format!(
            "keyfile already exists at {}",
            path.display()
        )));
    }

    // Generate 32 cryptographically random bytes.
    let mut keyfile = vec![0u8; KEYFILE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut keyfile);

    // Ensure the parent directory exists.
    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent).map_err(|e| {
                EnvVaultError::KeyfileError(format!("cannot create keyfile directory: {e}"))
            })?;
        }
    }

    fs::write(path, &keyfile)
        .map_err(|e| EnvVaultError::KeyfileError(format!("failed to write keyfile: {e}")))?;

    // On Unix, restrict permissions to owner-only read/write.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms).map_err(|e| {
            EnvVaultError::KeyfileError(format!("failed to set keyfile permissions: {e}"))
        })?;
    }

    Ok(keyfile)
}

/// Load a keyfile from disk and validate its length.
pub fn load_keyfile(path: &Path) -> Result<Vec<u8>> {
    if !path.exists() {
        return Err(EnvVaultError::KeyfileError(format!(
            "keyfile not found at {}",
            path.display()
        )));
    }

    let data = fs::read(path)
        .map_err(|e| EnvVaultError::KeyfileError(format!("failed to read keyfile: {e}")))?;

    if data.len() != KEYFILE_LEN {
        return Err(EnvVaultError::KeyfileError(format!(
            "keyfile must be exactly {} bytes, got {}",
            KEYFILE_LEN,
            data.len()
        )));
    }

    Ok(data)
}

/// Combine a password and keyfile into a single effective password.
///
/// Uses HMAC-SHA256 with the keyfile as the key and the password as
/// the message: `HMAC-SHA256(keyfile, password)`.
///
/// The result is fed into Argon2id instead of the raw password.
pub fn combine_password_keyfile(password: &[u8], keyfile_bytes: &[u8]) -> Result<Vec<u8>> {
    let mut mac = Hmac::<Sha256>::new_from_slice(keyfile_bytes)
        .map_err(|e| EnvVaultError::KeyfileError(format!("HMAC init failed: {e}")))?;

    mac.update(password);

    Ok(mac.finalize().into_bytes().to_vec())
}

/// Compute the SHA-256 hash of a keyfile for storage in the vault header.
///
/// This hash lets us verify the correct keyfile is being used without
/// storing the keyfile itself in the vault.
pub fn hash_keyfile(keyfile_bytes: &[u8]) -> String {
    use base64::engine::general_purpose::STANDARD as BASE64;
    use base64::Engine;
    use sha2::Digest;
    let hash = Sha256::digest(keyfile_bytes);
    BASE64.encode(hash)
}

/// Verify that a keyfile matches the expected hash stored in the header.
pub fn verify_keyfile_hash(keyfile_bytes: &[u8], expected_hash: &str) -> Result<()> {
    use subtle::ConstantTimeEq;

    let actual_hash = hash_keyfile(keyfile_bytes);

    // Use constant-time comparison to avoid timing side channels.
    if actual_hash
        .as_bytes()
        .ct_eq(expected_hash.as_bytes())
        .into()
    {
        Ok(())
    } else {
        Err(EnvVaultError::KeyfileError(
            "wrong keyfile — hash does not match the vault".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn generate_and_load_keyfile_roundtrip() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.keyfile");

        let generated = generate_keyfile(&path).unwrap();
        assert_eq!(generated.len(), KEYFILE_LEN);

        let loaded = load_keyfile(&path).unwrap();
        assert_eq!(generated, loaded);
    }

    #[test]
    fn generate_keyfile_fails_if_exists() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("test.keyfile");

        generate_keyfile(&path).unwrap();
        let result = generate_keyfile(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_keyfile_fails_if_missing() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("nonexistent.keyfile");

        let result = load_keyfile(&path);
        assert!(result.is_err());
    }

    #[test]
    fn load_keyfile_fails_on_wrong_length() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("bad.keyfile");
        fs::write(&path, [0u8; 16]).unwrap();

        let result = load_keyfile(&path);
        assert!(result.is_err());
    }

    #[test]
    fn combine_password_keyfile_is_deterministic() {
        let password = b"my-password";
        let keyfile = [0xABu8; 32];

        let result1 = combine_password_keyfile(password, &keyfile).unwrap();
        let result2 = combine_password_keyfile(password, &keyfile).unwrap();
        assert_eq!(result1, result2);
    }

    #[test]
    fn combine_differs_with_different_keyfile() {
        let password = b"my-password";
        let keyfile1 = [0xABu8; 32];
        let keyfile2 = [0xCDu8; 32];

        let result1 = combine_password_keyfile(password, &keyfile1).unwrap();
        let result2 = combine_password_keyfile(password, &keyfile2).unwrap();
        assert_ne!(result1, result2);
    }

    #[test]
    fn combine_differs_with_different_password() {
        let keyfile = [0xABu8; 32];

        let result1 = combine_password_keyfile(b"password1", &keyfile).unwrap();
        let result2 = combine_password_keyfile(b"password2", &keyfile).unwrap();
        assert_ne!(result1, result2);
    }

    #[test]
    fn hash_keyfile_is_deterministic() {
        let keyfile = [0x42u8; 32];
        let hash1 = hash_keyfile(&keyfile);
        let hash2 = hash_keyfile(&keyfile);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn verify_keyfile_hash_succeeds_for_correct_keyfile() {
        let keyfile = [0x42u8; 32];
        let hash = hash_keyfile(&keyfile);
        assert!(verify_keyfile_hash(&keyfile, &hash).is_ok());
    }

    #[test]
    fn verify_keyfile_hash_fails_for_wrong_keyfile() {
        let keyfile = [0x42u8; 32];
        let wrong_keyfile = [0x43u8; 32];
        let hash = hash_keyfile(&keyfile);
        assert!(verify_keyfile_hash(&wrong_keyfile, &hash).is_err());
    }
}
