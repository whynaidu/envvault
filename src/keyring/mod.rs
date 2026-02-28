//! OS keyring integration for password caching.
//!
//! Stores and retrieves the vault password from the operating system's
//! secure credential store:
//! - macOS: Keychain
//! - Windows: Credential Manager
//! - Linux: Secret Service (GNOME Keyring / KDE Wallet)
//!
//! All operations fail gracefully — if the keyring is unavailable, the
//! error is returned and the caller falls back to a password prompt.

use crate::errors::{EnvVaultError, Result};

/// Service name used in the OS keyring.
const SERVICE_NAME: &str = "envvault";

/// Build a keyring entry key from a vault path.
///
/// Uses the canonical path so that different relative paths to the
/// same vault resolve to the same keyring entry.
fn entry_key(vault_path: &str) -> String {
    format!("vault:{vault_path}")
}

/// Store a password in the OS keyring for a specific vault.
pub fn store_password(vault_path: &str, password: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, &entry_key(vault_path))
        .map_err(|e| EnvVaultError::KeyringError(format!("failed to create keyring entry: {e}")))?;

    entry.set_password(password).map_err(|e| {
        EnvVaultError::KeyringError(format!("failed to store password in keyring: {e}"))
    })?;

    Ok(())
}

/// Retrieve a password from the OS keyring for a specific vault.
///
/// Returns `None` if no password is stored (rather than an error).
pub fn get_password(vault_path: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(SERVICE_NAME, &entry_key(vault_path))
        .map_err(|e| EnvVaultError::KeyringError(format!("failed to create keyring entry: {e}")))?;

    match entry.get_password() {
        Ok(password) => Ok(Some(password)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e) => Err(EnvVaultError::KeyringError(format!(
            "failed to read from keyring: {e}"
        ))),
    }
}

/// Delete a stored password from the OS keyring.
pub fn delete_password(vault_path: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, &entry_key(vault_path))
        .map_err(|e| EnvVaultError::KeyringError(format!("failed to create keyring entry: {e}")))?;

    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // Already gone, that's fine.
        Err(e) => Err(EnvVaultError::KeyringError(format!(
            "failed to delete from keyring: {e}"
        ))),
    }
}
