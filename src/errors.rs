use std::path::PathBuf;
use thiserror::Error;

/// All errors that can occur in EnvVault.
#[derive(Debug, Error)]
pub enum EnvVaultError {
    // --- Crypto errors ---
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("Decryption failed — wrong password or corrupted data")]
    DecryptionFailed,

    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    // --- Vault errors ---
    #[error("Vault not found at {0}")]
    VaultNotFound(PathBuf),

    #[error("Vault already exists at {0}")]
    VaultAlreadyExists(PathBuf),

    #[error("Invalid vault format: {0}")]
    InvalidVaultFormat(String),

    #[error("HMAC verification failed — vault file may be tampered")]
    HmacMismatch,

    #[error("HMAC error: {0}")]
    HmacError(String),

    #[error("Secret '{0}' not found")]
    SecretNotFound(String),

    #[error("Secret '{0}' already exists (use `set` to update)")]
    SecretAlreadyExists(String),

    // --- Keyfile errors ---
    #[error("Keyfile error: {0}")]
    KeyfileError(String),

    // --- Keyring errors ---
    #[error("Keyring error: {0}")]
    KeyringError(String),

    // --- Config errors ---
    #[error("Config file error: {0}")]
    ConfigError(String),

    // --- IO errors ---
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    // --- Serialization errors ---
    #[error("Serialization error: {0}")]
    SerializationError(String),

    // --- CLI errors ---
    #[error("Command failed: {0}")]
    CommandFailed(String),

    #[error("User cancelled operation")]
    UserCancelled,

    #[error("Password mismatch — passwords do not match")]
    PasswordMismatch,

    #[error("Child process exited with code {0}")]
    ChildProcessFailed(i32),

    #[error("No command specified — use `envvault run -- <command>`")]
    NoCommandSpecified,

    // --- Phase 3 errors ---
    #[error("Audit error: {0}")]
    AuditError(String),

    #[error("Editor error: {0}")]
    EditorError(String),

    #[error("Environment '{0}' not found — no vault file exists")]
    EnvironmentNotFound(String),
}

/// Convenience type alias for EnvVault results.
pub type Result<T> = std::result::Result<T, EnvVaultError>;
