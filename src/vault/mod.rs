//! Vault module — encrypted secret storage.
//!
//! This module provides:
//! - `Secret` and `SecretMetadata` types (`secret`)
//! - Binary vault file format with HMAC integrity (`format`)
//! - High-level `VaultStore` for creating, opening, and managing vaults (`store`)

pub mod format;
pub mod secret;
pub mod store;

// Re-export the most commonly used items.
pub use format::{StoredArgon2Params, VaultHeader};
pub use secret::{Secret, SecretMetadata};
pub use store::VaultStore;
