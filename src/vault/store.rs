//! High-level vault operations used by CLI commands.
//!
//! `VaultStore` wraps the binary format layer and the crypto layer so
//! that the rest of the application can work with simple method calls
//! like `store.set_secret("DB_URL", "postgres://...")`.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use chrono::Utc;
use zeroize::Zeroize;

use crate::crypto::encryption::{decrypt, encrypt};
use crate::crypto::kdf::{derive_master_key_with_params, generate_salt, Argon2Params};
use crate::crypto::keyfile;
use crate::crypto::keys::MasterKey;
use crate::errors::{EnvVaultError, Result};

use super::format::{self, StoredArgon2Params, VaultHeader, CURRENT_VERSION};
use super::secret::{Secret, SecretMetadata};

/// The main vault handle.  Create one with `VaultStore::create` or
/// `VaultStore::open`, then use its methods to manage secrets.
pub struct VaultStore {
    /// Path to the `.vault` file on disk.
    path: PathBuf,

    /// Header metadata (version, salt, environment, timestamps).
    header: VaultHeader,

    /// In-memory map of secret name -> encrypted Secret.
    secrets: HashMap<String, Secret>,

    /// The derived master key (zeroized on drop).
    master_key: MasterKey,
}

impl VaultStore {
    // ------------------------------------------------------------------
    // Construction
    // ------------------------------------------------------------------

    /// Create a brand-new vault file at `path`.
    ///
    /// Generates a random salt, derives the master key from the
    /// password, and writes an empty vault to disk.
    ///
    /// Pass `None` for `argon2_params` to use sensible defaults.
    /// Pass `Some(settings.argon2_params())` to use config values.
    ///
    /// Pass `Some(bytes)` for `keyfile_bytes` to enable keyfile-based 2FA.
    /// The keyfile hash is stored in the vault header so `open` can
    /// verify the correct keyfile is used.
    pub fn create(
        path: &Path,
        password: &[u8],
        environment: &str,
        argon2_params: Option<&Argon2Params>,
        keyfile_bytes: Option<&[u8]>,
    ) -> Result<Self> {
        if path.exists() {
            return Err(EnvVaultError::VaultAlreadyExists(path.to_path_buf()));
        }

        // 1. Generate a random salt.
        let salt = generate_salt();

        // 2. Resolve Argon2 params (explicit or defaults).
        let effective_params = argon2_params.copied().unwrap_or_default();

        // 3. Combine password with keyfile (if provided) and derive master key.
        let mut effective_password = match keyfile_bytes {
            Some(kf) => keyfile::combine_password_keyfile(password, kf)?,
            None => password.to_vec(),
        };
        let mut master_bytes =
            derive_master_key_with_params(&effective_password, &salt, &effective_params)?;
        effective_password.zeroize();
        let master_key = MasterKey::new(master_bytes);
        master_bytes.zeroize();

        // 4. Build the header (store the params so open uses the same).
        let kf_hash = keyfile_bytes.map(keyfile::hash_keyfile);
        let header = VaultHeader {
            version: CURRENT_VERSION,
            salt: salt.to_vec(),
            created_at: Utc::now(),
            environment: environment.to_string(),
            argon2_params: Some(StoredArgon2Params {
                memory_kib: effective_params.memory_kib,
                iterations: effective_params.iterations,
                parallelism: effective_params.parallelism,
            }),
            keyfile_hash: kf_hash,
        };

        // 5. Start with an empty secrets map.
        let secrets = HashMap::new();

        let mut store = Self {
            path: path.to_path_buf(),
            header,
            secrets,
            master_key,
        };

        // 6. Persist the empty vault to disk.
        store.save()?;

        Ok(store)
    }

    /// Open an existing vault file, verifying its integrity.
    ///
    /// Reads the binary file, derives the master key from the
    /// password + stored salt (using stored Argon2 params), and
    /// verifies the HMAC **over the original bytes from disk**.
    ///
    /// If the vault was created with a keyfile, `keyfile_bytes` must be
    /// provided. If the vault has no keyfile requirement, the parameter
    /// is ignored.
    pub fn open(path: &Path, password: &[u8], keyfile_bytes: Option<&[u8]>) -> Result<Self> {
        // 1. Read the binary vault file (raw bytes preserved).
        let raw = format::read_vault(path)?;

        // 2. Validate keyfile requirement.
        //    If the vault header has a keyfile_hash, a keyfile is required.
        if let Some(ref expected_hash) = raw.header.keyfile_hash {
            match keyfile_bytes {
                Some(kf) => keyfile::verify_keyfile_hash(kf, expected_hash)?,
                None => {
                    return Err(EnvVaultError::KeyfileError(
                        "this vault requires a keyfile — use --keyfile <path>".into(),
                    ));
                }
            }
        }

        // 3. Combine password with keyfile (if provided) and derive master key.
        let mut effective_password = match keyfile_bytes {
            Some(kf) => keyfile::combine_password_keyfile(password, kf)?,
            None => password.to_vec(),
        };

        // 4. Derive the master key using the stored Argon2 params.
        //    Fall back to defaults for v0.1.0 vaults without stored params.
        let stored = raw.header.argon2_params.unwrap_or_default();
        let params = Argon2Params {
            memory_kib: stored.memory_kib,
            iterations: stored.iterations,
            parallelism: stored.parallelism,
        };
        let mut master_bytes =
            derive_master_key_with_params(&effective_password, &raw.header.salt, &params)?;
        effective_password.zeroize();
        let master_key = MasterKey::new(master_bytes);
        master_bytes.zeroize();

        // 3. Verify the HMAC over the *original raw bytes* from disk.
        //    This avoids the re-serialization round-trip bug where
        //    serde_json might produce different byte output.
        let mut hmac_key = master_key.derive_hmac_key()?;
        format::verify_hmac(
            &hmac_key,
            &raw.header_bytes,
            &raw.secrets_bytes,
            &raw.stored_hmac,
        )?;
        hmac_key.zeroize();

        // 4. Build the in-memory map.
        let secrets: HashMap<String, Secret> = raw
            .secrets
            .into_iter()
            .map(|s| (s.name.clone(), s))
            .collect();

        Ok(Self {
            path: path.to_path_buf(),
            header: raw.header,
            secrets,
            master_key,
        })
    }

    /// Build a `VaultStore` from pre-constructed parts.
    ///
    /// Used by `rotate-key` to create a new store with a new master key
    /// without writing to disk first.
    pub fn from_parts(path: PathBuf, header: VaultHeader, master_key: MasterKey) -> Self {
        Self {
            path,
            header,
            secrets: HashMap::new(),
            master_key,
        }
    }

    // ------------------------------------------------------------------
    // Secret operations
    // ------------------------------------------------------------------

    /// Add or update a secret.
    ///
    /// The plaintext value is encrypted with a per-secret key derived
    /// from the master key + secret name.  The per-secret key is
    /// zeroized immediately after use.
    pub fn set_secret(&mut self, name: &str, plaintext_value: &str) -> Result<()> {
        Self::validate_secret_name(name)?;

        // Derive a unique encryption key for this secret name.
        let mut secret_key = self.master_key.derive_secret_key(name)?;

        // Encrypt the plaintext value.
        let encrypted_value = encrypt(&secret_key, plaintext_value.as_bytes());

        // Zeroize the per-secret key immediately — we no longer need it.
        secret_key.zeroize();

        let encrypted_value = encrypted_value?;

        let now = Utc::now();

        // If the secret already exists, preserve the original created_at.
        let created_at = self
            .secrets
            .get(name)
            .map_or(now, |existing| existing.created_at);

        let secret = Secret {
            name: name.to_string(),
            encrypted_value,
            created_at,
            updated_at: now,
        };

        self.secrets.insert(name.to_string(), secret);
        Ok(())
    }

    /// Decrypt and return the plaintext value of a secret.
    ///
    /// The per-secret key is zeroized after decryption.
    pub fn get_secret(&self, name: &str) -> Result<String> {
        Self::validate_secret_name(name)?;
        let secret = self
            .secrets
            .get(name)
            .ok_or_else(|| EnvVaultError::SecretNotFound(name.to_string()))?;

        let mut secret_key = self.master_key.derive_secret_key(name)?;
        let plaintext_bytes = decrypt(&secret_key, &secret.encrypted_value)?;
        secret_key.zeroize();

        // Convert to String via from_utf8 which takes ownership (no clone).
        // On error, zeroize the bytes inside the error before discarding.
        String::from_utf8(plaintext_bytes).map_err(|e| {
            let mut bad_bytes = e.into_bytes();
            bad_bytes.zeroize();
            EnvVaultError::SerializationError("secret value is not valid UTF-8".to_string())
        })
    }

    /// Remove a secret from the vault.
    pub fn delete_secret(&mut self, name: &str) -> Result<()> {
        Self::validate_secret_name(name)?;
        if self.secrets.remove(name).is_none() {
            return Err(EnvVaultError::SecretNotFound(name.to_string()));
        }
        Ok(())
    }

    /// List metadata for all secrets, sorted by name.
    pub fn list_secrets(&self) -> Vec<SecretMetadata> {
        let mut list: Vec<SecretMetadata> = self
            .secrets
            .values()
            .map(|s| SecretMetadata {
                name: s.name.clone(),
                created_at: s.created_at,
                updated_at: s.updated_at,
            })
            .collect();

        list.sort_by(|a, b| a.name.cmp(&b.name));
        list
    }

    /// Decrypt all secrets and return them as a name -> plaintext map.
    ///
    /// Used by the `run` command to inject secrets into a child process.
    pub fn get_all_secrets(&self) -> Result<HashMap<String, String>> {
        let mut map = HashMap::with_capacity(self.secrets.len());

        for name in self.secrets.keys() {
            let value = self.get_secret(name)?;
            map.insert(name.clone(), value);
        }

        Ok(map)
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    /// Serialize the vault and write it to disk atomically.
    ///
    /// Computes a fresh HMAC over the header + secrets JSON and writes
    /// the full binary envelope via temp-file + rename.
    pub fn save(&mut self) -> Result<()> {
        // Collect secrets into a sorted Vec for deterministic output.
        let mut secret_list: Vec<Secret> = self.secrets.values().cloned().collect();
        secret_list.sort_by(|a, b| a.name.cmp(&b.name));

        let mut hmac_key = self.master_key.derive_hmac_key()?;

        format::write_vault(&self.path, &self.header, &secret_list, &hmac_key)?;
        hmac_key.zeroize();

        Ok(())
    }

    // ------------------------------------------------------------------
    // Accessors
    // ------------------------------------------------------------------

    /// Returns the path to the vault file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Returns the environment name (e.g. "dev").
    pub fn environment(&self) -> &str {
        &self.header.environment
    }

    /// Returns the number of secrets in the vault.
    pub fn secret_count(&self) -> usize {
        self.secrets.len()
    }

    /// Returns the vault creation timestamp.
    pub fn created_at(&self) -> chrono::DateTime<chrono::Utc> {
        self.header.created_at
    }

    /// Returns `true` if the vault contains a secret with the given name.
    ///
    /// This is a metadata-only check — no decryption is performed.
    pub fn contains_key(&self, name: &str) -> bool {
        self.secrets.contains_key(name)
    }

    /// Returns a reference to the vault header.
    ///
    /// Useful for inspecting stored Argon2 params, keyfile hash, etc.
    pub fn header(&self) -> &super::format::VaultHeader {
        &self.header
    }

    // ------------------------------------------------------------------
    // Validation
    // ------------------------------------------------------------------

    /// Validate that a secret name is safe.
    ///
    /// Allowed: ASCII letters, digits, underscores, hyphens, periods.
    /// Must be non-empty and at most 256 characters.
    fn validate_secret_name(name: &str) -> Result<()> {
        if name.is_empty() {
            return Err(EnvVaultError::CommandFailed(
                "secret name cannot be empty".into(),
            ));
        }
        if name.len() > 256 {
            return Err(EnvVaultError::CommandFailed(
                "secret name cannot exceed 256 characters".into(),
            ));
        }
        if !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        {
            return Err(EnvVaultError::CommandFailed(format!(
                "secret name '{name}' contains invalid characters — only ASCII letters, digits, underscores, hyphens, and periods are allowed"
            )));
        }
        Ok(())
    }
}
