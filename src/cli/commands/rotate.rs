//! `envvault rotate-key` — change the vault master password.
//!
//! Decrypts all secrets with the old password, generates a new salt,
//! re-derives the master key from the new password, re-encrypts all
//! secrets, and writes the vault atomically.
//!
//! Optionally changes the keyfile with `--new-keyfile <path>` or removes
//! the keyfile requirement with `--new-keyfile none`.

use std::path::Path;

use zeroize::Zeroize;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_new_password, prompt_password_for_vault, vault_path, Cli};
use crate::config::Settings;
use crate::crypto::kdf::generate_salt;
use crate::crypto::keyfile;
use crate::crypto::keys::MasterKey;
use crate::errors::Result;
use crate::vault::format::{StoredArgon2Params, VaultHeader, CURRENT_VERSION};
use crate::vault::VaultStore;

/// Execute the `rotate-key` command.
///
/// `new_keyfile_arg`: `None` = keep existing keyfile, `Some("none")` = remove
/// keyfile requirement, `Some(path)` = switch to a different keyfile.
pub fn execute(cli: &Cli, new_keyfile_arg: Option<&str>) -> Result<()> {
    let path = vault_path(cli)?;

    // 1. Open the vault with the current password.
    output::info("Enter your current vault password.");
    let keyfile_data = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let old_password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, old_password.as_bytes(), keyfile_data.as_deref())?;

    // 2. Decrypt all secrets into memory.
    let mut secrets = store.get_all_secrets()?;

    // 3. Prompt for the new password.
    output::info("Choose your new vault password.");
    let new_password = prompt_new_password()?;

    // 4. Load settings for Argon2 params.
    let cwd = std::env::current_dir()?;
    let settings = Settings::load(&cwd)?;
    let params = settings.argon2_params();

    // 5. Resolve keyfile for the new vault.
    let (new_keyfile_bytes, new_keyfile_hash) =
        resolve_new_keyfile(new_keyfile_arg, keyfile_data.as_deref(), &store)?;

    // 6. Generate a new salt and derive a new master key.
    let new_salt = generate_salt();
    let mut effective_password = match &new_keyfile_bytes {
        Some(kf) => keyfile::combine_password_keyfile(new_password.as_bytes(), kf)?,
        None => new_password.as_bytes().to_vec(),
    };
    let mut master_bytes =
        crate::crypto::kdf::derive_master_key_with_params(&effective_password, &new_salt, &params)?;
    effective_password.zeroize();
    let new_master_key = MasterKey::new(master_bytes);
    master_bytes.zeroize();

    // 7. Build a new header with the new salt and params.
    let new_header = VaultHeader {
        version: CURRENT_VERSION,
        salt: new_salt.to_vec(),
        created_at: store.created_at(),
        environment: store.environment().to_string(),
        argon2_params: Some(StoredArgon2Params {
            memory_kib: params.memory_kib,
            iterations: params.iterations,
            parallelism: params.parallelism,
        }),
        keyfile_hash: new_keyfile_hash,
    };

    // 8. Create a new vault store with the new key and re-encrypt secrets.
    let mut new_store = VaultStore::from_parts(path, new_header, new_master_key);

    for (name, value) in &secrets {
        new_store.set_secret(name, value)?;
    }

    // 9. Zeroize plaintext secrets from memory.
    for value in secrets.values_mut() {
        value.zeroize();
    }

    // 10. Save atomically.
    new_store.save()?;

    crate::audit::log_audit(
        cli,
        "rotate-key",
        None,
        Some(&format!(
            "{} secrets re-encrypted",
            new_store.secret_count()
        )),
    );

    // Print a message indicating what changed.
    let keyfile_msg = match new_keyfile_arg {
        Some("none") => " (keyfile requirement removed)",
        Some(_) => " (keyfile changed)",
        None => "",
    };

    output::success(&format!(
        "Password rotated for '{}' vault ({} secrets re-encrypted){}",
        new_store.environment(),
        new_store.secret_count(),
        keyfile_msg,
    ));

    Ok(())
}

/// Resolve the keyfile configuration for the new vault.
///
/// Returns `(keyfile_bytes, keyfile_hash)` for the new header.
fn resolve_new_keyfile(
    new_keyfile_arg: Option<&str>,
    existing_keyfile: Option<&[u8]>,
    store: &VaultStore,
) -> Result<(Option<Vec<u8>>, Option<String>)> {
    match new_keyfile_arg {
        // Explicit "none" removes keyfile requirement.
        Some("none") => {
            output::info("Removing keyfile requirement from vault.");
            Ok((None, None))
        }
        // New keyfile path provided.
        Some(path) => {
            output::info(&format!("Switching to new keyfile: {path}"));
            let bytes = keyfile::load_keyfile(Path::new(path))?;
            let hash = keyfile::hash_keyfile(&bytes);
            Ok((Some(bytes), Some(hash)))
        }
        // No flag: preserve existing keyfile configuration.
        None => Ok((
            existing_keyfile.map(|b| b.to_vec()),
            store.header().keyfile_hash.clone(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_new_keyfile_none_removes_requirement() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_path = tmp.path().join(".envvault").join("dev.vault");
        std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();

        // Create a vault with a keyfile.
        let kf_bytes = [0xABu8; 32];
        let store = VaultStore::create(
            &vault_path,
            b"test-password-long",
            "dev",
            None,
            Some(&kf_bytes),
        )
        .unwrap();

        let (bytes, hash) = resolve_new_keyfile(Some("none"), Some(&kf_bytes), &store).unwrap();
        assert!(bytes.is_none());
        assert!(hash.is_none());
    }

    #[test]
    fn resolve_new_keyfile_with_path_changes_hash() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_path = tmp.path().join(".envvault").join("dev.vault");
        std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();

        // Create a vault without a keyfile.
        let store =
            VaultStore::create(&vault_path, b"test-password-long", "dev", None, None).unwrap();

        // Generate a keyfile.
        let kf_path = tmp.path().join("new.keyfile");
        let kf_bytes = crate::crypto::keyfile::generate_keyfile(&kf_path).unwrap();

        let (bytes, hash) =
            resolve_new_keyfile(Some(kf_path.to_str().unwrap()), None, &store).unwrap();
        assert!(bytes.is_some());
        assert!(hash.is_some());
        assert_eq!(bytes.unwrap(), kf_bytes);
    }

    #[test]
    fn resolve_new_keyfile_preserves_existing() {
        let tmp = tempfile::TempDir::new().unwrap();
        let vault_path = tmp.path().join(".envvault").join("dev.vault");
        std::fs::create_dir_all(vault_path.parent().unwrap()).unwrap();

        let kf_bytes = [0xCDu8; 32];
        let store = VaultStore::create(
            &vault_path,
            b"test-password-long",
            "dev",
            None,
            Some(&kf_bytes),
        )
        .unwrap();

        let original_hash = store.header().keyfile_hash.clone();

        let (bytes, hash) = resolve_new_keyfile(None, Some(&kf_bytes), &store).unwrap();
        assert_eq!(bytes.unwrap(), kf_bytes);
        assert_eq!(hash, original_hash);
    }
}
