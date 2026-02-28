//! `envvault rotate-key` — change the vault master password.
//!
//! Decrypts all secrets with the old password, generates a new salt,
//! re-derives the master key from the new password, re-encrypts all
//! secrets, and writes the vault atomically.

use zeroize::Zeroize;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_new_password, prompt_password_for_vault, vault_path, Cli};
use crate::config::Settings;
use crate::crypto::kdf::generate_salt;
use crate::crypto::keys::MasterKey;
use crate::errors::Result;
use crate::vault::format::{StoredArgon2Params, VaultHeader, CURRENT_VERSION};
use crate::vault::VaultStore;

/// Execute the `rotate-key` command.
pub fn execute(cli: &Cli) -> Result<()> {
    let path = vault_path(cli)?;

    // 1. Open the vault with the current password.
    output::info("Enter your current vault password.");
    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let old_password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, old_password.as_bytes(), keyfile.as_deref())?;

    // 2. Decrypt all secrets into memory.
    let mut secrets = store.get_all_secrets()?;

    // 3. Prompt for the new password.
    output::info("Choose your new vault password.");
    let new_password = prompt_new_password()?;

    // 4. Load settings for Argon2 params.
    let cwd = std::env::current_dir()?;
    let settings = Settings::load(&cwd)?;
    let params = settings.argon2_params();

    // 5. Generate a new salt and derive a new master key.
    //    If the vault uses a keyfile, combine it with the new password.
    let new_salt = generate_salt();
    let mut effective_password = match &keyfile {
        Some(kf) => crate::crypto::keyfile::combine_password_keyfile(new_password.as_bytes(), kf)?,
        None => new_password.as_bytes().to_vec(),
    };
    let mut master_bytes =
        crate::crypto::kdf::derive_master_key_with_params(&effective_password, &new_salt, &params)?;
    effective_password.zeroize();
    let new_master_key = MasterKey::new(master_bytes);
    master_bytes.zeroize();

    // 6. Build a new header with the new salt and params.
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
        keyfile_hash: store.header().keyfile_hash.clone(),
    };

    // 7. Create a new vault store with the new key and re-encrypt secrets.
    let mut new_store = VaultStore::from_parts(path, new_header, new_master_key);

    for (name, value) in &secrets {
        new_store.set_secret(name, value)?;
    }

    // 8. Zeroize plaintext secrets from memory.
    for value in secrets.values_mut() {
        value.zeroize();
    }

    // 9. Save atomically.
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

    output::success(&format!(
        "Password rotated for '{}' vault ({} secrets re-encrypted)",
        new_store.environment(),
        new_store.secret_count()
    ));

    Ok(())
}
