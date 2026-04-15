//! `envvault rollback` — restore a secret's previous value (one-level undo).
//!
//! When a secret is updated via `envvault set`, the prior encrypted
//! value is retained in a single-slot history. `rollback` promotes
//! that retained value back to the current one and clears the slot.

use dialoguer::Confirm;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `rollback` command.
pub fn execute(cli: &Cli, key: &str, force: bool) -> Result<()> {
    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let mut store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    // Fail fast if there is nothing to restore, before we prompt.
    if !store.has_previous(key) {
        // get_secret distinguishes missing-secret from no-previous for
        // us, but we want a clean error: look up the name first to
        // surface a missing-secret error if that's the case.
        store.get_secret(key)?;
        return Err(EnvVaultError::NoPreviousValue(key.to_string()));
    }

    if !force {
        let ts_note = match store.previous_updated_at(key) {
            Some(ts) => format!(" (previously set {})", ts.format("%Y-%m-%d %H:%M:%S UTC")),
            None => String::new(),
        };
        let confirmed = Confirm::new()
            .with_prompt(format!("Roll back '{key}' to its previous value?{ts_note}"))
            .default(false)
            .interact()
            .map_err(|e| EnvVaultError::CommandFailed(format!("confirm prompt: {e}")))?;

        if !confirmed {
            output::info("Cancelled.");
            return Ok(());
        }
    }

    store.rollback_secret(key)?;
    store.save()?;

    crate::audit::log_audit(cli, "rollback", Some(key), Some("restored previous value"));
    output::success(&format!("Rolled back '{key}' to its previous value"));
    output::tip("Run your app: envvault run -- <command>");

    Ok(())
}
