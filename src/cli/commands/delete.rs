//! `envvault delete` — remove a secret from the vault.

use dialoguer::Confirm;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `delete` command.
pub fn execute(cli: &Cli, key: &str, force: bool) -> Result<()> {
    let path = vault_path(cli)?;

    // Unless --force is set, ask for confirmation before deleting.
    if !force {
        let confirmed = Confirm::new()
            .with_prompt(format!("Delete secret '{key}'?"))
            .default(false)
            .interact()
            .map_err(|e| EnvVaultError::CommandFailed(format!("confirm prompt: {e}")))?;

        if !confirmed {
            output::info("Cancelled.");
            return Ok(());
        }
    }

    // Open the vault (requires password).
    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let mut store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    // Delete the secret and save.
    store.delete_secret(key)?;
    store.save()?;

    crate::audit::log_audit(cli, "delete", Some(key), None);
    output::success(&format!("Deleted secret '{key}'"));

    Ok(())
}
