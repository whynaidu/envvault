//! `envvault set` — add or update a secret in the vault.

use std::io::{self, IsTerminal, Read};

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `set` command.
pub fn execute(cli: &Cli, key: &str, value: Option<&str>) -> Result<()> {
    let path = vault_path(cli)?;

    // Determine the secret value from one of three sources.
    let secret_value = if let Some(v) = value {
        // Source 1: Inline value on the command line.
        output::warning("Value provided on command line — it may appear in shell history.");
        v.to_string()
    } else if !io::stdin().is_terminal() {
        // Source 2: Piped input (stdin is not a terminal).
        let mut buf = String::new();
        io::stdin().read_to_string(&mut buf)?;
        buf.trim_end().to_string()
    } else {
        // Source 3: Interactive secure prompt (default).
        dialoguer::Password::new()
            .with_prompt(format!("Enter value for {key}"))
            .interact()
            .map_err(|e| {
                crate::errors::EnvVaultError::CommandFailed(format!("input prompt: {e}"))
            })?
    };

    // Open the vault, set the secret, and save.
    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let mut store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    let existed = store.get_secret(key).is_ok();
    store.set_secret(key, &secret_value)?;
    store.save()?;

    let op_detail = if existed { "updated" } else { "added" };
    crate::audit::log_audit(cli, "set", Some(key), Some(op_detail));

    if existed {
        output::success(&format!(
            "Secret '{}' updated in {}.vault ({} total)",
            key,
            cli.env,
            store.secret_count()
        ));
    } else {
        output::success(&format!(
            "Secret '{}' added to {}.vault ({} total)",
            key,
            cli.env,
            store.secret_count()
        ));
    }

    output::tip("Run your app: envvault run -- <command>");

    Ok(())
}
