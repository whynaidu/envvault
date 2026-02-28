//! `envvault get` — retrieve and print a single secret's value.

use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `get` command.
pub fn execute(cli: &Cli, key: &str) -> Result<()> {
    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;

    // Open the vault (requires password).
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    // Decrypt and print the secret value to stdout.
    let value = store.get_secret(key)?;
    println!("{value}");

    Ok(())
}
