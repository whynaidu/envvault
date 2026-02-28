//! `envvault list` — display all secrets in a table.

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `list` command.
pub fn execute(cli: &Cli) -> Result<()> {
    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;

    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    let secrets = store.list_secrets();

    output::info(&format!(
        "{} environment — {} secret(s)",
        cli.env,
        secrets.len()
    ));

    output::print_secrets_table(&secrets);

    Ok(())
}
