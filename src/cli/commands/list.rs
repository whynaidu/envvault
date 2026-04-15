//! `envvault list` — display all secrets in a table.

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `list` command.
///
/// `filter_tags` is a list of tag patterns; a secret is included only
/// if every pattern matches (substring, case-sensitive) against at
/// least one of the secret's tags. An empty slice returns all secrets.
pub fn execute(cli: &Cli, filter_tags: &[String]) -> Result<()> {
    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;

    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = match VaultStore::open(&path, password.as_bytes(), keyfile.as_deref()) {
        Ok(store) => store,
        Err(e) => {
            #[cfg(feature = "audit-log")]
            crate::audit::log_auth_failure(cli, &e.to_string());
            return Err(e);
        }
    };

    let all = store.list_secrets();
    let secrets: Vec<_> = if filter_tags.is_empty() {
        all
    } else {
        all.into_iter()
            .filter(|s| {
                filter_tags
                    .iter()
                    .all(|pattern| s.tags.iter().any(|t| t.contains(pattern)))
            })
            .collect()
    };

    if filter_tags.is_empty() {
        output::info(&format!(
            "{} environment — {} secret(s)",
            cli.env,
            secrets.len()
        ));
    } else {
        output::info(&format!(
            "{} environment — {} secret(s) matching tag filter {:?}",
            cli.env,
            secrets.len(),
            filter_tags
        ));
    }

    output::print_secrets_table(&secrets);

    #[cfg(feature = "audit-log")]
    crate::audit::log_read_audit(
        cli,
        "list",
        None,
        Some(&format!("{} secrets", secrets.len())),
    );

    Ok(())
}
