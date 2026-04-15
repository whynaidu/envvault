//! `envvault set` — add or update a secret in the vault.

use std::io::{self, IsTerminal, Read};

use crate::cli::output;
use crate::cli::{duration, load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `set` command.
#[allow(clippy::too_many_arguments)]
pub fn execute(
    cli: &Cli,
    key: &str,
    value: Option<&str>,
    force: bool,
    description: Option<&str>,
    tags: &[String],
    expires: Option<&str>,
    no_description: bool,
    no_tags: bool,
    no_expires: bool,
) -> Result<()> {
    let path = vault_path(cli)?;

    // Validate expiration duration up front so typos fail before we
    // prompt for the password.
    let expires_at = match expires {
        Some(d) => Some(duration::parse_future(d)?),
        None => None,
    };

    // Determine the secret value from one of three sources.
    let secret_value = if let Some(v) = value {
        // Source 1: Inline value on the command line.
        if !force {
            output::warning("Value provided on command line — it may appear in shell history.");
        }
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

    // Apply metadata updates, if any. Each flag is independent:
    //   --description / --no-description -> description
    //   --tag ... / --no-tags             -> tags
    //   --expires ... / --no-expires      -> expiration
    if let Some(desc) = description {
        store.set_description(key, Some(desc.to_string()))?;
    } else if no_description {
        store.set_description(key, None)?;
    }

    if !tags.is_empty() {
        store.set_tags(key, tags.to_vec())?;
    } else if no_tags {
        store.set_tags(key, Vec::new())?;
    }

    if let Some(exp) = expires_at {
        store.set_expires_at(key, Some(exp))?;
    } else if no_expires {
        store.set_expires_at(key, None)?;
    }

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

    if let Some(exp) = expires_at {
        output::info(&format!(
            "Expires at {}",
            exp.format("%Y-%m-%d %H:%M:%S UTC")
        ));
    }

    output::tip("Run your app: envvault run -- <command>");

    Ok(())
}
