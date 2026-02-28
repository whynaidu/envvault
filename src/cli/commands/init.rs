//! `envvault init` — create a new vault, optionally importing .env secrets.

use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;

use dialoguer::Confirm;

use crate::cli::env_parser::parse_env_line;
use crate::cli::output;
use crate::cli::{load_keyfile, prompt_new_password, Cli};
use crate::config::Settings;
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `init` command.
pub fn execute(cli: &Cli) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);
    let env = &cli.env;
    let vault_path = vault_dir.join(format!("{env}.vault"));

    // 1. Create the vault directory if it doesn't exist.
    if !vault_dir.exists() {
        fs::create_dir_all(&vault_dir)?;
        let dir_display = vault_dir.display();
        output::info(&format!("Created vault directory: {dir_display}"));
    }

    // 2. Check if a vault already exists for this environment.
    if vault_path.exists() {
        output::tip("Use `envvault set` to add secrets to the existing vault.");
        return Err(EnvVaultError::VaultAlreadyExists(vault_path));
    }

    // 3. Prompt for a new password (with confirmation).
    let password = prompt_new_password()?;

    // 4. Load optional keyfile and settings, then create the vault file.
    let keyfile = load_keyfile(cli)?;
    let settings = Settings::load(&cwd)?;
    let mut store = VaultStore::create(
        &vault_path,
        password.as_bytes(),
        &cli.env,
        Some(&settings.argon2_params()),
        keyfile.as_deref(),
    )?;
    if keyfile.is_some() {
        output::info("Vault created with keyfile — you must pass --keyfile on every command.");
    }
    output::success(&format!(
        "Vault created for '{}' environment at {}",
        cli.env,
        vault_path.display()
    ));

    // 5. Auto-detect .env file and offer to import it.
    let env_file = cwd.join(".env");
    if env_file.exists() {
        let should_import = Confirm::new()
            .with_prompt("Found .env file. Import secrets from it?")
            .default(true)
            .interact()
            .map_err(|e| {
                EnvVaultError::CommandFailed(format!("failed to read confirmation: {e}"))
            })?;

        if should_import {
            let count = import_env_file(&env_file, &mut store)?;
            store.save()?;
            output::success(&format!("Imported {count} secrets from .env"));
        }
    }

    // 6. Patch .gitignore to exclude the vault directory.
    crate::cli::gitignore::patch_gitignore(&cwd, &format!("{}/", cli.vault_dir));

    // 7. Install pre-commit git hook to catch accidental secret leaks.
    match crate::git::install_hook(&cwd) {
        Ok(crate::git::InstallResult::Installed) => {
            output::info("Installed pre-commit hook to detect secret leaks.");
        }
        Ok(crate::git::InstallResult::ExistingHookFound) => {
            output::warning("A pre-commit hook already exists — EnvVault hook was not installed.");
        }
        Ok(
            crate::git::InstallResult::AlreadyInstalled | crate::git::InstallResult::NotAGitRepo,
        )
        | Err(_) => {} // Non-fatal, skip silently.
    }

    // 8. Audit log.
    crate::audit::log_audit(cli, "init", None, Some("vault created"));

    // 9. Show helpful tips.
    output::tip("Run `envvault set <KEY>` to add a secret.");
    output::tip("Run `envvault list` to see all secrets.");
    output::tip("Run `envvault run -- <command>` to inject secrets into a command.");

    Ok(())
}

/// Parse a .env file and import each KEY=VALUE pair into the vault.
/// Returns the number of secrets imported.
///
/// Handles the `export` prefix that some .env files use:
///   export DATABASE_URL=postgres://...
fn import_env_file(path: &Path, store: &mut VaultStore) -> Result<usize> {
    let file = fs::File::open(path)?;
    let reader = BufReader::new(file);
    let mut count = 0;

    for line in reader.lines() {
        let line = line?;

        if let Some((key, value)) = parse_env_line(&line) {
            store.set_secret(key, value)?;
            count += 1;
        }
    }

    Ok(count)
}
