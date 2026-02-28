//! `envvault run` — inject secrets into a child process.

use std::process::Command;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `run` command.
pub fn execute(cli: &Cli, command: &[String], clean_env: bool) -> Result<()> {
    if command.is_empty() {
        return Err(EnvVaultError::NoCommandSpecified);
    }

    let path = vault_path(cli)?;

    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    // Decrypt all secrets into memory.
    let secrets = store.get_all_secrets()?;

    if clean_env {
        output::success(&format!(
            "Injected {} secrets into clean environment",
            secrets.len()
        ));
    } else {
        output::success(&format!(
            "Injected {} secrets into environment",
            secrets.len()
        ));
    }

    // Build the child process.
    let program = &command[0];
    let args = &command[1..];

    let mut cmd = Command::new(program);
    cmd.args(args);

    if clean_env {
        // Start with a completely empty environment — only vault secrets.
        cmd.env_clear();
    }

    let status = cmd.envs(&secrets).status()?;

    // Forward the child's exit code.
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(EnvVaultError::ChildProcessFailed(code)),
        None => Err(EnvVaultError::CommandFailed(
            "child process terminated by signal".into(),
        )),
    }
}
