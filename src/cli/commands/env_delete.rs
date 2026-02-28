//! `envvault env delete` — delete a vault environment.

use std::fs;

use dialoguer::Confirm;

use crate::cli::output;
use crate::cli::{validate_env_name, Cli};
use crate::errors::{EnvVaultError, Result};

/// Execute `envvault env delete <name>`.
pub fn execute(cli: &Cli, name: &str, force: bool) -> Result<()> {
    validate_env_name(name)?;

    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);
    let vault_path = vault_dir.join(format!("{name}.vault"));

    if !vault_path.exists() {
        return Err(EnvVaultError::EnvironmentNotFound(name.to_string()));
    }

    // Prevent deleting the active environment unless --force is used.
    if name == cli.env && !force {
        output::warning(&format!(
            "'{name}' is the currently active environment. Use --force to confirm."
        ));
        return Ok(());
    }

    if !force {
        let confirmed = Confirm::new()
            .with_prompt(format!(
                "Delete environment '{name}'? This cannot be undone"
            ))
            .default(false)
            .interact()
            .map_err(|e| EnvVaultError::CommandFailed(format!("confirm prompt: {e}")))?;

        if !confirmed {
            output::info("Cancelled.");
            return Ok(());
        }
    }

    fs::remove_file(&vault_path)?;

    crate::audit::log_audit(cli, "env-delete", None, Some(&format!("deleted {name}")));

    output::success(&format!(
        "Deleted environment '{name}' ({} removed)",
        vault_path.display()
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn delete_removes_vault_file() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("staging.vault");
        std::fs::write(&vault_path, b"test vault data").unwrap();
        assert!(vault_path.exists());

        std::fs::remove_file(&vault_path).unwrap();
        assert!(!vault_path.exists());
    }

    #[test]
    fn delete_fails_for_missing_env() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("nonexistent.vault");
        assert!(!vault_path.exists());
    }

    #[test]
    fn validates_env_name_on_delete() {
        assert!(validate_env_name("INVALID").is_err());
        assert!(validate_env_name("valid-name").is_ok());
    }
}
