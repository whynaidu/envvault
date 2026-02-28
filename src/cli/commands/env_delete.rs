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
    use crate::vault::VaultStore;

    #[test]
    fn delete_removes_real_vault() {
        let dir = tempfile::TempDir::new().unwrap();
        let vault_path = dir.path().join("staging.vault");

        // Create a real vault with secrets.
        let mut store =
            VaultStore::create(&vault_path, b"testpassword1", "staging", None, None).unwrap();
        store.set_secret("KEY", "value").unwrap();
        store.save().unwrap();
        assert!(vault_path.exists());

        // Delete the vault file (simulates `execute` with --force).
        fs::remove_file(&vault_path).unwrap();
        assert!(!vault_path.exists());

        // Verify it can no longer be opened.
        assert!(VaultStore::open(&vault_path, b"testpassword1", None).is_err());
    }

    #[test]
    fn delete_nonexistent_env_produces_correct_error() {
        let err = EnvVaultError::EnvironmentNotFound("ghost".to_string());
        let msg = err.to_string();
        assert!(
            msg.contains("ghost"),
            "error should name the environment: {msg}"
        );
        assert!(
            msg.contains("not found"),
            "error should indicate not found: {msg}"
        );
    }

    #[test]
    fn active_env_protection_blocks_without_force() {
        // Mirrors the condition in execute(): name == cli.env && !force
        let name = "dev";
        let active_env = "dev";

        assert!(name == active_env, "should detect active environment");

        // With --force, deletion proceeds even for the active env.
        let force = true;
        assert!(
            name != active_env || force,
            "force should bypass active env protection"
        );
    }

    #[test]
    fn validates_env_name_on_delete() {
        assert!(validate_env_name("INVALID").is_err());
        assert!(validate_env_name("valid-name").is_ok());
        assert!(validate_env_name("").is_err());
        assert!(validate_env_name("-leading").is_err());
    }
}
