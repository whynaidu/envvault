//! `envvault auth` — manage authentication methods (keyring, keyfile).
//!
//! Subcommands:
//! - `envvault auth keyring`          — save password to OS keyring
//! - `envvault auth keyring --delete` — remove password from keyring
//! - `envvault auth keyfile-generate`  — generate a new random keyfile
//!
//! When the keyring feature is not compiled in, keyring commands return
//! a helpful error message.

use crate::cli::output;
use crate::cli::Cli;
use crate::errors::{EnvVaultError, Result};

/// Execute `envvault auth keyring` — save or delete password in OS keyring.
pub fn execute_keyring(cli: &Cli, delete: bool) -> Result<()> {
    #[cfg(feature = "keyring-store")]
    {
        let path = crate::cli::vault_path(cli)?;
        let vault_id = path.to_string_lossy().to_string();

        if delete {
            crate::keyring::delete_password(&vault_id)?;
            output::success("Password removed from OS keyring.");
        } else {
            // Verify the password works before storing it.
            // Don't use keyring lookup here — user is explicitly setting the password.
            let keyfile = crate::cli::load_keyfile(cli)?;
            let password = crate::cli::prompt_password_for_vault(None)?;
            let _store =
                crate::vault::VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

            crate::keyring::store_password(&vault_id, &password)?;
            output::success("Password saved to OS keyring. Future opens will be automatic.");
        }

        Ok(())
    }

    #[cfg(not(feature = "keyring-store"))]
    {
        let _ = (cli, delete);
        Err(EnvVaultError::KeyringError(
            "keyring support not compiled — rebuild with `cargo build --features keyring-store`"
                .into(),
        ))
    }
}

/// Execute `envvault auth keyfile-generate` — create a new random keyfile.
pub fn execute_keyfile_generate(cli: &Cli, keyfile_path: Option<&str>) -> Result<()> {
    let cwd = std::env::current_dir()?;

    let path = match keyfile_path {
        Some(p) => std::path::PathBuf::from(p),
        None => cwd.join(&cli.vault_dir).join("keyfile"),
    };

    crate::crypto::keyfile::generate_keyfile(&path)?;

    let path_display = path.display();
    output::success(&format!("Keyfile generated at {path_display}"));
    output::warning("Keep this file secret! Anyone with it can help unlock your vault.");
    output::tip("Add the keyfile path to .gitignore to prevent accidental commits.");

    // Auto-patch .gitignore for the keyfile.
    let relative = path.strip_prefix(&cwd).map_or_else(
        |_| path.to_string_lossy().to_string(),
        |p| p.to_string_lossy().to_string(),
    );

    crate::cli::gitignore::patch_gitignore(&cwd, &relative);

    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::TempDir;

    #[test]
    fn keyring_disabled_returns_error() {
        // When compiled without keyring-store feature, execute_keyring should error.
        // This test always passes because we compile tests without the feature.
        #[cfg(not(feature = "keyring-store"))]
        {
            use clap::Parser;
            let cli = crate::cli::Cli::parse_from(["envvault", "auth", "keyring"]);
            let result = super::execute_keyring(&cli, false);
            assert!(result.is_err());
            let msg = result.unwrap_err().to_string();
            assert!(
                msg.contains("keyring support not compiled"),
                "unexpected error: {msg}"
            );
        }
    }

    #[test]
    fn keyfile_generate_creates_file() {
        use clap::Parser;

        let dir = TempDir::new().unwrap();
        let kf_path = dir.path().join("my.keyfile");

        let cli = crate::cli::Cli::parse_from([
            "envvault",
            "--vault-dir",
            dir.path().to_str().unwrap(),
            "auth",
            "keyfile-generate",
            kf_path.to_str().unwrap(),
        ]);

        super::execute_keyfile_generate(&cli, Some(kf_path.to_str().unwrap())).unwrap();

        assert!(kf_path.exists(), "keyfile should be created");
        let data = std::fs::read(&kf_path).unwrap();
        assert_eq!(data.len(), 32, "keyfile should be 32 bytes");
    }

    #[test]
    fn keyfile_generate_patches_gitignore() {
        use clap::Parser;

        let dir = TempDir::new().unwrap();
        let kf_path = dir.path().join("vault.keyfile");

        // Change to temp dir so .gitignore is written there.
        let original_dir = std::env::current_dir().unwrap();
        std::env::set_current_dir(dir.path()).unwrap();

        let cli = crate::cli::Cli::parse_from([
            "envvault",
            "--vault-dir",
            ".",
            "auth",
            "keyfile-generate",
            kf_path.to_str().unwrap(),
        ]);

        super::execute_keyfile_generate(&cli, Some(kf_path.to_str().unwrap())).unwrap();

        // Restore original dir.
        std::env::set_current_dir(original_dir).unwrap();

        let gitignore = std::fs::read_to_string(dir.path().join(".gitignore")).unwrap_or_default();
        assert!(
            gitignore.contains("keyfile"),
            "gitignore should contain keyfile entry: {gitignore}"
        );
    }
}
