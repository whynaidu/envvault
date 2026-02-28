//! CLI module — Clap argument parser, output helpers, and command implementations.

pub mod commands;
pub mod env_parser;
pub mod gitignore;
pub mod output;

use clap::Parser;

use zeroize::Zeroizing;

use crate::errors::{EnvVaultError, Result};

/// Minimum password length to prevent trivially weak passwords.
const MIN_PASSWORD_LEN: usize = 8;

/// EnvVault CLI: encrypted environment variable manager.
#[derive(Parser)]
#[command(
    name = "envvault",
    about = "Encrypted environment variable manager",
    version
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    /// Environment to use (default: dev)
    #[arg(short, long, default_value = "dev", global = true)]
    pub env: String,

    /// Vault directory (default: .envvault)
    #[arg(long, default_value = ".envvault", global = true)]
    pub vault_dir: String,

    /// Path to a keyfile for two-factor vault access
    #[arg(long, global = true)]
    pub keyfile: Option<String>,
}

/// All available subcommands.
#[derive(clap::Subcommand)]
pub enum Commands {
    /// Initialize a new vault (auto-imports .env)
    Init,

    /// Set a secret (add or update)
    Set {
        /// Secret name (e.g. DATABASE_URL)
        key: String,
        /// Secret value (omit for interactive prompt)
        value: Option<String>,
    },

    /// Get a secret's value
    Get {
        /// Secret name
        key: String,
    },

    /// List all secrets
    List,

    /// Delete a secret
    Delete {
        /// Secret name
        key: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },

    /// Run a command with secrets injected
    Run {
        /// Command and arguments (after --)
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,

        /// Start with a clean environment (only vault secrets, no inherited vars)
        #[arg(long)]
        clean_env: bool,
    },

    /// Change the vault's master password
    RotateKey,

    /// Export secrets to a file or stdout
    Export {
        /// Output format: env (default) or json
        #[arg(short, long, default_value = "env")]
        format: String,

        /// Output file path (prints to stdout if omitted)
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Import secrets from a file
    Import {
        /// Path to the file to import
        file: String,

        /// Import format: env (default) or json (auto-detected from extension)
        #[arg(short, long)]
        format: Option<String>,
    },

    /// Manage authentication methods (keyring, keyfile)
    Auth {
        #[command(subcommand)]
        action: AuthAction,
    },

    /// Manage environments (list, clone, delete)
    Env {
        #[command(subcommand)]
        action: EnvAction,
    },

    /// Compare secrets between two environments
    Diff {
        /// Target environment to compare against
        target_env: String,
        /// Show secret values in diff output
        #[arg(long)]
        show_values: bool,
    },

    /// Open secrets in an editor (decrypts to temp file, re-encrypts on save)
    Edit,

    /// Show version and check for updates
    Version,

    /// Generate shell completion scripts
    Completions {
        /// Shell to generate completions for (bash, zsh, fish, powershell)
        shell: String,
    },

    /// View the audit log of vault operations
    Audit {
        /// Number of entries to show (default: 50)
        #[arg(long, default_value = "50")]
        last: usize,
        /// Show entries since a duration ago (e.g. 7d, 24h, 30m)
        #[arg(long)]
        since: Option<String>,
    },
}

/// Auth subcommands for keyring and keyfile management.
#[derive(clap::Subcommand)]
pub enum AuthAction {
    /// Save vault password to OS keyring (auto-unlock)
    Keyring {
        /// Remove password from keyring instead of saving
        #[arg(long)]
        delete: bool,
    },

    /// Generate a new random keyfile
    KeyfileGenerate {
        /// Path for the keyfile (default: <vault_dir>/keyfile)
        path: Option<String>,
    },
}

/// Env subcommands for environment management.
#[derive(clap::Subcommand)]
pub enum EnvAction {
    /// List all vault environments
    List,

    /// Clone an environment to a new name
    Clone {
        /// Target environment name
        target: String,
        /// Prompt for a different password for the new vault
        #[arg(long)]
        new_password: bool,
    },

    /// Delete a vault environment
    Delete {
        /// Environment name to delete
        name: String,
        /// Skip confirmation prompt
        #[arg(short, long)]
        force: bool,
    },
}

// ---------------------------------------------------------------------------
// Shared helpers used by multiple commands
// ---------------------------------------------------------------------------

/// Get the vault password, trying in order:
/// 1. `ENVVAULT_PASSWORD` env var (CI/CD)
/// 2. OS keyring (if compiled with `keyring-store` feature)
/// 3. Interactive prompt
///
/// Returns `Zeroizing<String>` so the password is wiped from memory on drop.
pub fn prompt_password() -> Result<Zeroizing<String>> {
    prompt_password_for_vault(None)
}

/// Get the vault password with an optional vault path for keyring lookup.
///
/// Returns `Zeroizing<String>` so the password is wiped from memory on drop.
pub fn prompt_password_for_vault(vault_id: Option<&str>) -> Result<Zeroizing<String>> {
    // 1. Check the environment variable first (CI/CD friendly).
    if let Ok(pw) = std::env::var("ENVVAULT_PASSWORD") {
        if !pw.is_empty() {
            return Ok(Zeroizing::new(pw));
        }
    }

    // 2. Try the OS keyring (if feature enabled and vault_id provided).
    #[cfg(feature = "keyring-store")]
    if let Some(id) = vault_id {
        match crate::keyring::get_password(id) {
            Ok(Some(pw)) => return Ok(Zeroizing::new(pw)),
            Ok(None) => {} // No stored password, continue to prompt.
            Err(_) => {}   // Keyring unavailable, continue to prompt.
        }
    }

    // Suppress unused variable warning when keyring feature is off.
    #[cfg(not(feature = "keyring-store"))]
    let _ = vault_id;

    // 3. Fall back to interactive prompt.
    let pw = dialoguer::Password::new()
        .with_prompt("Enter vault password")
        .interact()
        .map_err(|e| EnvVaultError::CommandFailed(format!("password prompt: {e}")))?;
    Ok(Zeroizing::new(pw))
}

/// Prompt for a new password with confirmation (used during `init`).
///
/// Also respects `ENVVAULT_PASSWORD` for scripted/CI usage.
/// Enforces a minimum password length.
///
/// Returns `Zeroizing<String>` so the password is wiped from memory on drop.
pub fn prompt_new_password() -> Result<Zeroizing<String>> {
    // Check the environment variable first (CI/CD friendly).
    if let Ok(pw) = std::env::var("ENVVAULT_PASSWORD") {
        if !pw.is_empty() {
            if pw.len() < MIN_PASSWORD_LEN {
                return Err(EnvVaultError::CommandFailed(format!(
                    "password must be at least {MIN_PASSWORD_LEN} characters"
                )));
            }
            return Ok(Zeroizing::new(pw));
        }
    }

    loop {
        let password = dialoguer::Password::new()
            .with_prompt("Choose vault password")
            .with_confirmation(
                "Confirm vault password",
                "Passwords do not match, try again",
            )
            .interact()
            .map_err(|e| EnvVaultError::CommandFailed(format!("password prompt: {e}")))?;

        if password.len() < MIN_PASSWORD_LEN {
            output::warning(&format!(
                "Password must be at least {MIN_PASSWORD_LEN} characters. Try again."
            ));
            continue;
        }

        return Ok(Zeroizing::new(password));
    }
}

/// Build the full path to a vault file from the CLI arguments.
///
/// Example: `<cwd>/.envvault/dev.vault`
pub fn vault_path(cli: &Cli) -> Result<std::path::PathBuf> {
    let cwd = std::env::current_dir()?;
    let env = &cli.env;
    Ok(cwd.join(&cli.vault_dir).join(format!("{env}.vault")))
}

/// Load the keyfile bytes from the path in CLI args, if provided.
///
/// Returns `None` if `--keyfile` was not passed.
pub fn load_keyfile(cli: &Cli) -> Result<Option<Vec<u8>>> {
    match &cli.keyfile {
        Some(path) => {
            let bytes = crate::crypto::keyfile::load_keyfile(std::path::Path::new(path))?;
            Ok(Some(bytes))
        }
        None => Ok(None),
    }
}

/// Validate that an environment name is safe and sensible.
///
/// Allowed: lowercase letters, digits, hyphens. Must not be empty
/// or start/end with a hyphen. Max length 64 characters.
/// This prevents accidental typos from silently creating new vault files.
pub fn validate_env_name(name: &str) -> Result<()> {
    if name.is_empty() {
        return Err(EnvVaultError::ConfigError(
            "environment name cannot be empty".into(),
        ));
    }

    if name.len() > 64 {
        return Err(EnvVaultError::ConfigError(
            "environment name cannot exceed 64 characters".into(),
        ));
    }

    if !name
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
    {
        return Err(EnvVaultError::ConfigError(format!(
            "environment name '{name}' is invalid — only lowercase letters, digits, and hyphens are allowed"
        )));
    }

    if name.starts_with('-') || name.ends_with('-') {
        return Err(EnvVaultError::ConfigError(format!(
            "environment name '{name}' cannot start or end with a hyphen"
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_env_names() {
        assert!(validate_env_name("dev").is_ok());
        assert!(validate_env_name("staging").is_ok());
        assert!(validate_env_name("prod").is_ok());
        assert!(validate_env_name("us-east-1").is_ok());
        assert!(validate_env_name("v2").is_ok());
    }

    #[test]
    fn rejects_empty_name() {
        assert!(validate_env_name("").is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert!(validate_env_name("Dev").is_err());
        assert!(validate_env_name("PROD").is_err());
    }

    #[test]
    fn rejects_special_chars() {
        assert!(validate_env_name("dev.test").is_err());
        assert!(validate_env_name("dev/test").is_err());
        assert!(validate_env_name("dev test").is_err());
        assert!(validate_env_name("dev_test").is_err());
    }

    #[test]
    fn rejects_leading_trailing_hyphens() {
        assert!(validate_env_name("-dev").is_err());
        assert!(validate_env_name("dev-").is_err());
    }

    #[test]
    fn rejects_too_long_name() {
        let long_name = "a".repeat(65);
        assert!(validate_env_name(&long_name).is_err());
    }
}
