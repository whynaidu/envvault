//! `envvault completions` — generate shell completion scripts.
//!
//! Usage:
//!   envvault completions bash > ~/.bash_completion.d/envvault
//!   envvault completions zsh
//!   envvault completions fish
//!   envvault completions powershell

use std::io;

use clap::CommandFactory;
use clap_complete::{generate, Shell};

use crate::cli::Cli;
use crate::errors::{EnvVaultError, Result};

/// Execute the `completions` command.
pub fn execute(shell: &str) -> Result<()> {
    let shell = parse_shell(shell)?;
    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "envvault", &mut io::stdout());
    Ok(())
}

/// Parse a shell name string into a `Shell` enum.
fn parse_shell(name: &str) -> Result<Shell> {
    match name.to_lowercase().as_str() {
        "bash" => Ok(Shell::Bash),
        "zsh" => Ok(Shell::Zsh),
        "fish" => Ok(Shell::Fish),
        "powershell" | "ps" => Ok(Shell::PowerShell),
        "elvish" => Ok(Shell::Elvish),
        other => Err(EnvVaultError::CommandFailed(format!(
            "unknown shell '{other}' — supported: bash, zsh, fish, powershell, elvish"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shell_bash() {
        assert_eq!(parse_shell("bash").unwrap(), Shell::Bash);
    }

    #[test]
    fn parse_shell_zsh() {
        assert_eq!(parse_shell("zsh").unwrap(), Shell::Zsh);
    }

    #[test]
    fn parse_shell_fish() {
        assert_eq!(parse_shell("fish").unwrap(), Shell::Fish);
    }

    #[test]
    fn parse_shell_powershell() {
        assert_eq!(parse_shell("powershell").unwrap(), Shell::PowerShell);
        assert_eq!(parse_shell("ps").unwrap(), Shell::PowerShell);
    }

    #[test]
    fn parse_shell_case_insensitive() {
        assert_eq!(parse_shell("BASH").unwrap(), Shell::Bash);
        assert_eq!(parse_shell("Zsh").unwrap(), Shell::Zsh);
    }

    #[test]
    fn parse_shell_unknown_fails() {
        assert!(parse_shell("csh").is_err());
        assert!(parse_shell("").is_err());
    }
}
