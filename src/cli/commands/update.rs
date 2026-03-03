//! `envvault update` — self-update to the latest version.
//!
//! Detects how envvault was installed and runs the appropriate update command:
//! - cargo  → `cargo install envvault-cli --force`
//! - brew   → `brew upgrade envvault`
//! - script → re-runs the curl installer

use std::process::Command;

use console::style;

use crate::cli::output;
use crate::errors::{EnvVaultError, Result};

/// How envvault was installed.
#[derive(Debug, PartialEq)]
pub enum InstallMethod {
    Cargo,
    Homebrew,
    Script,
}

/// Detect how envvault was installed by inspecting the binary path.
pub fn detect_install_method() -> InstallMethod {
    let exe = match std::env::current_exe() {
        Ok(p) => p.to_string_lossy().to_string(),
        Err(_) => return InstallMethod::Script,
    };

    if exe.contains(".cargo/bin") {
        InstallMethod::Cargo
    } else if exe.contains("Cellar") || exe.contains("homebrew") || exe.contains("linuxbrew") {
        InstallMethod::Homebrew
    } else {
        InstallMethod::Script
    }
}

/// Execute the `update` command.
pub fn execute() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");

    // Check for updates first.
    let latest = crate::version_check::check_latest_version(current);
    match &latest {
        Some(ver) => {
            output::info(&format!(
                "Update available: {} → {}",
                style(current).red(),
                style(ver).green().bold()
            ));
        }
        None => {
            output::success(&format!("Already on the latest version ({current})."));
            return Ok(());
        }
    }

    let method = detect_install_method();

    match method {
        InstallMethod::Cargo => run_cargo_update(),
        InstallMethod::Homebrew => run_brew_update(),
        InstallMethod::Script => run_script_update(),
    }
}

fn run_cargo_update() -> Result<()> {
    output::info("Detected cargo install. Running: cargo install envvault-cli --force");
    println!();

    let status = Command::new("cargo")
        .args(["install", "envvault-cli", "--force"])
        .status()
        .map_err(|e| {
            EnvVaultError::CommandFailed(format!(
                "failed to run cargo: {e}. Run manually: cargo install envvault-cli --force"
            ))
        })?;

    if status.success() {
        println!();
        output::success("Update complete!");
        Ok(())
    } else {
        Err(EnvVaultError::CommandFailed(
            "cargo install failed. Run manually: cargo install envvault-cli --force".into(),
        ))
    }
}

fn run_brew_update() -> Result<()> {
    output::info("Detected Homebrew install. Running: brew upgrade envvault");
    println!();

    let status = Command::new("brew")
        .args(["upgrade", "envvault"])
        .status()
        .map_err(|e| {
            EnvVaultError::CommandFailed(format!(
                "failed to run brew: {e}. Run manually: brew upgrade envvault"
            ))
        })?;

    if status.success() {
        println!();
        output::success("Update complete!");
        Ok(())
    } else {
        Err(EnvVaultError::CommandFailed(
            "brew upgrade failed. Run manually: brew upgrade envvault".into(),
        ))
    }
}

fn run_script_update() -> Result<()> {
    output::info("Running install script to update...");
    println!();

    let status = Command::new("sh")
        .args([
            "-c",
            "curl -fsSL https://raw.githubusercontent.com/whynaidu/envvault/main/install.sh | sh",
        ])
        .status()
        .map_err(|e| {
            EnvVaultError::CommandFailed(format!(
                "failed to run install script: {e}. Run manually:\n  \
                 curl -fsSL https://raw.githubusercontent.com/whynaidu/envvault/main/install.sh | sh"
            ))
        })?;

    if status.success() {
        println!();
        output::success("Update complete!");
        Ok(())
    } else {
        Err(EnvVaultError::CommandFailed(
            "install script failed. Run manually:\n  \
             curl -fsSL https://raw.githubusercontent.com/whynaidu/envvault/main/install.sh | sh"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_method_from_cargo_path() {
        // We're running under cargo test, so the binary should be in a cargo-related path.
        // Just verify the function doesn't panic.
        let method = detect_install_method();
        assert!(
            method == InstallMethod::Cargo
                || method == InstallMethod::Script
                || method == InstallMethod::Homebrew
        );
    }
}
