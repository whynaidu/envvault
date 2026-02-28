//! `envvault env list` — list all vault environments.

use std::fs;

use comfy_table::{ContentArrangement, Table};
use console::style;

use crate::cli::output;
use crate::cli::Cli;
use crate::errors::Result;

/// Execute `envvault env list`.
pub fn execute(cli: &Cli) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);

    if !vault_dir.exists() {
        output::info("No vault directory found.");
        output::tip("Run `envvault init` to create a vault.");
        return Ok(());
    }

    let mut envs = list_environments(&vault_dir)?;
    envs.sort_by(|a, b| a.name.cmp(&b.name));

    if envs.is_empty() {
        output::info("No environments found.");
        output::tip("Run `envvault init` to create your first vault.");
        return Ok(());
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["Environment", "Size", "Active"]);

    for env in &envs {
        let active = if env.name == cli.env {
            style("*").green().bold().to_string()
        } else {
            String::new()
        };

        table.add_row(vec![env.name.clone(), format_size(env.size), active]);
    }

    output::info(&format!("{} environment(s) found:", envs.len()));
    println!("{table}");

    Ok(())
}

/// Information about a vault environment.
pub struct EnvInfo {
    pub name: String,
    pub size: u64,
}

/// Scan a vault directory for `*.vault` files.
pub fn list_environments(vault_dir: &std::path::Path) -> Result<Vec<EnvInfo>> {
    let mut envs = Vec::new();

    let entries = fs::read_dir(vault_dir)?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if let Some(ext) = path.extension() {
            if ext == "vault" {
                if let Some(stem) = path.file_stem() {
                    let name = stem.to_string_lossy().to_string();
                    let size = entry.metadata().map(|m| m.len()).unwrap_or(0);
                    envs.push(EnvInfo { name, size });
                }
            }
        }
    }

    Ok(envs)
}

/// Format file size in human-readable form.
#[allow(clippy::cast_precision_loss)] // File sizes are well within f64 precision range
fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_size_bytes() {
        assert_eq!(format_size(512), "512 B");
    }

    #[test]
    fn format_size_kilobytes() {
        assert_eq!(format_size(2048), "2.0 KB");
    }

    #[test]
    fn format_size_megabytes() {
        assert_eq!(format_size(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn list_environments_from_dir() {
        let dir = tempfile::TempDir::new().unwrap();
        // Create some .vault files.
        std::fs::write(dir.path().join("dev.vault"), b"test").unwrap();
        std::fs::write(dir.path().join("staging.vault"), b"test data").unwrap();
        std::fs::write(dir.path().join("not-a-vault.txt"), b"nope").unwrap();

        let envs = list_environments(dir.path()).unwrap();
        assert_eq!(envs.len(), 2);

        let names: Vec<&str> = envs.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"dev"));
        assert!(names.contains(&"staging"));
    }
}
