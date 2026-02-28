//! `envvault export` — export secrets in various formats.
//!
//! Supported formats:
//! - `env` (default): `.env` file format (KEY=value, one per line)
//! - `json`: JSON object { "KEY": "value", ... }

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `export` command.
pub fn execute(cli: &Cli, format: &str, output_path: Option<&str>) -> Result<()> {
    let path = vault_path(cli)?;

    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    // Decrypt all secrets.
    let secrets = store.get_all_secrets()?;

    // Sort by key for deterministic output.
    let sorted: BTreeMap<_, _> = secrets.into_iter().collect();

    // Format the output.
    let content = match format {
        "env" => format_as_env(&sorted),
        "json" => format_as_json(&sorted)?,
        other => {
            return Err(EnvVaultError::CommandFailed(format!(
                "unknown export format '{other}' — use 'env' or 'json'"
            )));
        }
    };

    crate::audit::log_audit(
        cli,
        "export",
        None,
        Some(&format!("{} secrets, format: {format}", sorted.len())),
    );

    // Write to file or stdout.
    match output_path {
        Some(dest) => {
            let dest_path = Path::new(dest);

            // Safety: refuse to overwrite vault files.
            if Path::new(dest)
                .extension()
                .is_some_and(|ext| ext.eq_ignore_ascii_case("vault"))
            {
                return Err(EnvVaultError::CommandFailed(
                    "refusing to export over a .vault file".into(),
                ));
            }

            fs::write(dest_path, &content).map_err(|e| {
                EnvVaultError::CommandFailed(format!("failed to write export file: {e}"))
            })?;

            output::success(&format!(
                "Exported {} secrets to {} (format: {})",
                sorted.len(),
                dest,
                format
            ));
        }
        None => {
            // Write to stdout (no success message, just raw output).
            print!("{content}");
        }
    }

    Ok(())
}

/// Format secrets as `.env` file content.
fn format_as_env(secrets: &BTreeMap<String, String>) -> String {
    use std::fmt::Write;
    let mut out = String::new();
    for (key, value) in secrets {
        // Quote values that contain spaces, special chars, or are empty.
        if value.is_empty()
            || value.contains(' ')
            || value.contains('#')
            || value.contains('"')
            || value.contains('\'')
            || value.contains('\n')
            || value.contains('$')
        {
            // Escape inner double quotes and newlines.
            let escaped = value
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n");
            let _ = writeln!(out, "{key}=\"{escaped}\"");
        } else {
            let _ = writeln!(out, "{key}={value}");
        }
    }
    out
}

/// Format secrets as a JSON object.
fn format_as_json(secrets: &BTreeMap<String, String>) -> Result<String> {
    serde_json::to_string_pretty(secrets)
        .map_err(|e| EnvVaultError::SerializationError(format!("JSON export: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_env_simple_values() {
        let mut secrets = BTreeMap::new();
        secrets.insert("A".into(), "hello".into());
        secrets.insert("B".into(), "world".into());

        let output = format_as_env(&secrets);
        assert_eq!(output, "A=hello\nB=world\n");
    }

    #[test]
    fn format_env_quotes_values_with_spaces() {
        let mut secrets = BTreeMap::new();
        secrets.insert("KEY".into(), "has space".into());

        let output = format_as_env(&secrets);
        assert_eq!(output, "KEY=\"has space\"\n");
    }

    #[test]
    fn format_env_quotes_empty_values() {
        let mut secrets = BTreeMap::new();
        secrets.insert("EMPTY".into(), String::new());

        let output = format_as_env(&secrets);
        assert_eq!(output, "EMPTY=\"\"\n");
    }

    #[test]
    fn format_env_quotes_values_with_dollar() {
        let mut secrets = BTreeMap::new();
        secrets.insert("KEY".into(), "price$100".into());

        let output = format_as_env(&secrets);
        assert_eq!(output, "KEY=\"price$100\"\n");
    }

    #[test]
    fn format_json_produces_valid_json() {
        let mut secrets = BTreeMap::new();
        secrets.insert("KEY".into(), "value".into());

        let output = format_as_json(&secrets).unwrap();
        let parsed: BTreeMap<String, String> = serde_json::from_str(&output).unwrap();
        assert_eq!(parsed["KEY"], "value");
    }
}
