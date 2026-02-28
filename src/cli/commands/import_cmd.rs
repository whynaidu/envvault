//! `envvault import` — import secrets from external files.
//!
//! Supported formats:
//! - `.env` files (auto-detected by extension or content)
//! - JSON files (object with string values)

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::cli::env_parser;
use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `import` command.
pub fn execute(cli: &Cli, file_path: &str, format: Option<&str>) -> Result<()> {
    let vault = vault_path(cli)?;
    let source = Path::new(file_path);

    if !source.exists() {
        return Err(EnvVaultError::CommandFailed(format!(
            "import file not found: {}",
            source.display()
        )));
    }

    let keyfile = load_keyfile(cli)?;
    let vault_id = vault.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let mut store = VaultStore::open(&vault, password.as_bytes(), keyfile.as_deref())?;

    // Detect format from flag or file extension.
    let detected_format = match format {
        Some(f) => f.to_string(),
        None => detect_format(source),
    };

    let secrets = match detected_format.as_str() {
        "env" => env_parser::parse_env_file(source)?,
        "json" => parse_json_file(source)?,
        other => {
            return Err(EnvVaultError::CommandFailed(format!(
                "unknown import format '{other}' — use 'env' or 'json'"
            )));
        }
    };

    if secrets.is_empty() {
        output::warning("No secrets found in the import file.");
        return Ok(());
    }

    // Import each secret into the vault.
    let mut count = 0;
    for (key, value) in &secrets {
        store.set_secret(key, value)?;
        output::info(&format!("  + {key}"));
        count += 1;
    }

    store.save()?;

    crate::audit::log_audit(
        cli,
        "import",
        None,
        Some(&format!("{count} secrets from {}", source.display())),
    );

    output::success(&format!(
        "Imported {} secrets from {} into '{}' vault",
        count,
        source.display(),
        store.environment()
    ));

    Ok(())
}

/// Detect the file format from its extension.
fn detect_format(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("json") => "json".to_string(),
        _ => "env".to_string(), // Default to .env format.
    }
}

/// Parse a JSON file (object with string values) into a key-value map.
fn parse_json_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| EnvVaultError::CommandFailed(format!("failed to read file: {e}")))?;

    let map: HashMap<String, serde_json::Value> = serde_json::from_str(&content)
        .map_err(|e| EnvVaultError::CommandFailed(format!("invalid JSON: {e}")))?;

    let mut secrets = HashMap::new();
    for (key, value) in map {
        let string_value = match value {
            serde_json::Value::String(s) => s,
            other => other.to_string(), // Convert non-strings to their JSON repr.
        };
        secrets.insert(key, string_value);
    }

    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parse_env_file_basic() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "KEY=value").unwrap();
        writeln!(file, "OTHER=123").unwrap();

        let secrets = env_parser::parse_env_file(file.path()).unwrap();
        assert_eq!(secrets["KEY"], "value");
        assert_eq!(secrets["OTHER"], "123");
    }

    #[test]
    fn parse_env_file_with_export_and_quotes() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "export A=\"hello world\"").unwrap();
        writeln!(file, "B='single'").unwrap();
        writeln!(file, "# comment").unwrap();

        let secrets = env_parser::parse_env_file(file.path()).unwrap();
        assert_eq!(secrets["A"], "hello world");
        assert_eq!(secrets["B"], "single");
        assert!(!secrets.contains_key("# comment"));
    }

    #[test]
    fn parse_json_file_basic() {
        let mut file = NamedTempFile::with_suffix(".json").unwrap();
        write!(file, r#"{{"KEY": "value", "NUM": "42"}}"#).unwrap();

        let secrets = parse_json_file(file.path()).unwrap();
        assert_eq!(secrets["KEY"], "value");
        assert_eq!(secrets["NUM"], "42");
    }

    #[test]
    fn detect_format_from_extension() {
        assert_eq!(detect_format(Path::new("secrets.json")), "json");
        assert_eq!(detect_format(Path::new(".env")), "env");
        assert_eq!(detect_format(Path::new("secrets.env")), "env");
        assert_eq!(detect_format(Path::new("noext")), "env");
    }
}
