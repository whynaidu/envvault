//! `envvault edit` — open secrets in an editor.
//!
//! Decrypts all secrets to a temporary file, launches `$VISUAL` / `$EDITOR` / `vi`,
//! and applies any changes back to the vault on save.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::Command;

use zeroize::Zeroize;

use crate::cli::env_parser::parse_env_line;
use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `edit` command.
pub fn execute(cli: &Cli) -> Result<()> {
    let path = vault_path(cli)?;

    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let mut store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    let mut secrets = store.get_all_secrets()?;

    // Write secrets to a temp file in KEY=VALUE format.
    let tmp_path = write_temp_file(&secrets)?;

    // Find the editor.
    let editor = find_editor();

    // Launch editor.
    let status = Command::new(&editor)
        .arg(&tmp_path)
        .status()
        .map_err(|e| EnvVaultError::EditorError(format!("failed to launch '{editor}': {e}")))?;

    if !status.success() {
        secure_delete(&tmp_path);
        for v in secrets.values_mut() {
            v.zeroize();
        }
        return Err(EnvVaultError::EditorError(format!(
            "editor exited with code {}",
            status.code().unwrap_or(-1)
        )));
    }

    // Parse the edited file.
    let mut edited_content = fs::read_to_string(&tmp_path)
        .map_err(|e| EnvVaultError::EditorError(format!("failed to read edited file: {e}")))?;

    // Securely wipe and delete temp file immediately.
    secure_delete(&tmp_path);

    let mut new_secrets = parse_edited_content(&edited_content);

    // Zeroize the raw edited content — no longer needed.
    edited_content.zeroize();

    // Compute and apply changes.
    let (added, removed, changed) = apply_changes(&mut store, &secrets, &new_secrets)?;

    // Zeroize plaintext secrets from memory — no longer needed.
    for v in secrets.values_mut() {
        v.zeroize();
    }
    for v in new_secrets.values_mut() {
        v.zeroize();
    }

    if added == 0 && removed == 0 && changed == 0 {
        output::info("No changes detected.");
        return Ok(());
    }

    store.save()?;

    crate::audit::log_audit(
        cli,
        "edit",
        None,
        Some(&format!(
            "{added} added, {removed} removed, {changed} changed"
        )),
    );

    output::success(&format!(
        "Edit complete: {added} added, {removed} removed, {changed} changed"
    ));

    Ok(())
}

/// Write secrets to a temp file in KEY=VALUE format.
/// Returns the path to the temp file.
fn write_temp_file(secrets: &HashMap<String, String>) -> Result<PathBuf> {
    let mut sorted: Vec<(&String, &String)> = secrets.iter().collect();
    sorted.sort_by_key(|(k, _)| *k);

    // Build a unique temp file path using PID + timestamp.
    let tmp_dir = std::env::temp_dir();
    let filename = format!(
        "envvault-edit-{}-{}.env",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)
    );
    let tmp_path = tmp_dir.join(filename);

    // Create the file with restrictive permissions atomically (no TOCTOU race).
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp_path)
            .map_err(|e| EnvVaultError::EditorError(format!("failed to create temp file: {e}")))?
    };

    #[cfg(not(unix))]
    let mut file = fs::File::create(&tmp_path)
        .map_err(|e| EnvVaultError::EditorError(format!("failed to create temp file: {e}")))?;

    writeln!(file, "# EnvVault — edit secrets below (KEY=VALUE format)")?;
    writeln!(file, "# Lines starting with '#' are ignored")?;
    writeln!(file)?;

    for (key, value) in &sorted {
        if value.contains(' ')
            || value.contains('#')
            || value.contains('"')
            || value.contains('\n')
            || value.is_empty()
        {
            let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
            writeln!(file, "{key}=\"{escaped}\"")?;
        } else {
            writeln!(file, "{key}={value}")?;
        }
    }

    file.flush()?;
    Ok(tmp_path)
}

/// Find the user's preferred editor.
fn find_editor() -> String {
    if let Ok(editor) = std::env::var("VISUAL") {
        if !editor.is_empty() {
            return editor;
        }
    }

    if let Ok(editor) = std::env::var("EDITOR") {
        if !editor.is_empty() {
            return editor;
        }
    }

    "vi".to_string()
}

/// Parse edited content back into a key-value map.
pub fn parse_edited_content(content: &str) -> HashMap<String, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        if let Some((key, value)) = parse_env_line(line) {
            map.insert(key.to_string(), value.to_string());
        }
    }
    map
}

/// Apply changes between old and new secrets. Returns (added, removed, changed) counts.
fn apply_changes(
    store: &mut VaultStore,
    old: &HashMap<String, String>,
    new: &HashMap<String, String>,
) -> Result<(usize, usize, usize)> {
    let mut added = 0;
    let mut removed = 0;
    let mut changed = 0;

    // Add or update secrets.
    for (key, new_value) in new {
        match old.get(key) {
            Some(old_value) if old_value == new_value => {}
            Some(_) => {
                store.set_secret(key, new_value)?;
                changed += 1;
            }
            None => {
                store.set_secret(key, new_value)?;
                added += 1;
            }
        }
    }

    // Remove deleted secrets.
    for key in old.keys() {
        if !new.contains_key(key) {
            store.delete_secret(key)?;
            removed += 1;
        }
    }

    Ok((added, removed, changed))
}

/// Overwrite a file's contents with zeros before deleting it.
/// This reduces the chance of secret recovery from disk.
/// Best-effort: failures are silently ignored.
fn secure_delete(path: &PathBuf) {
    if let Ok(metadata) = fs::metadata(path) {
        let len = metadata.len() as usize;
        if len > 0 {
            if let Ok(mut file) = fs::OpenOptions::new().write(true).open(path) {
                let zeros = vec![0u8; len];
                let _ = file.write_all(&zeros);
                let _ = file.flush();
            }
        }
    }
    let _ = fs::remove_file(path);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_edited_content_basic() {
        let content = "KEY=value\nOTHER=123\n# comment\n\n";
        let map = parse_edited_content(content);
        assert_eq!(map["KEY"], "value");
        assert_eq!(map["OTHER"], "123");
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_edited_content_with_quotes() {
        let content = "KEY=\"hello world\"\nOTHER='single'\n";
        let map = parse_edited_content(content);
        assert_eq!(map["KEY"], "hello world");
        assert_eq!(map["OTHER"], "single");
    }

    #[test]
    fn find_editor_respects_env() {
        let editor = find_editor();
        assert!(!editor.is_empty());
    }

    #[test]
    fn write_temp_file_creates_file() {
        let mut secrets = HashMap::new();
        secrets.insert("A".into(), "1".into());
        secrets.insert("B".into(), "has space".into());

        let tmp_path = write_temp_file(&secrets).unwrap();
        let content = fs::read_to_string(&tmp_path).unwrap();
        assert!(content.contains("A=1"));
        assert!(content.contains("B=\"has space\""));
        let _ = fs::remove_file(&tmp_path);
    }

    #[test]
    fn write_temp_file_sets_permissions() {
        let secrets = HashMap::new();
        let tmp_path = write_temp_file(&secrets).unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = fs::metadata(&tmp_path).unwrap().permissions();
            assert_eq!(perms.mode() & 0o777, 0o600);
        }

        let _ = fs::remove_file(&tmp_path);
    }
}
