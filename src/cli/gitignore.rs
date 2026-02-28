//! Shared `.gitignore` patching logic.
//!
//! Used by `init` (to add the vault directory) and `auth keyfile-generate`
//! (to add the keyfile path).

use std::fs;
use std::path::Path;

use crate::cli::output;

/// Append `entry` to `.gitignore` if not already present.
///
/// Creates the file if it doesn't exist. Silently ignores write errors
/// (non-fatal — gitignore is a convenience, not a requirement).
pub fn patch_gitignore(project_dir: &Path, entry: &str) {
    let gitignore_path = project_dir.join(".gitignore");

    let existing = fs::read_to_string(&gitignore_path).unwrap_or_default();

    if existing.lines().any(|line| line.trim() == entry) {
        return;
    }

    let separator = if existing.ends_with('\n') || existing.is_empty() {
        ""
    } else {
        "\n"
    };

    if fs::write(&gitignore_path, format!("{existing}{separator}{entry}\n")).is_ok() {
        output::info(&format!("Added '{entry}' to .gitignore"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn adds_entry_to_new_gitignore() {
        let dir = TempDir::new().unwrap();
        patch_gitignore(dir.path(), ".envvault/");

        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert!(content.contains(".envvault/"));
    }

    #[test]
    fn does_not_duplicate_entry() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), ".envvault/\n").unwrap();

        patch_gitignore(dir.path(), ".envvault/");

        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content.matches(".envvault/").count(), 1);
    }

    #[test]
    fn appends_with_newline_separator() {
        let dir = TempDir::new().unwrap();
        fs::write(dir.path().join(".gitignore"), "node_modules/").unwrap(); // no trailing newline

        patch_gitignore(dir.path(), ".envvault/");

        let content = fs::read_to_string(dir.path().join(".gitignore")).unwrap();
        assert_eq!(content, "node_modules/\n.envvault/\n");
    }
}
