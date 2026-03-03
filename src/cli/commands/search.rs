//! `envvault search` — search secrets by name pattern.
//!
//! Supports simple glob matching: `*` matches any sequence, `?` matches one char.
//! Matching is case-insensitive.

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `search` command.
pub fn execute(cli: &Cli, pattern: &str) -> Result<()> {
    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;

    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    let secrets = store.list_secrets();
    let matches: Vec<_> = secrets
        .iter()
        .filter(|s| glob_match(pattern, &s.name))
        .collect();

    if matches.is_empty() {
        output::info(&format!("No secrets matching '{pattern}'"));
        return Ok(());
    }

    output::info(&format!(
        "{} secret(s) matching '{pattern}':",
        matches.len()
    ));
    output::print_secrets_table(&matches.into_iter().cloned().collect::<Vec<_>>());

    #[cfg(feature = "audit-log")]
    crate::audit::log_read_audit(cli, "search", None, Some(&format!("pattern: {pattern}")));

    Ok(())
}

/// Simple glob matcher supporting `*` (any sequence) and `?` (single char).
/// Case-insensitive.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.to_ascii_lowercase();
    let text = text.to_ascii_lowercase();
    glob_match_inner(pattern.as_bytes(), text.as_bytes())
}

fn glob_match_inner(pattern: &[u8], text: &[u8]) -> bool {
    let mut p = 0;
    let mut t = 0;
    let mut star_p = usize::MAX; // position in pattern after last '*'
    let mut star_t = 0; // position in text when last '*' was matched

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star_p = p + 1;
            star_t = t;
            p += 1;
        } else if star_p != usize::MAX {
            p = star_p;
            star_t += 1;
            t = star_t;
        } else {
            return false;
        }
    }

    // Consume trailing '*' in pattern.
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn glob_exact_match() {
        assert!(glob_match("DB_URL", "DB_URL"));
        assert!(!glob_match("DB_URL", "DB_HOST"));
    }

    #[test]
    fn glob_star_wildcard() {
        assert!(glob_match("DB_*", "DB_URL"));
        assert!(glob_match("DB_*", "DB_HOST"));
        assert!(glob_match("*_KEY", "API_KEY"));
        assert!(glob_match("*_KEY", "SECRET_KEY"));
        assert!(!glob_match("DB_*", "API_KEY"));
    }

    #[test]
    fn glob_question_wildcard() {
        assert!(glob_match("DB_UR?", "DB_URL"));
        assert!(!glob_match("DB_UR?", "DB_URLS"));
    }

    #[test]
    fn glob_case_insensitive() {
        assert!(glob_match("db_url", "DB_URL"));
        assert!(glob_match("DB_URL", "db_url"));
        assert!(glob_match("Db_*", "DB_URL"));
    }

    #[test]
    fn glob_star_matches_empty() {
        assert!(glob_match("*", "ANYTHING"));
        assert!(glob_match("*", ""));
        assert!(glob_match("DB_*", "DB_"));
    }

    #[test]
    fn glob_multiple_stars() {
        assert!(glob_match("*DB*", "MY_DB_URL"));
        assert!(glob_match("*_*_*", "A_B_C"));
    }
}
