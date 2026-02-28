//! Shared `.env` file parsing logic.
//!
//! Used by both `init` (for auto-import) and `import` commands.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

use crate::errors::{EnvVaultError, Result};

/// Parse a single `.env` line into a (key, value) pair.
///
/// Returns `None` for blank lines, comments, and lines without `=`.
/// Handles: `export` prefix, double/single quotes, values with `=`.
pub fn parse_env_line(line: &str) -> Option<(&str, &str)> {
    let trimmed = line.trim();

    // Skip empty lines and comments.
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }

    // Strip optional `export ` prefix.
    let trimmed = trimmed.strip_prefix("export ").unwrap_or(trimmed);

    // Split on the first '=' to get KEY and VALUE.
    let (key, value) = trimmed.split_once('=')?;
    let key = key.trim();
    let value = value.trim();

    // Strip optional surrounding quotes from the value.
    let value = value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .unwrap_or(value);

    if key.is_empty() {
        return None;
    }

    Some((key, value))
}

/// Parse a `.env` file into a key-value map.
pub fn parse_env_file(path: &Path) -> Result<HashMap<String, String>> {
    let content = fs::read_to_string(path)
        .map_err(|e| EnvVaultError::CommandFailed(format!("failed to read file: {e}")))?;

    let mut secrets = HashMap::new();

    for line in content.lines() {
        if let Some((key, value)) = parse_env_line(line) {
            secrets.insert(key.to_string(), value.to_string());
        }
    }

    Ok(secrets)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_key_value() {
        assert_eq!(parse_env_line("KEY=value"), Some(("KEY", "value")));
    }

    #[test]
    fn parse_export_prefix() {
        assert_eq!(
            parse_env_line("export DATABASE_URL=postgres://localhost/db"),
            Some(("DATABASE_URL", "postgres://localhost/db"))
        );
    }

    #[test]
    fn parse_value_with_equals() {
        assert_eq!(parse_env_line("KEY=val=ue"), Some(("KEY", "val=ue")));
    }

    #[test]
    fn parse_double_quoted_value() {
        assert_eq!(
            parse_env_line(r#"KEY="hello world""#),
            Some(("KEY", "hello world"))
        );
    }

    #[test]
    fn parse_single_quoted_value() {
        assert_eq!(
            parse_env_line("KEY='hello world'"),
            Some(("KEY", "hello world"))
        );
    }

    #[test]
    fn parse_empty_value() {
        assert_eq!(parse_env_line("KEY="), Some(("KEY", "")));
    }

    #[test]
    fn parse_empty_quoted_value() {
        assert_eq!(parse_env_line(r#"KEY="""#), Some(("KEY", "")));
    }

    #[test]
    fn parse_skips_comments() {
        assert_eq!(parse_env_line("# this is a comment"), None);
    }

    #[test]
    fn parse_skips_blank_lines() {
        assert_eq!(parse_env_line(""), None);
        assert_eq!(parse_env_line("   "), None);
    }

    #[test]
    fn parse_skips_lines_without_equals() {
        assert_eq!(parse_env_line("NOEQUALS"), None);
    }

    #[test]
    fn parse_trims_whitespace() {
        assert_eq!(parse_env_line("  KEY  =  value  "), Some(("KEY", "value")));
    }
}
