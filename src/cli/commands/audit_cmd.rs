//! `envvault audit` — display the audit log.
//!
//! Usage:
//!   envvault audit               # show last 50 entries
//!   envvault audit --last 20     # show last 20
//!   envvault audit --since 7d    # entries from last 7 days

use chrono::Utc;

use crate::audit::{AuditEntry, AuditLog};
use crate::cli::output;
use crate::cli::Cli;
use crate::errors::{EnvVaultError, Result};

/// Execute the `audit` command.
pub fn execute(cli: &Cli, last: usize, since: Option<&str>) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);

    let audit = AuditLog::open(&vault_dir)
        .ok_or_else(|| EnvVaultError::AuditError("failed to open audit database".into()))?;

    let since_dt = match since {
        Some(s) => Some(parse_duration(s)?),
        None => None,
    };

    let entries = audit.query(last, since_dt)?;

    if entries.is_empty() {
        output::info("No audit entries found.");
        return Ok(());
    }

    print_audit_table(&entries);

    Ok(())
}

/// Parse a human-friendly duration string like "7d", "24h", "30m".
fn parse_duration(input: &str) -> Result<chrono::DateTime<Utc>> {
    let input = input.trim();

    let (num_str, unit) = if let Some(s) = input.strip_suffix('d') {
        (s, 'd')
    } else if let Some(s) = input.strip_suffix('h') {
        (s, 'h')
    } else if let Some(s) = input.strip_suffix('m') {
        (s, 'm')
    } else {
        return Err(EnvVaultError::CommandFailed(format!(
            "invalid duration '{input}' — use format like 7d, 24h, or 30m"
        )));
    };

    let num: i64 = num_str.parse().map_err(|_| {
        EnvVaultError::CommandFailed(format!(
            "invalid duration '{input}' — number part is not valid"
        ))
    })?;

    let duration = match unit {
        'd' => chrono::Duration::days(num),
        'h' => chrono::Duration::hours(num),
        'm' => chrono::Duration::minutes(num),
        _ => unreachable!(),
    };

    Ok(Utc::now() - duration)
}

/// Print audit entries in a formatted table.
pub fn print_audit_table(entries: &[AuditEntry]) {
    use comfy_table::{ContentArrangement, Table};
    use console::style;

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["Time", "Operation", "Environment", "Key", "Details"]);

    for entry in entries {
        let time = entry.timestamp.format("%Y-%m-%d %H:%M:%S").to_string();
        let op = colorize_operation(&entry.operation);
        let key = entry.key_name.as_deref().unwrap_or("-");
        let details = entry.details.as_deref().unwrap_or("-");

        table.add_row(vec![
            time,
            op,
            entry.environment.clone(),
            key.to_string(),
            details.to_string(),
        ]);
    }

    println!(
        "{}",
        style(format!("{} audit entries:", entries.len())).bold()
    );
    println!("{table}");
}

/// Colorize operation names for display.
fn colorize_operation(op: &str) -> String {
    use console::style;

    match op {
        "init" | "env-clone" => style(op).green().to_string(),
        "set" | "edit" => style(op).blue().to_string(),
        "delete" | "env-delete" => style(op).red().to_string(),
        "rotate-key" => style(op).yellow().to_string(),
        "export" | "import" => style(op).cyan().to_string(),
        "diff" => style(op).magenta().to_string(),
        _ => op.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_days() {
        let dt = parse_duration("7d").unwrap();
        let diff = Utc::now() - dt;
        // Should be roughly 7 days (within a few seconds).
        assert!((diff.num_days() - 7).abs() <= 1);
    }

    #[test]
    fn parse_duration_hours() {
        let dt = parse_duration("24h").unwrap();
        let diff = Utc::now() - dt;
        assert!((diff.num_hours() - 24).abs() <= 1);
    }

    #[test]
    fn parse_duration_minutes() {
        let dt = parse_duration("30m").unwrap();
        let diff = Utc::now() - dt;
        assert!((diff.num_minutes() - 30).abs() <= 1);
    }

    #[test]
    fn parse_duration_invalid() {
        assert!(parse_duration("abc").is_err());
        assert!(parse_duration("7x").is_err());
        assert!(parse_duration("d").is_err());
    }

    #[test]
    fn colorize_operation_returns_string() {
        // Just verify it doesn't panic for known and unknown operations.
        assert!(!colorize_operation("init").is_empty());
        assert!(!colorize_operation("set").is_empty());
        assert!(!colorize_operation("unknown").is_empty());
    }

    #[test]
    fn audit_query_roundtrip() {
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), Some("added"));
        audit.log("delete", "prod", Some("OLD"), None);

        let entries = audit.query(10, None).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn audit_with_since_filter() {
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), None);

        // Query with "1h" should include recent entries.
        let since = parse_duration("1h").unwrap();
        let entries = audit.query(10, Some(since)).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn audit_empty_returns_empty() {
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();
        let entries = audit.query(10, None).unwrap();
        assert!(entries.is_empty());
    }
}
