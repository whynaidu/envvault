//! `envvault audit` — display the audit log.
//!
//! Usage:
//!   envvault audit               # show last 50 entries
//!   envvault audit --last 20     # show last 20
//!   envvault audit --since 7d    # entries from last 7 days

use crate::cli::Cli;
use crate::errors::{EnvVaultError, Result};

/// Execute the `audit` command.
#[cfg(feature = "audit-log")]
pub fn execute(cli: &Cli, last: usize, since: Option<&str>) -> Result<()> {
    use crate::audit::AuditLog;
    use crate::cli::output;

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

/// Execute the `audit` command — stub when audit-log is disabled.
#[cfg(not(feature = "audit-log"))]
pub fn execute(_cli: &Cli, _last: usize, _since: Option<&str>) -> Result<()> {
    Err(EnvVaultError::AuditError(
        "audit log not available — rebuild with `cargo build --features audit-log`".into(),
    ))
}

// ---------------------------------------------------------------------------
// Audit export
// ---------------------------------------------------------------------------

/// Export audit log entries to JSON or CSV.
#[cfg(feature = "audit-log")]
pub fn execute_export(cli: &Cli, format: &str, output: Option<&str>) -> Result<()> {
    use crate::audit::{AuditEntryExport, AuditLog};
    use crate::cli::output as out;

    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);

    let audit = AuditLog::open(&vault_dir)
        .ok_or_else(|| EnvVaultError::AuditError("failed to open audit database".into()))?;

    // Query all entries (no limit).
    let entries = audit.query(i64::MAX as usize, None)?;

    if entries.is_empty() {
        out::info("No audit entries to export.");
        return Ok(());
    }

    let exports: Vec<AuditEntryExport> = entries.iter().map(AuditEntryExport::from).collect();

    let content = match format {
        "csv" => format_as_csv(&exports),
        _ => serde_json::to_string_pretty(&exports)
            .map_err(|e| EnvVaultError::AuditError(format!("JSON serialization failed: {e}")))?,
    };

    match output {
        Some(path) => {
            std::fs::write(path, &content)?;
            out::success(&format!(
                "Exported {} entries to {} ({})",
                exports.len(),
                path,
                format
            ));
        }
        None => {
            println!("{content}");
        }
    }

    Ok(())
}

/// Export stub when audit-log is disabled.
#[cfg(not(feature = "audit-log"))]
pub fn execute_export(_cli: &Cli, _format: &str, _output: Option<&str>) -> Result<()> {
    Err(EnvVaultError::AuditError(
        "audit log not available — rebuild with `cargo build --features audit-log`".into(),
    ))
}

/// Format audit entries as CSV.
#[cfg(feature = "audit-log")]
fn format_as_csv(entries: &[crate::audit::AuditEntryExport]) -> String {
    let mut buf = String::from("id,timestamp,operation,environment,key_name,details,user,pid\n");
    for e in entries {
        buf.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            e.id,
            csv_escape(&e.timestamp),
            csv_escape(&e.operation),
            csv_escape(&e.environment),
            csv_escape(e.key_name.as_deref().unwrap_or("")),
            csv_escape(e.details.as_deref().unwrap_or("")),
            csv_escape(e.user.as_deref().unwrap_or("")),
            e.pid.map_or(String::new(), |p| p.to_string()),
        ));
    }
    buf
}

/// Escape a value for CSV output (quote if it contains commas or quotes).
#[cfg(feature = "audit-log")]
fn csv_escape(value: &str) -> String {
    if value.contains(',') || value.contains('"') || value.contains('\n') {
        format!("\"{}\"", value.replace('"', "\"\""))
    } else {
        value.to_string()
    }
}

// ---------------------------------------------------------------------------
// Audit purge
// ---------------------------------------------------------------------------

/// Delete old audit entries.
#[cfg(feature = "audit-log")]
pub fn execute_purge(cli: &Cli, older_than: &str) -> Result<()> {
    use crate::audit::AuditLog;
    use crate::cli::output as out;

    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);

    let audit = AuditLog::open(&vault_dir)
        .ok_or_else(|| EnvVaultError::AuditError("failed to open audit database".into()))?;

    let before = parse_duration(older_than)?;
    let deleted = audit.purge(before)?;

    out::success(&format!(
        "Purged {} audit entries older than {}",
        deleted, older_than
    ));

    Ok(())
}

/// Purge stub when audit-log is disabled.
#[cfg(not(feature = "audit-log"))]
pub fn execute_purge(_cli: &Cli, _older_than: &str) -> Result<()> {
    Err(EnvVaultError::AuditError(
        "audit log not available — rebuild with `cargo build --features audit-log`".into(),
    ))
}

/// Parse a human-friendly duration string like "7d", "24h", "30m".
pub fn parse_duration(input: &str) -> Result<chrono::DateTime<chrono::Utc>> {
    use chrono::Utc;

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
#[cfg(feature = "audit-log")]
pub fn print_audit_table(entries: &[crate::audit::AuditEntry]) {
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
#[cfg(feature = "audit-log")]
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
    use chrono::Utc;

    #[test]
    fn parse_duration_days() {
        let dt = parse_duration("7d").unwrap();
        let diff = Utc::now() - dt;
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

    #[cfg(feature = "audit-log")]
    #[test]
    fn colorize_operation_returns_string() {
        assert!(!colorize_operation("init").is_empty());
        assert!(!colorize_operation("set").is_empty());
        assert!(!colorize_operation("unknown").is_empty());
    }

    #[cfg(feature = "audit-log")]
    #[test]
    fn audit_query_roundtrip() {
        use crate::audit::AuditLog;
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), Some("added"));
        audit.log("delete", "prod", Some("OLD"), None);

        let entries = audit.query(10, None).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[cfg(feature = "audit-log")]
    #[test]
    fn audit_with_since_filter() {
        use crate::audit::AuditLog;
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), None);

        let since = parse_duration("1h").unwrap();
        let entries = audit.query(10, Some(since)).unwrap();
        assert_eq!(entries.len(), 1);
    }

    #[cfg(feature = "audit-log")]
    #[test]
    fn audit_empty_returns_empty() {
        use crate::audit::AuditLog;
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();
        let entries = audit.query(10, None).unwrap();
        assert!(entries.is_empty());
    }

    #[cfg(feature = "audit-log")]
    #[test]
    fn export_json_roundtrip() {
        use crate::audit::{AuditEntryExport, AuditLog};
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), Some("added"));
        audit.log("delete", "prod", Some("OLD"), None);

        let entries = audit.query(100, None).unwrap();
        let exports: Vec<AuditEntryExport> = entries.iter().map(AuditEntryExport::from).collect();

        let json = serde_json::to_string_pretty(&exports).unwrap();
        let parsed: Vec<AuditEntryExport> = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].operation, "delete");
        assert_eq!(parsed[1].operation, "set");
    }

    #[cfg(feature = "audit-log")]
    #[test]
    fn export_csv_format() {
        use crate::audit::{AuditEntryExport, AuditLog};
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("MY_KEY"), Some("added"));

        let entries = audit.query(100, None).unwrap();
        let exports: Vec<AuditEntryExport> = entries.iter().map(AuditEntryExport::from).collect();
        let csv = format_as_csv(&exports);

        assert!(csv.starts_with("id,timestamp,operation,environment,key_name,details,user,pid\n"));
        assert!(csv.contains("set"));
        assert!(csv.contains("dev"));
        assert!(csv.contains("MY_KEY"));
    }

    #[cfg(feature = "audit-log")]
    #[test]
    fn purge_count_correct() {
        use crate::audit::AuditLog;
        let dir = tempfile::TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("A"), None);
        audit.log("set", "dev", Some("B"), None);
        audit.log("set", "dev", Some("C"), None);

        // Purge everything before 1 hour from now (should delete all).
        let future = Utc::now() + chrono::Duration::hours(1);
        let deleted = audit.purge(future).unwrap();
        assert_eq!(deleted, 3);
    }
}
