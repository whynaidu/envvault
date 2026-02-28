//! Audit log — SQLite-based operation history.
//!
//! Stores a record of every vault operation (set, delete, rotate, etc.)
//! in a local SQLite database at `<vault_dir>/audit.db`.
//!
//! Designed for graceful degradation: if the database can't be opened or
//! written to, operations silently continue without logging.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::Connection;

use crate::cli::Cli;
use crate::errors::{EnvVaultError, Result};

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub environment: String,
    pub key_name: Option<String>,
    pub details: Option<String>,
}

/// SQLite-backed audit log.
pub struct AuditLog {
    conn: Connection,
}

impl AuditLog {
    /// Open (or create) the audit database at `<vault_dir>/audit.db`.
    ///
    /// Returns `None` if the database can't be opened — callers should
    /// treat this as "audit logging unavailable" and continue normally.
    pub fn open(vault_dir: &Path) -> Option<Self> {
        let db_path = vault_dir.join("audit.db");
        let conn = Connection::open(&db_path).ok()?;

        // Set restrictive permissions on the audit database (owner-only).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            let _ = std::fs::set_permissions(&db_path, perms);
        }

        // Create the table if it doesn't exist.
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                operation   TEXT NOT NULL,
                environment TEXT NOT NULL,
                key_name    TEXT,
                details     TEXT
            );",
        )
        .ok()?;

        Some(Self { conn })
    }

    /// Record an operation. Fire-and-forget — errors are silently ignored.
    pub fn log(
        &self,
        operation: &str,
        environment: &str,
        key_name: Option<&str>,
        details: Option<&str>,
    ) {
        let now = Utc::now().to_rfc3339();
        let _ = self.conn.execute(
            "INSERT INTO audit_log (timestamp, operation, environment, key_name, details)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![now, operation, environment, key_name, details],
        );
    }

    /// Query recent audit entries.
    ///
    /// - `limit`: maximum number of entries to return (most recent first).
    /// - `since`: if provided, only return entries newer than this timestamp.
    pub fn query(&self, limit: usize, since: Option<DateTime<Utc>>) -> Result<Vec<AuditEntry>> {
        let limit_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let (sql, params): (&str, Vec<Box<dyn rusqlite::types::ToSql>>) = match since {
            Some(ref ts) => (
                "SELECT id, timestamp, operation, environment, key_name, details
                 FROM audit_log
                 WHERE timestamp >= ?1
                 ORDER BY id DESC
                 LIMIT ?2",
                vec![
                    Box::new(ts.to_rfc3339()) as Box<dyn rusqlite::types::ToSql>,
                    Box::new(limit_i64),
                ],
            ),
            None => (
                "SELECT id, timestamp, operation, environment, key_name, details
                 FROM audit_log
                 ORDER BY id DESC
                 LIMIT ?1",
                vec![Box::new(limit_i64) as Box<dyn rusqlite::types::ToSql>],
            ),
        };

        let mut stmt = self
            .conn
            .prepare(sql)
            .map_err(|e| EnvVaultError::AuditError(format!("query prepare: {e}")))?;

        let params_refs: Vec<&dyn rusqlite::types::ToSql> = params.iter().map(|p| &**p).collect();

        let rows = stmt
            .query_map(params_refs.as_slice(), |row| {
                let ts_str: String = row.get(1)?;
                let timestamp = DateTime::parse_from_rfc3339(&ts_str)
                    .map_or_else(|_| Utc::now(), |dt| dt.with_timezone(&Utc));

                Ok(AuditEntry {
                    id: row.get(0)?,
                    timestamp,
                    operation: row.get(2)?,
                    environment: row.get(3)?,
                    key_name: row.get(4)?,
                    details: row.get(5)?,
                })
            })
            .map_err(|e| EnvVaultError::AuditError(format!("query exec: {e}")))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| EnvVaultError::AuditError(format!("row parse: {e}")))?);
        }

        Ok(entries)
    }

    /// Return the path to the audit database (for testing/display).
    pub fn db_path(vault_dir: &Path) -> PathBuf {
        vault_dir.join("audit.db")
    }
}

/// Convenience helper: log an audit event using the CLI context.
///
/// Opens the audit database, logs the event, and silently ignores any errors.
/// This is safe to call from any command — it never fails the parent operation.
pub fn log_audit(cli: &Cli, op: &str, key: Option<&str>, details: Option<&str>) {
    let vault_dir = match std::env::current_dir() {
        Ok(cwd) => cwd.join(&cli.vault_dir),
        Err(_) => return,
    };

    if let Some(audit) = AuditLog::open(&vault_dir) {
        audit.log(op, &cli.env, key, details);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn open_creates_database() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path());
        assert!(audit.is_some(), "should open successfully");
        assert!(dir.path().join("audit.db").exists());
    }

    #[test]
    fn log_and_query_roundtrip() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("DB_URL"), Some("added"));
        audit.log("set", "dev", Some("API_KEY"), Some("added"));
        audit.log("delete", "dev", Some("OLD_KEY"), None);

        let entries = audit.query(10, None).unwrap();
        assert_eq!(entries.len(), 3);

        // Most recent first.
        assert_eq!(entries[0].operation, "delete");
        assert_eq!(entries[1].operation, "set");
        assert_eq!(entries[2].operation, "set");
    }

    #[test]
    fn query_with_limit() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        for i in 0..10 {
            audit.log("set", "dev", Some(&format!("KEY_{i}")), None);
        }

        let entries = audit.query(3, None).unwrap();
        assert_eq!(entries.len(), 3);
    }

    #[test]
    fn query_with_since_filter() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY_1"), None);

        // Query with a timestamp in the past should return the entry.
        let past = Utc::now() - chrono::Duration::hours(1);
        let entries = audit.query(10, Some(past)).unwrap();
        assert_eq!(entries.len(), 1);

        // Query with a timestamp in the future should return nothing.
        let future = Utc::now() + chrono::Duration::hours(1);
        let entries = audit.query(10, Some(future)).unwrap();
        assert_eq!(entries.len(), 0);
    }

    #[test]
    fn log_records_environment() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("init", "staging", None, Some("vault created"));

        let entries = audit.query(1, None).unwrap();
        assert_eq!(entries[0].environment, "staging");
        assert_eq!(entries[0].operation, "init");
        assert!(entries[0].key_name.is_none());
        assert_eq!(entries[0].details.as_deref(), Some("vault created"));
    }

    #[test]
    fn open_returns_none_on_bad_path() {
        // A path that doesn't exist as a directory should fail gracefully.
        let result = AuditLog::open(Path::new("/nonexistent/path/that/does/not/exist"));
        assert!(result.is_none());
    }

    #[cfg(unix)]
    #[test]
    fn audit_db_has_restrictive_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let _audit = AuditLog::open(dir.path()).unwrap();

        let db_path = dir.path().join("audit.db");
        let perms = std::fs::metadata(&db_path).unwrap().permissions();
        assert_eq!(
            perms.mode() & 0o777,
            0o600,
            "audit.db should have 0o600 permissions"
        );
    }
}
