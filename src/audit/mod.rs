//! Audit log — SQLite-based operation history.
//!
//! Stores a record of every vault operation (set, delete, rotate, etc.)
//! in a local SQLite database at `<vault_dir>/audit.db`.
//!
//! Designed for graceful degradation: if the database can't be opened or
//! written to, operations silently continue without logging.
//!
//! ## Tamper-evident hash chain (v0.6 / schema v6)
//!
//! Every entry carries an `entry_hash` column: a hex-encoded SHA-256
//! digest computed as
//!
//! ```text
//! entry_hash = SHA256( prev_hash || "|" || canonical_fields )
//! ```
//!
//! where `prev_hash` is the preceding entry's `entry_hash` (or the
//! literal string `"GENESIS"` for the first entry), and
//! `canonical_fields` concatenates the entry's data in a fixed order
//! separated by `|`. Modifying or deleting any entry invalidates the
//! hash of every subsequent entry — `verify_chain` walks the log and
//! reports the first break.

use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use rusqlite::Connection;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::cli::Cli;
use crate::errors::{EnvVaultError, Result};

/// Sentinel prev-hash used as the anchor of the chain.
pub const GENESIS_HASH: &str = "GENESIS";

/// A single audit log entry.
#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub id: i64,
    pub timestamp: DateTime<Utc>,
    pub operation: String,
    pub environment: String,
    pub key_name: Option<String>,
    pub details: Option<String>,
    pub user: Option<String>,
    pub pid: Option<i64>,
    /// SHA-256 hash over `prev_hash || "|" || canonical_fields`.
    /// `None` for entries written before the v6 migration.
    pub entry_hash: Option<String>,
}

/// Serializable audit entry for JSON/CSV export.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AuditEntryExport {
    pub id: i64,
    pub timestamp: String,
    pub operation: String,
    pub environment: String,
    pub key_name: Option<String>,
    pub details: Option<String>,
    pub user: Option<String>,
    pub pid: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub entry_hash: Option<String>,
}

impl From<&AuditEntry> for AuditEntryExport {
    fn from(e: &AuditEntry) -> Self {
        Self {
            id: e.id,
            timestamp: e.timestamp.to_rfc3339(),
            operation: e.operation.clone(),
            environment: e.environment.clone(),
            key_name: e.key_name.clone(),
            details: e.details.clone(),
            user: e.user.clone(),
            pid: e.pid,
            entry_hash: e.entry_hash.clone(),
        }
    }
}

/// Result of an audit-chain verification walk.
#[derive(Debug, Clone, Serialize)]
pub struct ChainVerification {
    pub entries_checked: usize,
    /// `true` if every entry's recomputed hash matches its stored
    /// `entry_hash` and the chain links are all intact.
    pub intact: bool,
    /// If `intact` is false, the id of the first entry where the
    /// stored hash disagrees with the recomputed hash.
    pub first_broken_id: Option<i64>,
    /// Number of entries that predate the hash-chain migration and
    /// carry a `NULL` stored hash. These are reported separately from
    /// breakage: a legacy entry is not a tamper indicator.
    pub legacy_entries: usize,
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

        // Run idempotent schema migration for v0.5.0 (user, pid, index).
        Self::migrate_v5(&conn);
        // Run idempotent schema migration for v0.6.0 (entry_hash chain).
        Self::migrate_v6(&conn);

        Some(Self { conn })
    }

    /// Idempotent migration: add user/pid columns and timestamp index.
    ///
    /// SQLite's `ALTER TABLE ADD COLUMN` errors if the column already exists,
    /// so we silently ignore those errors to make this safe to run every time.
    fn migrate_v5(conn: &Connection) {
        let _ = conn.execute_batch("ALTER TABLE audit_log ADD COLUMN user TEXT;");
        let _ = conn.execute_batch("ALTER TABLE audit_log ADD COLUMN pid INTEGER;");
        let _ = conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);",
        );
    }

    /// Idempotent migration: add the `entry_hash` column used by the
    /// v0.6 tamper-evident hash chain.
    ///
    /// Existing rows stay `NULL` — they predate the chain, and
    /// `verify_chain` accounts for that by tracking `legacy_entries`
    /// separately. Newly inserted rows get a chain hash linked to the
    /// most recent prior entry (even if that prior entry has no stored
    /// hash — we use `GENESIS` in that case to anchor the new chain).
    fn migrate_v6(conn: &Connection) {
        let _ = conn.execute_batch("ALTER TABLE audit_log ADD COLUMN entry_hash TEXT;");
    }

    /// Canonical string representation of an entry's fields, used as
    /// input to the chain hash.
    ///
    /// The format is stable and unambiguous: fields are joined with
    /// `|`, and `None` fields are encoded as `(null)` to distinguish
    /// from an empty string. Any change to this format is a schema
    /// migration concern — it would invalidate every existing chain.
    fn canonical_entry(
        timestamp: &str,
        operation: &str,
        environment: &str,
        key_name: Option<&str>,
        details: Option<&str>,
        user: Option<&str>,
        pid: Option<i64>,
    ) -> String {
        fn opt(s: Option<&str>) -> &str {
            s.unwrap_or("(null)")
        }
        let pid_str = pid.map_or_else(|| "(null)".to_string(), |p| p.to_string());
        format!(
            "{timestamp}|{operation}|{environment}|{k}|{d}|{u}|{pid_str}",
            k = opt(key_name),
            d = opt(details),
            u = opt(user),
        )
    }

    /// Compute the chain hash for an entry given its predecessor's
    /// stored hash (or `GENESIS_HASH` for the first entry).
    fn chain_hash(prev_hash: &str, canonical: &str) -> String {
        let mut h = Sha256::new();
        h.update(prev_hash.as_bytes());
        h.update(b"|");
        h.update(canonical.as_bytes());
        format!("{:x}", h.finalize())
    }

    /// Fetch the most recent entry's chain hash, or `GENESIS_HASH` if
    /// the log is empty or the latest entry predates the v6 migration.
    fn latest_prev_hash(&self) -> String {
        self.conn
            .query_row(
                "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get::<_, Option<String>>(0),
            )
            .ok()
            .flatten()
            .unwrap_or_else(|| GENESIS_HASH.to_string())
    }

    /// Record an operation. Fire-and-forget — errors are silently ignored.
    ///
    /// Each call links into the SHA-256 hash chain: the new entry's
    /// `entry_hash` covers the previous entry's hash plus this entry's
    /// canonical fields, so any later modification or deletion of an
    /// intermediate row is detectable with `verify_chain`.
    pub fn log(
        &self,
        operation: &str,
        environment: &str,
        key_name: Option<&str>,
        details: Option<&str>,
    ) {
        let timestamp = Utc::now().to_rfc3339();
        let user = std::env::var("USER")
            .or_else(|_| std::env::var("LOGNAME"))
            .ok();
        let pid = std::process::id() as i64;

        let canonical = Self::canonical_entry(
            &timestamp,
            operation,
            environment,
            key_name,
            details,
            user.as_deref(),
            Some(pid),
        );
        let prev_hash = self.latest_prev_hash();
        let entry_hash = Self::chain_hash(&prev_hash, &canonical);

        let _ = self.conn.execute(
            "INSERT INTO audit_log
                (timestamp, operation, environment, key_name, details, user, pid, entry_hash)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            rusqlite::params![
                timestamp,
                operation,
                environment,
                key_name,
                details,
                user,
                pid,
                entry_hash,
            ],
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
                "SELECT id, timestamp, operation, environment, key_name, details, user, pid, entry_hash
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
                "SELECT id, timestamp, operation, environment, key_name, details, user, pid, entry_hash
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
                    user: row.get(6)?,
                    pid: row.get(7)?,
                    entry_hash: row.get(8)?,
                })
            })
            .map_err(|e| EnvVaultError::AuditError(format!("query exec: {e}")))?;

        let mut entries = Vec::new();
        for row in rows {
            entries.push(row.map_err(|e| EnvVaultError::AuditError(format!("row parse: {e}")))?);
        }

        Ok(entries)
    }

    /// Walk the audit log in insertion order and verify the hash chain.
    ///
    /// Returns a `ChainVerification` describing how many entries were
    /// checked, whether the chain is intact, and if not, the id of the
    /// first broken entry. Legacy entries written before the v6
    /// migration (stored_hash is NULL) are counted separately and do
    /// not themselves mark the chain as broken — but any v6 entry
    /// after them is verified against the usual prev-hash rule.
    pub fn verify_chain(&self) -> Result<ChainVerification> {
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, timestamp, operation, environment, key_name, details, user, pid, entry_hash
                 FROM audit_log
                 ORDER BY id ASC",
            )
            .map_err(|e| EnvVaultError::AuditError(format!("verify prepare: {e}")))?;

        let rows = stmt
            .query_map([], |row| {
                let id: i64 = row.get(0)?;
                let timestamp: String = row.get(1)?;
                let operation: String = row.get(2)?;
                let environment: String = row.get(3)?;
                let key_name: Option<String> = row.get(4)?;
                let details: Option<String> = row.get(5)?;
                let user: Option<String> = row.get(6)?;
                let pid: Option<i64> = row.get(7)?;
                let stored_hash: Option<String> = row.get(8)?;
                Ok((
                    id,
                    timestamp,
                    operation,
                    environment,
                    key_name,
                    details,
                    user,
                    pid,
                    stored_hash,
                ))
            })
            .map_err(|e| EnvVaultError::AuditError(format!("verify exec: {e}")))?;

        let mut prev_hash = GENESIS_HASH.to_string();
        let mut entries_checked = 0usize;
        let mut legacy_entries = 0usize;
        let mut first_broken_id: Option<i64> = None;

        for row in rows {
            let (id, ts, op, env, key, det, usr, pid, stored) =
                row.map_err(|e| EnvVaultError::AuditError(format!("row parse: {e}")))?;
            entries_checked += 1;

            match stored {
                None => {
                    // Legacy row. It can't contribute to the chain
                    // link, but we preserve a stable anchor for later
                    // v6 rows: GENESIS remains the prev_hash until we
                    // see a v6 row whose hash is the "real" head.
                    legacy_entries += 1;
                }
                Some(stored_hash) => {
                    let canonical = Self::canonical_entry(
                        &ts,
                        &op,
                        &env,
                        key.as_deref(),
                        det.as_deref(),
                        usr.as_deref(),
                        pid,
                    );
                    let recomputed = Self::chain_hash(&prev_hash, &canonical);
                    if recomputed != stored_hash {
                        if first_broken_id.is_none() {
                            first_broken_id = Some(id);
                        }
                        // Stop at the first break — later entries
                        // will also mismatch, but the first one is
                        // what we want to surface.
                        break;
                    }
                    prev_hash = stored_hash;
                }
            }
        }

        Ok(ChainVerification {
            entries_checked,
            intact: first_broken_id.is_none(),
            first_broken_id,
            legacy_entries,
        })
    }

    /// Delete audit entries older than the given timestamp.
    /// Returns the number of entries deleted.
    pub fn purge(&self, before: DateTime<Utc>) -> Result<usize> {
        let count = self
            .conn
            .execute(
                "DELETE FROM audit_log WHERE timestamp < ?1",
                rusqlite::params![before.to_rfc3339()],
            )
            .map_err(|e| EnvVaultError::AuditError(format!("purge failed: {e}")))?;
        Ok(count)
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

/// Log a read operation only if `[audit] log_reads = true` in config.
///
/// Used by get/list/run to optionally record read access.
pub fn log_read_audit(cli: &Cli, op: &str, key: Option<&str>, details: Option<&str>) {
    let cwd = match std::env::current_dir() {
        Ok(cwd) => cwd,
        Err(_) => return,
    };

    let settings = crate::config::Settings::load(&cwd).unwrap_or_default();
    if !settings.audit.log_reads {
        return;
    }

    log_audit(cli, op, key, details);
}

/// Always log failed authentication attempts.
pub fn log_auth_failure(cli: &Cli, details: &str) {
    log_audit(cli, "auth-failed", None, Some(details));
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

    #[test]
    fn migrate_v5_is_idempotent() {
        let dir = TempDir::new().unwrap();
        // Open twice — migration runs both times, second should not error.
        let audit1 = AuditLog::open(dir.path());
        assert!(audit1.is_some());
        drop(audit1);

        let audit2 = AuditLog::open(dir.path());
        assert!(audit2.is_some());
    }

    #[test]
    fn log_records_user_and_pid() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), None);

        let entries = audit.query(1, None).unwrap();
        let entry = &entries[0];

        // PID should always be populated.
        assert!(entry.pid.is_some());
        assert!(entry.pid.unwrap() > 0);

        // User may or may not be set depending on the environment,
        // but the field should exist (Some or None).
    }

    #[test]
    fn timestamp_index_exists() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        // Query sqlite_master for our index.
        let mut stmt = audit
            .conn
            .prepare(
                "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_timestamp'",
            )
            .unwrap();
        let names: Vec<String> = stmt
            .query_map([], |row| row.get(0))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "idx_audit_timestamp");
    }

    #[test]
    fn purge_deletes_old_entries() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), None);

        // Purge everything before 1 hour from now — should delete our entry.
        let future = Utc::now() + chrono::Duration::hours(1);
        let deleted = audit.purge(future).unwrap();
        assert_eq!(deleted, 1);

        let entries = audit.query(10, None).unwrap();
        assert!(entries.is_empty());
    }

    #[test]
    fn purge_preserves_recent_entries() {
        let dir = TempDir::new().unwrap();
        let audit = AuditLog::open(dir.path()).unwrap();

        audit.log("set", "dev", Some("KEY"), None);

        // Purge everything before 1 hour ago — should NOT delete our recent entry.
        let past = Utc::now() - chrono::Duration::hours(1);
        let deleted = audit.purge(past).unwrap();
        assert_eq!(deleted, 0);

        let entries = audit.query(10, None).unwrap();
        assert_eq!(entries.len(), 1);
    }
}
