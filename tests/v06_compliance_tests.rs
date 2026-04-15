//! v0.6.0 compliance report + audit hash chain tests (Phase 6.4).
//!
//! Covers:
//! - `AuditLog::verify_chain` intact / broken cases (insert, tamper).
//! - Legacy (pre-v6) entries counted separately and not flagged as
//!   chain breaks on their own.
//! - `envvault audit verify` CLI success / failure paths.
//! - `envvault compliance-report` JSON schema smoke test via the
//!   binary end-to-end.
//! - The in-memory `build_report` aggregation for secrets / expiries /
//!   history counts.

use std::fs;

#[cfg(feature = "audit-log")]
use assert_cmd::Command;
#[cfg(feature = "audit-log")]
use assert_fs::TempDir as AssertTempDir;
#[cfg(feature = "audit-log")]
use predicates::prelude::*;
use tempfile::TempDir;

#[cfg(feature = "audit-log")]
use envvault::audit::AuditLog;
use envvault::vault::VaultStore;

fn vault_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(format!("{name}.vault"))
}

#[cfg(feature = "audit-log")]
fn envvault() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("envvault").expect("binary should exist")
}

// ---------------------------------------------------------------------------
// Hash chain
// ---------------------------------------------------------------------------

#[cfg(feature = "audit-log")]
#[test]
fn empty_log_verifies_as_intact() {
    let dir = TempDir::new().unwrap();
    let audit = AuditLog::open(dir.path()).unwrap();

    let result = audit.verify_chain().unwrap();
    assert!(result.intact);
    assert_eq!(result.entries_checked, 0);
    assert_eq!(result.legacy_entries, 0);
    assert!(result.first_broken_id.is_none());
}

#[cfg(feature = "audit-log")]
#[test]
fn fresh_log_writes_entry_hashes_and_verifies() {
    let dir = TempDir::new().unwrap();
    let audit = AuditLog::open(dir.path()).unwrap();

    audit.log("set", "dev", Some("A"), Some("added"));
    audit.log("set", "dev", Some("B"), Some("added"));
    audit.log("delete", "dev", Some("A"), None);

    let result = audit.verify_chain().unwrap();
    assert!(result.intact, "expected intact chain, got {result:?}");
    assert_eq!(result.entries_checked, 3);
    assert_eq!(result.legacy_entries, 0);

    // Every v6 entry should have a hash populated.
    let entries = audit.query(10, None).unwrap();
    assert_eq!(entries.len(), 3);
    for e in &entries {
        assert!(e.entry_hash.is_some(), "entry {} missing chain hash", e.id);
        // Hex-encoded SHA-256 is 64 chars.
        assert_eq!(e.entry_hash.as_ref().unwrap().len(), 64);
    }
}

#[cfg(feature = "audit-log")]
#[test]
fn tampering_with_details_breaks_chain() {
    // Write entries through the normal API, then reach into SQLite
    // directly and modify one entry's `details`. The chain must break
    // at the tampered row because its stored entry_hash no longer
    // matches its recomputed value.
    let dir = TempDir::new().unwrap();
    {
        let audit = AuditLog::open(dir.path()).unwrap();
        audit.log("set", "dev", Some("A"), Some("original"));
        audit.log("set", "dev", Some("B"), Some("also-original"));
        audit.log("set", "dev", Some("C"), Some("third"));
    }

    let db_path = dir.path().join("audit.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();

    // Flip details on the second entry.
    conn.execute("UPDATE audit_log SET details = 'tampered' WHERE id = 2", [])
        .unwrap();
    drop(conn);

    let audit = AuditLog::open(dir.path()).unwrap();
    let result = audit.verify_chain().unwrap();

    assert!(!result.intact, "tampering should break the chain");
    assert_eq!(result.first_broken_id, Some(2));
}

#[cfg(feature = "audit-log")]
#[test]
fn deleting_a_middle_entry_breaks_chain() {
    // Removing a row from the middle causes the next row's prev_hash
    // to change, so the next row's stored hash no longer matches its
    // recomputed value.
    let dir = TempDir::new().unwrap();
    {
        let audit = AuditLog::open(dir.path()).unwrap();
        for i in 0..5 {
            audit.log("set", "dev", Some(&format!("K{i}")), None);
        }
    }

    let db_path = dir.path().join("audit.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute("DELETE FROM audit_log WHERE id = 3", [])
        .unwrap();
    drop(conn);

    let audit = AuditLog::open(dir.path()).unwrap();
    let result = audit.verify_chain().unwrap();

    assert!(!result.intact);
    // First broken id is the row that used to have id=3's hash as its prev.
    assert_eq!(result.first_broken_id, Some(4));
}

#[cfg(feature = "audit-log")]
#[test]
fn legacy_entries_without_hash_do_not_break_chain() {
    // Create a schema that has the entry_hash column but insert rows
    // with NULL hashes to simulate entries written before the v6
    // migration. verify_chain should count them in legacy_entries and
    // still report the chain intact.
    let dir = TempDir::new().unwrap();
    let db_path = dir.path().join("audit.db");

    {
        let conn = rusqlite::Connection::open(&db_path).unwrap();
        conn.execute_batch(
            "CREATE TABLE audit_log (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT NOT NULL,
                operation   TEXT NOT NULL,
                environment TEXT NOT NULL,
                key_name    TEXT,
                details     TEXT,
                user        TEXT,
                pid         INTEGER,
                entry_hash  TEXT
            );",
        )
        .unwrap();
        // Insert two rows with NULL hashes.
        conn.execute(
            "INSERT INTO audit_log (timestamp, operation, environment, key_name, details, user, pid)
             VALUES ('2025-01-01T00:00:00Z', 'set', 'dev', 'LEGACY_A', 'first', NULL, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO audit_log (timestamp, operation, environment, key_name, details, user, pid)
             VALUES ('2025-01-02T00:00:00Z', 'set', 'dev', 'LEGACY_B', 'second', NULL, NULL)",
            [],
        )
        .unwrap();
    }

    let audit = AuditLog::open(dir.path()).unwrap();
    // Append new v6 entries after the legacy ones.
    audit.log("set", "dev", Some("NEW"), None);

    let result = audit.verify_chain().unwrap();
    assert!(
        result.intact,
        "legacy entries should not break the chain: {result:?}"
    );
    assert_eq!(result.entries_checked, 3);
    assert_eq!(result.legacy_entries, 2);
}

// ---------------------------------------------------------------------------
// CLI `audit verify`
// ---------------------------------------------------------------------------

#[cfg(feature = "audit-log")]
#[test]
fn audit_verify_help_is_exposed() {
    envvault()
        .args(["audit", "verify", "--help"])
        .assert()
        .success();
}

#[cfg(feature = "audit-log")]
#[test]
fn audit_verify_reports_intact() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-4-verify-intact";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args(["set", "KEY", "v", "--force", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args(["audit", "verify", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("intact"));
}

#[cfg(feature = "audit-log")]
#[test]
fn audit_verify_exits_nonzero_on_tamper() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-4-verify-broken";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();
    envvault()
        .args(["set", "KEY", "v", "--force", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    // Tamper with the init entry.
    let db_path = vault_dir.join("audit.db");
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute("UPDATE audit_log SET details = 'evil' WHERE id = 1", [])
        .unwrap();
    drop(conn);

    envvault()
        .args(["audit", "verify", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("broken"));
}

// ---------------------------------------------------------------------------
// Compliance report
// ---------------------------------------------------------------------------

#[test]
fn build_report_aggregates_secret_metadata() {
    use clap::Parser;
    use envvault::cli::commands::compliance_report::build_report;
    use envvault::cli::Cli;

    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "compliance");
    let pw = b"compliance-password-1";

    let future_30 = chrono::Utc::now() + chrono::Duration::days(30);
    let future_10 = chrono::Utc::now() + chrono::Duration::days(10);
    let past = chrono::Utc::now() - chrono::Duration::days(2);

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    // Plain secret, no metadata.
    store.set_secret("PLAIN", "v").unwrap();
    // Described and tagged.
    store.set_secret("STRIPE", "sk").unwrap();
    store
        .set_description("STRIPE", Some("Stripe prod".into()))
        .unwrap();
    store
        .set_tags("STRIPE", vec!["provider:stripe".into()])
        .unwrap();
    store.set_expires_at("STRIPE", Some(future_30)).unwrap();
    // Expires within 30d.
    store.set_secret("ROTATING", "r").unwrap();
    store.set_expires_at("ROTATING", Some(future_10)).unwrap();
    // Already expired.
    store.set_secret("STALE", "s").unwrap();
    store.set_expires_at("STALE", Some(past)).unwrap();
    // With history.
    store.set_secret("HISTORIC", "v1").unwrap();
    store.set_secret("HISTORIC", "v2").unwrap();

    // Build a bare Cli instance (the vault_dir doesn't matter for
    // secret aggregation; collect_audit may fail silently if the
    // audit DB isn't present, which is fine for this test).
    let cli = Cli::try_parse_from([
        "envvault",
        "--vault-dir",
        dir.path().to_str().unwrap(),
        "list",
    ])
    .unwrap();

    let report = build_report(&cli, &store).unwrap();

    assert_eq!(report.secrets.total, 5);
    assert_eq!(report.secrets.with_description, 1);
    assert_eq!(report.secrets.with_tags, 1);
    assert_eq!(report.secrets.with_expiration, 3);
    assert_eq!(report.secrets.expired, 1);
    assert_eq!(report.secrets.expiring_within_30d, 2);
    assert_eq!(report.secrets.with_history, 1);

    assert_eq!(report.expired_secrets.len(), 1);
    assert_eq!(report.expired_secrets[0].name, "STALE");
    assert!(report.expired_secrets[0].days_remaining < 0);

    assert_eq!(report.expiring_soon.len(), 2);
    // Sorted by expires_at ascending — ROTATING (10d) comes before STRIPE (30d).
    assert_eq!(report.expiring_soon[0].name, "ROTATING");
    assert_eq!(report.expiring_soon[1].name, "STRIPE");

    // Vault metadata surfaces.
    assert_eq!(report.vault.environment, "dev");
    assert_eq!(report.vault.encryption, "AES-256-GCM");
    assert_eq!(report.vault.kdf.algorithm, "Argon2id");
    assert_eq!(report.vault.format_version, 2);
}

#[cfg(feature = "audit-log")]
#[test]
fn cli_compliance_report_outputs_well_formed_json() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-4-compliance-cli";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "API_KEY",
            "v",
            "--force",
            "--description",
            "Stripe",
            "--tag",
            "provider:stripe",
            "--expires",
            "30d",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    let output_path = tmp.path().join("report.json");

    envvault()
        .args([
            "compliance-report",
            "--output",
            output_path.to_str().unwrap(),
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("Compliance report written"));

    let json = fs::read_to_string(&output_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("report must be valid JSON");

    // Spot-check the schema.
    assert_eq!(parsed["vault"]["environment"], "dev");
    assert_eq!(parsed["vault"]["encryption"], "AES-256-GCM");
    assert_eq!(parsed["secrets"]["total"], 1);
    assert_eq!(parsed["secrets"]["with_description"], 1);
    assert_eq!(parsed["secrets"]["with_tags"], 1);
    assert_eq!(parsed["secrets"]["with_expiration"], 1);
    assert_eq!(parsed["audit"]["available"], true);
    assert_eq!(parsed["audit"]["chain_status"], "intact");
    assert!(parsed["generator"]
        .as_str()
        .unwrap()
        .starts_with("envvault v"));
}

#[cfg(feature = "audit-log")]
#[test]
fn cli_compliance_report_rejects_unknown_format() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-4-compliance-format";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "compliance-report",
            "--format",
            "yaml",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("unsupported"));
}
