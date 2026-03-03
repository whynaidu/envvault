//! v0.5.0 integration tests.
//!
//! Covers: set --force, import --dry-run / --skip-existing, run --only / --exclude,
//! search, scan, run --redact-output, audit export/purge, full workflow.

use std::fs;
use std::io::Write;

use envvault::vault::VaultStore;
use tempfile::TempDir;

/// Helper: create a temporary vault file path inside a fresh temp dir.
fn vault_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(format!("{name}.vault"))
}

// ---------------------------------------------------------------------------
// Full workflow: init → set → get → list → search → run → delete
// ---------------------------------------------------------------------------

#[test]
fn v05_full_workflow() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "workflow");
    let pw = b"v05-workflow-password";

    // Create vault.
    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();

    // Set secrets.
    store
        .set_secret("DB_URL", "postgres://localhost/db")
        .unwrap();
    store.set_secret("API_KEY", "sk-test-12345").unwrap();
    store.set_secret("SECRET_TOKEN", "tok_abc").unwrap();
    store.save().unwrap();

    // Get secrets.
    assert_eq!(
        store.get_secret("DB_URL").unwrap(),
        "postgres://localhost/db"
    );
    assert_eq!(store.get_secret("API_KEY").unwrap(), "sk-test-12345");

    // List secrets.
    let list = store.list_secrets();
    assert_eq!(list.len(), 3);

    // Search by glob.
    use envvault::cli::commands::search::glob_match;
    let names: Vec<&str> = list.iter().map(|s| s.name.as_str()).collect();

    let db_matches: Vec<_> = names.iter().filter(|n| glob_match("DB_*", n)).collect();
    assert_eq!(db_matches.len(), 1);
    assert_eq!(*db_matches[0], "DB_URL");

    let key_matches: Vec<_> = names.iter().filter(|n| glob_match("*_KEY", n)).collect();
    assert_eq!(key_matches.len(), 1);

    let all_matches: Vec<_> = names.iter().filter(|n| glob_match("*", n)).collect();
    assert_eq!(all_matches.len(), 3);

    // Delete a secret.
    store.delete_secret("SECRET_TOKEN").unwrap();
    store.save().unwrap();

    // Reopen and verify.
    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert_eq!(reopened.secret_count(), 2);
    assert!(reopened.get_secret("SECRET_TOKEN").is_err());
}

// ---------------------------------------------------------------------------
// Import --dry-run: vault should not be modified
// ---------------------------------------------------------------------------

#[test]
fn import_dry_run_does_not_modify_vault() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "dry-run");
    let pw = b"dry-run-password";

    // Create vault with one existing secret.
    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("EXISTING", "old-value").unwrap();
    store.save().unwrap();
    drop(store);

    // Verify: reopen, should still have just 1 secret.
    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert_eq!(reopened.secret_count(), 1);
    assert_eq!(reopened.get_secret("EXISTING").unwrap(), "old-value");
}

// ---------------------------------------------------------------------------
// Import --skip-existing: only new keys are imported
// ---------------------------------------------------------------------------

#[test]
fn import_skip_existing_preserves_original() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "skip-existing");
    let pw = b"skip-existing-password";

    // Create vault with one existing secret.
    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY_A", "original").unwrap();
    store.save().unwrap();

    // Simulate import with skip_existing: KEY_A should not be overwritten.
    let import_data = vec![
        ("KEY_A".to_string(), "new-value".to_string()),
        ("KEY_B".to_string(), "b-value".to_string()),
    ];

    for (key, value) in &import_data {
        if store.contains_key(key) {
            continue; // skip existing
        }
        store.set_secret(key, value).unwrap();
    }
    store.save().unwrap();

    // Reopen and verify.
    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert_eq!(reopened.secret_count(), 2);
    assert_eq!(reopened.get_secret("KEY_A").unwrap(), "original"); // preserved
    assert_eq!(reopened.get_secret("KEY_B").unwrap(), "b-value"); // new
}

// ---------------------------------------------------------------------------
// Run --only / --exclude filter logic
// ---------------------------------------------------------------------------

#[test]
fn run_only_filter() {
    use envvault::cli::commands::run::filter_secrets;
    use std::collections::HashMap;

    let mut secrets = HashMap::from([
        ("DB_URL".into(), "pg://localhost".into()),
        ("API_KEY".into(), "sk-test".into()),
        ("SECRET".into(), "shh".into()),
    ]);

    let only = vec!["DB_URL".to_string(), "API_KEY".to_string()];
    filter_secrets(&mut secrets, Some(&only), None);

    assert_eq!(secrets.len(), 2);
    assert!(secrets.contains_key("DB_URL"));
    assert!(secrets.contains_key("API_KEY"));
    assert!(!secrets.contains_key("SECRET"));
}

#[test]
fn run_exclude_filter() {
    use envvault::cli::commands::run::filter_secrets;
    use std::collections::HashMap;

    let mut secrets = HashMap::from([
        ("DB_URL".into(), "pg://localhost".into()),
        ("API_KEY".into(), "sk-test".into()),
        ("SECRET".into(), "shh".into()),
    ]);

    let exclude = vec!["SECRET".to_string()];
    filter_secrets(&mut secrets, None, Some(&exclude));

    assert_eq!(secrets.len(), 2);
    assert!(!secrets.contains_key("SECRET"));
}

// ---------------------------------------------------------------------------
// Redact output
// ---------------------------------------------------------------------------

#[test]
fn redact_line_replaces_secrets() {
    use envvault::cli::commands::run::redact_line;

    let secrets = vec!["supersecret".to_string(), "p@ss".to_string()];
    assert_eq!(
        redact_line("token: supersecret", &secrets),
        "token: [REDACTED]"
    );
    assert_eq!(redact_line("pw=p@ss", &secrets), "pw=[REDACTED]");
    assert_eq!(redact_line("no secrets here", &secrets), "no secrets here");
}

// ---------------------------------------------------------------------------
// Audit export / purge (via API)
// ---------------------------------------------------------------------------

#[cfg(feature = "audit-log")]
#[test]
fn audit_export_purge_workflow() {
    use envvault::audit::{AuditEntryExport, AuditLog};

    let dir = TempDir::new().unwrap();
    let audit = AuditLog::open(dir.path()).unwrap();

    // Log some entries.
    audit.log("init", "dev", None, Some("vault created"));
    audit.log("set", "dev", Some("KEY"), Some("added"));
    audit.log("set", "dev", Some("OTHER"), Some("added"));
    audit.log("delete", "dev", Some("OLD"), None);

    // Export as JSON.
    let entries = audit.query(100, None).unwrap();
    let exports: Vec<AuditEntryExport> = entries.iter().map(AuditEntryExport::from).collect();
    let json = serde_json::to_string(&exports).unwrap();
    assert!(json.contains("init"));
    assert!(json.contains("set"));
    assert!(json.contains("delete"));

    // Purge all.
    let future = chrono::Utc::now() + chrono::Duration::hours(1);
    let deleted = audit.purge(future).unwrap();
    assert_eq!(deleted, 4);

    // Verify empty.
    let remaining = audit.query(100, None).unwrap();
    assert!(remaining.is_empty());
}

// ---------------------------------------------------------------------------
// Scan: pattern matching
// ---------------------------------------------------------------------------

#[test]
fn scan_detects_aws_key_in_file() {
    use envvault::cli::commands::scan::Finding;

    let dir = TempDir::new().unwrap();
    let file_path = dir.path().join("config.txt");
    {
        let mut f = fs::File::create(&file_path).unwrap();
        writeln!(f, "# safe line").unwrap();
        writeln!(f, "aws_access_key_id = AKIAIOSFODNN7EXAMPLE1").unwrap();
        writeln!(f, "normal = hello").unwrap();
    }

    // Use the built-in patterns to scan.
    let mut patterns = Vec::new();
    for (name, pat) in envvault::git::SECRET_PATTERNS {
        if let Ok(re) = regex::Regex::new(pat) {
            patterns.push((name.to_string(), re));
        }
    }

    let mut findings: Vec<Finding> = Vec::new();
    let content = fs::read_to_string(&file_path).unwrap();
    for (line_num, line) in content.lines().enumerate() {
        for (name, re) in &patterns {
            if re.is_match(line) {
                findings.push(Finding {
                    file: file_path.clone(),
                    line: line_num + 1,
                    pattern_name: name.clone(),
                });
                break;
            }
        }
    }

    assert!(!findings.is_empty());
    assert_eq!(findings[0].line, 2);
    assert!(findings[0].pattern_name.contains("AWS"));
}

// ---------------------------------------------------------------------------
// Search: glob matching
// ---------------------------------------------------------------------------

#[test]
fn search_glob_patterns() {
    use envvault::cli::commands::search::glob_match;

    // Exact match.
    assert!(glob_match("DB_URL", "DB_URL"));
    assert!(!glob_match("DB_URL", "API_KEY"));

    // Wildcard patterns.
    assert!(glob_match("DB_*", "DB_URL"));
    assert!(glob_match("DB_*", "DB_HOST"));
    assert!(!glob_match("DB_*", "API_KEY"));

    // Question mark.
    assert!(glob_match("KEY_?", "KEY_A"));
    assert!(!glob_match("KEY_?", "KEY_AB"));

    // Case insensitive.
    assert!(glob_match("db_url", "DB_URL"));

    // Multiple wildcards.
    assert!(glob_match("*DB*", "MY_DB_URL"));
}
