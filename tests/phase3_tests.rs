//! Phase 3 integration tests.
//!
//! Covers: multi-command workflows, vault corruption scenarios,
//! large vault performance, and export→import round-trips.

use std::fs;

use envvault::vault::VaultStore;
use tempfile::TempDir;

/// Helper: create a temporary vault file path inside a fresh temp dir.
fn vault_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(format!("{name}.vault"))
}

// ---------------------------------------------------------------------------
// Multi-command workflow: init → set → get → list → export → import roundtrip
// ---------------------------------------------------------------------------

#[test]
fn full_workflow_init_set_get_list_delete_reopen() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "workflow");
    let pw = b"workflow-password";

    // 1. Create vault (simulates `envvault init`).
    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    assert_eq!(store.secret_count(), 0);

    // 2. Set multiple secrets (simulates `envvault set KEY VAL`).
    store
        .set_secret("DB_URL", "postgres://localhost/mydb")
        .unwrap();
    store.set_secret("API_KEY", "sk-test-12345").unwrap();
    store.set_secret("SECRET_TOKEN", "tok_abc").unwrap();
    store.save().unwrap();
    assert_eq!(store.secret_count(), 3);

    // 3. Get secrets (simulates `envvault get KEY`).
    assert_eq!(
        store.get_secret("DB_URL").unwrap(),
        "postgres://localhost/mydb"
    );
    assert_eq!(store.get_secret("API_KEY").unwrap(), "sk-test-12345");

    // 4. List secrets (simulates `envvault list`).
    let list = store.list_secrets();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].name, "API_KEY"); // sorted alphabetically
    assert_eq!(list[1].name, "DB_URL");
    assert_eq!(list[2].name, "SECRET_TOKEN");

    // 5. Delete a secret (simulates `envvault delete`).
    store.delete_secret("SECRET_TOKEN").unwrap();
    store.save().unwrap();
    assert_eq!(store.secret_count(), 2);

    // 6. Reopen from disk and verify persistence.
    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert_eq!(reopened.secret_count(), 2);
    assert_eq!(
        reopened.get_secret("DB_URL").unwrap(),
        "postgres://localhost/mydb"
    );
    assert_eq!(reopened.get_secret("API_KEY").unwrap(), "sk-test-12345");
    assert!(reopened.get_secret("SECRET_TOKEN").is_err());
}

// ---------------------------------------------------------------------------
// Export → import roundtrip via get_all_secrets and set_secret
// ---------------------------------------------------------------------------

#[test]
fn export_import_roundtrip_via_api() {
    let dir = TempDir::new().unwrap();
    let source_path = vault_path(&dir, "source");
    let target_path = vault_path(&dir, "target");
    let pw = b"export-import-pw";

    // Create source vault with secrets.
    let mut source = VaultStore::create(&source_path, pw, "dev", None, None).unwrap();
    source.set_secret("A", "value-a").unwrap();
    source.set_secret("B", "value-b").unwrap();
    source.set_secret("C", "value with spaces").unwrap();
    source.set_secret("D", "value=\"quoted\"").unwrap();
    source.save().unwrap();

    // "Export" — decrypt all secrets.
    let exported = source.get_all_secrets().unwrap();
    assert_eq!(exported.len(), 4);

    // "Import" — create target vault and re-encrypt all.
    let mut target = VaultStore::create(&target_path, pw, "staging", None, None).unwrap();
    for (key, value) in &exported {
        target.set_secret(key, value).unwrap();
    }
    target.save().unwrap();

    // Verify target vault independently.
    let reopened = VaultStore::open(&target_path, pw, None).unwrap();
    assert_eq!(reopened.environment(), "staging");
    assert_eq!(reopened.secret_count(), 4);
    assert_eq!(reopened.get_secret("A").unwrap(), "value-a");
    assert_eq!(reopened.get_secret("C").unwrap(), "value with spaces");
    assert_eq!(reopened.get_secret("D").unwrap(), "value=\"quoted\"");
}

// ---------------------------------------------------------------------------
// Vault corruption scenarios
// ---------------------------------------------------------------------------

#[test]
fn truncated_vault_file_rejected() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "truncated");
    let pw = b"truncate-pw";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "value").unwrap();
    store.save().unwrap();

    // Truncate the file to just the magic bytes.
    let data = fs::read(&path).unwrap();
    fs::write(&path, &data[..8]).unwrap();

    let result = VaultStore::open(&path, pw, None);
    assert!(result.is_err(), "truncated vault must be rejected");
}

#[test]
fn empty_file_rejected() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "empty");

    // Write an empty file.
    fs::write(&path, b"").unwrap();

    let result = VaultStore::open(&path, b"any-pw", None);
    assert!(result.is_err(), "empty file must be rejected");
}

#[test]
fn wrong_magic_bytes_rejected() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "bad-magic");
    let pw = b"magic-pw";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.save().unwrap();

    // Overwrite magic bytes.
    let mut data = fs::read(&path).unwrap();
    data[0] = b'X';
    data[1] = b'Y';
    fs::write(&path, &data).unwrap();

    let result = VaultStore::open(&path, pw, None);
    assert!(result.is_err(), "wrong magic bytes must be rejected");
}

#[test]
fn corrupted_hmac_detected() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "bad-hmac");
    let pw = b"hmac-pw";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "value").unwrap();
    store.save().unwrap();

    // Flip the last byte (part of the HMAC tag).
    let mut data = fs::read(&path).unwrap();
    let last = data.len() - 1;
    data[last] ^= 0xFF;
    fs::write(&path, &data).unwrap();

    let result = VaultStore::open(&path, pw, None);
    assert!(result.is_err(), "corrupted HMAC must be rejected");
}

#[test]
fn corrupted_header_json_detected() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "bad-header");
    let pw = b"header-pw";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.save().unwrap();

    // Flip a byte in the header JSON region (byte 10 = inside the header JSON).
    let mut data = fs::read(&path).unwrap();
    if data.len() > 15 {
        data[12] ^= 0xFF;
        fs::write(&path, &data).unwrap();

        let result = VaultStore::open(&path, pw, None);
        assert!(result.is_err(), "corrupted header must be rejected");
    }
}

// ---------------------------------------------------------------------------
// Large vault performance test
// ---------------------------------------------------------------------------

#[test]
fn large_vault_with_many_secrets() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "large");
    let pw = b"large-vault-pw";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();

    // Insert 100 secrets.
    let count = 100;
    for i in 0..count {
        let key = format!("SECRET_{i:04}");
        let value = format!("value-{i}-{}", "x".repeat(100));
        store.set_secret(&key, &value).unwrap();
    }
    store.save().unwrap();

    // Reopen and verify all secrets.
    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert_eq!(reopened.secret_count(), count);

    let all = reopened.get_all_secrets().unwrap();
    assert_eq!(all.len(), count);

    // Spot check a few.
    assert!(all["SECRET_0000"].starts_with("value-0-"));
    assert!(all["SECRET_0050"].starts_with("value-50-"));
    assert!(all["SECRET_0099"].starts_with("value-99-"));

    // Verify list is sorted.
    let list = reopened.list_secrets();
    assert_eq!(list.len(), count);
    assert_eq!(list[0].name, "SECRET_0000");
    assert_eq!(list[count - 1].name, "SECRET_0099");
}

// ---------------------------------------------------------------------------
// Diff computation tests (via public API)
// ---------------------------------------------------------------------------

#[test]
fn diff_between_two_vaults() {
    use envvault::cli::commands::diff::compute_diff;

    let dir = TempDir::new().unwrap();
    let dev_path = vault_path(&dir, "dev");
    let staging_path = vault_path(&dir, "staging");
    let pw = b"diff-pw";

    // Create dev vault.
    let mut dev = VaultStore::create(&dev_path, pw, "dev", None, None).unwrap();
    dev.set_secret("SHARED", "same-value").unwrap();
    dev.set_secret("DEV_ONLY", "dev-secret").unwrap();
    dev.set_secret("CHANGED", "old-value").unwrap();
    dev.save().unwrap();

    // Create staging vault.
    let mut staging = VaultStore::create(&staging_path, pw, "staging", None, None).unwrap();
    staging.set_secret("SHARED", "same-value").unwrap();
    staging
        .set_secret("STAGING_ONLY", "staging-secret")
        .unwrap();
    staging.set_secret("CHANGED", "new-value").unwrap();
    staging.save().unwrap();

    // Decrypt both.
    let dev_secrets = dev.get_all_secrets().unwrap();
    let staging_secrets = staging.get_all_secrets().unwrap();

    // Compute diff (dev → staging).
    let diff = compute_diff(&dev_secrets, &staging_secrets);

    assert_eq!(diff.added, vec!["STAGING_ONLY"]);
    assert_eq!(diff.removed, vec!["DEV_ONLY"]);
    assert_eq!(diff.changed, vec!["CHANGED"]);
    assert_eq!(diff.unchanged, vec!["SHARED"]);
}

// ---------------------------------------------------------------------------
// Edit content parsing tests
// ---------------------------------------------------------------------------

#[test]
fn edit_parse_complex_content() {
    use envvault::cli::commands::edit::parse_edited_content;

    let content = r#"# Comment line
DB_URL=postgres://localhost/db
API_KEY="sk-12345 with spaces"
EMPTY=
# Another comment

MULTI_EQ=a=b=c
QUOTED_HASH="value # not a comment"
"#;

    let parsed = parse_edited_content(content);
    assert_eq!(parsed["DB_URL"], "postgres://localhost/db");
    assert_eq!(parsed["API_KEY"], "sk-12345 with spaces");
    assert_eq!(parsed["EMPTY"], "");
    assert_eq!(parsed["MULTI_EQ"], "a=b=c");
    assert_eq!(parsed["QUOTED_HASH"], "value # not a comment");
    assert_eq!(parsed.len(), 5);
}

// ---------------------------------------------------------------------------
// Audit log integration test
// ---------------------------------------------------------------------------

#[test]
fn audit_log_records_and_queries() {
    use envvault::audit::AuditLog;

    let dir = TempDir::new().unwrap();
    let audit = AuditLog::open(dir.path()).unwrap();

    // Log several operations.
    audit.log("init", "dev", None, Some("vault created"));
    audit.log("set", "dev", Some("DB_URL"), Some("added"));
    audit.log("set", "dev", Some("API_KEY"), Some("added"));
    audit.log("delete", "dev", Some("OLD_KEY"), None);
    audit.log("rotate-key", "dev", None, Some("3 secrets re-encrypted"));

    // Query all.
    let all = audit.query(100, None).unwrap();
    assert_eq!(all.len(), 5);

    // Most recent first.
    assert_eq!(all[0].operation, "rotate-key");
    assert_eq!(all[4].operation, "init");

    // Query with limit.
    let limited = audit.query(2, None).unwrap();
    assert_eq!(limited.len(), 2);
    assert_eq!(limited[0].operation, "rotate-key");
    assert_eq!(limited[1].operation, "delete");
}

// ---------------------------------------------------------------------------
// Version check cache serialization test
// ---------------------------------------------------------------------------

#[test]
fn version_check_cache_serialization() {
    use chrono::Utc;

    #[derive(serde::Serialize, serde::Deserialize)]
    struct CachedVersion {
        latest: String,
        checked_at: chrono::DateTime<Utc>,
    }

    let cached = CachedVersion {
        latest: "0.3.0".to_string(),
        checked_at: Utc::now(),
    };

    let json = serde_json::to_string(&cached).unwrap();
    let parsed: CachedVersion = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.latest, "0.3.0");
}
