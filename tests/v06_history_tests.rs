//! v0.6.0 secret history / rollback integration tests (Phase 6.3).
//!
//! Covers:
//! - `set_secret` capturing the prior encrypted value on update.
//! - `get_previous_secret` decrypting the retained value.
//! - `rollback_secret` promoting previous to current and clearing the slot.
//! - One-level history semantics (second update overwrites).
//! - Metadata preservation across rollback.
//! - Fresh vault has no previous value.
//! - CLI `get --previous` and `rollback` end-to-end.
//! - CLI `rollback -f` skips the confirmation prompt.
//! - JSON field is omitted when no history is retained.

use std::fs;

use assert_cmd::Command;
use assert_fs::TempDir as AssertTempDir;
use envvault::vault::VaultStore;
use predicates::prelude::*;
use tempfile::TempDir;

fn vault_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(format!("{name}.vault"))
}

fn envvault() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("envvault").expect("binary should exist")
}

// ---------------------------------------------------------------------------
// Store-level behavior
// ---------------------------------------------------------------------------

#[test]
fn fresh_set_has_no_previous_value() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "fresh");
    let pw = b"history-password-1";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v1").unwrap();

    assert!(!store.has_previous("KEY"));
    assert!(store.get_previous_secret("KEY").is_err());
}

#[test]
fn updating_a_secret_captures_previous_value() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "capture");
    let pw = b"history-password-2";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "first").unwrap();
    store.set_secret("KEY", "second").unwrap();

    assert!(store.has_previous("KEY"));
    assert_eq!(store.get_secret("KEY").unwrap(), "second");
    assert_eq!(store.get_previous_secret("KEY").unwrap(), "first");
}

#[test]
fn history_survives_save_and_reopen() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "persist");
    let pw = b"history-password-3";

    {
        let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
        store.set_secret("KEY", "v1").unwrap();
        store.set_secret("KEY", "v2").unwrap();
        store.save().unwrap();
    }

    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert!(reopened.has_previous("KEY"));
    assert_eq!(reopened.get_previous_secret("KEY").unwrap(), "v1");
    assert_eq!(reopened.get_secret("KEY").unwrap(), "v2");
}

#[test]
fn history_is_one_level_only() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "onelevel");
    let pw = b"history-password-4";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v1").unwrap();
    store.set_secret("KEY", "v2").unwrap();
    store.set_secret("KEY", "v3").unwrap();

    // The slot now holds v2, not v1.
    assert_eq!(store.get_secret("KEY").unwrap(), "v3");
    assert_eq!(store.get_previous_secret("KEY").unwrap(), "v2");
}

#[test]
fn rollback_promotes_previous_to_current_and_clears_slot() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "rollback");
    let pw = b"history-password-5";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("TOKEN", "old-secret").unwrap();
    store.set_secret("TOKEN", "new-secret").unwrap();

    assert!(store.has_previous("TOKEN"));
    store.rollback_secret("TOKEN").unwrap();

    assert_eq!(store.get_secret("TOKEN").unwrap(), "old-secret");
    assert!(!store.has_previous("TOKEN"));
    assert!(store.get_previous_secret("TOKEN").is_err());
}

#[test]
fn rollback_with_no_previous_errors() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "rollback-empty");
    let pw = b"history-password-6";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v1").unwrap();

    let err = store.rollback_secret("KEY").unwrap_err();
    let msg = err.to_string();
    assert!(
        msg.contains("no previous value") || msg.contains("nothing to roll back"),
        "expected no-previous-value error, got: {msg}"
    );
}

#[test]
fn rollback_preserves_description_tags_and_expiration() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "rollback-meta");
    let pw = b"history-password-7";

    let future = chrono::Utc::now() + chrono::Duration::days(30);

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("API_KEY", "v1").unwrap();
    store
        .set_description("API_KEY", Some("Stripe prod".into()))
        .unwrap();
    store
        .set_tags("API_KEY", vec!["provider:stripe".into()])
        .unwrap();
    store.set_expires_at("API_KEY", Some(future)).unwrap();

    store.set_secret("API_KEY", "v2").unwrap();
    store.rollback_secret("API_KEY").unwrap();

    let meta = &store.list_secrets()[0];
    assert_eq!(meta.description.as_deref(), Some("Stripe prod"));
    assert_eq!(meta.tags, vec!["provider:stripe"]);
    assert_eq!(meta.expires_at, Some(future));
    assert_eq!(store.get_secret("API_KEY").unwrap(), "v1");
}

#[test]
fn vault_without_history_omits_json_fields() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "no-history");
    let pw = b"no-history-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v1").unwrap();
    store.save().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert!(
        !bytes
            .windows(b"\"previous_encrypted_value\"".len())
            .any(|w| w == b"\"previous_encrypted_value\""),
        "previous_encrypted_value should be omitted when absent"
    );
    assert!(
        !bytes
            .windows(b"\"previous_updated_at\"".len())
            .any(|w| w == b"\"previous_updated_at\""),
        "previous_updated_at should be omitted when absent"
    );
}

#[test]
fn previous_updated_at_reflects_original_update_time() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "prev-ts");
    let pw = b"history-password-8";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v1").unwrap();
    let t1 = store.list_secrets()[0].updated_at;

    // Force a clock tick, then update.
    std::thread::sleep(std::time::Duration::from_millis(10));
    store.set_secret("KEY", "v2").unwrap();

    let prev_ts = store.previous_updated_at("KEY").expect("should be set");
    let t2 = store.list_secrets()[0].updated_at;

    assert_eq!(prev_ts, t1);
    assert!(t2 > t1);
}

// ---------------------------------------------------------------------------
// CLI-level behavior
// ---------------------------------------------------------------------------

#[test]
fn get_help_exposes_previous_flag() {
    envvault()
        .args(["get", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--previous"));
}

#[test]
fn rollback_help_shows_description() {
    envvault()
        .args(["rollback", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("previous value"));
}

#[test]
fn cli_get_previous_returns_old_value_after_update() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-history-cli-1";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "TOKEN",
            "old-value",
            "--force",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "TOKEN",
            "new-value",
            "--force",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    // Current value.
    envvault()
        .args(["get", "TOKEN", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("new-value"));

    // Previous value.
    envvault()
        .args(["get", "TOKEN", "--previous", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("old-value"));
}

#[test]
fn cli_get_previous_on_fresh_secret_errors() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-history-cli-2";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "KEY",
            "only-value",
            "--force",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args(["get", "KEY", "--previous", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no previous value"));
}

#[test]
fn cli_rollback_restores_previous_value() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-history-cli-3";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "TOKEN",
            "old",
            "--force",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "TOKEN",
            "new",
            "--force",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    // -f skips the confirmation prompt.
    envvault()
        .args(["rollback", "TOKEN", "-f", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("Rolled back"));

    envvault()
        .args(["get", "TOKEN", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("old"));

    // After rollback, --previous no longer has anything.
    envvault()
        .args(["get", "TOKEN", "--previous", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no previous value"));
}

#[test]
fn cli_rollback_without_history_errors() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-history-cli-4";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args([
            "set",
            "KEY",
            "only",
            "--force",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args(["rollback", "KEY", "-f", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("no previous value"));
}

#[test]
fn cli_rollback_on_missing_secret_errors() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-history-cli-5";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args(["rollback", "NOPE", "-f", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .failure()
        .stderr(predicate::str::contains("not found"));
}
