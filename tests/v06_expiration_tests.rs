//! v0.6.0 secret expiration integration tests (Phase 6.2).
//!
//! Covers:
//! - Setting / clearing `expires_at` on a `VaultStore`.
//! - Metadata preserved across value updates.
//! - `is_expired()` helpers on both `Secret` and `SecretMetadata`.
//! - CLI `set --expires`, `set --no-expires`, and expiry column.
//! - CLI `list --expired` and `list --expiring-in` filters.
//! - CLI `run` emitting a warning on stderr for expired secrets.

use std::fs;

use assert_cmd::Command;
use assert_fs::TempDir as AssertTempDir;
use chrono::Duration;
use envvault::vault::VaultStore;
use predicates::prelude::*;
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
fn expires_at_round_trips_through_save_reopen() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "expiry-roundtrip");
    let pw = b"expiry-password-1";

    let future = chrono::Utc::now() + Duration::days(30);

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("TOKEN", "secret").unwrap();
    store.set_expires_at("TOKEN", Some(future)).unwrap();
    store.save().unwrap();

    let reopened = VaultStore::open(&path, pw, None).unwrap();
    let s = &reopened.list_secrets()[0];
    // Chrono DateTime serializes to RFC3339 with sub-second precision,
    // so this is an exact equality.
    assert_eq!(s.expires_at, Some(future));
    assert!(!s.is_expired());
}

#[test]
fn expired_helper_flags_past_timestamps() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "expired-helper");
    let pw = b"expiry-password-2";

    let past = chrono::Utc::now() - Duration::days(1);

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("OLD", "v").unwrap();
    store.set_expires_at("OLD", Some(past)).unwrap();
    store.set_secret("FRESH", "v").unwrap();

    let list = store.list_secrets();
    let old = list.iter().find(|s| s.name == "OLD").unwrap();
    let fresh = list.iter().find(|s| s.name == "FRESH").unwrap();
    assert!(old.is_expired());
    assert!(!fresh.is_expired());
}

#[test]
fn no_expires_clears_expiration() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "clear-expiry");
    let pw = b"expiry-password-3";

    let future = chrono::Utc::now() + Duration::days(1);

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v").unwrap();
    store.set_expires_at("KEY", Some(future)).unwrap();
    store.save().unwrap();

    store.set_expires_at("KEY", None).unwrap();
    store.save().unwrap();

    let reopened = VaultStore::open(&path, pw, None).unwrap();
    assert!(reopened.list_secrets()[0].expires_at.is_none());
}

#[test]
fn set_secret_value_update_preserves_expires_at() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "preserve-expiry");
    let pw = b"expiry-password-4";

    let future = chrono::Utc::now() + Duration::days(7);

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("TOKEN", "v1").unwrap();
    store.set_expires_at("TOKEN", Some(future)).unwrap();

    // Rotating the value must not clobber the expiry.
    store.set_secret("TOKEN", "v2").unwrap();

    let s = &store.list_secrets()[0];
    assert_eq!(s.expires_at, Some(future));
    assert_eq!(store.get_secret("TOKEN").unwrap(), "v2");
}

#[test]
fn set_expires_at_on_missing_secret_errors() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "missing-expiry");
    let pw = b"expiry-password-5";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    let err = store
        .set_expires_at("NOPE", Some(chrono::Utc::now()))
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("not found"));
}

#[test]
fn vault_without_any_expiration_omits_json_field() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "no-expiry");
    let pw = b"no-expiry-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("K", "v").unwrap();
    store.save().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert!(
        !bytes
            .windows(b"\"expires_at\"".len())
            .any(|w| w == b"\"expires_at\""),
        "expires_at field should be omitted when not set"
    );
}

// ---------------------------------------------------------------------------
// CLI-level behavior
// ---------------------------------------------------------------------------

#[test]
fn set_help_exposes_expires_flags() {
    envvault()
        .args(["set", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--expires"))
        .stdout(predicate::str::contains("--no-expires"));
}

#[test]
fn list_help_exposes_expiry_filters() {
    envvault()
        .args(["list", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("--expired"))
        .stdout(predicate::str::contains("--expiring-in"));
}

#[test]
fn set_expires_and_no_expires_are_mutually_exclusive() {
    envvault()
        .args(["set", "KEY", "value", "--expires", "30d", "--no-expires"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn list_expired_and_expiring_in_are_mutually_exclusive() {
    envvault()
        .args(["list", "--expired", "--expiring-in", "7d"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("cannot be used with"));
}

#[test]
fn set_rejects_invalid_expiration_duration() {
    // Clap accepts any string; our parser rejects unknown units.
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    envvault()
        .args([
            "set",
            "KEY",
            "v",
            "--force",
            "--expires",
            "bogus",
            "--vault-dir",
            vault_dir.to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", "long-enough-password")
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid duration"));
}

#[test]
fn cli_set_with_expires_surfaces_in_list() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    let vault_dir_str = vault_dir.to_str().unwrap();
    let pw = "phase6-expiry-cli";

    envvault()
        .args(["init", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    // Set a secret that expires in 30 days.
    envvault()
        .args([
            "set",
            "API_KEY",
            "sk-abcdef",
            "--force",
            "--expires",
            "30d",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("Expires at"));

    // `list` shows an Expires column and the `expiring-in` filter
    // finds it when the window is wide enough.
    envvault()
        .args(["list", "--expiring-in", "90d", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("API_KEY"))
        .stdout(predicate::str::contains("Expires"));

    // `list --expired` finds nothing (we just set a 30d expiry).
    envvault()
        .args(["list", "--expired", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("0 secret(s)"));

    // `--no-expires` clears the expiration.
    envvault()
        .args([
            "set",
            "API_KEY",
            "sk-new-value",
            "--force",
            "--no-expires",
            "--vault-dir",
            vault_dir_str,
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success();

    envvault()
        .args(["list", "--expiring-in", "90d", "--vault-dir", vault_dir_str])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", pw)
        .assert()
        .success()
        .stdout(predicate::str::contains("0 secret(s)"));
}

#[test]
fn cli_run_warns_about_expired_secret() {
    // Create a vault with an already-expired secret (via VaultStore so
    // we can plant a past timestamp), then invoke `envvault run` and
    // confirm a warning is printed to stderr.
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    fs::create_dir_all(&vault_dir).unwrap();
    let vault_path = vault_dir.join("dev.vault");
    let pw = b"expiry-run-warning";

    let past = chrono::Utc::now() - Duration::days(3);

    let mut store = VaultStore::create(&vault_path, pw, "dev", None, None).unwrap();
    store.set_secret("STALE_TOKEN", "oldvalue").unwrap();
    store.set_expires_at("STALE_TOKEN", Some(past)).unwrap();
    store.set_secret("FRESH", "newvalue").unwrap();
    store.save().unwrap();

    // Use `true` (POSIX no-op) as the child command. It exits 0 and
    // emits no output, so the only stderr should be our warning.
    envvault()
        .args([
            "run",
            "--vault-dir",
            vault_dir.to_str().unwrap(),
            "--",
            "true",
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", std::str::from_utf8(pw).unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("STALE_TOKEN"))
        .stderr(predicate::str::contains("expired"))
        .stderr(predicate::str::contains("3 days ago"));
}

#[test]
fn cli_run_does_not_warn_when_expired_secret_is_excluded() {
    let tmp = AssertTempDir::new().unwrap();
    let vault_dir = tmp.path().join(".envvault");
    fs::create_dir_all(&vault_dir).unwrap();
    let vault_path = vault_dir.join("dev.vault");
    let pw = b"expiry-run-exclude";

    let past = chrono::Utc::now() - Duration::days(1);

    let mut store = VaultStore::create(&vault_path, pw, "dev", None, None).unwrap();
    store.set_secret("STALE", "old").unwrap();
    store.set_expires_at("STALE", Some(past)).unwrap();
    store.set_secret("FRESH", "new").unwrap();
    store.save().unwrap();

    // Filter out the stale secret; the warning must not fire.
    envvault()
        .args([
            "run",
            "--only",
            "FRESH",
            "--vault-dir",
            vault_dir.to_str().unwrap(),
            "--",
            "true",
        ])
        .current_dir(tmp.path())
        .env("ENVVAULT_PASSWORD", std::str::from_utf8(pw).unwrap())
        .assert()
        .success()
        .stderr(predicate::str::contains("STALE").not());
}
