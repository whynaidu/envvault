//! Integration tests for the EnvVault vault module.

use std::fs;

use envvault::vault::VaultStore;
use tempfile::TempDir;

/// Helper: create a temporary vault file path inside a fresh temp dir.
fn vault_path() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test.vault");
    (dir, path)
}

// ---------------------------------------------------------------------------
// Create and re-open round-trip
// ---------------------------------------------------------------------------

#[test]
fn create_vault_and_reopen() {
    let (_dir, path) = vault_path();
    let password = b"test-password";

    // Create a new vault.
    let mut store = VaultStore::create(&path, password, "dev", None, None).expect("create vault");

    // Add a secret and save.
    store
        .set_secret("DB_URL", "postgres://localhost/db")
        .unwrap();
    store.save().unwrap();

    // Re-open with the same password — should succeed.
    let store2 = VaultStore::open(&path, password, None).expect("open vault");
    assert_eq!(store2.environment(), "dev");
    assert_eq!(store2.secret_count(), 1);

    let value = store2.get_secret("DB_URL").unwrap();
    assert_eq!(value, "postgres://localhost/db");
}

// ---------------------------------------------------------------------------
// Set and get secret round-trip
// ---------------------------------------------------------------------------

#[test]
fn set_and_get_secret_roundtrip() {
    let (_dir, path) = vault_path();
    let password = b"roundtrip-pw";

    let mut store = VaultStore::create(&path, password, "staging", None, None).unwrap();
    store.set_secret("API_KEY", "sk-12345abcde").unwrap();
    store.set_secret("SECRET_TOKEN", "tok_xyz").unwrap();
    store.save().unwrap();

    // Re-open and verify both secrets.
    let store2 = VaultStore::open(&path, password, None).unwrap();
    assert_eq!(store2.get_secret("API_KEY").unwrap(), "sk-12345abcde");
    assert_eq!(store2.get_secret("SECRET_TOKEN").unwrap(), "tok_xyz");
}

// ---------------------------------------------------------------------------
// Update existing secret preserves created_at
// ---------------------------------------------------------------------------

#[test]
fn update_secret_preserves_created_at() {
    let (_dir, path) = vault_path();
    let password = b"update-pw";

    let mut store = VaultStore::create(&path, password, "dev", None, None).unwrap();
    store.set_secret("KEY", "value-1").unwrap();

    // Remember the original created_at.
    let meta_before = store.list_secrets();
    let created_before = meta_before[0].created_at;

    // Update the same secret.
    store.set_secret("KEY", "value-2").unwrap();

    let meta_after = store.list_secrets();
    let created_after = meta_after[0].created_at;

    // created_at must stay the same after an update.
    assert_eq!(created_before, created_after);

    // The value should be the new one.
    assert_eq!(store.get_secret("KEY").unwrap(), "value-2");
}

// ---------------------------------------------------------------------------
// List secrets returns sorted metadata
// ---------------------------------------------------------------------------

#[test]
fn list_secrets_returns_sorted_metadata() {
    let (_dir, path) = vault_path();
    let password = b"list-pw";

    let mut store = VaultStore::create(&path, password, "dev", None, None).unwrap();
    store.set_secret("ZEBRA", "z").unwrap();
    store.set_secret("ALPHA", "a").unwrap();
    store.set_secret("MIDDLE", "m").unwrap();

    let list = store.list_secrets();
    assert_eq!(list.len(), 3);
    assert_eq!(list[0].name, "ALPHA");
    assert_eq!(list[1].name, "MIDDLE");
    assert_eq!(list[2].name, "ZEBRA");
}

// ---------------------------------------------------------------------------
// Delete secret
// ---------------------------------------------------------------------------

#[test]
fn delete_secret_removes_it() {
    let (_dir, path) = vault_path();
    let password = b"delete-pw";

    let mut store = VaultStore::create(&path, password, "dev", None, None).unwrap();
    store.set_secret("TO_DELETE", "bye").unwrap();
    store.set_secret("TO_KEEP", "stay").unwrap();

    store.delete_secret("TO_DELETE").unwrap();
    assert_eq!(store.secret_count(), 1);

    // Getting the deleted secret should fail.
    let result = store.get_secret("TO_DELETE");
    assert!(result.is_err());

    // Deleting again should also fail.
    let result = store.delete_secret("TO_DELETE");
    assert!(result.is_err());

    // The other secret is still there.
    assert_eq!(store.get_secret("TO_KEEP").unwrap(), "stay");
}

// ---------------------------------------------------------------------------
// Get all secrets (for `run` command)
// ---------------------------------------------------------------------------

#[test]
fn get_all_secrets_decrypts_everything() {
    let (_dir, path) = vault_path();
    let password = b"all-pw";

    let mut store = VaultStore::create(&path, password, "prod", None, None).unwrap();
    store.set_secret("A", "1").unwrap();
    store.set_secret("B", "2").unwrap();
    store.set_secret("C", "3").unwrap();

    let all = store.get_all_secrets().unwrap();
    assert_eq!(all.len(), 3);
    assert_eq!(all["A"], "1");
    assert_eq!(all["B"], "2");
    assert_eq!(all["C"], "3");
}

// ---------------------------------------------------------------------------
// Wrong password fails to open (HMAC mismatch)
// ---------------------------------------------------------------------------

#[test]
fn wrong_password_fails_to_open() {
    let (_dir, path) = vault_path();

    // Create with one password.
    let mut store = VaultStore::create(&path, b"correct-password", "dev", None, None).unwrap();
    store.set_secret("SECRET", "value").unwrap();
    store.save().unwrap();

    // Try to open with a different password — HMAC should not match.
    let result = VaultStore::open(&path, b"wrong-password", None);
    assert!(result.is_err(), "wrong password must fail to open vault");
}

// ---------------------------------------------------------------------------
// Tampered file is detected
// ---------------------------------------------------------------------------

#[test]
fn tampered_file_detected() {
    let (_dir, path) = vault_path();

    let mut store = VaultStore::create(&path, b"tamper-pw", "dev", None, None).unwrap();
    store.set_secret("KEY", "value").unwrap();
    store.save().unwrap();

    // Read the raw file and flip a byte in the middle (secrets region).
    let mut data = fs::read(&path).expect("read vault file");
    let mid = data.len() / 2;
    data[mid] ^= 0xFF;
    fs::write(&path, &data).expect("write tampered file");

    // Opening should fail because the HMAC no longer matches.
    let result = VaultStore::open(&path, b"tamper-pw", None);
    assert!(result.is_err(), "tampered vault must be rejected");
}

// ---------------------------------------------------------------------------
// Vault already exists error
// ---------------------------------------------------------------------------

#[test]
fn create_vault_twice_fails() {
    let (_dir, path) = vault_path();
    let password = b"dup-pw";

    VaultStore::create(&path, password, "dev", None, None).unwrap();

    // Creating again at the same path should fail.
    let result = VaultStore::create(&path, password, "dev", None, None);
    assert!(result.is_err(), "creating vault twice must fail");
}

// ---------------------------------------------------------------------------
// Non-existent vault file
// ---------------------------------------------------------------------------

#[test]
fn open_nonexistent_vault_fails() {
    let (_dir, path) = vault_path();
    let result = VaultStore::open(&path, b"any-password", None);
    assert!(result.is_err(), "opening nonexistent vault must fail");
}

// ---------------------------------------------------------------------------
// Secret not found
// ---------------------------------------------------------------------------

#[test]
fn get_nonexistent_secret_fails() {
    let (_dir, path) = vault_path();
    let store = VaultStore::create(&path, b"pw", "dev", None, None).unwrap();

    let result = store.get_secret("DOES_NOT_EXIST");
    assert!(result.is_err());
}
