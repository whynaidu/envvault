//! Integration tests for Phase 2 features:
//! rotate-key, export, import, keyfile, stored Argon2 params.

use std::collections::HashMap;
use std::fs;

use envvault::crypto::kdf::Argon2Params;
use envvault::crypto::keyfile;
use envvault::vault::VaultStore;
use tempfile::TempDir;

/// Helper: create a temporary vault file path inside a fresh temp dir.
fn vault_path() -> (TempDir, std::path::PathBuf) {
    let dir = TempDir::new().expect("create temp dir");
    let path = dir.path().join("test.vault");
    (dir, path)
}

// ---------------------------------------------------------------------------
// Stored Argon2 params roundtrip
// ---------------------------------------------------------------------------

#[test]
fn custom_argon2_params_roundtrip() {
    let (_dir, path) = vault_path();
    let password = b"custom-params-test";

    // Use non-default (but fast for testing) Argon2 params.
    let custom_params = Argon2Params {
        memory_kib: 8_192, // 8 MB (fast for testing)
        iterations: 1,
        parallelism: 1,
    };

    // Create with custom params.
    let mut store = VaultStore::create(&path, password, "dev", Some(&custom_params), None)
        .expect("create vault");
    store.set_secret("KEY", "value").unwrap();
    store.save().unwrap();

    // Re-open — should use stored params, not defaults.
    let store2 = VaultStore::open(&path, password, None).expect("open vault with stored params");
    assert_eq!(store2.get_secret("KEY").unwrap(), "value");
}

#[test]
fn default_params_still_work() {
    let (_dir, path) = vault_path();
    let password = b"default-params";

    // Create with default params (None).
    let mut store = VaultStore::create(&path, password, "dev", None, None).expect("create vault");
    store.set_secret("A", "1").unwrap();
    store.save().unwrap();

    let store2 = VaultStore::open(&path, password, None).expect("open vault");
    assert_eq!(store2.get_secret("A").unwrap(), "1");
}

// ---------------------------------------------------------------------------
// Rotate key (manual simulation since we can't prompt interactively)
// ---------------------------------------------------------------------------

#[test]
fn rotate_key_re_encrypts_all_secrets() {
    let (_dir, path) = vault_path();
    let old_password = b"old-password-123";
    let new_password = b"new-password-456";

    // Create vault with old password.
    let mut store =
        VaultStore::create(&path, old_password, "dev", None, None).expect("create vault");
    store.set_secret("DB_URL", "postgres://localhost").unwrap();
    store.set_secret("API_KEY", "sk_test_123").unwrap();
    store.save().unwrap();

    // Decrypt all secrets.
    let secrets = store.get_all_secrets().unwrap();

    // "Rotate" — create a new vault at the same path with new password.
    // (Delete the old one first since VaultStore::create checks existence.)
    fs::remove_file(&path).unwrap();

    let mut new_store =
        VaultStore::create(&path, new_password, "dev", None, None).expect("create new vault");
    for (name, value) in &secrets {
        new_store.set_secret(name, value).unwrap();
    }
    new_store.save().unwrap();

    // Old password should no longer work.
    let result = VaultStore::open(&path, old_password, None);
    assert!(result.is_err(), "old password must fail");

    // New password should work.
    let reopened = VaultStore::open(&path, new_password, None).expect("open with new password");
    assert_eq!(
        reopened.get_secret("DB_URL").unwrap(),
        "postgres://localhost"
    );
    assert_eq!(reopened.get_secret("API_KEY").unwrap(), "sk_test_123");
}

// ---------------------------------------------------------------------------
// Export / Import roundtrip
// ---------------------------------------------------------------------------

#[test]
fn export_env_format_roundtrip() {
    let (_dir, path) = vault_path();
    let password = b"export-test-pw";

    let mut store = VaultStore::create(&path, password, "dev", None, None).unwrap();
    store
        .set_secret("DB_URL", "postgres://localhost/db")
        .unwrap();
    store.set_secret("API_KEY", "sk-12345").unwrap();
    store.save().unwrap();

    let secrets = store.get_all_secrets().unwrap();

    // Format as .env.
    let sorted: std::collections::BTreeMap<_, _> = secrets.into_iter().collect();
    let mut env_content = String::new();
    for (key, value) in &sorted {
        env_content.push_str(&format!("{key}={value}\n"));
    }

    // Write to a temp .env file.
    let env_path = _dir.path().join("exported.env");
    fs::write(&env_path, &env_content).unwrap();

    // Create a new vault and import the .env file.
    let new_path = _dir.path().join("imported.vault");
    let mut new_store = VaultStore::create(&new_path, password, "imported", None, None).unwrap();

    // Parse the .env file manually.
    for line in env_content.lines() {
        if let Some((key, value)) = line.split_once('=') {
            new_store.set_secret(key.trim(), value.trim()).unwrap();
        }
    }
    new_store.save().unwrap();

    // Verify secrets match.
    assert_eq!(
        new_store.get_secret("DB_URL").unwrap(),
        "postgres://localhost/db"
    );
    assert_eq!(new_store.get_secret("API_KEY").unwrap(), "sk-12345");
}

#[test]
fn export_json_format_roundtrip() {
    let (_dir, path) = vault_path();
    let password = b"json-export-pw";

    let mut store = VaultStore::create(&path, password, "dev", None, None).unwrap();
    store.set_secret("TOKEN", "abc-xyz").unwrap();
    store.save().unwrap();

    let secrets = store.get_all_secrets().unwrap();

    // Serialize to JSON.
    let json = serde_json::to_string(&secrets).unwrap();

    // Parse back.
    let parsed: HashMap<String, String> = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["TOKEN"], "abc-xyz");
}

// ---------------------------------------------------------------------------
// Keyfile
// ---------------------------------------------------------------------------

#[test]
fn keyfile_generate_and_combine() {
    let dir = TempDir::new().unwrap();
    let keyfile_path = dir.path().join("test.keyfile");

    // Generate keyfile.
    let keyfile_bytes = keyfile::generate_keyfile(&keyfile_path).unwrap();
    assert_eq!(keyfile_bytes.len(), 32);

    // Combine with password.
    let combined = keyfile::combine_password_keyfile(b"my-password", &keyfile_bytes).unwrap();
    assert_eq!(combined.len(), 32); // HMAC-SHA256 output is 32 bytes.

    // Verify the hash.
    let hash = keyfile::hash_keyfile(&keyfile_bytes);
    keyfile::verify_keyfile_hash(&keyfile_bytes, &hash).unwrap();
}

#[test]
fn keyfile_combined_password_produces_different_master_key() {
    use envvault::crypto::kdf::{derive_master_key_with_params, generate_salt};

    let salt = generate_salt();
    let password = b"same-password";
    let keyfile = [0xABu8; 32];

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    // Derive without keyfile.
    let key_without = derive_master_key_with_params(password, &salt, &fast_params).unwrap();

    // Derive with keyfile (combined password).
    let combined = keyfile::combine_password_keyfile(password, &keyfile).unwrap();
    let key_with = derive_master_key_with_params(&combined, &salt, &fast_params).unwrap();

    assert_ne!(key_without, key_with, "keyfile must change the derived key");
}

// ---------------------------------------------------------------------------
// VaultStore::from_parts
// ---------------------------------------------------------------------------

#[test]
fn from_parts_creates_empty_vault() {
    use envvault::crypto::kdf::{derive_master_key_with_params, generate_salt};
    use envvault::crypto::keys::MasterKey;
    use envvault::vault::format::{StoredArgon2Params, VaultHeader, CURRENT_VERSION};

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("from-parts.vault");
    let password = b"from-parts-test";
    let salt = generate_salt();

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    let master_bytes = derive_master_key_with_params(password, &salt, &fast_params).unwrap();
    let master_key = MasterKey::new(master_bytes);

    let header = VaultHeader {
        version: CURRENT_VERSION,
        salt: salt.to_vec(),
        created_at: chrono::Utc::now(),
        environment: "test".to_string(),
        argon2_params: Some(StoredArgon2Params {
            memory_kib: fast_params.memory_kib,
            iterations: fast_params.iterations,
            parallelism: fast_params.parallelism,
        }),
        keyfile_hash: None,
    };

    let mut store = VaultStore::from_parts(path.clone(), header, master_key);
    store.set_secret("KEY", "value").unwrap();
    store.save().unwrap();

    // Re-open and verify.
    let store2 = VaultStore::open(&path, password, None).unwrap();
    assert_eq!(store2.get_secret("KEY").unwrap(), "value");
    assert_eq!(store2.environment(), "test");
}

// ---------------------------------------------------------------------------
// Rotate key using from_parts (exercises the real code path)
// ---------------------------------------------------------------------------

#[test]
fn rotate_key_via_from_parts() {
    use envvault::crypto::kdf::{derive_master_key_with_params, generate_salt};
    use envvault::crypto::keys::MasterKey;
    use envvault::vault::format::{StoredArgon2Params, VaultHeader, CURRENT_VERSION};

    let (_dir, path) = vault_path();
    let old_password = b"rotate-old-pw!!";
    let new_password = b"rotate-new-pw!!";

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    // Create vault with old password and some secrets.
    let mut store =
        VaultStore::create(&path, old_password, "dev", Some(&fast_params), None).unwrap();
    store.set_secret("DB_URL", "postgres://old").unwrap();
    store.set_secret("TOKEN", "secret-123").unwrap();
    store.save().unwrap();

    // Decrypt all secrets (simulates what rotate.rs does).
    let secrets = store.get_all_secrets().unwrap();

    // Build new header preserving keyfile_hash (should be None here).
    let new_salt = generate_salt();
    let master_bytes =
        derive_master_key_with_params(new_password, &new_salt, &fast_params).unwrap();
    let new_master_key = MasterKey::new(master_bytes);

    let new_header = VaultHeader {
        version: CURRENT_VERSION,
        salt: new_salt.to_vec(),
        created_at: store.created_at(),
        environment: store.environment().to_string(),
        argon2_params: Some(StoredArgon2Params {
            memory_kib: fast_params.memory_kib,
            iterations: fast_params.iterations,
            parallelism: fast_params.parallelism,
        }),
        keyfile_hash: store.header().keyfile_hash.clone(),
    };

    // Create new store via from_parts and re-encrypt all secrets.
    let mut new_store = VaultStore::from_parts(path.clone(), new_header, new_master_key);
    for (name, value) in &secrets {
        new_store.set_secret(name, value).unwrap();
    }
    new_store.save().unwrap();

    // Old password must fail.
    assert!(VaultStore::open(&path, old_password, None).is_err());

    // New password must work.
    let reopened = VaultStore::open(&path, new_password, None).unwrap();
    assert_eq!(reopened.get_secret("DB_URL").unwrap(), "postgres://old");
    assert_eq!(reopened.get_secret("TOKEN").unwrap(), "secret-123");
}

// ---------------------------------------------------------------------------
// Keyfile integration: create and open vault with keyfile
// ---------------------------------------------------------------------------

#[test]
fn create_vault_with_keyfile_and_reopen() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("kf.vault");
    let kf_path = dir.path().join("test.keyfile");
    let password = b"keyfile-vault-pw";

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    // Generate keyfile.
    let kf_bytes = keyfile::generate_keyfile(&kf_path).unwrap();

    // Create vault with keyfile.
    let mut store =
        VaultStore::create(&vault, password, "dev", Some(&fast_params), Some(&kf_bytes)).unwrap();
    store.set_secret("SECRET", "value-with-kf").unwrap();
    store.save().unwrap();

    // Re-open with keyfile — should succeed.
    let store2 = VaultStore::open(&vault, password, Some(&kf_bytes)).unwrap();
    assert_eq!(store2.get_secret("SECRET").unwrap(), "value-with-kf");
    assert!(store2.header().keyfile_hash.is_some());
}

#[test]
fn open_keyfile_vault_without_keyfile_fails() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("kf-req.vault");
    let kf_path = dir.path().join("test.keyfile");
    let password = b"keyfile-req-pw!!";

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    let kf_bytes = keyfile::generate_keyfile(&kf_path).unwrap();

    let store =
        VaultStore::create(&vault, password, "dev", Some(&fast_params), Some(&kf_bytes)).unwrap();
    drop(store);

    // Open without keyfile — must fail with a clear error.
    let result = VaultStore::open(&vault, password, None);
    match result {
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("keyfile"),
                "error should mention keyfile: {msg}"
            );
        }
        Ok(_) => panic!("expected error when opening keyfile vault without keyfile"),
    }
}

#[test]
fn open_keyfile_vault_with_wrong_keyfile_fails() {
    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("kf-wrong.vault");
    let kf_path = dir.path().join("correct.keyfile");
    let password = b"kf-wrong-test!!1";

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    let correct_kf = keyfile::generate_keyfile(&kf_path).unwrap();
    let wrong_kf = [0xFFu8; 32];

    let store = VaultStore::create(
        &vault,
        password,
        "dev",
        Some(&fast_params),
        Some(&correct_kf),
    )
    .unwrap();
    drop(store);

    // Open with wrong keyfile — must fail.
    let result = VaultStore::open(&vault, password, Some(&wrong_kf));
    assert!(result.is_err());
}

#[test]
fn rotate_preserves_keyfile_hash() {
    use envvault::crypto::kdf::{derive_master_key_with_params, generate_salt};
    use envvault::crypto::keys::MasterKey;
    use envvault::vault::format::{StoredArgon2Params, VaultHeader, CURRENT_VERSION};

    let dir = TempDir::new().unwrap();
    let vault = dir.path().join("rotate-kf.vault");
    let kf_path = dir.path().join("rotate.keyfile");
    let old_password = b"rotate-kf-old!!";
    let new_password = b"rotate-kf-new!!";

    let fast_params = Argon2Params {
        memory_kib: 8_192,
        iterations: 1,
        parallelism: 1,
    };

    // Create vault with keyfile.
    let kf_bytes = keyfile::generate_keyfile(&kf_path).unwrap();
    let mut store = VaultStore::create(
        &vault,
        old_password,
        "dev",
        Some(&fast_params),
        Some(&kf_bytes),
    )
    .unwrap();
    store.set_secret("KEY", "val").unwrap();
    store.save().unwrap();

    // Simulate rotation via from_parts — preserve keyfile_hash.
    let secrets = store.get_all_secrets().unwrap();
    let original_kf_hash = store.header().keyfile_hash.clone();
    assert!(original_kf_hash.is_some(), "vault should have keyfile_hash");

    let new_salt = generate_salt();
    let combined = keyfile::combine_password_keyfile(new_password, &kf_bytes).unwrap();
    let master_bytes = derive_master_key_with_params(&combined, &new_salt, &fast_params).unwrap();
    let new_master_key = MasterKey::new(master_bytes);

    let new_header = VaultHeader {
        version: CURRENT_VERSION,
        salt: new_salt.to_vec(),
        created_at: store.created_at(),
        environment: store.environment().to_string(),
        argon2_params: Some(StoredArgon2Params {
            memory_kib: fast_params.memory_kib,
            iterations: fast_params.iterations,
            parallelism: fast_params.parallelism,
        }),
        keyfile_hash: store.header().keyfile_hash.clone(),
    };

    let mut new_store = VaultStore::from_parts(vault.clone(), new_header, new_master_key);
    for (name, value) in &secrets {
        new_store.set_secret(name, value).unwrap();
    }
    new_store.save().unwrap();

    // Verify keyfile_hash is preserved after rotation.
    let reopened = VaultStore::open(&vault, new_password, Some(&kf_bytes)).unwrap();
    assert_eq!(reopened.header().keyfile_hash, original_kf_hash);
    assert_eq!(reopened.get_secret("KEY").unwrap(), "val");

    // Opening without keyfile must still fail.
    assert!(VaultStore::open(&vault, new_password, None).is_err());
}
