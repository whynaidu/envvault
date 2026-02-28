//! Integration tests for the EnvVault crypto module.

use envvault::crypto::keys::{derive_hmac_key, derive_secret_key, MasterKey};
use envvault::crypto::{decrypt, derive_master_key, encrypt, generate_salt};

// ---------------------------------------------------------------------------
// Encryption round-trip
// ---------------------------------------------------------------------------

#[test]
fn encrypt_decrypt_roundtrip() {
    // Use a random 32-byte key.
    let key = [0xABu8; 32];
    let plaintext = b"DATABASE_URL=postgres://localhost/mydb";

    let ciphertext = encrypt(&key, plaintext).expect("encrypt should succeed");

    // Ciphertext must be longer than plaintext (12-byte nonce + 16-byte tag).
    assert!(ciphertext.len() > plaintext.len());

    let recovered = decrypt(&key, &ciphertext).expect("decrypt should succeed");
    assert_eq!(recovered, plaintext);
}

#[test]
fn encrypt_produces_different_ciphertext_each_time() {
    let key = [0xCDu8; 32];
    let plaintext = b"SECRET=hello";

    let ct1 = encrypt(&key, plaintext).expect("encrypt 1");
    let ct2 = encrypt(&key, plaintext).expect("encrypt 2");

    // Because each call generates a new random nonce, the output must differ.
    assert_ne!(
        ct1, ct2,
        "two encryptions of the same plaintext must differ"
    );
}

#[test]
fn decrypt_with_wrong_key_fails() {
    let key = [0x11u8; 32];
    let wrong_key = [0x22u8; 32];
    let plaintext = b"TOP_SECRET=42";

    let ciphertext = encrypt(&key, plaintext).expect("encrypt");
    let result = decrypt(&wrong_key, &ciphertext);

    assert!(result.is_err(), "decryption with the wrong key must fail");
}

#[test]
fn decrypt_with_truncated_data_fails() {
    // Anything shorter than 12 bytes (nonce length) should fail.
    let key = [0xAAu8; 32];
    let result = decrypt(&key, &[0u8; 5]);
    assert!(result.is_err(), "truncated ciphertext must fail");
}

#[test]
fn decrypt_with_corrupted_ciphertext_fails() {
    let key = [0xBBu8; 32];
    let plaintext = b"VALUE=abc";

    let mut ciphertext = encrypt(&key, plaintext).expect("encrypt");
    // Flip a byte in the ciphertext portion (after the 12-byte nonce).
    if let Some(byte) = ciphertext.get_mut(15) {
        *byte ^= 0xFF;
    }

    let result = decrypt(&key, &ciphertext);
    assert!(result.is_err(), "corrupted ciphertext must fail auth check");
}

// ---------------------------------------------------------------------------
// Key derivation (Argon2id)
// ---------------------------------------------------------------------------

#[test]
fn derive_master_key_same_inputs_same_output() {
    let password = b"my-secure-passphrase";
    let salt = generate_salt();

    let key1 = derive_master_key(password, &salt).expect("derive 1");
    let key2 = derive_master_key(password, &salt).expect("derive 2");

    assert_eq!(key1, key2, "same password + salt must produce the same key");
}

#[test]
fn derive_master_key_different_salts_different_keys() {
    let password = b"same-password";
    let salt1 = generate_salt();
    let salt2 = generate_salt();

    let key1 = derive_master_key(password, &salt1).expect("derive 1");
    let key2 = derive_master_key(password, &salt2).expect("derive 2");

    assert_ne!(key1, key2, "different salts must produce different keys");
}

#[test]
fn derive_master_key_different_passwords_different_keys() {
    let salt = generate_salt();

    let key1 = derive_master_key(b"password-one", &salt).expect("derive 1");
    let key2 = derive_master_key(b"password-two", &salt).expect("derive 2");

    assert_ne!(
        key1, key2,
        "different passwords must produce different keys"
    );
}

// ---------------------------------------------------------------------------
// HKDF per-secret key derivation
// ---------------------------------------------------------------------------

#[test]
fn hkdf_different_secret_names_produce_different_keys() {
    let master = [0x99u8; 32];

    let key_a = derive_secret_key(&master, "DATABASE_URL").expect("derive A");
    let key_b = derive_secret_key(&master, "API_KEY").expect("derive B");

    assert_ne!(
        key_a, key_b,
        "different secret names must produce different keys"
    );
}

#[test]
fn hkdf_same_secret_name_produces_same_key() {
    let master = [0x77u8; 32];

    let key1 = derive_secret_key(&master, "MY_SECRET").expect("derive 1");
    let key2 = derive_secret_key(&master, "MY_SECRET").expect("derive 2");

    assert_eq!(key1, key2, "same inputs must produce the same key");
}

#[test]
fn hmac_key_differs_from_secret_keys() {
    let master = [0x55u8; 32];

    let hmac_key = derive_hmac_key(&master).expect("hmac key");
    let secret_key = derive_secret_key(&master, "ANY_NAME").expect("secret key");

    assert_ne!(
        hmac_key, secret_key,
        "HMAC key and secret key must be different"
    );
}

// ---------------------------------------------------------------------------
// MasterKey wrapper
// ---------------------------------------------------------------------------

#[test]
fn master_key_wrapper_derives_keys() {
    let raw = [0x44u8; 32];
    let mk = MasterKey::new(raw);

    // Derive through the wrapper and through the free functions — must match.
    let via_wrapper = mk.derive_secret_key("TEST").expect("wrapper derive");
    let via_fn = derive_secret_key(&raw, "TEST").expect("fn derive");
    assert_eq!(via_wrapper, via_fn);

    let hmac_wrapper = mk.derive_hmac_key().expect("wrapper hmac");
    let hmac_fn = derive_hmac_key(&raw).expect("fn hmac");
    assert_eq!(hmac_wrapper, hmac_fn);
}

// ---------------------------------------------------------------------------
// End-to-end: password -> master key -> per-secret key -> encrypt/decrypt
// ---------------------------------------------------------------------------

#[test]
fn full_crypto_pipeline() {
    let password = b"hunter2";
    let salt = generate_salt();

    // Step 1: Derive master key from password.
    let master_bytes = derive_master_key(password, &salt).expect("derive master");
    let master = MasterKey::new(master_bytes);

    // Step 2: Derive a per-secret encryption key.
    let secret_key = master
        .derive_secret_key("DATABASE_URL")
        .expect("derive secret key");

    // Step 3: Encrypt a value.
    let plaintext = b"postgres://user:pass@localhost/db";
    let ciphertext = encrypt(&secret_key, plaintext).expect("encrypt");

    // Step 4: Decrypt it back.
    let recovered = decrypt(&secret_key, &ciphertext).expect("decrypt");
    assert_eq!(recovered, plaintext.to_vec());
}
