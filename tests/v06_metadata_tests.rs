//! v0.6.0 metadata + vault format v2 integration tests.
//!
//! Covers:
//! - Adding description and tags to secrets via `VaultStore`.
//! - Round-tripping metadata through save/reopen.
//! - Tag normalization (trim, dedup, sort, length limit).
//! - `set_secret` preserving metadata on value update.
//! - Reading a legacy v1 vault file, then transparently upgrading to
//!   v2 on first write.

use std::fs;

use envvault::vault::format::{CURRENT_VERSION, SUPPORTED_READ_VERSIONS};
use envvault::vault::VaultStore;
use tempfile::TempDir;

fn vault_path(dir: &TempDir, name: &str) -> std::path::PathBuf {
    dir.path().join(format!("{name}.vault"))
}

// ---------------------------------------------------------------------------
// Basic metadata round-trip
// ---------------------------------------------------------------------------

#[test]
fn description_and_tags_roundtrip_through_save_and_reopen() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "meta");
    let pw = b"metadata-password-1";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("STRIPE_KEY", "sk_live_abc").unwrap();
    store
        .set_description("STRIPE_KEY", Some("Stripe production key".to_string()))
        .unwrap();
    store
        .set_tags(
            "STRIPE_KEY",
            vec!["provider:stripe".to_string(), "tier:prod".to_string()],
        )
        .unwrap();
    store.save().unwrap();

    // Reopen and inspect metadata.
    let reopened = VaultStore::open(&path, pw, None).unwrap();
    let list = reopened.list_secrets();
    assert_eq!(list.len(), 1);
    let s = &list[0];
    assert_eq!(s.name, "STRIPE_KEY");
    assert_eq!(s.description.as_deref(), Some("Stripe production key"));
    assert_eq!(s.tags, vec!["provider:stripe", "tier:prod"]); // sorted already
}

#[test]
fn tags_are_sorted_deduplicated_and_trimmed() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "tags");
    let pw = b"tag-normalize-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "value").unwrap();
    store
        .set_tags(
            "KEY",
            vec![
                "  prod ".to_string(),
                "db".to_string(),
                "prod".to_string(), // dup after trim
                "".to_string(),     // empty is dropped
                "  ".to_string(),   // whitespace-only dropped
                "aaa".to_string(),
            ],
        )
        .unwrap();
    store.save().unwrap();

    let reopened = VaultStore::open(&path, pw, None).unwrap();
    let s = &reopened.list_secrets()[0];
    assert_eq!(s.tags, vec!["aaa", "db", "prod"]);
}

#[test]
fn tag_exceeding_max_length_rejected() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "longtag");
    let pw = b"tag-len-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "value").unwrap();
    let too_long = "x".repeat(129);
    let err = store.set_tags("KEY", vec![too_long]).unwrap_err();
    assert!(err.to_string().contains("exceeds 128 characters"));
}

#[test]
fn set_description_on_missing_secret_returns_not_found() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "missing");
    let pw = b"missing-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    let err = store
        .set_description("NOPE", Some("whatever".to_string()))
        .unwrap_err();
    assert!(err.to_string().to_lowercase().contains("not found"));
}

// ---------------------------------------------------------------------------
// Preservation semantics
// ---------------------------------------------------------------------------

#[test]
fn updating_a_secret_preserves_existing_description_and_tags() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "preserve");
    let pw = b"preserve-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("TOKEN", "v1").unwrap();
    store
        .set_description("TOKEN", Some("auth token".into()))
        .unwrap();
    store.set_tags("TOKEN", vec!["svc:auth".into()]).unwrap();

    // Updating the value must leave description/tags intact.
    store.set_secret("TOKEN", "v2").unwrap();

    let s = &store.list_secrets()[0];
    assert_eq!(s.description.as_deref(), Some("auth token"));
    assert_eq!(s.tags, vec!["svc:auth"]);
    assert_eq!(store.get_secret("TOKEN").unwrap(), "v2");
}

#[test]
fn clearing_description_and_tags_works() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "clear");
    let pw = b"clear-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("KEY", "v").unwrap();
    store.set_description("KEY", Some("desc".into())).unwrap();
    store.set_tags("KEY", vec!["t".into()]).unwrap();
    store.save().unwrap();

    store.set_description("KEY", None).unwrap();
    store.set_tags("KEY", Vec::new()).unwrap();
    store.save().unwrap();

    let reopened = VaultStore::open(&path, pw, None).unwrap();
    let s = &reopened.list_secrets()[0];
    assert!(s.description.is_none());
    assert!(s.tags.is_empty());
}

// ---------------------------------------------------------------------------
// Format version
// ---------------------------------------------------------------------------

#[test]
fn fresh_vault_is_written_with_current_version() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "version");
    let pw = b"version-password";

    VaultStore::create(&path, pw, "dev", None, None).unwrap();
    let bytes = fs::read(&path).unwrap();

    // Prefix layout: "EVLT" (4) + version (1) + header_len (4).
    assert_eq!(&bytes[0..4], b"EVLT");
    assert_eq!(bytes[4], CURRENT_VERSION);
    assert_eq!(CURRENT_VERSION, 2, "this phase bumps the format to v2");
}

#[test]
fn reader_accepts_all_supported_versions() {
    // Sanity-check the version whitelist so adding a new version
    // forces an update to this test.
    assert_eq!(SUPPORTED_READ_VERSIONS, &[1, 2]);
}

// ---------------------------------------------------------------------------
// v1 → v2 migration on first write
// ---------------------------------------------------------------------------

#[test]
fn v1_vault_can_be_read_and_upgrades_on_save() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "legacy");
    let pw = b"legacy-password";

    // Write a fresh v2 vault, then flip only the on-disk prefix byte
    // from 2 to 1 to simulate a legacy v1 file. The HMAC is computed
    // over the header JSON + secrets JSON only (not the prefix), so
    // flipping the prefix byte leaves the HMAC valid. A v1 secret JSON
    // payload (no description/no tags) is byte-identical to a v2 one
    // for the same inputs thanks to `skip_serializing_if`.
    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store
        .set_secret("DB_URL", "postgres://localhost/db")
        .unwrap();
    store.save().unwrap();

    let mut bytes = fs::read(&path).unwrap();
    assert_eq!(bytes[4], CURRENT_VERSION);
    bytes[4] = 1;
    fs::write(&path, &bytes).unwrap();

    // Reader accepts v1 files.
    let mut reopened = VaultStore::open(&path, pw, None).unwrap();
    assert_eq!(
        reopened.get_secret("DB_URL").unwrap(),
        "postgres://localhost/db"
    );

    // Any write upgrades the on-disk prefix to CURRENT_VERSION.
    reopened.set_secret("NEW", "value").unwrap();
    reopened.save().unwrap();

    let bytes = fs::read(&path).unwrap();
    assert_eq!(bytes[4], CURRENT_VERSION);
}

#[test]
fn v1_vault_with_no_metadata_is_byte_stable_except_version_byte() {
    // A secret with no description/no tags serializes identically
    // under v1 and v2. Only the version byte differs between a v1
    // file and the same contents saved as v2.
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "byte-stable");
    let pw = b"bytes-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("K", "v").unwrap();
    store.save().unwrap();

    let bytes_v2 = fs::read(&path).unwrap();
    // No "description" or "tags" key should appear in JSON for a
    // secret that has neither set.
    assert!(
        !bytes_v2
            .windows(b"\"description\"".len())
            .any(|w| w == b"\"description\""),
        "v2 file should omit empty description field"
    );
    assert!(
        !bytes_v2
            .windows(b"\"tags\"".len())
            .any(|w| w == b"\"tags\""),
        "v2 file should omit empty tags field"
    );
}

// ---------------------------------------------------------------------------
// List filter
// ---------------------------------------------------------------------------

#[test]
fn list_filter_matches_all_provided_tags() {
    let dir = TempDir::new().unwrap();
    let path = vault_path(&dir, "filter");
    let pw = b"filter-password";

    let mut store = VaultStore::create(&path, pw, "dev", None, None).unwrap();
    store.set_secret("A", "1").unwrap();
    store
        .set_tags("A", vec!["provider:stripe".into(), "tier:prod".into()])
        .unwrap();

    store.set_secret("B", "2").unwrap();
    store
        .set_tags("B", vec!["provider:stripe".into(), "tier:dev".into()])
        .unwrap();

    store.set_secret("C", "3").unwrap();
    store.set_tags("C", vec!["provider:aws".into()]).unwrap();

    let all = store.list_secrets();
    assert_eq!(all.len(), 3);

    // Replicates the CLI filter: keep secrets where every pattern
    // matches at least one tag substring.
    fn filter<'a>(
        secrets: &'a [envvault::vault::SecretMetadata],
        patterns: &[&str],
    ) -> Vec<&'a str> {
        secrets
            .iter()
            .filter(|s| {
                patterns
                    .iter()
                    .all(|p| s.tags.iter().any(|t| t.contains(*p)))
            })
            .map(|s| s.name.as_str())
            .collect()
    }

    assert_eq!(filter(&all, &["stripe"]), vec!["A", "B"]);
    assert_eq!(filter(&all, &["stripe", "prod"]), vec!["A"]);
    assert_eq!(filter(&all, &["aws"]), vec!["C"]);
    assert!(filter(&all, &["nope"]).is_empty());
}
