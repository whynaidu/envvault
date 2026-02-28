//! Version check — query crates.io for the latest published version.
//!
//! Behind the `version-check` feature flag. Caches results for 24 hours
//! in `~/.config/envvault/version-check.json`. Never fails — returns `None`
//! on any error.

use std::fs;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// How long to cache the version check result.
const CACHE_TTL_HOURS: i64 = 24;

/// Cached version check result.
#[derive(Serialize, Deserialize)]
struct CachedVersion {
    latest: String,
    checked_at: DateTime<Utc>,
}

/// Check for the latest version of envvault on crates.io.
///
/// Returns `Some(version_string)` if a newer version is available,
/// or `None` if already up-to-date or on any error.
pub fn check_latest_version(current: &str) -> Option<String> {
    // Try cache first.
    if let Some(cached) = read_cache() {
        let age = Utc::now() - cached.checked_at;
        if age.num_hours() < CACHE_TTL_HOURS {
            return if cached.latest == current {
                None
            } else {
                Some(cached.latest)
            };
        }
    }

    // Fetch from crates.io.
    let latest = fetch_latest_version()?;

    // Cache the result (fire-and-forget).
    let _ = write_cache(&latest);

    if latest == current {
        None
    } else {
        Some(latest)
    }
}

/// Fetch the latest version from crates.io API.
#[cfg(feature = "version-check")]
fn fetch_latest_version() -> Option<String> {
    let resp = ureq::get("https://crates.io/api/v1/crates/envvault")
        .set(
            "User-Agent",
            &format!("envvault/{}", env!("CARGO_PKG_VERSION")),
        )
        .call()
        .ok()?;

    let body: serde_json::Value = resp.into_json().ok()?;
    let version = body.get("crate")?.get("max_version")?.as_str()?.to_string();

    Some(version)
}

#[cfg(not(feature = "version-check"))]
fn fetch_latest_version() -> Option<String> {
    None
}

/// Path to the cache file.
fn cache_path() -> Option<PathBuf> {
    let config_dir = dirs_cache_path()?;
    Some(config_dir.join("version-check.json"))
}

/// Get the envvault config directory.
fn dirs_cache_path() -> Option<PathBuf> {
    // Use $HOME/.config/envvault on all platforms.
    let home = std::env::var("HOME")
        .or_else(|_| std::env::var("USERPROFILE"))
        .ok()?;
    let path = PathBuf::from(home).join(".config").join("envvault");
    Some(path)
}

/// Read the cached version check.
fn read_cache() -> Option<CachedVersion> {
    let path = cache_path()?;
    let content = fs::read_to_string(path).ok()?;
    serde_json::from_str(&content).ok()
}

/// Write a version check result to cache.
fn write_cache(version: &str) -> Option<()> {
    let path = cache_path()?;

    // Create the directory if needed.
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).ok()?;
    }

    let cached = CachedVersion {
        latest: version.to_string(),
        checked_at: Utc::now(),
    };

    let content = serde_json::to_string_pretty(&cached).ok()?;
    fs::write(path, content).ok()?;

    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_roundtrip() {
        // Test serialization/deserialization directly without env var manipulation.
        let dir = tempfile::TempDir::new().unwrap();
        let cache_file = dir.path().join("version-check.json");

        let cached = CachedVersion {
            latest: "1.2.3".to_string(),
            checked_at: Utc::now(),
        };

        let content = serde_json::to_string_pretty(&cached).unwrap();
        fs::write(&cache_file, &content).unwrap();

        let read_back: CachedVersion =
            serde_json::from_str(&fs::read_to_string(&cache_file).unwrap()).unwrap();
        assert_eq!(read_back.latest, "1.2.3");
    }

    #[test]
    fn check_returns_none_without_feature() {
        // Without the version-check feature, fetch always returns None.
        #[cfg(not(feature = "version-check"))]
        {
            assert!(fetch_latest_version().is_none());
        }
    }

    #[test]
    fn cache_path_returns_some() {
        // cache_path depends on HOME being set, which it normally is.
        // Test the path construction logic directly.
        let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"));
        if let Ok(home) = home {
            let expected = PathBuf::from(home)
                .join(".config")
                .join("envvault")
                .join("version-check.json");
            let actual = cache_path();
            assert_eq!(actual, Some(expected));
        }
    }
}
