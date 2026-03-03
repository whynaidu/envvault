//! Global user-level configuration at `~/.config/envvault/config.toml`.
//!
//! Provides machine-wide defaults that project-level `.envvault.toml` can override.

use serde::{Deserialize, Serialize};

use super::settings::AuditSettings;

/// Global configuration loaded from `~/.config/envvault/config.toml`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GlobalConfig {
    /// Default editor for `envvault edit`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,

    /// Default keyfile path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile_path: Option<String>,

    /// Audit settings.
    #[serde(default)]
    pub audit: AuditSettings,
}

impl GlobalConfig {
    /// Load the global config from `~/.config/envvault/config.toml`.
    ///
    /// Returns defaults if the file is missing or cannot be parsed.
    pub fn load() -> Self {
        let Some(path) = Self::config_path() else {
            return Self::default();
        };

        let Ok(contents) = std::fs::read_to_string(&path) else {
            return Self::default();
        };

        toml::from_str(&contents).unwrap_or_default()
    }

    /// Path to the global config file.
    fn config_path() -> Option<std::path::PathBuf> {
        let home = std::env::var("HOME")
            .or_else(|_| std::env::var("USERPROFILE"))
            .ok()?;
        Some(
            std::path::PathBuf::from(home)
                .join(".config")
                .join("envvault")
                .join("config.toml"),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_config_returns_defaults_when_file_missing() {
        let config = GlobalConfig::load();
        assert!(config.editor.is_none());
        assert!(config.keyfile_path.is_none());
        assert!(!config.audit.log_reads);
    }
}
