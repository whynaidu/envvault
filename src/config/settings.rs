use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::errors::{EnvVaultError, Result};

/// Project-level configuration, loaded from `.envvault.toml`.
///
/// Every field has a sensible default so EnvVault works out-of-the-box
/// without any config file at all.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    /// Which environment to use when none is specified (e.g. "dev").
    #[serde(default = "default_environment")]
    pub default_environment: String,

    /// Directory (relative to project root) where vault files are stored.
    #[serde(default = "default_vault_dir")]
    pub vault_dir: String,

    /// Argon2 memory cost in KiB (default: 64 MB).
    #[serde(default = "default_argon2_memory_kib")]
    pub argon2_memory_kib: u32,

    /// Argon2 iteration count (default: 3).
    #[serde(default = "default_argon2_iterations")]
    pub argon2_iterations: u32,

    /// Argon2 parallelism degree (default: 4).
    #[serde(default = "default_argon2_parallelism")]
    pub argon2_parallelism: u32,

    /// Default keyfile path (used when `--keyfile` is not passed on the CLI).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keyfile_path: Option<String>,

    /// Restrict which environment names are allowed (typo protection).
    /// If set, any env name not in this list is rejected.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_environments: Option<Vec<String>>,

    /// Preferred editor for `envvault edit` (overrides $VISUAL / $EDITOR).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub editor: Option<String>,

    /// Audit log settings.
    #[serde(default)]
    pub audit: AuditSettings,

    /// Secret scanning settings (for future use).
    #[serde(default)]
    pub secret_scanning: SecretScanningSettings,
}

/// Audit log configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuditSettings {
    /// Whether to log read operations (get, list, run). Default: false.
    #[serde(default)]
    pub log_reads: bool,
}

/// Secret scanning configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretScanningSettings {
    /// Custom regex patterns to scan for leaked secrets.
    #[serde(default)]
    pub custom_patterns: Vec<CustomPattern>,

    /// Path to a gitleaks-format TOML config file for additional rules.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gitleaks_config: Option<String>,
}

/// A custom secret scanning pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub name: String,
    pub regex: String,
}

// ── Serde default helpers ────────────────────────────────────────────

fn default_environment() -> String {
    "dev".to_string()
}

fn default_vault_dir() -> String {
    ".envvault".to_string()
}

fn default_argon2_memory_kib() -> u32 {
    65_536 // 64 MB
}

fn default_argon2_iterations() -> u32 {
    3
}

fn default_argon2_parallelism() -> u32 {
    4
}

// ── Implementation ───────────────────────────────────────────────────

impl Default for Settings {
    fn default() -> Self {
        Self {
            default_environment: default_environment(),
            vault_dir: default_vault_dir(),
            argon2_memory_kib: default_argon2_memory_kib(),
            argon2_iterations: default_argon2_iterations(),
            argon2_parallelism: default_argon2_parallelism(),
            keyfile_path: None,
            allowed_environments: None,
            editor: None,
            audit: AuditSettings::default(),
            secret_scanning: SecretScanningSettings::default(),
        }
    }
}

impl Settings {
    /// Name of the config file we look for in the project root.
    const FILE_NAME: &'static str = ".envvault.toml";

    /// Load settings from `<project_dir>/.envvault.toml`.
    ///
    /// If the file does not exist, sensible defaults are returned.
    /// If the file exists but cannot be parsed, an error is returned.
    pub fn load(project_dir: &Path) -> Result<Self> {
        let config_path = project_dir.join(Self::FILE_NAME);

        if !config_path.exists() {
            return Ok(Self::default());
        }

        let contents = std::fs::read_to_string(&config_path)?;

        let settings: Settings = toml::from_str(&contents).map_err(|e| {
            EnvVaultError::ConfigError(format!("Failed to parse {}: {e}", config_path.display()))
        })?;

        Ok(settings)
    }

    /// Build the full path to a vault file for a given environment.
    ///
    /// Example: `project_dir/.envvault/dev.vault`
    pub fn vault_path(&self, project_dir: &Path, env_name: &str) -> PathBuf {
        project_dir
            .join(&self.vault_dir)
            .join(format!("{env_name}.vault"))
    }

    /// Convert the Argon2 settings into crypto-layer params.
    pub fn argon2_params(&self) -> crate::crypto::kdf::Argon2Params {
        crate::crypto::kdf::Argon2Params {
            memory_kib: self.argon2_memory_kib,
            iterations: self.argon2_iterations,
            parallelism: self.argon2_parallelism,
        }
    }
}

/// Validate that an environment name is in the allowed list (if configured).
///
/// Returns `Ok(())` if no `allowed_environments` is set, or if the name is in the list.
pub fn validate_env_against_config(env_name: &str, settings: &Settings) -> Result<()> {
    if let Some(ref allowed) = settings.allowed_environments {
        if !allowed.iter().any(|a| a == env_name) {
            return Err(EnvVaultError::ConfigError(format!(
                "environment '{}' is not in allowed list: {:?}",
                env_name, allowed
            )));
        }
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn default_settings_are_sensible() {
        let s = Settings::default();
        assert_eq!(s.default_environment, "dev");
        assert_eq!(s.vault_dir, ".envvault");
        assert_eq!(s.argon2_memory_kib, 65_536);
        assert_eq!(s.argon2_iterations, 3);
        assert_eq!(s.argon2_parallelism, 4);
        assert!(s.keyfile_path.is_none());
        assert!(s.allowed_environments.is_none());
        assert!(s.editor.is_none());
        assert!(!s.audit.log_reads);
        assert!(s.secret_scanning.custom_patterns.is_empty());
    }

    #[test]
    fn load_returns_defaults_when_no_config_file() {
        let tmp = TempDir::new().unwrap();
        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(settings.default_environment, "dev");
    }

    #[test]
    fn load_parses_toml_file() {
        let tmp = TempDir::new().unwrap();
        let config = r#"
default_environment = "staging"
vault_dir = "secrets"
argon2_memory_kib = 131072
argon2_iterations = 5
argon2_parallelism = 8
"#;
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(settings.default_environment, "staging");
        assert_eq!(settings.vault_dir, "secrets");
        assert_eq!(settings.argon2_memory_kib, 131_072);
        assert_eq!(settings.argon2_iterations, 5);
        assert_eq!(settings.argon2_parallelism, 8);
    }

    #[test]
    fn load_uses_defaults_for_missing_fields() {
        let tmp = TempDir::new().unwrap();
        let config = "default_environment = \"prod\"\n";
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(settings.default_environment, "prod");
        // Rest should be defaults
        assert_eq!(settings.vault_dir, ".envvault");
        assert_eq!(settings.argon2_iterations, 3);
    }

    #[test]
    fn load_errors_on_invalid_toml() {
        let tmp = TempDir::new().unwrap();
        fs::write(tmp.path().join(".envvault.toml"), "not valid {{toml").unwrap();

        let result = Settings::load(tmp.path());
        assert!(result.is_err());
    }

    #[test]
    fn vault_path_builds_correct_path() {
        let s = Settings::default();
        let project = Path::new("/home/user/myproject");
        let path = s.vault_path(project, "dev");
        assert_eq!(
            path,
            PathBuf::from("/home/user/myproject/.envvault/dev.vault")
        );
    }

    #[test]
    fn vault_path_respects_custom_vault_dir() {
        let s = Settings {
            vault_dir: "secrets".to_string(),
            ..Settings::default()
        };
        let project = Path::new("/home/user/myproject");
        let path = s.vault_path(project, "staging");
        assert_eq!(
            path,
            PathBuf::from("/home/user/myproject/secrets/staging.vault")
        );
    }

    #[test]
    fn load_parses_keyfile_path() {
        let tmp = TempDir::new().unwrap();
        let config = "keyfile_path = \"/home/user/.envvault/keyfile\"\n";
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(
            settings.keyfile_path.as_deref(),
            Some("/home/user/.envvault/keyfile")
        );
    }

    #[test]
    fn load_parses_allowed_environments() {
        let tmp = TempDir::new().unwrap();
        let config = "allowed_environments = [\"dev\", \"staging\", \"prod\"]\n";
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(
            settings.allowed_environments,
            Some(vec![
                "dev".to_string(),
                "staging".to_string(),
                "prod".to_string()
            ])
        );
    }

    #[test]
    fn load_parses_editor() {
        let tmp = TempDir::new().unwrap();
        let config = "editor = \"nano\"\n";
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(settings.editor.as_deref(), Some("nano"));
    }

    #[test]
    fn load_parses_audit_section() {
        let tmp = TempDir::new().unwrap();
        let config = "[audit]\nlog_reads = true\n";
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert!(settings.audit.log_reads);
    }

    #[test]
    fn load_parses_secret_scanning_custom_patterns() {
        let tmp = TempDir::new().unwrap();
        let config = r#"
[[secret_scanning.custom_patterns]]
name = "Slack Token"
regex = "xoxb-[0-9A-Za-z-]+"
"#;
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(settings.secret_scanning.custom_patterns.len(), 1);
        assert_eq!(
            settings.secret_scanning.custom_patterns[0].name,
            "Slack Token"
        );
    }

    #[test]
    fn allowed_environments_rejects_unlisted_env() {
        let settings = Settings {
            allowed_environments: Some(vec![
                "dev".to_string(),
                "staging".to_string(),
                "prod".to_string(),
            ]),
            ..Settings::default()
        };

        assert!(validate_env_against_config("dev", &settings).is_ok());
        assert!(validate_env_against_config("staging", &settings).is_ok());
        assert!(validate_env_against_config("prod", &settings).is_ok());

        let err = validate_env_against_config("pdro", &settings).unwrap_err();
        assert!(err.to_string().contains("not in allowed list"));
    }

    #[test]
    fn unknown_toml_fields_are_ignored() {
        let tmp = TempDir::new().unwrap();
        let config = "default_environment = \"dev\"\nunknown_field = \"should be fine\"\n";
        fs::write(tmp.path().join(".envvault.toml"), config).unwrap();

        // Should NOT error — we don't deny unknown fields for forward-compat.
        let settings = Settings::load(tmp.path()).unwrap();
        assert_eq!(settings.default_environment, "dev");
    }

    #[test]
    fn allowed_environments_allows_all_when_not_configured() {
        let settings = Settings::default();
        assert!(validate_env_against_config("anything", &settings).is_ok());
    }
}
