//! `envvault scan` — scan files for leaked secrets.
//!
//! Walks the directory tree and checks each text file against built-in
//! and custom secret patterns. Reports findings with file path and line number.

use std::fs;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::cli::output;
use crate::errors::Result;

/// A single finding from a secret scan.
#[derive(Debug)]
pub struct Finding {
    pub file: PathBuf,
    pub line: usize,
    pub pattern_name: String,
}

/// Directories to skip during scanning.
const SKIP_DIRS: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    ".envvault",
    "__pycache__",
    ".venv",
    "vendor",
    "dist",
    ".next",
];

/// File extensions to treat as binary (skip).
const BINARY_EXTENSIONS: &[&str] = &[
    "png", "jpg", "jpeg", "gif", "bmp", "ico", "svg", "woff", "woff2", "ttf", "eot", "otf", "mp3",
    "mp4", "avi", "mov", "zip", "tar", "gz", "bz2", "xz", "7z", "rar", "pdf", "doc", "docx", "xls",
    "xlsx", "ppt", "pptx", "exe", "dll", "so", "dylib", "o", "a", "pyc", "class", "jar", "war",
    "wasm", "db", "sqlite", "sqlite3",
];

/// Execute the `scan` command.
pub fn execute(ci: bool, dir: Option<&str>, gitleaks_config: Option<&str>) -> Result<()> {
    let scan_dir = match dir {
        Some(d) => PathBuf::from(d),
        None => std::env::current_dir()?,
    };

    if !scan_dir.is_dir() {
        return Err(crate::errors::EnvVaultError::CommandFailed(format!(
            "not a directory: {}",
            scan_dir.display()
        )));
    }

    // Build patterns: built-in + custom from config.
    let mut patterns: Vec<(String, Regex)> = Vec::new();

    for (name, pat) in crate::git::SECRET_PATTERNS {
        match Regex::new(pat) {
            Ok(re) => patterns.push((name.to_string(), re)),
            Err(_) => continue,
        }
    }

    // Load custom patterns from config if available.
    let gitleaks_config_from_settings;
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(settings) = crate::config::Settings::load(&cwd) {
            for custom in &settings.secret_scanning.custom_patterns {
                match Regex::new(&custom.regex) {
                    Ok(re) => patterns.push((custom.name.clone(), re)),
                    Err(e) => {
                        output::warning(&format!("Invalid custom pattern '{}': {e}", custom.name));
                    }
                }
            }
            gitleaks_config_from_settings = settings.secret_scanning.gitleaks_config.clone();
        } else {
            gitleaks_config_from_settings = None;
        }
    } else {
        gitleaks_config_from_settings = None;
    }

    // Load gitleaks rules from CLI flag or config.
    let gitleaks_path = gitleaks_config.or(gitleaks_config_from_settings.as_deref());
    if let Some(path) = gitleaks_path {
        match load_gitleaks_rules(Path::new(path)) {
            Ok(rules) => {
                let count = rules.len();
                patterns.extend(rules);
                if count > 0 {
                    output::info(&format!("Loaded {count} gitleaks rules from {path}"));
                }
            }
            Err(e) => {
                output::warning(&format!("Failed to load gitleaks config '{path}': {e}"));
            }
        }
    }

    // Walk directory and scan files.
    let mut findings = Vec::new();
    walk_and_scan(&scan_dir, &patterns, &mut findings);

    if findings.is_empty() {
        output::success("No secrets detected.");
        return Ok(());
    }

    // Report findings.
    output::warning(&format!("{} potential secret(s) found:", findings.len()));
    println!();

    for f in &findings {
        let rel_path = f.file.strip_prefix(&scan_dir).unwrap_or(&f.file).display();
        println!("  {}:{} — {}", rel_path, f.line, f.pattern_name);
    }

    if ci {
        std::process::exit(1);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Gitleaks rule loading
// ---------------------------------------------------------------------------

/// A gitleaks TOML config file structure.
#[derive(serde::Deserialize)]
struct GitleaksConfig {
    #[serde(default)]
    rules: Vec<GitleaksRule>,
}

/// A single gitleaks rule with an id, description, and regex.
#[derive(serde::Deserialize)]
struct GitleaksRule {
    #[serde(default)]
    id: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    regex: String,
}

/// Load rules from a gitleaks-format TOML file.
///
/// Each rule has `id`, `description`, and `regex` fields. Rules whose regex
/// fails to compile (e.g. uses PCRE-only features like lookarounds) are
/// silently skipped.
pub fn load_gitleaks_rules(path: &Path) -> Result<Vec<(String, Regex)>> {
    let content = fs::read_to_string(path)?;
    let config: GitleaksConfig = toml::from_str(&content).map_err(|e| {
        crate::errors::EnvVaultError::ConfigError(format!("failed to parse gitleaks config: {e}"))
    })?;

    let mut rules = Vec::new();
    for rule in &config.rules {
        if rule.regex.is_empty() {
            continue;
        }
        let name = if !rule.description.is_empty() {
            rule.description.clone()
        } else if !rule.id.is_empty() {
            rule.id.clone()
        } else {
            "unnamed gitleaks rule".to_string()
        };

        match Regex::new(&rule.regex) {
            Ok(re) => rules.push((name, re)),
            Err(_) => {
                // Silently skip rules with incompatible regex (PCRE lookarounds, etc.)
            }
        }
    }

    Ok(rules)
}

/// Recursively walk the directory, scanning each text file.
fn walk_and_scan(dir: &Path, patterns: &[(String, Regex)], findings: &mut Vec<Finding>) {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    for entry in entries.flatten() {
        let path = entry.path();

        if path.is_dir() {
            let dir_name = entry.file_name();
            let name = dir_name.to_string_lossy();
            if SKIP_DIRS.iter().any(|&s| s == name.as_ref()) {
                continue;
            }
            walk_and_scan(&path, patterns, findings);
        } else if path.is_file() {
            // Skip binary files.
            if is_binary(&path) {
                continue;
            }
            // Skip vault files and the audit database.
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                if ext == "vault" {
                    continue;
                }
            }
            scan_file(&path, patterns, findings);
        }
    }
}

/// Check if a file is likely binary based on extension.
fn is_binary(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some(ext) => BINARY_EXTENSIONS.contains(&ext),
        None => false,
    }
}

/// Scan a single file for secret patterns.
fn scan_file(path: &Path, patterns: &[(String, Regex)], findings: &mut Vec<Finding>) {
    let content = match fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return, // Skip files that can't be read as UTF-8.
    };

    for (line_num, line) in content.lines().enumerate() {
        for (name, re) in patterns {
            if re.is_match(line) {
                findings.push(Finding {
                    file: path.to_path_buf(),
                    line: line_num + 1,
                    pattern_name: name.clone(),
                });
                break; // One finding per line is enough.
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn detects_aws_access_key() {
        let re = Regex::new(r"AKIA[0-9A-Z]{16}").unwrap();
        assert!(re.is_match("aws_key = AKIAIOSFODNN7EXAMPLE"));
        assert!(!re.is_match("not_a_key = hello"));
    }

    #[test]
    fn scan_file_finds_secrets() {
        let dir = TempDir::new().unwrap();
        let file_path = dir.path().join("config.py");
        let mut file = fs::File::create(&file_path).unwrap();
        writeln!(file, "# Config file").unwrap();
        writeln!(file, "aws_key = \"AKIAIOSFODNN7EXAMPLE1\"").unwrap();
        writeln!(file, "safe_value = \"hello\"").unwrap();

        let patterns = vec![(
            "AWS Access Key".to_string(),
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        )];

        let mut findings = Vec::new();
        scan_file(&file_path, &patterns, &mut findings);

        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 2);
        assert_eq!(findings[0].pattern_name, "AWS Access Key");
    }

    #[test]
    fn walk_skips_git_directory() {
        let dir = TempDir::new().unwrap();

        // Create .git directory with a "secret".
        let git_dir = dir.path().join(".git");
        fs::create_dir(&git_dir).unwrap();
        let secret_file = git_dir.join("config");
        fs::write(&secret_file, "AKIAIOSFODNN7EXAMPLE1\n").unwrap();

        // Create a normal file.
        fs::write(dir.path().join("safe.txt"), "nothing here\n").unwrap();

        let patterns = vec![(
            "AWS Access Key".to_string(),
            Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
        )];

        let mut findings = Vec::new();
        walk_and_scan(dir.path(), &patterns, &mut findings);

        assert!(findings.is_empty(), "should not scan .git directory");
    }

    #[test]
    fn is_binary_detects_common_types() {
        assert!(is_binary(Path::new("image.png")));
        assert!(is_binary(Path::new("data.zip")));
        assert!(is_binary(Path::new("lib.so")));
        assert!(!is_binary(Path::new("config.py")));
        assert!(!is_binary(Path::new("README.md")));
        assert!(!is_binary(Path::new("noext")));
    }

    // --- Gitleaks rule loading tests ---

    #[test]
    fn load_gitleaks_rules_parses_valid_toml() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitleaks.toml");
        let config = r#"
[[rules]]
id = "aws-access-key"
description = "AWS Access Key ID"
regex = "AKIA[0-9A-Z]{16}"

[[rules]]
id = "generic-secret"
description = "Generic Secret"
regex = "secret[_-]?key\\s*=\\s*[\"'][^\"']{8,}"
"#;
        fs::write(&config_path, config).unwrap();

        let rules = load_gitleaks_rules(&config_path).unwrap();
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].0, "AWS Access Key ID");
        assert_eq!(rules[1].0, "Generic Secret");
    }

    #[test]
    fn load_gitleaks_rules_skips_invalid_regex() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitleaks.toml");
        // Use a PCRE lookahead which Rust's regex crate does not support.
        let config = r#"
[[rules]]
id = "valid-rule"
description = "Valid Rule"
regex = "AKIA[0-9A-Z]{16}"

[[rules]]
id = "invalid-rule"
description = "Uses Lookahead"
regex = "(?<=password=).+"
"#;
        fs::write(&config_path, config).unwrap();

        let rules = load_gitleaks_rules(&config_path).unwrap();
        // Only the valid rule should be loaded.
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0, "Valid Rule");
    }

    #[test]
    fn load_gitleaks_rules_uses_id_as_fallback_name() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitleaks.toml");
        let config = r#"
[[rules]]
id = "my-rule-id"
regex = "SECRET_[A-Z]+"
"#;
        fs::write(&config_path, config).unwrap();

        let rules = load_gitleaks_rules(&config_path).unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].0, "my-rule-id");
    }

    #[test]
    fn load_gitleaks_rules_handles_empty_rules() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join(".gitleaks.toml");
        let config = "# empty config\n";
        fs::write(&config_path, config).unwrap();

        let rules = load_gitleaks_rules(&config_path).unwrap();
        assert!(rules.is_empty());
    }
}
