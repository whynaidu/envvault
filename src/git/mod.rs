//! Git integration — pre-commit hook for secret leak prevention.
//!
//! The pre-commit hook scans staged files for patterns that look like
//! hardcoded secrets (API keys, tokens, passwords). If a match is found,
//! the commit is blocked with a descriptive error message.

use std::fs;
use std::path::Path;

use crate::errors::{EnvVaultError, Result};

/// The filename of the pre-commit hook.
const HOOK_NAME: &str = "pre-commit";

/// Common patterns that indicate hardcoded secrets.
/// Each entry is (pattern_name, regex_pattern).
const SECRET_PATTERNS: &[(&str, &str)] = &[
    ("AWS Access Key", r"AKIA[0-9A-Z]{16}"),
    (
        "AWS Secret Key",
        r#"(?i)(aws_secret|secret_key)\s*[=:]\s*["']?[A-Za-z0-9/+=]{40}"#,
    ),
    ("GitHub Token", r"gh[ps]_[A-Za-z0-9_]{36,}"),
    (
        "Generic API Key",
        r#"(?i)(api[_-]?key|apikey)\s*[=:]\s*["']?[A-Za-z0-9_\-]{20,}"#,
    ),
    (
        "Generic Secret",
        r#"(?i)(secret|password|passwd|token)\s*[=:]\s*["']?[^\s'"]{8,}"#,
    ),
    ("Stripe Key", r"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    ("GitHub Fine-Grained Token", r"github_pat_[A-Za-z0-9_]{82}"),
    ("Slack Token", r"xox[bpas]-[A-Za-z0-9\-]+"),
    ("Anthropic API Key", r"sk-ant-[A-Za-z0-9\-]+"),
    (
        "Private Key Header",
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
    ),
];

/// Generate the shell script content for the pre-commit hook.
fn hook_script() -> String {
    use std::fmt::Write;
    let mut patterns = String::new();
    for (name, pattern) in SECRET_PATTERNS {
        let _ = write!(
            patterns,
            "    if echo \"$staged_content\" | grep -qE '{pattern}'; then\n\
             \x20       echo \"  [!] Possible {name} found in staged files\"\n\
             \x20       found=1\n\
             \x20   fi\n",
        );
    }

    format!(
        r#"#!/bin/sh
# EnvVault pre-commit hook — blocks commits containing hardcoded secrets.
# Auto-installed by `envvault init`. Remove this file to disable.

staged_content=$(git diff --cached --diff-filter=ACM -U0)
found=0

{patterns}
if [ "$found" -eq 1 ]; then
    echo ""
    echo "  EnvVault: Potential secrets detected in staged files!"
    echo "  Use 'envvault set <KEY>' to store secrets securely."
    echo "  To bypass this check: git commit --no-verify"
    echo ""
    exit 1
fi

exit 0
"#
    )
}

/// Install the EnvVault pre-commit hook into the project's `.git/hooks/`.
///
/// If a pre-commit hook already exists, it is left untouched and a
/// warning is returned instead of overwriting.
pub fn install_hook(project_dir: &Path) -> Result<InstallResult> {
    let git_dir = project_dir.join(".git");
    if !git_dir.is_dir() {
        return Ok(InstallResult::NotAGitRepo);
    }

    let hooks_dir = git_dir.join("hooks");
    if !hooks_dir.exists() {
        fs::create_dir_all(&hooks_dir).map_err(|e| {
            EnvVaultError::CommandFailed(format!("failed to create hooks dir: {e}"))
        })?;
    }

    let hook_path = hooks_dir.join(HOOK_NAME);

    if hook_path.exists() {
        // Check if it's our hook (contains our marker comment).
        let existing = fs::read_to_string(&hook_path).unwrap_or_default();
        if existing.contains("EnvVault pre-commit hook") {
            return Ok(InstallResult::AlreadyInstalled);
        }
        return Ok(InstallResult::ExistingHookFound);
    }

    let script = hook_script();
    fs::write(&hook_path, script).map_err(|e| {
        EnvVaultError::CommandFailed(format!("failed to write pre-commit hook: {e}"))
    })?;

    // Make the hook executable on Unix.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o755);
        fs::set_permissions(&hook_path, perms).map_err(|e| {
            EnvVaultError::CommandFailed(format!("failed to set hook permissions: {e}"))
        })?;
    }

    Ok(InstallResult::Installed)
}

/// Result of attempting to install the pre-commit hook.
pub enum InstallResult {
    /// Hook was installed successfully.
    Installed,
    /// Our hook is already installed.
    AlreadyInstalled,
    /// A different pre-commit hook already exists (not ours).
    ExistingHookFound,
    /// Not inside a git repository.
    NotAGitRepo,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn install_hook_in_non_git_dir() {
        let dir = TempDir::new().unwrap();
        match install_hook(dir.path()).unwrap() {
            InstallResult::NotAGitRepo => {}
            _ => panic!("expected NotAGitRepo"),
        }
    }

    #[test]
    fn install_hook_creates_hook_file() {
        let dir = TempDir::new().unwrap();
        // Create a fake .git/hooks directory.
        fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();

        match install_hook(dir.path()).unwrap() {
            InstallResult::Installed => {}
            _ => panic!("expected Installed"),
        }

        let hook_path = dir.path().join(".git/hooks/pre-commit");
        assert!(hook_path.exists());

        let content = fs::read_to_string(&hook_path).unwrap();
        assert!(content.contains("EnvVault pre-commit hook"));
    }

    #[test]
    fn install_hook_twice_returns_already_installed() {
        let dir = TempDir::new().unwrap();
        fs::create_dir_all(dir.path().join(".git/hooks")).unwrap();

        install_hook(dir.path()).unwrap();

        match install_hook(dir.path()).unwrap() {
            InstallResult::AlreadyInstalled => {}
            _ => panic!("expected AlreadyInstalled"),
        }
    }

    #[test]
    fn install_hook_respects_existing_hook() {
        let dir = TempDir::new().unwrap();
        let hooks_dir = dir.path().join(".git/hooks");
        fs::create_dir_all(&hooks_dir).unwrap();

        // Write a foreign pre-commit hook.
        fs::write(hooks_dir.join("pre-commit"), "#!/bin/sh\necho hi\n").unwrap();

        match install_hook(dir.path()).unwrap() {
            InstallResult::ExistingHookFound => {}
            _ => panic!("expected ExistingHookFound"),
        }
    }

    #[test]
    fn hook_script_contains_secret_patterns() {
        let script = hook_script();
        assert!(script.contains("AWS Access Key"));
        assert!(script.contains("Stripe Key"));
        assert!(script.contains("GitHub Fine-Grained Token"));
        assert!(script.contains("Slack Token"));
        assert!(script.contains("Anthropic API Key"));
        assert!(script.contains("Private Key Header"));
        assert!(script.contains("EnvVault"));
    }
}
