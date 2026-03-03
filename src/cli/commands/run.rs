//! `envvault run` — inject secrets into a child process.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};

use zeroize::Zeroize;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `run` command.
pub fn execute(
    cli: &Cli,
    command: &[String],
    clean_env: bool,
    only: Option<&[String]>,
    exclude: Option<&[String]>,
    redact_output: bool,
    allowed_commands: Option<&[String]>,
) -> Result<()> {
    if command.is_empty() {
        return Err(EnvVaultError::NoCommandSpecified);
    }

    // Validate the command against the allow list (if configured).
    if let Some(allowed) = allowed_commands {
        validate_allowed_command(&command[0], allowed)?;
    }

    let path = vault_path(cli)?;

    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = match VaultStore::open(&path, password.as_bytes(), keyfile.as_deref()) {
        Ok(store) => store,
        Err(e) => {
            #[cfg(feature = "audit-log")]
            crate::audit::log_auth_failure(cli, &e.to_string());
            return Err(e);
        }
    };

    // Decrypt all secrets into memory.
    let mut secrets = store.get_all_secrets()?;

    // Apply --only filter: keep only the specified keys.
    if let Some(only_keys) = only {
        secrets.retain(|k, _| only_keys.iter().any(|o| o == k));
    }

    // Apply --exclude filter: remove the specified keys.
    if let Some(exclude_keys) = exclude {
        secrets.retain(|k, _| !exclude_keys.iter().any(|e| e == k));
    }

    if clean_env {
        output::success(&format!(
            "Injected {} secrets into clean environment",
            secrets.len()
        ));
    } else {
        output::success(&format!(
            "Injected {} secrets into environment",
            secrets.len()
        ));
    }

    // Build the child process.
    let program = &command[0];
    let args = &command[1..];

    let mut cmd = Command::new(program);
    cmd.args(args);

    if clean_env {
        cmd.env_clear();
    }

    // Always inject the marker so child processes know they're running under envvault.
    cmd.env("ENVVAULT_INJECTED", "true");

    // Apply process isolation on Unix (prevent /proc/pid/environ leaks).
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: apply_process_isolation calls prctl/ptrace, which are simple
        // kernel syscalls with no memory side effects. Called after fork()
        // but before exec().
        unsafe {
            cmd.pre_exec(|| {
                apply_process_isolation();
                Ok(())
            });
        }
    }

    #[cfg(feature = "audit-log")]
    let secret_count = secrets.len();

    let status = if redact_output {
        // Pipe stdout/stderr and redact secret values.
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        let mut child = cmd.envs(&secrets).spawn()?;

        let secret_values: Vec<String> = secrets
            .values()
            .filter(|v| !v.is_empty())
            .cloned()
            .collect();

        // Read and redact stdout.
        if let Some(stdout) = child.stdout.take() {
            let values = secret_values.clone();
            std::thread::spawn(move || {
                let reader = BufReader::new(stdout);
                for line in reader.lines().map_while(|r| r.ok()) {
                    println!("{}", redact_line(&line, &values));
                }
            });
        }

        // Read and redact stderr.
        if let Some(stderr) = child.stderr.take() {
            let values = secret_values;
            std::thread::spawn(move || {
                let reader = BufReader::new(stderr);
                for line in reader.lines().map_while(|r| r.ok()) {
                    eprintln!("{}", redact_line(&line, &values));
                }
            });
        }

        child.wait()?
    } else {
        cmd.envs(&secrets).status()?
    };

    // Zeroize plaintext secrets — the child process has its own copies.
    for v in secrets.values_mut() {
        v.zeroize();
    }

    #[cfg(feature = "audit-log")]
    crate::audit::log_read_audit(
        cli,
        "run",
        None,
        Some(&format!("{secret_count} secrets injected")),
    );

    // Forward the child's exit code.
    match status.code() {
        Some(0) => Ok(()),
        Some(code) => Err(EnvVaultError::ChildProcessFailed(code)),
        None => Err(EnvVaultError::CommandFailed(
            "child process terminated by signal".into(),
        )),
    }
}

/// Validate that a command is in the allowed list.
///
/// Extracts the basename from the command path (e.g. `/usr/bin/node` → `node`)
/// and checks if it's in the allow list.
pub fn validate_allowed_command(program: &str, allowed: &[String]) -> Result<()> {
    let basename = Path::new(program)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(program);

    if allowed.iter().any(|a| a == basename) {
        Ok(())
    } else {
        Err(EnvVaultError::CommandNotAllowed(format!(
            "'{basename}' is not in the allowed commands list: {:?}",
            allowed
        )))
    }
}

/// Apply OS-level process isolation to prevent secret leaks.
///
/// - Linux: `PR_SET_DUMPABLE(0)` prevents reading `/proc/pid/environ`
/// - macOS: `PT_DENY_ATTACH` prevents debugger attachment
#[cfg(unix)]
fn apply_process_isolation() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: prctl is a simple kernel syscall with no memory side effects.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // SAFETY: ptrace is a simple kernel syscall with no memory side effects.
        unsafe {
            libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0);
        }
    }
}

/// Replace any occurrence of secret values in a line with `[REDACTED]`.
pub fn redact_line(line: &str, secret_values: &[String]) -> String {
    let mut result = line.to_string();
    for value in secret_values {
        if !value.is_empty() {
            result = result.replace(value.as_str(), "[REDACTED]");
        }
    }
    result
}

/// Filter secrets by only/exclude lists. Used for testing.
pub fn filter_secrets(
    secrets: &mut std::collections::HashMap<String, String>,
    only: Option<&[String]>,
    exclude: Option<&[String]>,
) {
    if let Some(only_keys) = only {
        secrets.retain(|k, _| only_keys.iter().any(|o| o == k));
    }
    if let Some(exclude_keys) = exclude {
        secrets.retain(|k, _| !exclude_keys.iter().any(|e| e == k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn filter_only_keeps_specified_keys() {
        let mut secrets = HashMap::from([
            ("A".into(), "1".into()),
            ("B".into(), "2".into()),
            ("C".into(), "3".into()),
        ]);
        let only = vec!["A".to_string(), "C".to_string()];
        filter_secrets(&mut secrets, Some(&only), None);
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("A"));
        assert!(secrets.contains_key("C"));
        assert!(!secrets.contains_key("B"));
    }

    #[test]
    fn filter_exclude_removes_specified_keys() {
        let mut secrets = HashMap::from([
            ("A".into(), "1".into()),
            ("B".into(), "2".into()),
            ("C".into(), "3".into()),
        ]);
        let exclude = vec!["B".to_string()];
        filter_secrets(&mut secrets, None, Some(&exclude));
        assert_eq!(secrets.len(), 2);
        assert!(secrets.contains_key("A"));
        assert!(secrets.contains_key("C"));
    }

    #[test]
    fn filter_only_and_exclude_combined() {
        let mut secrets = HashMap::from([
            ("A".into(), "1".into()),
            ("B".into(), "2".into()),
            ("C".into(), "3".into()),
        ]);
        let only = vec!["A".to_string(), "B".to_string()];
        let exclude = vec!["B".to_string()];
        filter_secrets(&mut secrets, Some(&only), Some(&exclude));
        assert_eq!(secrets.len(), 1);
        assert!(secrets.contains_key("A"));
    }

    #[test]
    fn filter_no_flags_keeps_all() {
        let mut secrets = HashMap::from([("A".into(), "1".into()), ("B".into(), "2".into())]);
        filter_secrets(&mut secrets, None, None);
        assert_eq!(secrets.len(), 2);
    }

    #[test]
    fn redact_replaces_secret_values() {
        let secrets = vec!["s3cr3t".to_string(), "p@ssw0rd".to_string()];
        assert_eq!(
            redact_line("my password is s3cr3t", &secrets),
            "my password is [REDACTED]"
        );
        assert_eq!(redact_line("auth: p@ssw0rd", &secrets), "auth: [REDACTED]");
    }

    #[test]
    fn redact_leaves_safe_lines_alone() {
        let secrets = vec!["secret123".to_string()];
        assert_eq!(redact_line("no secrets here", &secrets), "no secrets here");
    }

    #[test]
    fn redact_handles_empty_secrets() {
        let secrets: Vec<String> = vec![];
        assert_eq!(redact_line("some output", &secrets), "some output");
    }

    #[test]
    fn redact_multiple_occurrences() {
        let secrets = vec!["tok".to_string()];
        assert_eq!(
            redact_line("tok and tok again", &secrets),
            "[REDACTED] and [REDACTED] again"
        );
    }

    // --- allowed_commands tests ---

    #[test]
    fn allowed_command_passes_for_basename() {
        let allowed = vec!["node".to_string(), "python".to_string()];
        assert!(validate_allowed_command("node", &allowed).is_ok());
        assert!(validate_allowed_command("python", &allowed).is_ok());
    }

    #[test]
    fn allowed_command_extracts_basename_from_path() {
        let allowed = vec!["node".to_string()];
        assert!(validate_allowed_command("/usr/bin/node", &allowed).is_ok());
        assert!(validate_allowed_command("/usr/local/bin/node", &allowed).is_ok());
    }

    #[test]
    fn disallowed_command_returns_error() {
        let allowed = vec!["node".to_string()];
        let err = validate_allowed_command("python", &allowed).unwrap_err();
        assert!(err.to_string().contains("not in the allowed commands list"));
    }

    #[test]
    fn disallowed_command_with_full_path_returns_error() {
        let allowed = vec!["node".to_string()];
        let err = validate_allowed_command("/usr/bin/python", &allowed).unwrap_err();
        assert!(err.to_string().contains("python"));
    }
}
