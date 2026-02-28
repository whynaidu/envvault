//! Integration tests for the EnvVault CLI.
//!
//! These tests exercise the binary end-to-end using `assert_cmd`.
//! Tests that require interactive password input are difficult to
//! automate, so we focus on non-interactive cases (--help, version)
//! and structural checks (vault directory creation).

use assert_cmd::Command;
use assert_fs::TempDir;
use predicates::prelude::*;

/// Helper: get a Command pointing at the envvault binary.
fn envvault() -> Command {
    #[allow(deprecated)]
    Command::cargo_bin("envvault").expect("binary should exist")
}

#[test]
fn help_flag_shows_usage() {
    envvault()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Encrypted environment variable manager",
        ))
        .stdout(predicate::str::contains("init"))
        .stdout(predicate::str::contains("set"))
        .stdout(predicate::str::contains("get"))
        .stdout(predicate::str::contains("list"))
        .stdout(predicate::str::contains("delete"))
        .stdout(predicate::str::contains("run"))
        .stdout(predicate::str::contains("rotate-key"))
        .stdout(predicate::str::contains("export"))
        .stdout(predicate::str::contains("import"));
}

#[test]
fn version_flag_shows_version() {
    envvault()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("envvault"));
}

#[test]
fn no_args_shows_help() {
    // Running with no subcommand should show an error or help.
    envvault()
        .assert()
        .failure()
        .stderr(predicate::str::contains("Usage"));
}

#[test]
fn get_on_missing_vault_fails() {
    let tmp = TempDir::new().unwrap();

    // Trying to get a secret from a non-existent vault should fail.
    // We pipe "testpass" to stdin to avoid the interactive prompt hanging.
    envvault()
        .args([
            "get",
            "MY_KEY",
            "--vault-dir",
            tmp.path().join(".envvault").to_str().unwrap(),
        ])
        .current_dir(tmp.path())
        .write_stdin("testpass\n")
        .assert()
        .failure();
}

#[test]
fn run_with_no_command_fails() {
    envvault().arg("run").assert().failure();
}

#[test]
fn invalid_env_name_rejected() {
    envvault()
        .args(["--env", "UPPER", "list"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("invalid"));
}

#[test]
fn export_help_shows_format_options() {
    envvault()
        .args(["export", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("format"))
        .stdout(predicate::str::contains("output"));
}

#[test]
fn import_help_shows_file_arg() {
    envvault()
        .args(["import", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("file"));
}

#[test]
fn auth_help_shows_subcommands() {
    envvault()
        .args(["auth", "--help"])
        .assert()
        .success()
        .stdout(predicate::str::contains("keyring"))
        .stdout(predicate::str::contains("keyfile-generate"));
}
