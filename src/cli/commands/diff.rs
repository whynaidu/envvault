//! `envvault diff` — compare secrets between two environments.
//!
//! Usage:
//!   envvault diff staging              # compare dev (default) vs staging
//!   envvault --env prod diff staging --show-values

use std::collections::BTreeSet;

use zeroize::Zeroize;

use crate::cli::output;
use crate::cli::{load_keyfile, prompt_password_for_vault, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Outcome of comparing two vaults.
pub struct DiffResult {
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub changed: Vec<String>,
    pub unchanged: Vec<String>,
}

/// Execute the `diff` command.
pub fn execute(cli: &Cli, target_env: &str, show_values: bool) -> Result<()> {
    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);

    let env = &cli.env;
    let source_path = vault_dir.join(format!("{env}.vault"));
    let target_path = vault_dir.join(format!("{target_env}.vault"));

    if !source_path.exists() {
        return Err(EnvVaultError::EnvironmentNotFound(cli.env.clone()));
    }
    if !target_path.exists() {
        return Err(EnvVaultError::EnvironmentNotFound(target_env.to_string()));
    }

    // Open source vault.
    let keyfile = load_keyfile(cli)?;
    let vault_id = source_path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let source = VaultStore::open(&source_path, password.as_bytes(), keyfile.as_deref())?;
    let mut source_secrets = source.get_all_secrets()?;

    // Try opening target with the same password first.
    let mut target_secrets =
        match VaultStore::open(&target_path, password.as_bytes(), keyfile.as_deref()) {
            Ok(target) => target.get_all_secrets()?,
            Err(EnvVaultError::HmacMismatch | EnvVaultError::DecryptionFailed) => {
                // Different password — prompt for target.
                output::info(&format!(
                    "Target vault '{target_env}' uses a different password."
                ));
                let target_vault_id = target_path.to_string_lossy();
                let target_pw = prompt_password_for_vault(Some(&target_vault_id))?;
                let target =
                    VaultStore::open(&target_path, target_pw.as_bytes(), keyfile.as_deref())?;
                target.get_all_secrets()?
            }
            Err(e) => return Err(e),
        };

    // Compute diff.
    let diff = compute_diff(&source_secrets, &target_secrets);

    crate::audit::log_audit(
        cli,
        "diff",
        None,
        Some(&format!("compared {env} vs {target_env}")),
    );

    // Print results.
    print_diff(
        cli,
        target_env,
        &diff,
        &source_secrets,
        &target_secrets,
        show_values,
    );

    // Zeroize plaintext secrets before returning.
    for v in source_secrets.values_mut() {
        v.zeroize();
    }
    for v in target_secrets.values_mut() {
        v.zeroize();
    }

    Ok(())
}

/// Compare two secret maps and categorize keys.
pub fn compute_diff(
    source: &std::collections::HashMap<String, String>,
    target: &std::collections::HashMap<String, String>,
) -> DiffResult {
    let source_keys: BTreeSet<&String> = source.keys().collect();
    let target_keys: BTreeSet<&String> = target.keys().collect();

    // Keys only in target = added (already sorted by BTreeSet).
    let added: Vec<String> = target_keys
        .difference(&source_keys)
        .map(|k| (*k).clone())
        .collect();

    // Keys only in source = removed (already sorted by BTreeSet).
    let removed: Vec<String> = source_keys
        .difference(&target_keys)
        .map(|k| (*k).clone())
        .collect();

    // Keys in both — partition into changed vs unchanged.
    let (mut changed, mut unchanged): (Vec<String>, Vec<String>) = source_keys
        .intersection(&target_keys)
        .map(|k| (*k).clone())
        .partition(|key| source[key] != target[key]);

    changed.sort();
    unchanged.sort();

    DiffResult {
        added,
        removed,
        changed,
        unchanged,
    }
}

/// Print the diff results with colored output.
fn print_diff(
    cli: &Cli,
    target_env: &str,
    diff: &DiffResult,
    source: &std::collections::HashMap<String, String>,
    target: &std::collections::HashMap<String, String>,
    show_values: bool,
) {
    use console::style;

    println!(
        "\n{} {} vs {}",
        style("Diff:").bold(),
        style(&cli.env).cyan(),
        style(target_env).cyan()
    );
    println!();

    for key in &diff.added {
        if show_values {
            println!(
                "  {} {} = {}",
                style("+").green().bold(),
                style(key).green(),
                style(&target[key]).green()
            );
        } else {
            println!("  {} {}", style("+").green().bold(), style(key).green());
        }
    }

    for key in &diff.removed {
        if show_values {
            println!(
                "  {} {} = {}",
                style("-").red().bold(),
                style(key).red(),
                style(&source[key]).red()
            );
        } else {
            println!("  {} {}", style("-").red().bold(), style(key).red());
        }
    }

    for key in &diff.changed {
        if show_values {
            println!(
                "  {} {} = {} → {}",
                style("~").yellow().bold(),
                style(key).yellow(),
                style(&source[key]).red(),
                style(&target[key]).green()
            );
        } else {
            println!(
                "  {} {} {}",
                style("~").yellow().bold(),
                style(key).yellow(),
                style("(changed)").dim()
            );
        }
    }

    println!();
    println!(
        "  {} added, {} removed, {} changed, {} unchanged",
        style(diff.added.len()).green().bold(),
        style(diff.removed.len()).red().bold(),
        style(diff.changed.len()).yellow().bold(),
        style(diff.unchanged.len()).dim()
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn diff_identical_vaults() {
        let mut a = HashMap::new();
        a.insert("KEY".into(), "value".into());

        let diff = compute_diff(&a, &a);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        assert_eq!(diff.unchanged, vec!["KEY"]);
    }

    #[test]
    fn diff_added_keys() {
        let a = HashMap::new();
        let mut b = HashMap::new();
        b.insert("NEW_KEY".into(), "value".into());

        let diff = compute_diff(&a, &b);
        assert_eq!(diff.added, vec!["NEW_KEY"]);
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_removed_keys() {
        let mut a = HashMap::new();
        a.insert("OLD_KEY".into(), "value".into());
        let b = HashMap::new();

        let diff = compute_diff(&a, &b);
        assert!(diff.added.is_empty());
        assert_eq!(diff.removed, vec!["OLD_KEY"]);
        assert!(diff.changed.is_empty());
    }

    #[test]
    fn diff_changed_values() {
        let mut a = HashMap::new();
        a.insert("KEY".into(), "old_value".into());
        let mut b = HashMap::new();
        b.insert("KEY".into(), "new_value".into());

        let diff = compute_diff(&a, &b);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert_eq!(diff.changed, vec!["KEY"]);
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn diff_mixed_changes() {
        let mut source = HashMap::new();
        source.insert("KEEP".into(), "same".into());
        source.insert("MODIFY".into(), "old".into());
        source.insert("REMOVE".into(), "gone".into());

        let mut target = HashMap::new();
        target.insert("KEEP".into(), "same".into());
        target.insert("MODIFY".into(), "new".into());
        target.insert("ADD".into(), "fresh".into());

        let diff = compute_diff(&source, &target);
        assert_eq!(diff.added, vec!["ADD"]);
        assert_eq!(diff.removed, vec!["REMOVE"]);
        assert_eq!(diff.changed, vec!["MODIFY"]);
        assert_eq!(diff.unchanged, vec!["KEEP"]);
    }

    #[test]
    fn diff_empty_vaults() {
        let a: HashMap<String, String> = HashMap::new();
        let b: HashMap<String, String> = HashMap::new();

        let diff = compute_diff(&a, &b);
        assert!(diff.added.is_empty());
        assert!(diff.removed.is_empty());
        assert!(diff.changed.is_empty());
        assert!(diff.unchanged.is_empty());
    }

    #[test]
    fn diff_results_are_sorted() {
        let mut source = HashMap::new();
        source.insert("Z_KEY".into(), "v".into());
        source.insert("A_KEY".into(), "v".into());

        let mut target = HashMap::new();
        target.insert("M_KEY".into(), "v".into());
        target.insert("B_KEY".into(), "v".into());

        let diff = compute_diff(&source, &target);
        assert_eq!(diff.added, vec!["B_KEY", "M_KEY"]);
        assert_eq!(diff.removed, vec!["A_KEY", "Z_KEY"]);
    }

    #[test]
    fn diff_same_key_same_value_is_unchanged() {
        let mut a = HashMap::new();
        a.insert("DB_URL".into(), "postgres://localhost".into());
        let mut b = HashMap::new();
        b.insert("DB_URL".into(), "postgres://localhost".into());

        let diff = compute_diff(&a, &b);
        assert!(diff.changed.is_empty());
        assert_eq!(diff.unchanged, vec!["DB_URL"]);
    }
}
