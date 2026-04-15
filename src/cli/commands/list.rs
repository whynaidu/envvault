//! `envvault list` — display all secrets in a table.

use crate::cli::output;
use crate::cli::{duration, load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::Result;
use crate::vault::VaultStore;

/// Execute the `list` command.
///
/// `filter_tags` — a secret is included only if every pattern matches
/// (substring, case-sensitive) at least one of the secret's tags.
/// `expired` — when true, keep only secrets past their expiration.
/// `expiring_in` — when `Some`, keep only secrets whose expiration
/// falls between now and `now + DURATION`.
pub fn execute(
    cli: &Cli,
    filter_tags: &[String],
    expired: bool,
    expiring_in: Option<&str>,
) -> Result<()> {
    // Resolve --expiring-in up front so bad input fails before any
    // password prompt.
    let expiring_cutoff = match expiring_in {
        Some(s) => Some(duration::parse_future(s)?),
        None => None,
    };

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

    let now = chrono::Utc::now();
    let mut secrets: Vec<_> = store.list_secrets();

    if !filter_tags.is_empty() {
        secrets.retain(|s| {
            filter_tags
                .iter()
                .all(|pattern| s.tags.iter().any(|t| t.contains(pattern)))
        });
    }

    if expired {
        secrets.retain(|s| matches!(s.expires_at, Some(exp) if exp <= now));
    } else if let Some(cutoff) = expiring_cutoff {
        // "Expiring in 7d" = has an expiry > now AND <= now + 7d.
        // Already-expired secrets are excluded; use `--expired` for those.
        secrets.retain(|s| matches!(s.expires_at, Some(exp) if exp > now && exp <= cutoff));
    }

    let count = secrets.len();
    let suffix = match (filter_tags.is_empty(), expired, &expiring_in) {
        (true, false, None) => String::new(),
        (false, false, None) => format!(" matching tag filter {filter_tags:?}"),
        (true, true, None) => " expired".to_string(),
        (false, true, None) => format!(" expired matching tag filter {filter_tags:?}"),
        (true, false, Some(d)) => format!(" expiring within {d}"),
        (false, false, Some(d)) => {
            format!(" expiring within {d} matching tag filter {filter_tags:?}")
        }
        // --expired and --expiring-in are mutually exclusive via clap.
        (_, true, Some(_)) => String::new(),
    };

    output::info(&format!(
        "{} environment — {} secret(s){}",
        cli.env, count, suffix
    ));

    output::print_secrets_table(&secrets);

    #[cfg(feature = "audit-log")]
    crate::audit::log_read_audit(cli, "list", None, Some(&format!("{count} secrets")));

    Ok(())
}
