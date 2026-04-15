//! `envvault compliance-report` — generate a compliance summary in JSON.
//!
//! Produces a single-vault report containing the encryption
//! parameters, secret inventory, expiration status, key-rotation
//! history, and audit-chain status. Intended as machine-readable
//! input for SOC 2 / HIPAA / PCI-DSS audit tooling.
//!
//! Single-environment by design for v0.6. A cross-env aggregate
//! report fits the same schema and will be added alongside the
//! multi-vault unlock plumbing (tracked under roadmap follow-ups).

use chrono::{DateTime, Utc};
use serde::Serialize;

use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Top-level compliance report payload.
#[derive(Debug, Serialize)]
pub struct ComplianceReport {
    pub generator: String,
    pub generated_at: DateTime<Utc>,
    pub vault: VaultSection,
    pub secrets: SecretsSummary,
    pub expired_secrets: Vec<ExpiryEntry>,
    pub expiring_soon: Vec<ExpiryEntry>,
    pub audit: AuditSection,
}

#[derive(Debug, Serialize)]
pub struct VaultSection {
    pub path: String,
    pub environment: String,
    pub created_at: DateTime<Utc>,
    pub format_version: u8,
    pub encryption: &'static str,
    pub kdf: KdfSection,
    pub keyfile_required: bool,
}

#[derive(Debug, Serialize)]
pub struct KdfSection {
    pub algorithm: &'static str,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

#[derive(Debug, Serialize)]
pub struct SecretsSummary {
    pub total: usize,
    pub with_description: usize,
    pub with_tags: usize,
    pub with_expiration: usize,
    pub expired: usize,
    pub expiring_within_30d: usize,
    pub with_history: usize,
}

#[derive(Debug, Serialize)]
pub struct ExpiryEntry {
    pub name: String,
    pub expires_at: DateTime<Utc>,
    pub description: Option<String>,
    /// Days remaining (negative if already expired).
    pub days_remaining: i64,
}

#[derive(Debug, Serialize)]
pub struct AuditSection {
    pub available: bool,
    pub total_entries: usize,
    pub last_entry_at: Option<DateTime<Utc>>,
    pub chain_status: String,
    pub chain_entries_checked: usize,
    pub chain_legacy_entries: usize,
    pub read_logging_enabled: bool,
    pub key_rotations: Vec<KeyRotationEntry>,
}

#[derive(Debug, Serialize)]
pub struct KeyRotationEntry {
    pub timestamp: DateTime<Utc>,
    pub user: Option<String>,
    pub details: Option<String>,
}

/// Execute the `compliance-report` command.
pub fn execute(cli: &Cli, format: &str, output_path: Option<&str>) -> Result<()> {
    if format != "json" {
        return Err(EnvVaultError::CommandFailed(format!(
            "unsupported compliance-report format '{format}' — only 'json' is supported"
        )));
    }

    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;
    let vault_id = path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let store = VaultStore::open(&path, password.as_bytes(), keyfile.as_deref())?;

    let report = build_report(cli, &store)?;

    let json = serde_json::to_string_pretty(&report)
        .map_err(|e| EnvVaultError::SerializationError(format!("report JSON: {e}")))?;

    match output_path {
        Some(p) => {
            std::fs::write(p, &json)?;
            crate::cli::output::success(&format!("Compliance report written to {p}"));
        }
        None => println!("{json}"),
    }

    crate::audit::log_audit(cli, "compliance-report", None, Some(&cli.env));

    Ok(())
}

/// Build an in-memory `ComplianceReport` for the currently-open vault.
///
/// Exposed for tests so they can exercise the aggregation logic
/// without re-prompting for a password.
pub fn build_report(cli: &Cli, store: &VaultStore) -> Result<ComplianceReport> {
    let now = Utc::now();
    let header = store.header();
    let kdf_params = header.argon2_params.unwrap_or_default();

    // Secrets inventory.
    let secrets = store.list_secrets();
    let mut with_description = 0usize;
    let mut with_tags = 0usize;
    let mut with_expiration = 0usize;
    let mut expired = 0usize;
    let mut expiring_within_30d = 0usize;
    let mut with_history = 0usize;
    let mut expired_entries = Vec::new();
    let mut expiring_entries = Vec::new();

    let window_30d = now + chrono::Duration::days(30);

    for s in &secrets {
        if s.description.is_some() {
            with_description += 1;
        }
        if !s.tags.is_empty() {
            with_tags += 1;
        }
        if let Some(exp) = s.expires_at {
            with_expiration += 1;
            let days_remaining = (exp - now).num_days();
            if exp <= now {
                expired += 1;
                expired_entries.push(ExpiryEntry {
                    name: s.name.clone(),
                    expires_at: exp,
                    description: s.description.clone(),
                    days_remaining,
                });
            } else if exp <= window_30d {
                expiring_within_30d += 1;
                expiring_entries.push(ExpiryEntry {
                    name: s.name.clone(),
                    expires_at: exp,
                    description: s.description.clone(),
                    days_remaining,
                });
            }
        }
        if store.has_previous(&s.name) {
            with_history += 1;
        }
    }

    // Stable sort: soonest expiring first within each list.
    expired_entries.sort_by_key(|e| e.expires_at);
    expiring_entries.sort_by_key(|e| e.expires_at);

    let vault_section = VaultSection {
        path: store.path().to_string_lossy().to_string(),
        environment: store.environment().to_string(),
        created_at: store.created_at(),
        format_version: header.version,
        encryption: "AES-256-GCM",
        kdf: KdfSection {
            algorithm: "Argon2id",
            memory_kib: kdf_params.memory_kib,
            iterations: kdf_params.iterations,
            parallelism: kdf_params.parallelism,
        },
        keyfile_required: header.keyfile_hash.is_some(),
    };

    let audit_section = collect_audit(cli)?;

    Ok(ComplianceReport {
        generator: format!("envvault v{}", env!("CARGO_PKG_VERSION")),
        generated_at: now,
        vault: vault_section,
        secrets: SecretsSummary {
            total: secrets.len(),
            with_description,
            with_tags,
            with_expiration,
            expired,
            expiring_within_30d,
            with_history,
        },
        expired_secrets: expired_entries,
        expiring_soon: expiring_entries,
        audit: audit_section,
    })
}

/// Pull audit-log stats (when the audit-log feature is enabled).
#[cfg(feature = "audit-log")]
fn collect_audit(cli: &Cli) -> Result<AuditSection> {
    use crate::audit::AuditLog;

    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);

    let audit = match AuditLog::open(&vault_dir) {
        Some(a) => a,
        None => {
            return Ok(AuditSection {
                available: false,
                total_entries: 0,
                last_entry_at: None,
                chain_status: "unavailable".to_string(),
                chain_entries_checked: 0,
                chain_legacy_entries: 0,
                read_logging_enabled: false,
                key_rotations: Vec::new(),
            });
        }
    };

    // All entries, newest first.
    let entries = audit.query(i64::MAX as usize, None)?;
    let last_entry_at = entries.first().map(|e| e.timestamp);

    let key_rotations: Vec<KeyRotationEntry> = entries
        .iter()
        .filter(|e| e.operation == "rotate-key")
        .map(|e| KeyRotationEntry {
            timestamp: e.timestamp,
            user: e.user.clone(),
            details: e.details.clone(),
        })
        .collect();

    let verification = audit.verify_chain()?;
    let chain_status = if verification.intact {
        "intact".to_string()
    } else {
        match verification.first_broken_id {
            Some(id) => format!("broken at entry {id}"),
            None => "broken".to_string(),
        }
    };

    let settings = crate::config::Settings::load(&cwd).unwrap_or_default();

    Ok(AuditSection {
        available: true,
        total_entries: entries.len(),
        last_entry_at,
        chain_status,
        chain_entries_checked: verification.entries_checked,
        chain_legacy_entries: verification.legacy_entries,
        read_logging_enabled: settings.audit.log_reads,
        key_rotations,
    })
}

#[cfg(not(feature = "audit-log"))]
fn collect_audit(_cli: &Cli) -> Result<AuditSection> {
    Ok(AuditSection {
        available: false,
        total_entries: 0,
        last_entry_at: None,
        chain_status: "feature-disabled".to_string(),
        chain_entries_checked: 0,
        chain_legacy_entries: 0,
        read_logging_enabled: false,
        key_rotations: Vec::new(),
    })
}
