#[cfg(feature = "audit-log")]
pub mod audit;

#[cfg(not(feature = "audit-log"))]
pub mod audit {
    //! No-op audit stub when the `audit-log` feature is disabled.
    pub fn log_audit(
        _cli: &crate::cli::Cli,
        _op: &str,
        _key: Option<&str>,
        _details: Option<&str>,
    ) {
    }

    pub fn log_read_audit(
        _cli: &crate::cli::Cli,
        _op: &str,
        _key: Option<&str>,
        _details: Option<&str>,
    ) {
    }

    pub fn log_auth_failure(_cli: &crate::cli::Cli, _details: &str) {}
}

pub mod cli;
pub mod config;
pub mod crypto;
pub mod errors;
pub mod git;
pub mod vault;
pub mod version_check;

#[cfg(feature = "keyring-store")]
pub mod keyring;
