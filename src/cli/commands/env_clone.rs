//! `envvault env clone` — clone an environment's secrets to a new vault.

use zeroize::Zeroize;

use crate::cli::output;
use crate::cli::{
    load_keyfile, prompt_new_password, prompt_password_for_vault, validate_env_name, Cli,
};
use crate::config::Settings;
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute `envvault env clone <target>`.
pub fn execute(cli: &Cli, target: &str, new_password: bool) -> Result<()> {
    validate_env_name(target)?;

    let cwd = std::env::current_dir()?;
    let vault_dir = cwd.join(&cli.vault_dir);
    let env = &cli.env;
    let source_path = vault_dir.join(format!("{env}.vault"));
    let target_path = vault_dir.join(format!("{target}.vault"));

    if !source_path.exists() {
        return Err(EnvVaultError::EnvironmentNotFound(cli.env.clone()));
    }
    if target_path.exists() {
        return Err(EnvVaultError::VaultAlreadyExists(target_path));
    }

    // Open source vault and decrypt all secrets.
    let keyfile = load_keyfile(cli)?;
    let vault_id = source_path.to_string_lossy();
    let password = prompt_password_for_vault(Some(&vault_id))?;
    let source = VaultStore::open(&source_path, password.as_bytes(), keyfile.as_deref())?;
    let mut secrets = source.get_all_secrets()?;

    // Determine the target password.
    let target_pw = if new_password {
        output::info("Choose a password for the new vault.");
        prompt_new_password()?
    } else {
        password
    };

    // Create the target vault with the same (or new) password.
    let settings = Settings::load(&cwd)?;
    let mut target_store = VaultStore::create(
        &target_path,
        target_pw.as_bytes(),
        target,
        Some(&settings.argon2_params()),
        keyfile.as_deref(),
    )?;

    // Copy all secrets.
    let count = secrets.len();
    for (name, value) in &secrets {
        target_store.set_secret(name, value)?;
    }
    target_store.save()?;

    // Zeroize plaintext secrets.
    for value in secrets.values_mut() {
        value.zeroize();
    }

    crate::audit::log_audit(
        cli,
        "env-clone",
        None,
        Some(&format!("{count} secrets, {env} -> {target}")),
    );

    output::success(&format!(
        "Cloned {} secrets from '{}' to '{}' environment",
        count, cli.env, target
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_vault(
        dir: &std::path::Path,
        env: &str,
        password: &str,
        secrets: &HashMap<String, String>,
    ) {
        let vault_path = dir.join(format!("{env}.vault"));
        let mut store =
            VaultStore::create(&vault_path, password.as_bytes(), env, None, None).unwrap();
        for (k, v) in secrets {
            store.set_secret(k, v).unwrap();
        }
        store.save().unwrap();
    }

    #[test]
    fn clone_copies_all_secrets() {
        let dir = tempfile::TempDir::new().unwrap();
        let mut secrets = HashMap::new();
        secrets.insert("DB_URL".into(), "postgres://localhost".into());
        secrets.insert("API_KEY".into(), "secret123".into());

        create_test_vault(dir.path(), "dev", "testpassword1", &secrets);

        // Clone dev -> staging.
        let staging_path = dir.path().join("staging.vault");
        let source_path = dir.path().join("dev.vault");
        let source = VaultStore::open(&source_path, b"testpassword1", None).unwrap();
        let source_secrets = source.get_all_secrets().unwrap();

        let mut target =
            VaultStore::create(&staging_path, b"testpassword1", "staging", None, None).unwrap();
        for (k, v) in &source_secrets {
            target.set_secret(k, v).unwrap();
        }
        target.save().unwrap();

        // Verify target has the same secrets.
        let reopened = VaultStore::open(&staging_path, b"testpassword1", None).unwrap();
        let target_secrets = reopened.get_all_secrets().unwrap();
        assert_eq!(target_secrets.len(), 2);
        assert_eq!(target_secrets["DB_URL"], "postgres://localhost");
        assert_eq!(target_secrets["API_KEY"], "secret123");
    }

    #[test]
    fn clone_rejects_invalid_target_name() {
        let result = validate_env_name("INVALID");
        assert!(result.is_err());
    }

    #[test]
    fn clone_fails_if_target_exists() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("staging.vault");
        std::fs::write(&path, b"exists").unwrap();
        assert!(path.exists());
    }
}
