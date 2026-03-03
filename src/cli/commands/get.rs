//! `envvault get` — retrieve and print a single secret's value.

use crate::cli::{load_keyfile, prompt_password_for_vault, vault_path, Cli};
use crate::errors::{EnvVaultError, Result};
use crate::vault::VaultStore;

/// Execute the `get` command.
pub fn execute(cli: &Cli, key: &str, clipboard: bool) -> Result<()> {
    let path = vault_path(cli)?;
    let keyfile = load_keyfile(cli)?;

    // Open the vault (requires password).
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

    // Decrypt the secret value.
    let value = store.get_secret(key)?;

    if clipboard {
        copy_to_clipboard(&value)?;
        crate::cli::output::success(&format!("Copied '{key}' to clipboard (clears in 30s)"));

        // Spawn a background process to clear the clipboard after 30 seconds.
        spawn_clipboard_clear();
    } else {
        println!("{value}");
    }

    #[cfg(feature = "audit-log")]
    crate::audit::log_read_audit(cli, "get", Some(key), None);

    Ok(())
}

/// Copy a value to the system clipboard using arboard.
fn copy_to_clipboard(value: &str) -> Result<()> {
    let mut clip = arboard::Clipboard::new()
        .map_err(|e| EnvVaultError::ClipboardError(format!("failed to access clipboard: {e}")))?;
    clip.set_text(value)
        .map_err(|e| EnvVaultError::ClipboardError(format!("failed to copy to clipboard: {e}")))?;
    Ok(())
}

/// Spawn a detached background process to clear the clipboard after 30 seconds.
///
/// Best-effort: if it fails, we just warn — the secret was already copied.
#[cfg(unix)]
fn spawn_clipboard_clear() {
    use std::process::{Command, Stdio};

    // Try xclip first, fall back to xsel, then pbcopy (macOS).
    let clear_cmd = "sleep 30 && \
        (printf '' | xclip -selection clipboard 2>/dev/null || \
         xsel --clipboard --delete 2>/dev/null || \
         printf '' | pbcopy 2>/dev/null || true)";

    let result = Command::new("sh")
        .args(["-c", clear_cmd])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();

    if result.is_err() {
        crate::cli::output::warning("Could not schedule clipboard auto-clear");
    }
}

#[cfg(not(unix))]
fn spawn_clipboard_clear() {
    crate::cli::output::warning(
        "Clipboard auto-clear is not supported on this platform — clear manually",
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clipboard_copy_returns_error_on_invalid_clipboard() {
        // In a headless CI environment, clipboard access may fail.
        // This tests that our error wrapping works correctly.
        let result = copy_to_clipboard("test-value");
        // We can't assert success because CI may not have a display server,
        // but we CAN assert that any error is correctly wrapped.
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(msg.contains("clipboard") || msg.contains("Clipboard"));
        }
    }
}
