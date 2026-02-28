//! `envvault version` — display version and check for updates.

use console::style;

use crate::errors::Result;

/// Execute the `version` command.
pub fn execute() -> Result<()> {
    let current = env!("CARGO_PKG_VERSION");
    println!("envvault {current}");

    // Check for updates (behind feature flag, never fails).
    match crate::version_check::check_latest_version(current) {
        Some(latest) => {
            println!(
                "\n{} A newer version is available: {} → {}",
                style("Update available!").yellow().bold(),
                style(current).red(),
                style(&latest).green().bold()
            );
            println!("  Run {} to update", style("cargo install envvault").cyan());
        }
        None => {
            println!("{}", style("You're up to date!").green());
        }
    }

    Ok(())
}
