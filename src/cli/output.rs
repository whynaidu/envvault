//! Colored terminal output helpers.
//!
//! All user-facing output goes through these functions so we get
//! consistent styling across every command.

use comfy_table::{ContentArrangement, Table};
use console::style;

use crate::vault::SecretMetadata;

/// Print a green success message: "check_mark {msg}"
pub fn success(msg: &str) {
    println!("{} {}", style("\u{2713}").green().bold(), msg);
}

/// Print a red error message: "x_mark {msg}"
pub fn error(msg: &str) {
    eprintln!("{} {}", style("\u{2717}").red().bold(), msg);
}

/// Print a yellow warning: "warning_sign {msg}"
pub fn warning(msg: &str) {
    eprintln!("{} {}", style("\u{26a0}").yellow().bold(), msg);
}

/// Print a blue info message: "info_sign {msg}"
pub fn info(msg: &str) {
    println!("{} {}", style("\u{2139}").blue().bold(), msg);
}

/// Print a dim tip/hint: "arrow {msg}"
pub fn tip(msg: &str) {
    println!("{} {}", style("\u{2192}").dim(), style(msg).dim());
}

/// Print a table of secret metadata (Name, Created, Updated).
pub fn print_secrets_table(secrets: &[SecretMetadata]) {
    if secrets.is_empty() {
        info("No secrets in this vault yet.");
        tip("Run `envvault set <KEY>` to add your first secret.");
        return;
    }

    let mut table = Table::new();
    table.set_content_arrangement(ContentArrangement::Dynamic);
    table.set_header(vec!["Name", "Created", "Updated"]);

    for s in secrets {
        table.add_row(vec![
            s.name.clone(),
            s.created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            s.updated_at.format("%Y-%m-%d %H:%M:%S").to_string(),
        ]);
    }

    println!("{table}");
}
