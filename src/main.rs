use clap::Parser;
use envvault::cli::{validate_env_name, AuditAction, AuthAction, Cli, Commands, EnvAction};

fn main() {
    let cli = Cli::parse();

    // Validate the environment name early to catch typos.
    if let Err(e) = validate_env_name(&cli.env) {
        envvault::cli::output::error(&e.to_string());
        std::process::exit(1);
    }

    // If allowed_environments is configured, reject names not in the list.
    if let Ok(cwd) = std::env::current_dir() {
        if let Ok(settings) = envvault::config::Settings::load(&cwd) {
            if let Err(e) = envvault::config::validate_env_against_config(&cli.env, &settings) {
                envvault::cli::output::error(&e.to_string());
                std::process::exit(1);
            }
        }
    }

    let result = match cli.command {
        Commands::Init => envvault::cli::commands::init::execute(&cli),
        Commands::Set {
            ref key,
            ref value,
            force,
        } => envvault::cli::commands::set::execute(&cli, key, value.as_deref(), force),
        Commands::Get { ref key, clipboard } => {
            envvault::cli::commands::get::execute(&cli, key, clipboard)
        }
        Commands::List => envvault::cli::commands::list::execute(&cli),
        Commands::Delete { ref key, force } => {
            envvault::cli::commands::delete::execute(&cli, key, force)
        }
        Commands::Run {
            ref command,
            clean_env,
            ref only,
            ref exclude,
            redact_output,
            ref allowed_commands,
        } => envvault::cli::commands::run::execute(
            &cli,
            command,
            clean_env,
            only.as_deref(),
            exclude.as_deref(),
            redact_output,
            allowed_commands.as_deref(),
        ),
        Commands::RotateKey { ref new_keyfile } => {
            envvault::cli::commands::rotate::execute(&cli, new_keyfile.as_deref())
        }
        Commands::Export {
            ref format,
            ref output,
        } => envvault::cli::commands::export::execute(&cli, format, output.as_deref()),
        Commands::Import {
            ref file,
            ref format,
            dry_run,
            skip_existing,
        } => envvault::cli::commands::import_cmd::execute(
            &cli,
            file,
            format.as_deref(),
            dry_run,
            skip_existing,
        ),
        Commands::Env { ref action } => match action {
            EnvAction::List => envvault::cli::commands::env_list::execute(&cli),
            EnvAction::Clone {
                ref target,
                new_password,
            } => envvault::cli::commands::env_clone::execute(&cli, target, *new_password),
            EnvAction::Delete { ref name, force } => {
                envvault::cli::commands::env_delete::execute(&cli, name, *force)
            }
        },
        Commands::Diff {
            ref target_env,
            show_values,
        } => envvault::cli::commands::diff::execute(&cli, target_env, show_values),
        Commands::Edit => envvault::cli::commands::edit::execute(&cli),
        Commands::Version => envvault::cli::commands::version::execute(),
        Commands::Completions { ref shell } => envvault::cli::commands::completions::execute(shell),
        Commands::Scan {
            ci,
            ref dir,
            ref gitleaks_config,
        } => envvault::cli::commands::scan::execute(ci, dir.as_deref(), gitleaks_config.as_deref()),
        Commands::Search { ref pattern } => envvault::cli::commands::search::execute(&cli, pattern),
        Commands::Audit {
            ref action,
            last,
            ref since,
        } => match action {
            Some(AuditAction::Export {
                ref format,
                ref output,
            }) => {
                envvault::cli::commands::audit_cmd::execute_export(&cli, format, output.as_deref())
            }
            Some(AuditAction::Purge { ref older_than }) => {
                envvault::cli::commands::audit_cmd::execute_purge(&cli, older_than)
            }
            None => envvault::cli::commands::audit_cmd::execute(&cli, last, since.as_deref()),
        },
        Commands::Auth { ref action } => match action {
            AuthAction::Keyring { delete } => {
                envvault::cli::commands::auth::execute_keyring(&cli, *delete)
            }
            AuthAction::KeyfileGenerate { ref path } => {
                envvault::cli::commands::auth::execute_keyfile_generate(&cli, path.as_deref())
            }
        },
    };

    if let Err(e) = result {
        envvault::cli::output::error(&e.to_string());
        std::process::exit(1);
    }
}
