use clap::Parser;
use envvault::cli::{validate_env_name, AuthAction, Cli, Commands, EnvAction};

fn main() {
    let cli = Cli::parse();

    // Validate the environment name early to catch typos.
    if let Err(e) = validate_env_name(&cli.env) {
        envvault::cli::output::error(&e.to_string());
        std::process::exit(1);
    }

    let result = match cli.command {
        Commands::Init => envvault::cli::commands::init::execute(&cli),
        Commands::Set { ref key, ref value } => {
            envvault::cli::commands::set::execute(&cli, key, value.as_deref())
        }
        Commands::Get { ref key } => envvault::cli::commands::get::execute(&cli, key),
        Commands::List => envvault::cli::commands::list::execute(&cli),
        Commands::Delete { ref key, force } => {
            envvault::cli::commands::delete::execute(&cli, key, force)
        }
        Commands::Run {
            ref command,
            clean_env,
        } => envvault::cli::commands::run::execute(&cli, command, clean_env),
        Commands::RotateKey => envvault::cli::commands::rotate::execute(&cli),
        Commands::Export {
            ref format,
            ref output,
        } => envvault::cli::commands::export::execute(&cli, format, output.as_deref()),
        Commands::Import {
            ref file,
            ref format,
        } => envvault::cli::commands::import_cmd::execute(&cli, file, format.as_deref()),
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
        Commands::Audit { last, ref since } => {
            envvault::cli::commands::audit_cmd::execute(&cli, last, since.as_deref())
        }
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
