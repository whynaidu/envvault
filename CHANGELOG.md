# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.0] - 2026-04-15

Phase 6 — Secret Lifecycle + Metadata. Adds first-class metadata
(description, tags, expiration), one-level undo history, and a
tamper-evident audit chain with JSON compliance reports. Vault format
bumps to v2; v1 files are read transparently and upgrade on first
write. Test suite grows from 159 to 283.

### Added
- **Vault format v2** — `Secret` records now carry optional `description`, `tags`, and `expires_at` metadata
- Readers accept both v1 and v2 vaults; any write transparently upgrades a v1 file to v2
- `envvault set --description <TEXT>` — attach a human-readable description to a secret
- `envvault set --tag <TAG>` (repeatable) — attach classification tags (e.g., `provider:stripe`)
- `envvault set --expires <DURATION>` — record an expiration timestamp (e.g. `30m`, `24h`, `90d`, `2w`, `1y`)
- `envvault set --no-description` / `--no-tags` / `--no-expires` — clear existing metadata
- `envvault list --tag <PATTERN>` (repeatable, AND semantics) — filter secrets by tag substring
- `envvault list --expired` — show only secrets past their expiration
- `envvault list --expiring-in <DURATION>` — show secrets expiring within a window
- `envvault run` now prints a warning on stderr for each expired secret it injects (e.g. `STALE_TOKEN expired 3 days ago`)
- `list` output conditionally adds `Description` / `Tags` / `Expires` columns when any secret has metadata; expired entries are highlighted in red
- `VaultStore::set_description`, `set_tags`, `set_expires_at` public API
- `Secret::is_expired()` and `SecretMetadata::is_expired()` helpers
- `envvault::cli::duration` module — shared duration parser (`m/h/d/w/y`) reused by `set`, `list`, and `audit`
- **One-level secret history** — `set` now retains the prior encrypted value in a single-slot history
- `envvault get <KEY> --previous` — decrypt and print the retained prior value (works with `--clipboard`)
- `envvault rollback <KEY>` — restore the retained prior value and clear the slot (`-f` skips confirmation)
- `VaultStore::get_previous_secret`, `rollback_secret`, `has_previous`, `previous_updated_at` public API
- `Secret.previous_encrypted_value` + `previous_updated_at` fields (skip-serializing when absent; format-v2 compatible, no bump)
- History preserved through save/reopen; wiped on `rotate-key` and `env clone` (those re-encrypt from plaintext)
- Rollback preserves description, tags, and expiration — it's a value-level undo
- Tag normalization: trim, drop empties, dedup, sort, 128-char length limit
- Metadata (description, tags, expires_at) preserved across `set_secret` value updates
- **Tamper-evident audit log** — each entry now carries an `entry_hash` SHA-256 digest linked to its predecessor, forming a hash chain (audit schema v6)
- `envvault audit verify` — walks the chain, reports intact / first-broken-id, non-zero exit on mismatch
- `envvault compliance-report` — single-vault JSON report with encryption config, KDF params, secret/expiration inventory, key-rotation history, and chain-verification status (SOC 2 / HIPAA / PCI-DSS ready)
- `AuditLog::verify_chain` and `ChainVerification` public API
- Entries written before the v6 migration are counted as `legacy_entries` and do not themselves flag the chain as broken

### Errors
- New `EnvVaultError::NoPreviousValue(String)` — raised by `get --previous` and `rollback` when no history is retained

## [0.5.1] - 2026-03-03

### Added
- `envvault update` command — auto-detects install method (cargo, homebrew, curl) and self-updates
- `version` command now suggests `envvault update` instead of `cargo install`

## [0.5.0] - 2026-03-03

### Added
- `search <pattern>` command — find secrets by glob pattern (`*`, `?` wildcards, case-insensitive)
- `scan` command — detect leaked secrets in project files using built-in and custom regex patterns
- `scan --ci` flag — exit code 1 when secrets found (for CI/CD pipelines)
- `set --force` flag — skip the shell-history warning for inline values
- `import --dry-run` flag — preview what would be imported without modifying the vault
- `import --skip-existing` flag — only import new secrets, preserving existing values
- `run --only` and `--exclude` flags — filter which secrets are injected (comma-separated)
- `run --redact-output` flag — replace secret values with `[REDACTED]` in child process output
- `ENVVAULT_INJECTED=true` marker — always injected into child process environment by `run`
- `audit export` subcommand — export audit log entries to JSON or CSV
- `audit purge` subcommand — delete audit entries older than a specified duration
- `[audit] log_reads` config option — optionally log read operations (get, list, run)
- `[secret_scanning] custom_patterns` config — user-defined regex patterns for `scan`
- `keyfile_path` config option — default keyfile path in `.envvault.toml` or global config
- `allowed_environments` config option — restrict valid environment names (typo protection)
- `editor` config option — set preferred editor for `envvault edit`
- Global config support (`~/.config/envvault/config.toml`)
- Audit log schema v5 — added `user`, `pid` columns and timestamp index
- `get --clipboard` flag — copy secret to clipboard with 30-second auto-clear
- `rotate-key --new-keyfile` flag — change or remove keyfile during password rotation
- `run --allowed-commands` flag — restrict which commands can be executed (comma-separated basenames)
- Process isolation for `run` — prevents `/proc/pid/environ` leaks (Linux) and debugger attachment (macOS)
- `scan --gitleaks-config` flag — load rules from a gitleaks-format TOML config file
- `[secret_scanning] gitleaks_config` config option — default gitleaks config path in `.envvault.toml`

### Changed
- `audit-log` feature flag — audit log can be disabled with `--no-default-features` for smaller binary
- Upgraded `rand` to 0.9, `ureq` to 3
- Cleaned up `.gitignore` (removed leaked test artifact paths)

## [0.4.1] - 2026-03-02

### Fixed
- Switched Linux release builds from glibc (`linux-gnu`) to statically-linked musl (`linux-musl`), fixing `GLIBC_2.39 not found` errors on Amazon Linux and other distros with older glibc
- Resolved macOS symlink handling in keyfile gitignore test
- Fixed `cargo fmt` formatting in `env_delete` test

### Changed
- Optimized GitHub Actions CI workflows
- Install script (`install.sh`) now downloads musl binaries for Linux

## [0.4.0] - 2026-02-28

### Added
- GitHub Actions CI workflow (Linux, macOS, Windows)
- GitHub Actions release workflow with cross-platform binary builds
- Homebrew formula (`Formula/envvault.rb`)
- Curl installer script (`install.sh`)
- `README.md` with full documentation
- `CHANGELOG.md` (this file)
- `Cargo.toml` metadata for crates.io publishing

### Changed
- Cleaned up `.gitignore` (removed test artifacts, added project patterns)

## [0.3.0] - 2026-02-27

### Added
- `diff` command — compare secrets between two environments
- `edit` command — open secrets in `$EDITOR` (decrypts to temp file, re-encrypts on save)
- `env list` — list all vault environments
- `env clone` — clone an environment (with optional new password)
- `env delete` — delete a vault environment
- `audit` command — view the SQLite audit log of vault operations
- `completions` command — generate shell completions (bash, zsh, fish, powershell)
- `version` command — show version and check for updates
- Audit log (SQLite) wired into all mutating commands
- `version-check` feature flag (optional update check via GitHub API)

## [0.2.0] - 2026-02-26

### Added
- `rotate-key` command — change the vault's master password
- `export` command — export secrets to `.env` or JSON format
- `import` command — import secrets from `.env` or JSON files
- `auth keyring` — save/delete vault password in OS keyring
- `auth keyfile-generate` — generate a random keyfile for two-factor vault access
- Keyfile authentication (HMAC-SHA256 combined with password)
- OS keyring integration (behind `keyring-store` feature flag)
- Git pre-commit hook for secret leak detection
- Constant-time comparison for keyfile hashes

### Security
- HKDF info labels use full prefixes to prevent key reuse across domains
- Keyfile hash stored in vault header; missing keyfile produces a clear error
- Keyring entries keyed by vault file path (prevents cross-vault leakage)

## [0.1.0] - 2026-02-25

### Added
- `init` command — initialize a new vault (auto-imports `.env` if present)
- `set` command — add or update a secret (interactive or inline)
- `get` command — retrieve a secret's value
- `list` command — list all secret names
- `delete` command — remove a secret (with confirmation)
- `run` command — execute a command with secrets injected as environment variables
- AES-256-GCM per-secret encryption with random nonces
- Argon2id key derivation (64 MB memory, 3 iterations, 4 parallelism)
- HMAC-SHA256 vault integrity verification
- HKDF-SHA256 per-secret key derivation
- Binary vault format with magic bytes and versioning
- `.envvault.toml` configuration file support
- `ENVVAULT_PASSWORD` environment variable for CI/CD usage
- Atomic file writes (temp file + rename)

[0.6.0]: https://github.com/whynaidu/envvault/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/whynaidu/envvault/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/whynaidu/envvault/compare/v0.4.1...v0.5.0
[0.4.1]: https://github.com/whynaidu/envvault/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/whynaidu/envvault/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/whynaidu/envvault/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/whynaidu/envvault/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/whynaidu/envvault/releases/tag/v0.1.0
