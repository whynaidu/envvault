# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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

[0.4.0]: https://github.com/vedant-naidu/envvault/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/vedant-naidu/envvault/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/vedant-naidu/envvault/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/vedant-naidu/envvault/releases/tag/v0.1.0
