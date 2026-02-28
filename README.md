# EnvVault

**A local-first encrypted environment variable manager.**

[![CI](https://github.com/whynaidu/envvault/actions/workflows/ci.yml/badge.svg)](https://github.com/whynaidu/envvault/actions/workflows/ci.yml)
[![Crates.io](https://img.shields.io/crates/v/envvault)](https://crates.io/crates/envvault)
[![License](https://img.shields.io/crates/l/envvault)](LICENSE-MIT)

Replace plaintext `.env` files with AES-256-GCM encrypted vault files. No cloud service, no infrastructure — just a CLI and a password.

## Features

- **Per-secret encryption** — each secret is individually encrypted with AES-256-GCM
- **Strong key derivation** — Argon2id (64 MB memory, 3 iterations) protects against brute-force attacks
- **Multiple environments** — separate vault files for dev, staging, prod, etc.
- **Auto-import** — detects existing `.env` files and imports them on `envvault init`
- **Secret injection** — run any command with secrets injected as environment variables
- **Two-factor auth** — optional keyfile + password for high-security vaults
- **OS keyring** — auto-unlock vaults via your OS credential store
- **Audit log** — SQLite-backed log of all vault operations
- **Diff & edit** — compare environments and edit secrets in your `$EDITOR`
- **Export/import** — exchange secrets as `.env` or JSON files
- **Git hooks** — pre-commit scanning for leaked secrets
- **Shell completions** — bash, zsh, fish, and PowerShell

## Installation

### Cargo (from source)

```sh
cargo install envvault-cli
```

### Download binary

Grab the latest release for your platform from [GitHub Releases](https://github.com/whynaidu/envvault/releases).

### Homebrew (macOS / Linux)

```sh
brew install whynaidu/tap/envvault
```

### Curl installer

```sh
curl -fsSL https://raw.githubusercontent.com/whynaidu/envvault/main/install.sh | sh
```

## Quick Start

```sh
# Initialize a vault (auto-imports .env if present)
envvault init

# Add a secret
envvault set DATABASE_URL          # interactive prompt (recommended)
envvault set API_KEY "sk-abc123"   # inline (visible in shell history)

# Retrieve a secret
envvault get DATABASE_URL

# List all secrets
envvault list

# Run a command with secrets injected
envvault run -- node server.js

# Use a different environment
envvault -e staging set DATABASE_URL
envvault -e staging run -- node server.js
```

## Command Reference

| Command | Description |
|---------|-------------|
| `init` | Initialize a new vault (auto-imports `.env`) |
| `set <KEY> [VALUE]` | Add or update a secret (omit value for interactive prompt) |
| `get <KEY>` | Retrieve a secret's value |
| `list` | List all secret names |
| `delete <KEY>` | Delete a secret (`-f` to skip confirmation) |
| `run -- <CMD>` | Run a command with secrets as env vars (`--clean-env` for isolation) |
| `rotate-key` | Change the vault's master password |
| `export` | Export secrets (`-f env\|json`, `-o <file>`) |
| `import <FILE>` | Import secrets from `.env` or JSON |
| `diff <ENV>` | Compare secrets between environments (`--show-values`) |
| `edit` | Open secrets in `$EDITOR` |
| `env list` | List all vault environments |
| `env clone <TARGET>` | Clone current environment (`--new-password`) |
| `env delete <NAME>` | Delete a vault environment (`-f` to skip confirmation) |
| `audit` | View audit log (`--last N`, `--since 7d`) |
| `completions <SHELL>` | Generate shell completions (bash, zsh, fish, powershell) |
| `version` | Show version info |
| `auth keyring` | Save/delete vault password in OS keyring (`--delete`) |
| `auth keyfile-generate` | Generate a random keyfile |

### Global Options

| Option | Description |
|--------|-------------|
| `-e, --env <NAME>` | Environment to use (default: `dev`) |
| `--vault-dir <DIR>` | Vault directory (default: `.envvault`) |
| `--keyfile <PATH>` | Path to keyfile for two-factor auth |

## Configuration

EnvVault can be configured with a `.envvault.toml` file in your project root:

```toml
# Default environment when -e is not specified
default_environment = "dev"

# Directory for vault files (relative to project root)
vault_dir = ".envvault"

# Argon2id KDF parameters
argon2_memory_kib = 65536    # 64 MB
argon2_iterations = 3
argon2_parallelism = 4
```

All fields are optional — sensible defaults are used when omitted.

## Feature Flags

EnvVault has two optional Cargo feature flags:

| Feature | Description |
|---------|-------------|
| `keyring-store` | Enable OS keyring integration for auto-unlock (`cargo install envvault-cli --features keyring-store`) |
| `version-check` | Check for new versions on `envvault version` (`cargo install envvault-cli --features version-check`) |

Both are disabled by default to minimize dependencies.

## Security Model

- **Encryption**: AES-256-GCM with per-secret random 12-byte nonces
- **Key derivation**: Argon2id (memory-hard, GPU-resistant) with per-vault random salt
- **Per-secret keys**: HKDF-SHA256 derives a unique encryption key for each secret from the master key
- **Integrity**: HMAC-SHA256 over the entire vault file detects tampering
- **Memory safety**: All key material is zeroized after use via the `zeroize` crate
- **Atomic writes**: Vault files are written to a temp file and renamed to prevent corruption
- **Keyfile auth**: Optional second factor combined with password via HMAC-SHA256
- **Constant-time comparison**: Keyfile hashes compared using `subtle::ConstantTimeEq`

### Vault Format

```
[EVLT magic: 4 bytes][version: 1 byte][header_len: 4 bytes][header JSON][secrets JSON][HMAC-SHA256: 32 bytes]
```

Key names are stored in plaintext so `list` works without decryption. Values are individually encrypted.

## License

Licensed under either of:

- [MIT License](LICENSE-MIT)
- [Apache License, Version 2.0](LICENSE-APACHE)

at your option.
