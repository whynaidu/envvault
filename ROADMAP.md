# EnvVault Roadmap

> Last updated: March 2026

## Where We Are Today (v0.4.0)

EnvVault is a local-first encrypted environment variable manager. It replaces plaintext `.env` files with AES-256-GCM encrypted vault files — no cloud, no server, no infrastructure. Just a CLI and a password.

**What's shipped:**
- 19 commands covering the full secrets lifecycle (init, set, get, list, delete, run, rotate-key, export, import, diff, edit, env management, audit, completions, auth, version)
- AES-256-GCM per-secret encryption with Argon2id KDF (64 MB memory-hard)
- HMAC-SHA256 integrity verification, HKDF-SHA256 per-secret key derivation
- Three auth methods: password, keyfile (two-factor), OS keyring (auto-unlock)
- SQLite audit log of all vault mutations
- Git pre-commit hook for secret leak detection
- Cross-platform: Linux, macOS, Windows (x86_64 + ARM64)
- Distributed via cargo, Homebrew, curl installer, and GitHub Releases
- 159 tests, clippy-clean, zero unsafe code

**Market position:** EnvVault sits in a unique gap — more features than encrypted-file tools (SOPS, dotenvx, age) but zero infrastructure unlike platforms (Vault, Doppler, Infisical). It's the only local-first CLI with audit logging, multiple auth methods, and per-environment vaults that works offline out of the box.

---

## The Landscape

### What developers are saying

- **23.8 million secrets leaked** on public GitHub in 2024 (GitGuardian). 70% remain active today.
- **85% of organizations** have plaintext secrets in their repos (2025 State of Cloud Security).
- Developer teams report **8+ hours of work per .env change** when manually distributing secrets across 20 developers.
- The #1 complaint: *"The safer path feels slower or harder than the insecure one."*
- AI coding tools (85% adoption) are **increasing secret leak rates by 40%** — agents can `cat .env` or run `env` to discover secrets.
- dotenvx-pro (hosted sync) **shut down February 2026**, leaving users without a sync solution.
- SOPS is **under-maintained** after Mozilla budget cuts; transferred to community governance.

### Competitive gaps EnvVault can exploit

| What cloud tools require | What EnvVault offers |
|--------------------------|---------------------|
| Server infrastructure (Vault, Infisical) | Zero infrastructure |
| Internet connectivity (Doppler, Chamber) | Works fully offline |
| SaaS subscription ($6-12/user/mo) | Free and open source |
| Account creation + API keys before first use | `cargo install envvault-cli` and go |
| AWS-specific (Chamber) or cloud-specific | Cloud-agnostic, runs anywhere |

| What local tools lack | What EnvVault has |
|----------------------|-------------------|
| Audit trail (SOPS, dotenvx, age) | SQLite audit log |
| Multiple auth (dotenvx: single keypair) | Password + keyfile + keyring |
| Environment management (SOPS) | Per-env vault files with clone/diff |
| Key rotation (most CLI tools) | `rotate-key` command |
| Secret lifecycle (all CLI tools) | Audit, diff, edit, import/export |

---

## Roadmap

### Phase 5 — v0.5.0: Security Hardening + DX Polish

*Theme: Make the secure path the easy path.*

#### 5.1 AI-Agent Safe Mode (HIGH PRIORITY)

85% of developers now use AI coding tools. Agents with shell access can trivially read `.env` files or run `env` to discover secrets. EnvVault should be the tool developers trust in AI-assisted workflows.

- **`envvault run --redact-output`** — scan stdout/stderr of child processes and replace secret values with `[REDACTED]` before displaying. Prevents secrets from appearing in terminal output where AI agents or screen-sharing can capture them.
- **`envvault run --allowed-commands <list>`** — only inject secrets when the child process matches an allowlist. Prevents an AI agent from running `env` or `printenv` to exfiltrate secrets.
- **Environment variable naming** — prefix injected vars with metadata: `ENVVAULT_INJECTED=true` so applications can distinguish vault-injected vars from ambient environment.
- **Process isolation** — on Linux, use `prctl(PR_SET_DUMPABLE, 0)` to prevent `/proc/<pid>/environ` from leaking secrets to other processes. On macOS, use `ptrace(PT_DENY_ATTACH)`.

#### 5.2 Enhanced Secret Scanning

The current pre-commit hook detects a fixed set of patterns. Expand to a layered defense:

- **Custom pattern support** — allow `.envvault.toml` to define project-specific patterns:
  ```toml
  [secret_scanning]
  custom_patterns = [
    { name = "internal-api", regex = "mycompany_[a-zA-Z0-9]{32}" },
  ]
  ```
- **Gitleaks-compatible rule format** — import rules from the Gitleaks ecosystem for broader coverage.
- **`envvault scan`** command — on-demand scanning of the working directory for leaked secrets (not just pre-commit).
- **`envvault scan --ci`** — exit code for CI pipelines. Non-zero if secrets detected.

#### 5.3 CLI UX Improvements

- **`envvault get --clipboard`** — copy secret to clipboard without terminal output. Uses `xclip`/`wl-copy` on Linux, `pbcopy` on macOS, `clip.exe` on Windows. Auto-clears clipboard after 30 seconds.
- **`envvault set --force`** — suppress the shell-history warning for CI scripts that intentionally pass inline values.
- **`envvault import --dry-run`** — preview which secrets will be added/updated/unchanged before importing.
- **`envvault import --skip-existing`** — only import secrets that don't already exist in the vault.
- **`envvault run --only KEY1,KEY2`** — inject only specific secrets (not the entire vault).
- **`envvault run --exclude KEY1,KEY2`** — inject all secrets except the listed ones.
- **`envvault search <pattern>`** — find secrets by name pattern (glob or regex). Useful for large vaults.
- **`envvault rotate-key --keyfile`** — support changing the keyfile during key rotation (currently only password can be rotated).

#### 5.4 Config Improvements

- **`keyfile_path`** in `.envvault.toml` — declare the keyfile location once instead of passing `--keyfile` on every command:
  ```toml
  keyfile_path = ".envvault/keyfile"
  ```
- **`allowed_environments`** list — prevent silent vault proliferation from typos:
  ```toml
  allowed_environments = ["dev", "staging", "prod", "test"]
  ```
  Typing `envvault -e pdro set ...` would error instead of creating `pdro.vault`.
- **`editor`** setting — project-level editor override for `envvault edit`:
  ```toml
  editor = "code --wait"
  ```
- **Global config** at `~/.config/envvault/config.toml` — user-level defaults that apply across all projects (e.g., preferred editor, keyring behavior).

#### 5.5 Audit System Hardening

- **Log read access** — `get`, `list`, and `run` should be logged for compliance. Add a config toggle:
  ```toml
  [audit]
  log_reads = true   # default: false
  ```
- **Log failed auth attempts** — wrong password, wrong keyfile, HMAC mismatch. These are the most security-relevant events and currently go unrecorded.
- **Capture user identity** — record `$USER` / `$LOGNAME` and process ID in audit entries. Essential for team vaults.
- **`envvault audit export --format json`** — export audit logs as JSON or CSV for compliance tooling.
- **`envvault audit purge --older-than 90d`** — configurable retention policy.
- **SQLite index on timestamp** — currently audit queries are full table scans. Add index for performance with large logs.

#### 5.6 Internal Quality

- **`audit-log` feature flag** — make `rusqlite` optional. Reduces binary size by ~250KB for minimal/CI installs. The `log_audit()` calls compile to no-ops when disabled.
- **Expand CLI integration tests** — add end-to-end tests that use `ENVVAULT_PASSWORD` to exercise `init → set → get → list → run → delete` against the actual binary.
- **Fix flaky test** — `keyfile_generate_patches_gitignore` uses `set_current_dir` which races with parallel tests. Restructure to use subprocess or scoped CWD.
- **Upgrade deps** — `rand` 0.8 → 0.9, `ureq` 2.x → 3.x.

---

### Phase 6 — v0.6.0: Secret Lifecycle + Metadata

*Theme: Secrets are not static — they expire, rotate, and carry context.*

#### 6.1 Secret Metadata

Add an optional `metadata` field to the `Secret` struct (`HashMap<String, String>`, skip-serializing-if-empty). This enables:

- **Descriptions** — `envvault set API_KEY --description "Stripe production key"`
- **Tags** — `envvault set API_KEY --tag provider:stripe --tag tier:prod`
- **`envvault list --tag provider:stripe`** — filter secrets by tag.
- **Vault format v2** — bump the version byte, implement `migrate_v1_to_v2()` so existing vaults upgrade transparently on first write.

#### 6.2 Secret Expiration

- **TTL on secrets** — `envvault set API_KEY --expires 90d` records an expiry timestamp in metadata.
- **`envvault list --expired`** — show secrets past their expiration date.
- **Warning on `run`** — when injecting expired secrets, print a warning: `WARNING: API_KEY expired 3 days ago`.
- **`envvault audit --expired`** — compliance view of all expired secrets across environments.

#### 6.3 Secret History / Versioning

- **Keep previous value** — when `set` updates a secret, store the previous encrypted value as a single-level history entry.
- **`envvault get KEY --previous`** — retrieve the last-known value before the current one.
- **`envvault rollback KEY`** — restore the previous value.
- This is not full version history (that would bloat vault files) — just one level of undo.

#### 6.4 Compliance Report Generation

For organizations going through SOC 2, HIPAA, or PCI-DSS audits:

- **`envvault compliance-report`** — generates a JSON/PDF report containing:
  - Encryption algorithm and KDF parameters
  - Key rotation history (from audit log)
  - Secret access log (if `log_reads = true`)
  - Expiration status of all secrets
  - Last audit timestamp
- **Audit log signing** — append an HMAC chain to audit entries. Each entry includes the hash of the previous entry, creating a tamper-evident log. If any entry is modified or deleted, the chain breaks.

---

### Phase 7 — v0.7.0: Team Collaboration

*Theme: From solo developer tool to team-ready secrets management.*

This is the biggest gap between EnvVault and platforms like Doppler/Infisical. The goal: enable team secret sharing **without requiring a server**.

#### 7.1 Asymmetric Encryption for Sharing

- **`envvault identity init`** — generate an X25519 keypair. Public key stored in `.envvault/identities/`. Private key stored in OS keyring or as a keyfile.
- **`envvault identity add <name> <public-key>`** — register a teammate's public key.
- **`.envvault/team.toml`** — declares team members and their public keys:
  ```toml
  [[members]]
  name = "alice"
  public_key = "age1..."

  [[members]]
  name = "bob"
  public_key = "age1..."
  ```
- **Vault re-encryption for recipients** — `envvault share --to alice,bob` re-encrypts the vault's master password with each recipient's public key. Recipients can unlock without knowing the original password.
- **Use the `age` encryption format** (X25519 + ChaCha20-Poly1305) for the sharing layer. The vault contents remain AES-256-GCM encrypted.

#### 7.2 Git-Based Sync

Vault files are already binary blobs that can be committed to git. Build on this:

- **`envvault sync push`** / **`envvault sync pull`** — thin wrappers around `git add .envvault/ && git commit && git push` with smart conflict resolution.
- **Merge strategy** — when two people edit the same vault, compare secret-by-secret and:
  - Auto-merge if different keys were changed
  - Prompt for conflict resolution if the same key was changed by both
- **`.envvault/.gitattributes`** — register a custom merge driver for `.vault` files.

#### 7.3 Access Policies

- **Per-environment access** — declare who can access which environments:
  ```toml
  [access]
  prod = ["alice"]         # only alice can decrypt prod
  staging = ["alice", "bob"]
  dev = ["*"]              # everyone
  ```
- **Read-only mode** — some team members can `get` and `run` but not `set` or `delete`.
- **Enforced via encryption** — access control is cryptographic, not policy-based. If you don't have the key, you can't decrypt. No server needed to enforce.

#### 7.4 Onboarding / Offboarding

- **`envvault team add <name>`** — add a new team member, re-encrypt relevant vaults for their public key.
- **`envvault team remove <name>`** — remove a team member and automatically rotate all vault passwords they had access to.
- **Onboarding workflow** — new developer runs `envvault identity init`, shares their public key, team lead runs `envvault team add`, new developer can now decrypt.

---

### Phase 8 — v0.8.0: Ecosystem Integration

*Theme: Meet developers where they are.*

#### 8.1 CI/CD Integration

- **GitHub Actions action** — `uses: whynaidu/envvault-action@v1`:
  ```yaml
  - uses: whynaidu/envvault-action@v1
    with:
      vault-password: ${{ secrets.ENVVAULT_PASSWORD }}
      environment: prod
  # Secrets are now available as environment variables
  ```
- **GitLab CI template** — `.gitlab-ci.yml` include for secret injection.
- **Generic CI helper** — `envvault ci export --format github` outputs `::add-mask::` and `GITHUB_ENV` lines. `--format gitlab` outputs `export` commands for GitLab.

#### 8.2 Container Integration

- **`envvault run --docker <image>`** — build a `docker run -e` command with all secrets injected, without writing them to a file or Dockerfile.
- **`envvault export --format docker-env`** — generate a `--env-file` compatible output.
- **`envvault export --format kubernetes-secret`** — generate a Kubernetes `Secret` YAML manifest (base64-encoded values).

#### 8.3 Framework Integration

- **`envvault export --format dotenv`** — already exists, but add:
- **Watch mode** — `envvault watch` monitors the vault file and regenerates a cached `.env` in memory for frameworks that need it. The `.env` file lives in a tmpfs mount and is never written to persistent storage.
- **Node.js loader** — `node --require envvault/register app.js` that calls `envvault export` at startup and populates `process.env`.

#### 8.4 Import from Other Tools

- **`envvault import --from sops <file>`** — parse SOPS-encrypted YAML/JSON (requires `sops` binary or `age` key).
- **`envvault import --from dotenvx <file>`** — parse dotenvx encrypted `.env` files.
- **`envvault import --from 1password <vault-name>`** — import via `op` CLI.
- **`envvault import --from aws-ssm --prefix /myapp/`** — import from AWS SSM Parameter Store.
- **Migration guides** — documentation for moving from each tool.

#### 8.5 IDE Integration

- **VS Code extension** — `envvault-vscode`:
  - Inline secret name autocomplete in code files (reads vault key names, never values)
  - "Peek secret" command that shows the value in a transient notification (never written to editor state)
  - Status bar indicator showing active environment
  - Command palette integration for all envvault commands
- **JetBrains plugin** — same feature set for IntelliJ, WebStorm, etc.

---

### Phase 9 — v0.9.0: Advanced Security

*Theme: Defense in depth for high-security environments.*

#### 9.1 Hardware Key Support

- **YubiKey / FIDO2** — use a hardware key as the second factor instead of a keyfile:
  ```sh
  envvault init --hardware-key
  envvault set API_KEY  # tap YubiKey to unlock
  ```
- **Implementation** — use the `ctap-hid-fido2` or `openpgp-card` crate. The hardware key performs ECDH; the result is combined with the password via HMAC (same pattern as keyfile).
- **TPM binding** — on Linux, bind the vault to the machine's TPM. The vault can only be opened on the specific machine that created it (useful for production servers).

#### 9.2 Memory Protection

- **`mlock`** — lock secret pages in memory to prevent swapping to disk. Use `libc::mlock` on Unix.
- **Guard pages** — allocate secrets in a dedicated memory region with guard pages before and after to detect buffer overflows.
- **`prctl(PR_SET_DUMPABLE, 0)`** — prevent core dumps from containing secrets.

#### 9.3 Canary Secrets

- **`envvault set --canary HONEYPOT_KEY`** — create a secret that should never be used. If it appears in any log, network request, or external service, you know there's been a leak.
- **Webhook notification** — when a canary secret is detected in use (via an external service like CanaryTokens), trigger an alert.

#### 9.4 Encrypted Audit Log

- **Option to encrypt audit.db** — the audit database is currently plaintext. For high-security environments, encrypt it with the vault's master key. Trade-off: viewing the audit log requires authentication.
- **Config toggle:**
  ```toml
  [audit]
  encrypted = true
  ```

#### 9.5 ChaCha20-Poly1305 Alternative

- AES-256-GCM is fast on hardware with AES-NI but slower on low-end ARM (Raspberry Pi, older Android).
- Offer ChaCha20-Poly1305 as an opt-in cipher for portability:
  ```toml
  cipher = "chacha20-poly1305"  # default: "aes-256-gcm"
  ```

---

### Phase 10 — v1.0.0: Stable Release

*Theme: Production-ready, battle-tested, fully documented.*

#### 10.1 Stability Guarantees

- **Vault format frozen** — v2 format is the stable format. Migration path guaranteed from v1 → v2. No breaking changes without a major version bump.
- **CLI interface frozen** — all existing commands, flags, and exit codes are stable. New features are additive only.
- **MSRV policy** — document minimum supported Rust version (currently 1.70). Bump only in minor releases.

#### 10.2 TUI Mode

- **`envvault tui`** — interactive terminal UI built with `ratatui`:
  - Browse environments and secrets
  - Fuzzy search across all secrets
  - Inline edit values
  - Side-by-side diff between environments
  - Audit log viewer with filters

#### 10.3 Plugin System

- **`envvault plugin install <name>`** — extend EnvVault with community plugins:
  - **Provider plugins** — fetch secrets from external sources (AWS, GCP, Azure, 1Password) and inject them alongside vault secrets.
  - **Hook plugins** — custom actions on secret set/get/delete (e.g., auto-rotate an AWS key when it expires).
  - **Scanner plugins** — custom secret detection patterns.
- **Plugin format** — WASM modules (via `wasmtime`) for sandboxed, cross-platform plugins. Or simple shell scripts for lightweight extensions.

#### 10.4 SDK / Library API

- **Rust crate** — `envvault` is already a library (`lib.rs`). Stabilize the public API surface for programmatic use.
- **Python bindings** — via PyO3. `pip install envvault` provides a Python module:
  ```python
  from envvault import Vault
  vault = Vault.open(".envvault/dev.vault", password="...")
  db_url = vault.get("DATABASE_URL")
  ```
- **Node.js bindings** — via napi-rs. `npm install envvault` provides:
  ```javascript
  const { Vault } = require('envvault');
  const vault = Vault.open('.envvault/dev.vault', { password: '...' });
  ```
- **Go bindings** — via CGO or a subprocess wrapper.

#### 10.5 Comprehensive Documentation

- **docs.rs API docs** — full rustdoc for the library.
- **User guide** — hosted at `envvault.dev` or GitHub Pages:
  - Getting started (5-minute tutorial)
  - Configuration reference
  - Security model deep-dive
  - Team workflow guide
  - CI/CD integration recipes
  - Migration guides (from SOPS, dotenvx, Vault, .env files)
  - Compliance guide (SOC 2, HIPAA, PCI-DSS artifacts)
- **Man pages** — installed via Homebrew.

---

## Release Timeline (Estimated)

| Version | Theme | Key Deliverables |
|---------|-------|-----------------|
| **v0.5.0** | Security + DX | AI-safe mode, clipboard, search, config improvements, audit hardening |
| **v0.6.0** | Secret Lifecycle | Metadata, TTL/expiry, secret history, compliance reports, vault format v2 |
| **v0.7.0** | Team Collaboration | Asymmetric encryption, git-based sync, access policies, onboarding |
| **v0.8.0** | Ecosystem | CI/CD actions, Docker, framework loaders, import from SOPS/dotenvx, IDE extensions |
| **v0.9.0** | Advanced Security | Hardware keys, memory protection, canary secrets, encrypted audit, ChaCha20 |
| **v1.0.0** | Stable Release | TUI, plugin system, language SDKs, frozen API/format, docs site |

---

## Guiding Principles

1. **Local-first, always.** Cloud features are opt-in layers. EnvVault must work fully offline, forever.
2. **Zero infrastructure.** No server, no database, no Docker container, no cloud account. `cargo install` and go.
3. **The secure path must be the easy path.** If developers choose `.env` files because they're easier, we've failed.
4. **Beginner-friendly.** Clear error messages, helpful tips, rich CLI output. A developer with zero security background should be productive in 5 minutes.
5. **No vendor lock-in.** Export to any format. Import from any tool. The vault format is documented and open.
6. **Cryptographic access control.** Permissions enforced by encryption, not policy files. If you don't have the key, you can't read the secret. No server needed.

---

## Competitive Positioning

**Tagline:** *"What dotenvx and SOPS should have been."*

| | .env files | SOPS | dotenvx | Infisical | Doppler | **EnvVault** |
|---|---|---|---|---|---|---|
| Encryption at rest | No | Yes | Yes | Yes | Yes | **Yes** |
| Works offline | Yes | Partial | Yes | No | No | **Yes** |
| Audit trail | No | No | No | Yes | Yes | **Yes** |
| Multiple auth methods | N/A | GPG/KMS | Keypair | SSO/Token | SSO/Token | **Password + keyfile + keyring** |
| Per-environment vaults | Manual | Manual | Yes | Yes | Yes | **Yes** |
| Key rotation | Manual | Manual | No | Yes | Yes | **Yes** |
| Diff environments | No | No | No | Yes | Yes | **Yes** |
| Secret lifecycle | No | No | No | Partial | Yes | **Planned (v0.6)** |
| Team sharing | Copy/paste | GPG keys | Git | Built-in | Built-in | **Planned (v0.7)** |
| AI-agent safety | No | No | No | No | No | **Planned (v0.5)** |
| Infrastructure required | None | KMS (optional) | None | Server | Cloud | **None** |
| Cost | Free | Free | Free | Free/$72/mo | Free/$230/mo | **Free** |
| Open source | N/A | Yes (MPL) | Yes (BSD) | Yes (MIT) | No | **Yes (MIT/Apache)** |

---

*This roadmap is a living document. Priorities may shift based on community feedback, security research, and ecosystem changes. Contributions welcome at [github.com/whynaidu/envvault](https://github.com/whynaidu/envvault).*
