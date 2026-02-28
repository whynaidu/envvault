#!/bin/sh
# EnvVault installer — downloads the latest release binary for your platform.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/whynaidu/envvault/main/install.sh | sh
#
# Environment variables:
#   ENVVAULT_VERSION   — install a specific version (e.g. "v0.4.0")
#   INSTALL_DIR        — install directory (default: /usr/local/bin or ~/.local/bin)

set -eu

REPO="whynaidu/envvault"
BINARY="envvault"

# ── Helpers ──────────────────────────────────────────────────────────

info()  { printf '  \033[1;34m>\033[0m %s\n' "$@"; }
ok()    { printf '  \033[1;32m✓\033[0m %s\n' "$@"; }
err()   { printf '  \033[1;31m✗\033[0m %s\n' "$@" >&2; exit 1; }

need() {
    command -v "$1" >/dev/null 2>&1 || err "Required command not found: $1"
}

# ── Detect platform ─────────────────────────────────────────────────

detect_os() {
    case "$(uname -s)" in
        Linux*)  echo "linux" ;;
        Darwin*) echo "macos" ;;
        *)       err "Unsupported OS: $(uname -s). Use 'cargo install envvault' instead." ;;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)   echo "x86_64" ;;
        aarch64|arm64)  echo "aarch64" ;;
        *)              err "Unsupported architecture: $(uname -m)" ;;
    esac
}

# Map OS + arch to a GitHub release target triple
target_triple() {
    os="$1"
    arch="$2"
    case "${os}" in
        linux) echo "${arch}-unknown-linux-gnu" ;;
        macos) echo "${arch}-apple-darwin" ;;
    esac
}

# ── Resolve version ─────────────────────────────────────────────────

resolve_version() {
    if [ -n "${ENVVAULT_VERSION:-}" ]; then
        echo "${ENVVAULT_VERSION}"
        return
    fi
    need curl
    version=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"tag_name": *"//;s/".*//')
    [ -n "${version}" ] || err "Could not determine latest version from GitHub API"
    echo "${version}"
}

# ── Checksum verification ───────────────────────────────────────────

verify_checksum() {
    archive="$1"
    checksum_file="$2"

    expected=$(awk '{print $1}' "$checksum_file")

    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$archive" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$archive" | awk '{print $1}')
    else
        err "No sha256sum or shasum found — cannot verify download"
    fi

    if [ "$actual" != "$expected" ]; then
        err "Checksum mismatch!\n  Expected: ${expected}\n  Got:      ${actual}"
    fi
    ok "Checksum verified"
}

# ── Install directory ───────────────────────────────────────────────

resolve_install_dir() {
    if [ -n "${INSTALL_DIR:-}" ]; then
        echo "${INSTALL_DIR}"
        return
    fi
    if [ -w /usr/local/bin ]; then
        echo "/usr/local/bin"
    else
        mkdir -p "${HOME}/.local/bin"
        echo "${HOME}/.local/bin"
    fi
}

# ── Main ─────────────────────────────────────────────────────────────

main() {
    need curl
    need tar

    os=$(detect_os)
    arch=$(detect_arch)
    target=$(target_triple "$os" "$arch")
    version=$(resolve_version)

    archive_name="${BINARY}-${version}-${target}.tar.gz"
    base_url="https://github.com/${REPO}/releases/download/${version}"

    info "Installing ${BINARY} ${version} (${target})"

    tmpdir=$(mktemp -d)
    trap 'rm -rf "$tmpdir"' EXIT

    info "Downloading ${archive_name}..."
    curl -fsSL "${base_url}/${archive_name}"         -o "${tmpdir}/${archive_name}"
    curl -fsSL "${base_url}/${archive_name}.sha256"  -o "${tmpdir}/${archive_name}.sha256"

    verify_checksum "${tmpdir}/${archive_name}" "${tmpdir}/${archive_name}.sha256"

    tar xzf "${tmpdir}/${archive_name}" -C "${tmpdir}"

    install_dir=$(resolve_install_dir)
    install -m 755 "${tmpdir}/${BINARY}" "${install_dir}/${BINARY}"

    ok "Installed ${BINARY} to ${install_dir}/${BINARY}"

    # Check if install dir is in PATH
    case ":${PATH}:" in
        *":${install_dir}:"*) ;;
        *)
            info "Add ${install_dir} to your PATH:"
            info "  export PATH=\"${install_dir}:\$PATH\""
            ;;
    esac

    info "Run 'envvault --help' to get started"
}

main
