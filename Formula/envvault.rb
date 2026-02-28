class Envvault < Formula
  desc "Local-first encrypted environment variable manager"
  homepage "https://github.com/vedant-naidu/envvault"
  license any_of: ["MIT", "Apache-2.0"]
  version "0.4.0"

  on_macos do
    on_arm do
      url "https://github.com/vedant-naidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_MACOS_ARM64"
    end

    on_intel do
      url "https://github.com/vedant-naidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "PLACEHOLDER_MACOS_X86_64"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/vedant-naidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_LINUX_ARM64"
    end

    on_intel do
      url "https://github.com/vedant-naidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "PLACEHOLDER_LINUX_X86_64"
    end
  end

  def install
    bin.install "envvault"
  end

  def post_install
    # Generate shell completions
    (bash_completion/"envvault").write Utils.safe_popen_read(bin/"envvault", "completions", "bash")
    (zsh_completion/"_envvault").write Utils.safe_popen_read(bin/"envvault", "completions", "zsh")
    (fish_completion/"envvault.fish").write Utils.safe_popen_read(bin/"envvault", "completions", "fish")
  end

  test do
    assert_match "envvault", shell_output("#{bin}/envvault --version")
  end
end
