class Envvault < Formula
  desc "Local-first encrypted environment variable manager"
  homepage "https://github.com/whynaidu/envvault"
  license any_of: ["MIT", "Apache-2.0"]
  version "0.4.0"

  on_macos do
    on_arm do
      url "https://github.com/whynaidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-aarch64-apple-darwin.tar.gz"
      sha256 "2b7bc29d249410af48b6c6af7d0be6c1b283cd5791abcd53d20f7347bbed6e92"
    end

    on_intel do
      url "https://github.com/whynaidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-x86_64-apple-darwin.tar.gz"
      sha256 "875d4b7c2d5138f2f562fb76ad6f522bc0b8b4cfa30906d68afc55eee3841782"
    end
  end

  on_linux do
    on_arm do
      url "https://github.com/whynaidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "5cd97e80d8e9e59057d2a9e84f0862c5bc7c3dbe3c3729b38d212db06472657e"
    end

    on_intel do
      url "https://github.com/whynaidu/envvault/releases/download/v0.4.0/envvault-v0.4.0-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "0fa53df4e0e3dd9f9cbb61f098acc53f508a5effbbd83b49889665120df6af7e"
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
