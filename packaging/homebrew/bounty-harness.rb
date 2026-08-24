# Homebrew formula for BountyHarness.
#
# Intended tap layout (future): Mr-Neutr0n/homebrew-tap, then:
#   brew install Mr-Neutr0n/tap/bounty-harness
#
# RELEASE CHECKLIST (maintainer):
#   1. Bump VERSION file and this formula's version to the same value.
#   2. Push tag:  git tag v3.1.0 && git push origin v3.1.0
#      (.github/workflows/release.yml attaches the archive to the GitHub
#       Release and prints its sha256 into the run summary.)
#   3. Copy that sha256 into the line below.
#   4. Verify locally before committing to the tap:
#        curl -fsSL <release-tarball-url> -o bh.tgz
#        shasum -a 256 bh.tgz          # must match the value above

class BountyHarness < Formula
  desc "Agent harness for authorized bug bounty work: 46 skill packages, safety tiers, tracing"
  homepage "https://github.com/Mr-Neutr0n/bounty-harness"
  url "https://github.com/Mr-Neutr0n/bounty-harness/archive/refs/tags/v#{version}.tar.gz"
  version "3.1.0"
  # PLACEHOLDER - compute on release with: shasum -a 256 on the tagged tarball.
  # CI prints the exact digest into the release run summary.
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"

  license "MIT"

  depends_on "python@3.12" => [:build, :test]
  depends_on "git" => :test

  def install
    # Install the whole tree under libexec; skills/registry resolve paths
    # relative to the binaries themselves (BASH_SOURCE-based REPO_ROOT).
    libexec.install Dir["*"]

    bin_name = OS.mac? ? "" : "" # both architectures use the same scripts
    %w[bb-init bb-validate bb-run bb-hunt bb-tools].each do |b|
      (libexec/"bin").chmod 0755 if File.executable?(libexec/"bin"/b)
      bin.install_symlink libexec/"bin"/b
    end
    bin_name # silence unused-var lint in older rubocop versions
  end

  test do
    # Version comes from the VERSION file shipped inside the archive.
    assert_match version.to_s, shell_output("#{bin}/bb-run --version")
    # Discovery proves the path-independent resolution works from brew's prefix.
    output = shell_output("#{bin}/bb-run list")
    assert_match "recon", output
  end
end
