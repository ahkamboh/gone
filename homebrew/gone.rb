# Source-build formula for gone.
#
# This file is a skeleton for two uses:
#   1. an eventual submission to homebrew-core (which builds from source),
#   2. local testing with `brew install --build-from-source ./homebrew/gone.rb`.
#
# It is NOT the formula end users get from the tap. At release time the
# Release workflow generates a prebuilt-binary formula named gone-cli.rb
# (named after the cargo package) and pushes it to ahkamboh/homebrew-tap.
# See docs/release.md.
class Gone < Formula
  desc "See what deleted data can still be recovered, erase it for good, prove it"
  homepage "https://github.com/ahkamboh/gone"
  url "https://github.com/ahkamboh/gone/archive/refs/tags/v0.1.0.tar.gz"
  # Fill in after tagging v0.1.0:
  #   curl -sL https://github.com/ahkamboh/gone/archive/refs/tags/v0.1.0.tar.gz | shasum -a 256
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  license any_of: ["MIT", "Apache-2.0"]

  depends_on "rust" => :build

  def install
    # The workspace holds several crates; only the CLI ships a binary.
    # --locked keeps the build on the committed Cargo.lock.
    system "cargo", "install", *std_cargo_args(path: "crates/cli")
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/gone --version")
  end
end
