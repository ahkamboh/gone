# Releasing gone

This is the maintainer runbook for shipping release binaries. The pipeline has two parts: dist-workspace.toml at the repo root (what to build) and .github/workflows/release.yml (how to build it). Both are driven by cargo-dist 0.30.x, whose CLI binary is called dist. Everything below assumes that version.

## What a release produces

Pushing a tag that starts with v runs the Release workflow. For each release it makes:

- gone-cli-aarch64-apple-darwin.tar.gz, gone-cli-x86_64-apple-darwin.tar.gz, gone-cli-x86_64-unknown-linux-gnu.tar.gz and gone-cli-x86_64-pc-windows-msvc.zip, each with a .sha256 sidecar, plus a combined sha256.sum
- gone-cli-installer.sh and gone-cli-installer.ps1 for curl and irm one-line installs
- source.tar.gz
- a GitHub Release with generated notes. A tag with a prerelease suffix such as -rc.1 is marked as a prerelease automatically.
- a commit to ahkamboh/homebrew-tap that updates Formula/gone-cli.rb. This step is skipped for prereleases.

One naming wrinkle: artifacts and installers are named after the cargo package gone-cli, but the installed binary is called gone. dist has no option to rename the app. Users will run commands like brew install ahkamboh/tap/gone-cli and then type gone.

## Cutting a release

1. Confirm main is green: cargo test --workspace and cargo build --release -p gone-cli.
2. Bump version in the root Cargo.toml under [workspace.package]. All crates inherit it. Commit and push.
3. Tag and push:

```
git tag v0.1.0
git push --tags
```

4. Watch the Release workflow. Four build legs plus packaging take roughly 15 to 30 minutes.
5. Spot check the result. Download one archive, compare its hash against sha256.sum, and run the installer on a clean machine or VM:

```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/ahkamboh/gone/releases/download/v0.1.0/gone-cli-installer.sh | sh
gone --version
```

## Testing the pipeline safely

Tag a prerelease the first time:

```
git tag v0.1.0-rc.1 && git push --tags
```

The rc suffix makes dist mark the GitHub Release as a prerelease and skips the Homebrew tap publish, so a broken first run never reaches brew users. To scrap a test release:

```
gh release delete v0.1.0-rc.1 --yes
git push origin --delete v0.1.0-rc.1
git tag -d v0.1.0-rc.1
```

## Validating config changes

After editing dist-workspace.toml, run dist plan locally before tagging. It prints every release, artifact and CI matrix leg it would produce, and rejects unknown config keys. Install dist with the official installer:

```
curl --proto '=https' --tlsv1.2 -LsSf https://github.com/axodotdev/cargo-dist/releases/download/v0.30.0/cargo-dist-installer.sh | sh
```

release.yml carries three intentional hand edits on top of dist generate output: the v-only tag filter, the aes_armv8 step, and the tap commit identity. dist-workspace.toml sets allow-dirty = ["ci"] so dist accepts them. If you ever regenerate the workflow with dist generate, re-apply those edits; they are listed in the header comment of release.yml.

## One-time manual prerequisites

The pipeline runs without any of these, but binaries come out unsigned and the brew publish fails until the tap exists. Each is a one-time setup.

### Homebrew tap and token

1. Create the public repo github.com/ahkamboh/homebrew-tap. The homebrew- prefix is what makes brew tap ahkamboh/tap work, and the repo must be public so brew can clone it anonymously.
2. Create a fine-grained personal access token with Contents: read and write on the homebrew-tap repo only.
3. Add it as the Actions secret HOMEBREW_TAP_TOKEN in ahkamboh/gone.

The publish-homebrew-formula job uses that token to check out the tap and commit the generated formula as github-actions[bot].

Known nit: dist warns that the Homebrew publish job has no homepage because gone-cli's Cargo.toml does not inherit the workspace homepage. Adding homepage.workspace = true to crates/cli/Cargo.toml fixes it; that file was out of scope when this pipeline was set up.

### Windows code signing with SignPath

Windows binaries are unsigned, so SmartScreen will warn users. SignPath signs open source projects for free. Setup:

1. Apply for the OSS program at https://signpath.io. The application asks for the public repo URL and the license, and approval is manual.
2. In the SignPath portal, create a project for gone, link it to the GitHub repository, and add an artifact configuration that describes what gets signed (gone.exe inside the msvc zip).
3. Create an API token and store it as the SIGNPATH_API_TOKEN secret in this repo.
4. Wire signing into release.yml between the build legs and the release upload. dist has no built-in SignPath step; the supported extension point is a custom job, described in the cargo-dist book under custom CI jobs. Until this is wired, expect SmartScreen warnings and say so in the release notes.

For reference, dist 0.30 has an unstable built-in for SSL.com eSigner (ssldotcom-windows-sign) but nothing for SignPath.

### Apple Developer ID and notarization

macOS binaries are also unsigned. A CLI installed through curl or brew skips Gatekeeper's quarantine check, so this is optional today; it becomes important if the GUI ever ships a .app, and it helps users who download archives through a browser.

1. Enroll in the Apple Developer Program and create a Developer ID Application certificate.
2. Export it as a .p12, base64 encode it, and store it as the CODESIGN_CERTIFICATE secret, with the export password in CODESIGN_CERTIFICATE_PASSWORD and the identity string in CODESIGN_IDENTITY. With those three secrets in place, setting macos-sign = true in dist-workspace.toml makes dist codesign the macOS binaries itself.
3. For notarization, create an app-specific password at appleid.apple.com and store it as AC_PASSWORD, and store your App Store Connect provider short name (usually your team id) as AC_PROVIDER. Those are the variable names common notarization helpers such as gon read.
4. dist signs but does not notarize, so add a step after the build on each macOS leg: zip the signed binary, run xcrun notarytool submit --wait with the credentials above, then re-pack the archive. Bare executables cannot take a stapled ticket; notarizing the zip is enough because Gatekeeper looks the ticket up online.

### The aes_armv8 flag

Two places set it, and both matter:

- .cargo/config.toml sets rustflags = ["--cfg", "aes_armv8"] under [target.aarch64-apple-darwin].
- release.yml repeats it as an env RUSTFLAGS on the aarch64 build leg. An env RUSTFLAGS replaces config-file rustflags rather than adding to them, so the step makes the flag immune to anything in the runner environment that might set RUSTFLAGS globally.

The flag turns on the ARMv8 hardware AES backend in the RustCrypto aes crate. Without it the sanitize engine uses the software fallback and runs about 40x slower, which dominates erase time.

Do not copy this flag to other targets. It emits ARMv8 crypto instructions unconditionally. Every Apple Silicon Mac has them, but plenty of aarch64 Linux boards do not; the Raspberry Pi 4's Cortex-A72 is the usual example. That is why the aarch64 Linux block in .cargo/config.toml stays commented out. If an aarch64-unknown-linux-gnu target is ever added, ship it without the flag or detect support at runtime.

### cargo-binstall, once the crates are on crates.io

The [package.metadata.binstall] table must live in crates/cli/Cargo.toml, which this pipeline setup did not touch. When the crates are ready to publish (the path dependencies need version numbers first), add:

```toml
[package.metadata.binstall]
pkg-url = "{ repo }/releases/download/v{ version }/{ name }-v{ version }-{ target }{ archive-suffix }"
pkg-fmt = "tgz"

[package.metadata.binstall.overrides.x86_64-pc-windows-msvc]
pkg-fmt = "zip"
```

The template matches the artifact names dist produces, so cargo binstall gone-cli will find the prebuilt archives. binstall reads this metadata from the published crate on crates.io, so it only starts working after cargo publish.

## First-tag checklist

- dist plan looks right locally and the working tree is committed
- homebrew-tap exists and HOMEBREW_TAP_TOKEN is set
- tag v0.1.0-rc.1 first; confirm all four build legs pass and the release page has every archive
- confirm the tap was untouched by the rc, then tag v0.1.0
- brew install ahkamboh/tap/gone-cli on a clean Mac and run gone --version
