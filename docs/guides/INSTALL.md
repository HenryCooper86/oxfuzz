# Install & Build

[← Back to the README](../../README.md)

### Prerequisites

| Dependency | Required? | Notes |
| --- | --- | --- |
| **Rust 1.94+** | Yes | Pinned in `rust-toolchain.toml` |
| **Node 20.19+ or 22.12+ / npm** | Desktop app | Vite 7 requirement; CI uses Node 22 |
| **Docker** | Yes | Mandatory boundary for harness builds, fuzz runs, and crash parsing |
| **SQLite 3.35+** | Embedded | Bundled, no action needed |
| **Fuzzing engines** | Bundled | AFL++, honggfuzz, libFuzzer, and syzkaller live in the sandbox image |

### The CLI binary

```bash
git clone <your-oxfuzz-remote>
cd oxfuzz
cargo build --release
# Binary: target/release/oxfuzz

# Build and verify the versioned sandbox toolchain. Equivalent:
# target/release/oxfuzz doctor --build-image
./scripts/build-sandbox.sh
```

The CLI resolves its config directory in a documented order (`--config`,
`HF_CONFIG_DIR`, the per-user config dir, then the enclosing source tree with
a stderr warning); see [the Configuration reference](CONFIGURATION.md#config-directory-resolution).

### Download a prebuilt app

Prebuilt installers for each release are attached to the
**[Releases page](https://github.com/HenryCooper86/oxfuzz/releases)**:

| Platform | File |
| --- | --- |
| macOS (Apple silicon) | `oxfuzz_*_aarch64.dmg` |
| macOS (Intel) | `oxfuzz_*_x64.dmg` |
| Linux | `oxfuzz_*.AppImage`, `.deb`, `.rpm` |
| Windows | `oxfuzz_*.msi`, `*-setup.exe` |

These builds have no organization-controlled code-signing identity. macOS
bundles have an ad-hoc signature but are not notarized; Windows bundles are
unsigned. The OS may warn on first launch -- see the release notes for the
per-platform steps. Docker must be installed and running before any fuzzing
starts.

Maintainers tag a reviewed release commit. Pushing the tag opens a draft and
builds each platform. The publication job checks source CI for that exact
commit, all required installer assets, and reviewed userspace, sandbox, and
installed-client acceptance references before it can publish. A failed or
incomplete candidate stays a draft for correction and a publish-job retry;
do not publish it manually around those checks:

```bash
git tag v0.1.0
git push origin v0.1.0
```

### Building the desktop app yourself (macOS)

```bash
./scripts/build-app.sh
# App:  target/release/bundle/macos/oxfuzz.app
# DMG:  target/release/bundle/dmg/oxfuzz_<version>_aarch64.dmg
```

To install a packaged build, open the `.dmg` and drag **oxfuzz** into
**Applications**. The app is ad-hoc signed (not notarized), so on first launch
macOS Gatekeeper will block it: right-click the app and choose **Open** once (or
run `xattr -cr /Applications/oxfuzz.app`). See the
**[Getting Started guide](GETTING_STARTED.md#installing-the-desktop-app)**
for the full walkthrough.

### DefectDojo (optional findings dashboard)

oxfuzz adopts a local DefectDojo rather than bundling one. `scripts/setup-defectdojo.sh`
(double-click `setup-defectdojo.command`) installs it for you: it clones
the reviewed DefectDojo release commit, pulls digest-pinned released images,
starts the stack on `http://localhost:8080`, and writes an owner-only
`config/defectdojo.toml`. The
environment-setup entry points (`rebuild-sandbox-image.command`,
`scripts/build-app.sh`) run it best-effort and idempotently; set
`HF_SKIP_DEFECTDOJO=1` to skip. Fuzzing never depends on it.

```bash
./scripts/setup-defectdojo.sh        # first run pulls several GB; idempotent thereafter
```

`scripts/health-check.sh` delegates to `oxfuzz doctor`, which probes the
Docker daemon, sandbox image, and engine tools inside that image. Host engine
binaries and optional integrations do not determine core readiness.

## Release Readiness

A release candidate is ready only when its source gates, sandbox health, CLI
artifact, and platform bundle have all been verified from the same commit.
The repository provides a local gate runner, CI pipelines that run the same
ten gates on every push and split them into jobs so a red pipeline identifies
the broken category without opening a log, and release build scripts:

```bash
./scripts/tests/gates.sh
./scripts/build-sandbox.sh
./scripts/test-semgrep-sandbox.sh
./scripts/build-release.sh
target/release/oxfuzz doctor
./scripts/build-app.sh
```

The Semgrep gate runs only the committed C fixtures through the fixed wrapper
inside the already-built versioned sandbox. A source-only release build does
not download or run Semgrep. Release candidates can require the sandbox gate
from the CLI build with
`OXFUZZ_VERIFY_SEMGREP_SANDBOX=1 ./scripts/build-release.sh`.

On macOS, `build-app.sh` verifies the `.app` signature and the generated DMG.
Its default ad-hoc signature is suitable for local QA and clearly labeled
experimental distribution, not a trusted macOS release. Trusted distribution
still needs the organization's Developer ID signing and notarization workflow.
Use the **[release checklist](RELEASE_CHECKLIST.md)**
for the full evidence, packaging, safety, and handoff gates.
