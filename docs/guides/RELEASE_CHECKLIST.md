# Release checklist

Use this checklist for every CLI or desktop release candidate. A release is a
set of artifacts tied to one Git commit, not merely a passing local build.
Record the commit, version, GitLab pipeline, platform, architecture, signing
identity class, and artifact checksums in the release evidence.

## 1. Freeze the candidate

- Confirm the intended branch and merge request.
- Confirm `git status --short` contains only the release changes.
- Record the candidate with `git rev-parse HEAD`.
- Confirm the version agrees across `Cargo.toml`,
  `crates/hf-gui/package.json`, and
  `crates/hf-gui/src-tauri/tauri.conf.json`.
- Review user-facing changes, known limitations, dependency/license changes,
  migrations, and configuration compatibility.
- Confirm no secret, local `.env`, runtime database, corpus, crash artifact, or
  customer target source is staged.

## 2. Run source quality gates

Rust development gates must run in the order defined by `AGENTS.md`:

```bash
cargo fmt --all
cargo clippy --fix --allow-dirty --workspace -- -D warnings
cargo clippy --workspace -- -D warnings
cargo check --workspace
cargo doc --workspace --no-deps
```

Run workspace tests through the repository filter so failures remain readable:

```bash
./scripts/cargo-test-filtered.sh --workspace
```

Then run the wider local gate set:

```bash
./scripts/tests/gates.sh
```

Do not substitute the local runner for GitLab CI. The pipeline additionally
checks locked, all-target, and all-feature Rust builds; the focused
`hf-service` release-readiness test; frontend tests/build/lint; the automotive
sidecar tests/lint; and the release CLI artifact.

## 3. Verify the mandatory sandbox

```bash
./scripts/build-sandbox.sh
./scripts/build-release.sh
target/release/oxfuzz doctor
target/release/oxfuzz doctor --json
```

The doctor command must exit successfully and report the Docker daemon,
versioned sandbox image, and bundled engine tools as ready. Host-installed
fuzzing engines do not satisfy this gate. Optional integrations may be
unavailable only when they are outside the release scope and the limitation is
documented.

For an automotive-enabled candidate, also run the separately distributed
sidecar checks and confirm its pinned dependencies:

```bash
cd sidecars/scapy_automotive
python -m unittest discover -s tests -v
ruff check --no-cache src tests
cd ../..
./scripts/build-scapy-sidecar.sh
```

Automotive support remains disabled by runtime policy until an operator enables
the subsystem and exact allowlists. Do not connect a physical interface as a
release test.

Verify the automotive report path with retained fixture evidence only. The
deterministic report must work without a provider; the fake-provider tests must
accept known citations, reject invented operation/state/transcript citations,
and retain the deterministic fact sheet on fallback:

```bash
./scripts/cargo-test-filtered.sh -p hf-service --features automotive-scapy \
  --test automotive_report
./scripts/cargo-test-filtered.sh -p hf-service --features automotive-scapy \
  campaign_report_
./scripts/cargo-test-filtered.sh -p hf-web --features automotive-scapy \
  --test api automotive_report_route_
```

## 4. Verify CLI behavior

```bash
target/release/oxfuzz --version
target/release/oxfuzz --help >/dev/null
target/release/oxfuzz doctor
```

Use the bundled deterministic fixtures for read-only discovery and service
smoke checks. Do not execute generated harnesses on the host. Any campaign used
for release verification must follow normal sandbox, guardrail, and human
promotion boundaries.

## 5. Build and inspect the desktop bundle

```bash
./scripts/build-app.sh
```

The script builds the frontend, produces the platform bundle, and verifies the
macOS application signature and DMG when running on macOS. Inspect the fresh
artifact under `target/release/bundle`; do not verify an older debug build.

For local macOS QA, the script defaults to an ad-hoc signature. A public macOS
distribution requires an organization-controlled Developer ID identity and a
separate notarization/stapling workflow. Do not describe an ad-hoc build as
notarized or Gatekeeper-ready.

For a macOS candidate, retain the output from these checks:

```bash
codesign --verify --deep --strict --verbose=2 \
  target/release/bundle/macos/oxfuzz.app
hdiutil verify target/release/bundle/dmg/*.dmg
```

Launch the fresh bundle and verify:

- first-run/setup behavior and provider configuration without exposing keys;
- Dashboard readiness and blocked-action explanations;
- project selection and deterministic target discovery;
- exact-revision harness review and promotion state;
- bounded run configuration and cooperative cancellation controls;
- retained triage, report, artifact, run-history, and policy-audit views;
- Settings enforcement of sandboxing, blocked fuzzer networking, and human
  promotion;
- optional automotive UI is visibly disabled until policy is configured.

## 6. Review security and operational boundaries

- The REST API is loopback-only by default.
- Non-loopback binding fails closed without `HF_WEB_TOKEN`.
- CORS origins and project roots are exact allowlists.
- Generated harnesses, engine binaries, and crash parsing stay inside
  `hf-runtime`.
- Approval applies to one promoted harness revision and never weakens
  isolation.
- Fuzzer networking remains blocked.
- Logs, reports, screenshots, and export bundles contain no credentials or
  private target material beyond the approved release evidence.

Stop the release if any of these claims cannot be demonstrated from the
candidate commit.

## 7. Approve the GitLab candidate

- Require every pipeline job to pass on the exact candidate commit.
- Review the merge-request diff, dependency changes, generated artifacts, and
  unresolved discussions.
- Record artifact names, sizes, and SHA-256 checksums.
- Record signing/notarization status separately from functional verification.
- State supported platform/architecture combinations and known limitations.
- Merge through GitLab after approval; create a version tag only from the
  reviewed merge commit.

Example checksum command:

```bash
find target/release/bundle -type f \
  \( -name '*.dmg' -o -name '*.deb' -o -name '*.AppImage' -o -name '*.rpm' \) \
  -exec shasum -a 256 {} \;
```

Keep the GitLab pipeline URL, commit SHA, checksums, and platform verification
notes together. That record is the release evidence for later reproduction and
incident review.
