# macOS installed candidate, 2026-09-27

Outcome: **partial** for an ad-hoc signed Apple silicon desktop candidate on
macOS 27.0. This record does not satisfy the installed-client release gate.

The clean source revision was `9c329d06afd8139b1f11ce304985936c8f70f399`.
`HF_SKIP_DEFECTDOJO=1 ./scripts/build-app.sh` completed without a manual Cargo
profile override. The script applies `CARGO_PROFILE_RELEASE_STRIP=none` on
macOS 27 to avoid the [Rust proc-macro loader issue](https://github.com/rust-lang/rust/issues/157750).
The build log has SHA-256
`4a207d408943f6bbe5ac20a73f6859cdcbeb135b132d5e21dd5e80597c86425a`.
The shell and Node script suite passed 22 tests; its log has SHA-256
`f3c1595b81f1d5ff14cd8e958944fc23ac561f6f75476a1bd0b6dc09c9b5e8b8`.

The `oxfuzz_0.5.1_aarch64.dmg` SHA-256 was
`26a993b82ce87a15b873b8a6340b850daf28d35552d96a46f30c3897b381f6cf`.
`hdiutil verify` accepted it. A copy of its `.app` was installed into a
disposable directory, and `codesign --verify --deep --strict` passed. Both
that copy and the standalone build's `Contents/MacOS/hf-gui` had SHA-256
`c4ae31cf181200e9700095cfc3e304a4e974bd53802099bf6a046d83c94bb1f9`.
The signature was ad-hoc, with no team identifier or notarization.

The copied app launched and relaunched with disposable `HOME`, database, data,
and workspace paths. Its Settings view showed the selected private config and
data directories. It reported Docker and sandbox tools ready. The provider
test returned `Connected to model glm-5.2. Reply: OK` through the locally
configured BigModel Coding Plan endpoint. Provider credentials and private
run logs are not included in this record.

The native folder picker did not yield a selected project through the available
computer-use controls, so the project choice, installed campaign Stop,
retained history after restart, and keyboard workflow remain unverified. This
observation does not establish an app defect. The app also displayed a recent
project from existing WebView state despite the disposable process `HOME`, so
this was not a clean first-launch wizard check. No harness was executed from
the desktop app. The DMG was copied into a disposable directory rather than
installed in `/Applications`. Intel macOS, Linux, Windows, organization signing,
notarization, and representative-user checks remain open.

Private build and copied-bundle evidence is under
`/Users/admin/.codex/qualification-evidence/a6-local-bundle-2026-09-27/`.
