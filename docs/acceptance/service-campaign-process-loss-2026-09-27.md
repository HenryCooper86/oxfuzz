# Service campaign process-loss qualification, 2026-09-27

Outcome: **passed** for one approved libFuzzer userspace campaign on a
disposable macOS arm64 workspace. This adds real service admission evidence to
the bounded recovery fault suite; it is not the complete A3 fault schedule.

The clean source revision was `403b0b0187eb0c0f54a56616df9e3c53be07aa5e`.
The [ignored live test](../../crates/hf-service/src/container/live_recovery_tests.rs)
had SHA-256 `9cbaa0e9ab5906fe3032cd1da7470e7c6a50a3d9aba66bf6039fa4523ef06b38`.
The approved `parser.c` and `harness.c` combined source digest was
`a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591`.
The sandbox image ID was
`sha256:a43a1e6fc8bcff6e19bb823999b9df20787395caaf4fb68744086beb5475429c`.
The harness passed provider-reviewed compile, smoke, and promotion before the
campaign started. All fixture compilation and execution used `hf-runtime`.

The parent observed a durable run ID and an active container with the
disposable workspace ownership label, then killed only its child service
process. The reopened journal reported one interrupted run. The reopened
database still showed that run as running until recovery marked it failed. A
fresh Docker runtime removed the abandoned owned container and admitted a
harmless command. A fresh service then admitted a distinct ten-second
libFuzzer campaign. The ownership registry and Docker inventory were empty at
the end. The final host inventory also showed no `hf-run-` containers.

The private clean-run evidence is under
`/Users/admin/.codex/qualification-evidence/a3-service-live-2026-09-27/`.
`clean-test.log` has SHA-256
`8c714be633a2bbf4162a287f2ec9cff7cefd12b7af7acf1285299e362f19bc78`;
the clean run reported one passing test in 91.66 seconds. Its
`a3-service-952163af-fad7-435a-9ac2-c31883627911/recovery.json` has SHA-256
`29d1f564f596e26307bfb6a10f043fc8f5deb13ccb22be6b514334501ce385f7`.
Provider credentials and private child logs are not included here.

This test does not inject disk exhaustion, kill after a persisted closeout
step, or establish the 12-hour soak result. It does not qualify AFL++,
honggfuzz, Linux/KVM, or physical interfaces for this fault scenario.
