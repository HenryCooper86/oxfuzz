# Bounded campaign output failure, 2026-09-27

Outcome: **passed** for one approved libFuzzer userspace campaign on a
disposable macOS arm64 workspace. This is an output-budget fault injection,
not a host filesystem exhaustion test.

The clean source revision was `a17bdea1564b5e1811626b877371629b30d5cf3f`.
The [ignored live test](../../crates/hf-service/src/container/live_recovery_tests.rs)
had SHA-256 `cea62061015a055ddaf04a8db09b399cb8b477db896be5a4650f011860d6d360`.
The approved C source digest was
`a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591`;
the sandbox image ID was
`sha256:a43a1e6fc8bcff6e19bb823999b9df20787395caaf4fb68744086beb5475429c`.
The harness passed provider-reviewed compile, smoke, and promotion before the
campaign. All fixture compilation and execution used `hf-runtime`.

After observing the active workspace-owned sandbox, the parent wrote a
65 MiB file to that run's disposable output directory. The service's
64 MiB per-file retained-evidence limit stopped the campaign and reported a
budget failure. The retained run status was `Failed`, the journal had no
interrupted run, the ownership registry was empty, and the container was
absent from Docker's all-state inventory. The final host inventory showed no
`hf-run-` containers.

The private clean-run evidence file
`/Users/admin/.codex/qualification-evidence/a3-service-live-2026-09-27/a3-output-01eccd0c-f0e8-4a68-9b40-abc02ce0438c/recovery.json`
has SHA-256 `33b15c19d4f4e4fb3c1af7318c6146ff8db759b6459f25e7b95efc0963c787c8`.
The injected file was written by the test controller inside the disposable
workspace, rather than by the fuzzer or an exhausted filesystem. This result
does not establish behavior under `ENOSPC`, slow writes, or the 12-hour soak.
