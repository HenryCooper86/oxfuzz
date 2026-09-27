# Persisted closeout process-loss qualification, 2026-09-27

Outcome: **passed** on a clean revision with a disposable terminal run and a
test-only pause immediately after the service committed its first closeout
step. This checks the closeout persistence and resume decision; it does not
execute a fuzzer or represent a crash-bearing closeout.

The source revision was `7e0fe7e3e262da6d65891e1e16f3928146d9f9fa`.
The [process-loss test](../../crates/hf-service/src/container/live_recovery_tests.rs)
had SHA-256 `fe964492efb5b4859377bd1808a6998c6b139ddc4744a403604696016a9a0fcf`.
The parent observed a marker written after the `Triage` outcome was committed,
terminated only its child process, and reopened the SQLite store. The retained
`Triage` row was `completed` with `0 crash(es) attributed`. A fresh service
resumed at `Minimize`, retained the identical `Triage` row, and returned all
seven closeout steps. The ordinary `hf-service` library suite and required
Rust quality gates passed before the clean-revision qualification.

The private evidence file
`/Users/admin/.codex/qualification-evidence/a3-service-live-2026-09-27/a3-closeout-7b97d7cf-de7a-4282-a588-d326d2d9d84a/recovery.json`
has SHA-256 `096407cafa67b9d051a4f92907b3710c337224a619ae0140b092ec1f5832f0b9`.
The earlier red run completed closeout before a pause could occur. A later
probe exposed missing synthetic workspace files; those were added to match the
minimum retained run layout before counting the passing result.

This does not test a crash after an external side effect and before its
closeout row, nor does it establish the 12-hour fault soak or disk-pressure
behavior.
