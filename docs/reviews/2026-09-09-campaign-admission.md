# Phase 2A: campaign admission defects found during live preparation

Date: 2026-09-09. Starting main revision: `c94c496a`.

## Observed failures

The selected libFuzzer preflight reported configured model access. Fresh isolated
projects for libFuzzer, AFL++, and honggfuzz completed discovery and packet export,
but all three required-model drafts failed before compilation or execution. The
configured provider referenced an unset API-key environment variable. Provider
construction skipped that entry yet returned an empty successful pool.

CLI checks also reproduced two run-policy defects: an omitted duration used
3,600 seconds instead of the configured default, and rejected duration requests
created storage before policy rejection. Those actions preceded the service's
correct final execution-policy check.

## Changes

- Configuration-driven provider pools reject an empty constructed provider set.
  Missing and empty environment keys are unavailable. Existing file-to-environment
  provider fallback can now work when file entries produce no usable provider.
  A partial pool remains usable when at least one entry is constructed.
- CLI normal-run admission resolves the existing service policy before storage
  bootstrap or seed preparation. Omitted duration uses the configured default;
  final execution retains its own policy check. Invalid replay IDs also fail
  before bootstrap.
- Regression tests cover missing/empty keys, a configuration with no usable
  backend, configured duration, and pre-side-effect duration rejection.

This corrects readiness and startup behavior; it does not establish provider
connectivity, live harness qualification, or campaign effectiveness.

## Verification

Red tests reproduced empty-pool success, empty-key acceptance, database creation
on a rejected run, and the incorrect 3,600-second default.

Local workspace verification: **3,242 passed, 0 failed, 7 ignored** in 179 test
groups. The 93 script tests, 518 GUI tests, frontend build/bundle/lint checks,
formatting, fixing and strict Clippy, all-target Clippy, compilation, and
standard documentation passed. Strict private-item documentation and dependency
policy passed with warnings denied; domain line coverage remained 91.12%.
Translation pairing passed. The five CLI subprocess cases passed again after
adding child-process failure diagnostics.

The first published milestone passed hosted Rust, macOS, frontend, coverage,
and dependency jobs. Its new Windows CLI subprocess tests returned empty
stdout; their original assertions hid the child exit status and stderr. The
subprocess assertions now retain those diagnostics so the next hosted run can
identify the Windows startup failure. Windows acceptance remains open until a
clean hosted run; no JSON parsing assertion is removed or weakened.

## Live preparation and remaining acceptance

The user subsequently configured Ollama Cloud credentials locally and selected
`glm-5.3:cloud`. Actual required-model authoring succeeded for libFuzzer, AFL++,
and honggfuzz on an isolated bounded parser fixture. The sources contain no host
I/O and call the intended target. The credential is stored only in ignored private
configuration, never in repository evidence.

Independent model review, sandbox qualification, exact-source human approval,
full campaigns, and cancellation/recovery remain separate acceptance steps.
No substitute provider response, automatic approval, or host harness execution
is used. The live study retains separate per-engine projects and authoring
evidence in a temporary isolated database/workspace. Functional implementation
continues without claiming these outstanding execution checks passed.

Provider configuration follows [Ollama authentication](https://docs.ollama.com/api/authentication)
and the [GLM-5.3 model entry](https://ollama.com/library/glm-5.3).
