# Manual qualification of the fuzzing workflow

The implementation has automated tests using controlled runtimes. Live results
must be collected separately. This guide lists the operator work remaining for
the six engineering improvements; it does not claim those results already exist.

## Use the unified application

1. Open the rebuilt application and select your project. Keep Dashboard,
   Targets, Harness, Run, Coverage, History, and Triage on that project so every
   operation refers to the same retained evidence.
2. In Settings → Fuzzing, choose a workflow budget scope and limits. A scope is
   shared by discovery, harness work, review, and reporting. Reusing the scope
   retains its spending across restarts. Configure provider prices before using
   a monetary limit. Dashboard shows the scope's usage and any exhausted limit.
3. In Harness, inspect the complete source, build it through the application,
   review the model assessment, and approve only the exact source you intend to
   execute. Use normal smoke qualification and promotion.
4. For a bounded initial check, use one CPU, 2048 MiB, the existing 10-second
   smoke, and a 30-second campaign. Keep networking disabled. Check that History
   retains the source, executable, image, corpus, seed, termination, and output.

AFL++ behavioral qualification adds up to five sandbox probe commands after the
engine smoke. Their combined runtime allowance is at most one additional smoke
duration; the configured per-probe timeout can reduce it further. Review these
diagnostic limits as part of the qualification scope. Missing probe tools or
runtime failures produce explicit unavailable evidence.

## Collect the missing live evidence

| Improvement | Operator check | Evidence to retain |
| --- | --- | --- |
| Minimized crashes | Triage an approved retained finding. Inspect original and candidate replay observations; a changed or intermittent failure must keep the original input. | Crash record, replay logs and counts, original/candidate digests, executable and image. |
| Behavioral qualification | Smoke an AFL++ harness with meaningful distinct inputs. Inspect fresh-input and persistent sequence observations in Harness. | Qualification report and per-input maps. Equal sample maps are advisory; unavailable measurements remain explicit. |
| Model budgets | Use a small bounded test workflow and inspect Dashboard before and after a provider request and application restart. | Scope, reserved/observed usage, denied resource and terminal reason. |
| Coverage experiments | Select a completed baseline, prepare an experiment, make the reviewed corpus/harness change, review the guided launch, and approve it. | Baseline, reviewed inputs, associated campaign, comparison, including failed or unchanged outcomes. |
| Custom mutators | In Harness, import source for the supported upstream engine API. Rebuild, review, smoke and promote the new revision; inspect callback observations. | Imported source, native artifact/image identity, smoke observations, retained campaign and replay inputs. See [managed mutators](../design/managed-mutators-design.md). |

Use ordinary Stop and restart controls to inspect recovery without deleting
retained attempts. Cancelling an experiment record and stopping its campaign are
distinct operations in the application.

## Measure effectiveness on real projects

Follow the [held-out effectiveness protocol](../acceptance/effectiveness-baseline-protocol.md).
Its manifest pins three public projects and revisions; verify those checkouts
before preparing any harness. Review and freeze each source yourself, including
upstream/reference harnesses used for comparison. Preserve their licenses and
record any adaptation. Do not label an automatically generated reference as an
independently authored human baseline.

For each condition, collect the calibration database needed to obtain the
actual staged-source digest. Use matched engine, sanitizer, image, resource and
duration settings. Freeze at least three different seeds per condition for an
initial comparison; short runs characterize only those budgets and inputs.

Schema 2 accepts one prepared-harness mapping per trial:

```json
{
  "path": "harnesses/reviewed-source.c",
  "sha256": "<SHA-256 of the exact reviewed source file>",
  "source_sha256": "<staged-source digest from that condition's calibration>",
  "origin": "upstream"
}
```

The paths are relative to the frozen cohort file. Supported origins are
`generated`, `upstream`, and `reference`. Freeze with `--prepared-harnesses` and
use the runner's `--dry-run` first. It checks prepared files without executing
them. After reviewing every exact source and the complete bounded matrix,
`--approve-prepared-harnesses` explicitly authorizes that prepared matrix for a
live run. The model review and service execution controls still apply.

The runner writes `results.json`, `summary.md`, and, when complete bound evidence
is available, `observations.json`. Use `scripts.effectiveness_report` to verify
the exported records. Retain failed preparations and runs. Compare useful target
coverage, successful onboarding, observed reproduction and total cost; execution
rate and unique stack signatures alone do not establish bugs or effectiveness.

The remaining manual deliverable is the measured live report. Automated tests,
a prepared cohort, and a successful dry run are not a qualified live baseline.
