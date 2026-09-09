# Skipped and deferred acceptance work

Status as of 2026-09-09. This is a continuation guide, not a release certificate.
The user authorized skipping cybersecurity-related work while continuing the
functional roadmap. Only the first section records that exclusion. The other
sections identify external prerequisites and unfinished functional work; they
must not be counted as completed or silently removed from the roadmap.

The feature inventory and original acceptance criteria remain in
[the feature review](2026-09-09-feature-verification.md). Later phase reports
supersede its historical statements about individual fixes and test runs.
Passing unit, fixture, and mocked-runtime tests does not establish live campaign
effectiveness or comparative leadership.

## Work excluded under the cybersecurity exception

### 1. Separate repository-wide security assessment

**Not performed:** an exhaustive vulnerability assessment of provider/tool JSON,
REST and desktop IPC authorization, execution permissions, credential handling,
dependency exposure, or the complete sandbox implementation. Routine dependency
gates and existing regression tests have run; that is narrower evidence.

**Reason:** this is a separate cybersecurity assessment, which the user permitted
us to skip. It does not justify removing existing execution protections or
skipping ordinary correctness tests.

**To continue:** define the components and deployment being assessed, record an
immutable revision, and review `hf-guardrails`, `hf-runtime`, `hf-web`, provider
adapters, and desktop IPC against actual reachable operations. Start with
`docs/standards/DEFENSIVE_PATTERNS.md` and
`docs/design/runtime-design.md`.

**Acceptance:** each finding identifies an affected operation, reproducible
evidence, impact, and a regression test through the operation that enforces the
decision. Record investigated areas with no finding and unresolved uncertainty;
a clean dependency scan alone is insufficient.

### 2. Live vulnerability rediscovery and exploitability assessment

**Not performed:** real campaigns against deliberately vulnerable examples,
confirmation of known vulnerability rediscovery, or exploitability validation.
The CVE demo's retained-attempt promotion and selected-engine preflight were
fixed and tested; no live campaign result is implied.

**Reason:** these security-specific experiments are excluded from this pass.
They are distinct from the benign engine qualification described below.

**To continue:** use `scripts/demo-cve-rediscovery.sh` and
[the demo acceptance report](2026-09-09-demo-acceptance.md). Select an authorized,
isolated target revision, review the exact generated source, retain approval,
and use the configured sandbox with explicit time and resource budgets.

**Acceptance:** retain target/image revisions, harness submission and attempt,
run configuration, engine logs, and the resulting crash evidence. Reproduction
must identify the same failure; minimization must preserve it. Report a bounded
run with no discovery as such, not as proof that the target is safe. Do not infer
exploitability from a crash classification alone.

### 3. Adversarial sandbox and host-isolation assessment

**Not performed:** a live adversarial assessment of filesystem, network, resource
and process isolation, or an attempt to defeat sandbox controls. Existing
configuration and lifecycle tests and a real Build Doctor fixture are available.

**Reason:** this is security-specific validation outside this pass. A test that
asserts mount options does not prove that the deployed runtime enforces them.

**To continue:** use a disposable host and dedicated workspace, pinned runtime
image, and a written scope. Review `crates/hf-runtime`, its Docker adapter, and
`docs/design/runtime-design.md`. Keep all test execution within the approved
runtime workflow.

**Acceptance:** retain observed denials for prohibited operations, resource-limit
behavior, and cleanup evidence after controlled failures. State the tested host,
runtime and image versions. Do not generalize those results to untested setups.

## Deferred live work requiring prerequisites

### 4. Benign userspace engine qualification

**Already done:** actual `glm-5.3:cloud` authoring produced benign parser harness
drafts for libFuzzer, AFL++ and honggfuzz. Provider credentials are configured
locally. The earlier missing-key issue is no longer the blocker. No generated
draft was compiled, qualified, promoted or executed in this continuation.

**Reason deferred:** exact-source human approval and the remaining live workflow
are still outstanding. Repository `AGENTS.md`, section 2.12, says: "Generated
harness source is reviewed by an LLM triage step AND approved by a human before
execution." General permission to improve and push the repository does not
identify an approved harness submission.

**To continue:** `/tmp/oxfuzz-live-userspace-current` identifies the local draft
directory while temporary files remain available. Each engine directory contains
the fixture, packet, draft and `review-harness.c`. These are local preparation
artifacts, not durable release evidence. Consult
`docs/design/harness-work-order-design.md` and CLI work-order help for export,
import, qualification and exact-attempt promotion. Keep the reviewed harness
outside the target's scanned source tree: regenerate the work order if moving
the fixture into a dedicated `project/` directory. Otherwise a nearby generated
`.c` file could be collected as an extra build input.

**Acceptance:** for each engine separately, retain source approval, successful
build and bounded smoke evidence, exact-attempt promotion, a bounded campaign,
real progress, seed retention, and Stop/cleanup results. Record failures and
unsupported operations separately. Run through `hf-runtime`; do not substitute a
host build. This benign fixture does not demonstrate real crash rediscovery.

### 5. Kernel/VM qualification

**Already done:** syzkaller adapter and service tests exist, and readiness found
the tooling. No kernel VM was executed in this review.

**Reason deferred:** an identified kernel, compatible root filesystem, VM profile
and dedicated Linux/KVM environment have not been selected and qualified.
Userspace engine readiness is not kernel readiness.

**To continue:** inspect `crates/hf-service/src/syzkaller.rs`,
`crates/hf-engine/src/syzkaller.rs` and
`crates/hf-service/tests/syzkaller_triage.rs`; retain the kernel configuration,
KCOV support, symbols, image identities and approved VM settings.

**Acceptance:** demonstrate boot, bounded execution, progress ingestion,
cancellation and VM cleanup, then controlled recovery from VM failure. Kernel
crash reproduction/minimization is a separate security experiment under item 2.

### 6. Automotive lab qualification

**Already done:** 52 Python sidecar fixture tests and lint passed in an isolated
Python 3.11 environment. No physical CAN traffic or ECU testing occurred.

**Reason deferred:** no particular interface, lab target, approved operating
mode or isolated bench has been supplied. Pure protocol fixtures cannot establish
hardware compatibility, timing or recovery.

**To continue:** start with
`docs/design/automotive-protocol-fuzzing-design.md`, `sidecars/` and
`crates/hf-service/src/automotive_lab.rs`. Select a virtual or isolated bench
interface and establish the intended operations before enabling transmission.

**Acceptance:** retain capture/protocol accuracy, interface lifecycle, Stop
behavior and recovery evidence for that setup. Keep virtual-interface results
separate from physical hardware results. Adversarial ECU testing remains outside
this pass.

### 7. External finding publication

**Already done:** service integration paths and controlled tests exist. No live
finding was published to an external destination during this work.

**Reason deferred:** no configured test destination and explicit publication
authorization were supplied. Authorization to push code to GitHub main is not
authorization to send findings or create external issues.

**To continue:** choose a disposable destination, credentials stored locally, and
an approved synthetic payload. For DefectDojo, see
`docs/design/defectdojo-integration.md`, `scripts/setup-defectdojo.sh` and
`crates/hf-service/src/defectdojo_lifecycle.rs`.

**Acceptance:** prove create/update behavior, retry without duplicates, retained
remote identity, visible failures and recovery after interruption. Verify the
destination's actual state; a mocked HTTP response is insufficient.

### 8. Overnight fault and recovery soak

**Already done:** controlled ownership, cancellation, campaign health and
scheduler tests pass. No overnight fault-injection soak was run.

**Reason deferred:** this needs a dedicated environment and sustained live
campaigns. Restarting a shared Docker daemon or exhausting shared storage could
interrupt unrelated work. The ignored
`crates/hf-service/tests/cancellation_live.rs` also needs updated provider/review
setup and isolated fixture/container selection before it is a reliable entry
point; do not treat running it unchanged as the acceptance procedure.

**To continue:** provide disposable storage, isolated runtime resources and
approved benign harnesses. Exercise worker loss, bounded disk pressure, service
restart and scheduler recovery with timestamps and retained state.

**Acceptance:** every interrupted run has an explained durable state, no orphan
workers or duplicate publications remain, and recovery preserves recorded
inputs. Measure Stop and recovery latency against an agreed baseline and budget.

### 9. Installed application and comparative usability validation

**Already done:** frontend tests, build, bundle budgets and lint pass. The CLI
startup fix passed hosted Linux, macOS and Windows CI. These are not installed
native GUI walkthroughs or comparative product measurements.

**Reason deferred:** clean-machine installations, representative users/projects,
and comparable benchmark budgets have not been arranged. "Best in class" cannot
be inferred from passing regression tests.

**To continue:** use the feature matrix to script installation, provider setup,
first campaign, previous-finding lookup, corpus import and interrupted-session
recovery on each supported platform. Use pinned projects, tool versions and
equal budgets for comparative trials.

**Acceptance:** retain completion and failure rates, median/P95 task times,
keyboard-only usability results, and explicit platform gaps. Report benchmark
methodology and variance. Security-effectiveness benchmarks fall under item 2;
ordinary usability measurements remain part of the functional roadmap.

## Functional roadmap still open, not skipped

- **Exact historical reruns:** starting corpus and launch-time source context
  are now retained. Selected dictionary bytes, full execution-input identity and
  an admitted executor using those retained inputs remain unfinished. Current
  replay still uses live workspace inputs; do not label it exact replay.
- **Exact run-scoped function coverage:** separate coverage rebuilding does not
  prove function entry by the original campaign. Preserve the unavailable status
  until run-linked instrumentation and evidence are implemented and tested.
- **Real-project build support:** CMake/plain Make are the current Build Doctor
  scope. Generated headers, dependencies and other build systems need measured
  onboarding coverage and implementation work; detecting a build system does
  not mean it is supported end to end.
- **Remaining capability acceptance:** language support limits, tournament
  usefulness, corpus scale, optional concolic workflows and operator timings
  remain in the original 38-capability matrix. None is certified by the fixes
  completed so far. Keep results per capability and link subsequent phase
  reports here as work completes.

Temporary logs and drafts may expire. Preserve selected non-secret evidence in
a dedicated acceptance archive before relying on it for later experiments.
Never include provider credentials in a handoff bundle or commit.
