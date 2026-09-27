# Acceptance record format

Store one reviewed record per tested capability, environment, and candidate
revision. Records may live outside Git when they contain private target source,
logs, or credentials; link a sanitized summary from release notes or the
capability checklist. Keep failures and unavailable evidence as records too.

Each record contains:

| Field | Required content |
| --- | --- |
| Claim and outcome | Operation, language, engine, platform, pass/fail/unavailable, and the exact behavior observed. Do not infer vulnerability absence from a clean bounded run. |
| Source identity | Candidate commit, dirty-tree patch digest if applicable, target revision, selected function, exact approved harness attempt and source digest. |
| Runtime identity | Operating system/architecture, container image digest, engine/tool versions, provider family/model revision without credentials, and relevant feature/configuration snapshot. |
| Execution limits | CPU, memory, duration, corpus entry/byte limits, model budget, and number of trials. Include the approval identifier and scope for real harness or interface execution. |
| Evidence | Run/replay/crash UUIDs, retained manifest/artifact hashes, logs and report locations, observed Stop latency, cleanup state, and any missing evidence. |
| Review | Operator and reviewer, time, limitations, unsupported steps, and links to follow-up defects or rerun records. |

Record absolute artifact locations in a private inventory where necessary, but
share content hashes and sanitized links in the release summary. Never copy API
keys, credentials, raw private source, or customer crash payloads into public
records. A record without a tested revision, exact runtime identity, and
inspectable result is incomplete.

Use [Capability Acceptance](../guides/CAPABILITY_ACCEPTANCE.md) for the
scenario checklist and [Support Matrix](../guides/SUPPORT_MATRIX.md) for the
claims that these records may qualify. Run every generated harness through
`hf-runtime` only after exact-source review and human approval.

The [2026-09-27 performance record](performance-2026-09-27.md) provides a
sanitized example for a no-harness benchmark, with raw samples and separate
executor and history claims.
The [held-out effectiveness protocol](effectiveness-baseline-protocol.md)
defines a frozen cohort format; it has no live trial results yet.
The [2026-09-27 userspace attempt record](userspace-attempts-2026-09-27.md)
retains failed exploratory outcomes without counting them as accepted samples.
The [2026-09-27 C userspace qualification](userspace-2026-09-27.md) records ten
passing libFuzzer, AFL++, and honggfuzz cycles on one clean candidate and image.
The [local isolation](isolation-2026-09-27.md) and
[owned-container recovery](runtime-recovery-2026-09-27.md) records provide
partial A3 evidence; they do not complete the fault-soak checklist.

For desktop publication, the draft release contains a hidden
`oxfuzz-release-acceptance` JSON block. Enter the candidate commit and reviewed
HTTPS record URL plus `sha256:` digest for `userspace_engines`,
`sandbox_isolation`, and `installed_clients`. These three claims are mandatory
for the desktop release workflow. Additional claimed kernel, automotive, or
finding-publication capability needs its own scope entry and reference. The
workflow checks this index before publication; a person must inspect the
linked evidence and its digest.
