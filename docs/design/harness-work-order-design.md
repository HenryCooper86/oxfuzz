# Harness Work Order v2

Status: **active**. Owner: `hf-service`. The approved implementation details,
limits, durable records, stable errors, and REST resources are defined in the
[Harness Work Order v2 specification](../superpowers/specs/2026-08-30-harness-work-order-v2-design.md).

## 1. Purpose

Harness Work Order v2 supports provider-free harness authoring without making
import an execution operation. An operator can export retained target evidence,
author a harness directly or through an external tool, import the result as an
immutable draft, and explicitly qualify one selected submission through the
existing sandboxed harness path.

## 2. Active Flow

1. **Export** creates a deterministic, content-addressed packet from retained
   target evidence, a bounded source excerpt plus complete-source digest,
   normalized compile context, lint rules, and bounded seed references. Export
   persists the packet before returning and invokes no provider or runtime.
2. **Import** persists exact UTF-8 source, untrusted authoring provenance,
   repair ancestry, source digest, and deterministic lint findings. Import
   invokes no provider, build, review, smoke run, or promotion.
3. **Qualification** is a separate explicit operation. It rejects stale target
   or compile evidence and blocking import lint before dispatch, then uses the
   existing sandbox compile, independent exact-digest review, and bounded smoke
   operations. Every stage and terminal result is durable; qualification never
   promotes.
4. **Ranking** reads retained attempt evidence only. It orders compilation
   success, smoke verdict (`Pass`, `Suspect`, `Fail`, absent), repair ancestry,
   throughput, submission time, and identifier without starting a process or
   changing the active harness.
5. **Promotion** accepts one explicit attempt identifier and can activate only
   its exact active `SmokePassed` harness revision with matching reviewed and
   smoked source and executable digests. The existing atomic promotion operation
   persists the human approval for that exact evidence.

The feature is exposed through service-owned operations, thin CLI commands, and
REST resources. Presentation layers parse and render I/O but do not reproduce
qualification, ranking, or promotion policy.

## 3. Safety and Recovery

Work orders, submissions, and terminal attempts are immutable durable evidence.
Startup recovery marks unfinished attempts interrupted; retry creates a new
attempt. Clearing ordinary run history preserves the work-order records and
their terminal summaries.

No export, import, read, list, or ranking operation executes a harness. Compile,
review, and smoke remain separate qualification steps under the existing human
approval, guardrail, and `hf-runtime` sandbox requirements. A crash-bearing
`Fail` attempt is ineligible for clean promotion. A crash-free `Suspect` attempt
is technically eligible only through an explicit operator promotion request;
the recommended action is to refine it and smoke the new revision first.
