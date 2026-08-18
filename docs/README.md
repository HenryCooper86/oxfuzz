# oxfuzz documentation

This directory contains operator guides, architecture decisions, engineering
standards, and the screenshot evidence used by the project README. Start with
the document that matches your task.

## By audience

| Audience | Start here | Then read |
| --- | --- | --- |
| New users and enthusiasts | [Getting Started](guides/GETTING_STARTED.md) | [The Desktop App](guides/DESKTOP_APP.md), the [CLI Reference](guides/CLI_REFERENCE.md), and the [Safety Model](guides/SAFETY_MODEL.md) |
| Fuzzing operators | [Getting Started](guides/GETTING_STARTED.md) | [Harness Standard](standards/HARNESS_STANDARD.md), [Target Taxonomy](standards/TARGET_TAXONOMY.md), and [Engine Adapter Standard](standards/ENGINE_ADAPTER_STANDARD.md) |
| Release managers | [Release Checklist](guides/RELEASE_CHECKLIST.md) | [Test Strategy](standards/TEST_STRATEGY.md), [Engineering Standards](standards/ENGINEERING_STANDARDS.md), and `AGENTS.md` |
| Contributors | [AGENTS.md](../AGENTS.md) at the repository root | [Design Overview](design/DESIGN_OVERVIEW.md), [Test Strategy](standards/TEST_STRATEGY.md), and the design for the subsystem being changed |
| API and integration users | [Web API Security Design](design/web-api-security-design.md) | [Service Orchestration](design/service-orchestration-design.md), the [Configuration reference](guides/CONFIGURATION.md), and generated API help |
| Automotive security users | [Automotive Protocol Fuzzing Design](design/automotive-protocol-fuzzing-design.md) | The automotive workflows in the [CLI Reference](guides/CLI_REFERENCE.md) and the [release checklist](guides/RELEASE_CHECKLIST.md) |

## Operator guides

- [Getting Started](guides/GETTING_STARTED.md) explains the product and the
  four-stage campaign in plain language.
- [Install & Build](guides/INSTALL.md) covers prerequisites, the CLI and desktop
  builds, prebuilt apps, and optional DefectDojo.
- [The Desktop App](guides/DESKTOP_APP.md) walks a campaign end to end in the
  primary UI, plus the AI Assistant and settings.
- [CLI Reference](guides/CLI_REFERENCE.md) documents every subcommand, the
  quick-start flow, optional Semgrep enrichment, and automotive workflows.
- [Configuration](guides/CONFIGURATION.md) describes the config tree, providers,
  and environment.
- [Safety Model](guides/SAFETY_MODEL.md) covers sandboxing, guardrails, and
  human-in-the-loop approval.
- [Release Checklist](guides/RELEASE_CHECKLIST.md) defines the source,
  sandbox, packaging, security, and GitLab handoff gates.
- [Continuous Integration](guides/CI.md) documents the two-host gate setup.
- [Syzkaller Setup](guides/SYZKALLER_SETUP.md) covers the advanced kernel
  workflow and its stronger environment requirements.
- [Screenshot Guide](screenshots/README.md) defines the reproducible image set,
  safety constraints, and privacy review.

## Architecture and design

[Architecture](ARCHITECTURE.md) is the high-level map: the inward-pointing
layering, the `hf-service` spine, and the crate map. The
[Design Overview](design/DESIGN_OVERVIEW.md) is the entry point for detailed
subsystem designs, which cover:

- target discovery, harness generation, engine integration, corpus/coverage,
  and crash triage;
- service orchestration, runtime isolation, provider/tool prompt security, and
  web API security;
- portfolio campaigns, issue trackers, DefectDojo, and automotive protocol
  fuzzing.

Implementation must follow the current design. If a design is impractical,
update and review the design before changing production behavior.

## Engineering standards

- [Test Strategy](standards/TEST_STRATEGY.md)
- [Defensive Patterns](standards/DEFENSIVE_PATTERNS.md)
- [Engineering Standards](standards/ENGINEERING_STANDARDS.md)
- [Database Schema](standards/DATABASE_SCHEMA.md)
- [Agent Autonomy](standards/AGENT_AUTONOMY.md)
- [Tool Call Protocol](standards/TOOL_CALL_PROTOCOL.md)
- [Target Taxonomy](standards/TARGET_TAXONOMY.md)
- [Harness Standard](standards/HARNESS_STANDARD.md)
- [Engine Adapter Standard](standards/ENGINE_ADAPTER_STANDARD.md)

[AGENTS.md](../AGENTS.md) is the mandatory repository protocol. When a guide, design, and
implementation disagree, treat that mismatch as a defect: verify the service
behavior, then update the owning design and user-facing documentation together.

## Documentation change checklist

- Claims match current service behavior and safety boundaries.
- Commands exist and use current flags.
- Relative links and image paths resolve from their source file.
- Screenshots contain no secrets or private target material.
- User-facing workflow language matches the current four-stage Progress model.
- Optional features are identified as compile-time and/or runtime gated.
- Release claims distinguish local verification, signing, and notarization.
