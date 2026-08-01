# Automotive Fuzzing Campaign Report: `complete`

| | |
|---|---|
| Project | `complete` |
| Generated | 2026-07-16T09:00:00Z |
| Tool | oxfuzz 0.1.0 |
| Evidence window | 5 retained operation(s) |

## Executive Summary

This report synthesizes **5 retained automotive operation(s)**: **5 completed**, **0 partial**, **0 failed**, **0 running**, and **0 cancelled**. The bounded snapshot contains **1 unique protocol-state digest(s)** and **1 promoted state-corpus artifact(s)** across **1 observed protocol(s)**.

No terminal operation failure is present in this retained evidence window.

Protocol-state novelty is **not source coverage** and does not by itself prove a vulnerability.

## Scope and Safety Posture

| Control | Effective posture |
|---|---|
| Runtime automotive policy | enabled |
| Allowed protocols | `uds` |
| Allowed modes | `virtual_can` |
| Virtual interfaces | 2 allowlisted |
| Physical bench | enabled; fresh approval required; 3 allowlisted interface(s) |
| Dangerous diagnostic services | exceptionally allowed by policy |
| Per-operation bounds | 5 events; 6 seconds; 7 transmitted events/second |

All captured, mutation, planning, and replay evidence remains subject to service validation, sandbox isolation, typed limits, guardrails, and the human-approval boundary.

## Campaign Workflow

| Stage | Status | Completed | Failed |
|---|---|---:|---:|
| Adapter capability inspection | Complete | 1 | 0 |
| Immutable capture analysis | Complete | 1 | 0 |
| Deterministic mutation generation | Complete | 1 | 0 |
| Typed replay-plan construction | Complete | 1 | 0 |
| Supervised virtual replay | Complete | 1 | 0 |

Physical-bench validation is intentionally excluded from campaign-completeness scoring. It remains a separately approved activity after the exact plan and budgets are known.

## Protocol-State Exploration

| Protocol | Unique states | Promoted artifacts |
|---|---:|---:|
| `uds` | 1 | 1 |

### State Evidence

- `[STATE:2fe325136b771614edd4ace673a81b7297ae1665e20ab9040b876c1c947e52de]` (`uds`), observed by [OP:00000000-0000-0000-0000-000000000002].
- Promoted `[STATE:2fe325136b771614edd4ace673a81b7297ae1665e20ab9040b876c1c947e52de]` from [OP:00000000-0000-0000-0000-000000000002], artifact digest `5656565656565656565656565656565656565656565656565656565656565656` at `project/.service/automotive/state-corpus/uds/evidence`.

## Findings

No retained terminal operation failure requires triage in this evidence window.
### Interpretation Boundary

Observed states, successful decoding, and completed replay steps are campaign evidence. They do not by themselves prove exploitability, security impact, or unsafe vehicle behavior.

## Evidence Manifest

| Operation evidence | Stage | Mode / protocol | Status | Validated result | Request digest | Transcript evidence | Artifact directory |
|---|---|---|---|---|---|---|---|
| [OP:00000000-0000-0000-0000-000000000001] | `capabilities` | `offline_pcap` / `uds` | done | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/capabilities` |
| [OP:00000000-0000-0000-0000-000000000002] | `analyze_capture` | `offline_pcap` / `uds` | done | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/analyze_capture` |
| [OP:00000000-0000-0000-0000-000000000003] | `generate_mutations` | `offline_pcap` / `uds` | done | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/generate_mutations` |
| [OP:00000000-0000-0000-0000-000000000004] | `build_replay_plan` | `offline_pcap` / `uds` | done | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/build_replay_plan` |
| [OP:00000000-0000-0000-0000-000000000005] | `execute_replay` | `virtual_can` / `uds` | done | complete | `cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd` | [TRANSCRIPT:efefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefef] | `.service/automotive/execute_replay` |

## Limitations

- The report covers only the bounded retained evidence snapshot and cannot infer events that were not persisted.
- Protocol-state digests are not source-code line, function, region, or edge coverage.
- A completed operation confirms contract-valid execution, not absence of security defects.
- Offline and virtual evidence does not validate a physical ECU, vehicle network, timing behavior, or bench wiring.
- AI-assisted interpretation, when appended, is advisory and cannot authorize execution or establish a finding.

## Recommendations

1. Preserve the current operation evidence and compare future campaign snapshots for regressions.
---

_Deterministic evidence report generated by oxfuzz 0.1.0 on 2026-07-16T09:00:00Z._
