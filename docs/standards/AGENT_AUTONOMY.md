# Agent Autonomy Standard

Status: **active**. Scope: `hf-agent`, `hf-service`, sub-agents.

## 1. Autonomy Levels

| Level | Behavior | Example |
| --- | --- | --- |
| `Assist` | Propose only; user executes. | Suggest targets. |
| `Draft` | Prepare artifacts; user approves before use. | Draft harness. |
| `Supervised` | Execute non-destructive actions; pause on High-risk. | Smoke fuzz. |
| `Autonomous` | Run the full loop; HITL only at gates. | Unattended campaign. |

Default: `Draft` for harness, `Supervised` for smoke fuzz, `Assist` for
crash report publication.

## 2. Delegation

- Parent agent delegates to sub-agents via the `Task` tool.
- Sub-agent definitions are built in: `hf-agent` parses them from embedded
  builtins. User-defined TOMLs in `config_dir()/agents/` -- `config/agents/`
  in a source checkout, the pinned per-user config root in an installed
  desktop application -- override a built-in with the same id; the directory
  is optional and no definitions ship as repository files.
- Sub-agents return a single result message; they do not stream to the user.

## 3. Sub-Agents

| Agent | Owns | Autonomy |
| --- | --- | --- |
| `discovery-agent` | Target ranking | Assist |
| `harness-agent` | Harness draft/iterate | Draft |
| `triage-agent` | Crash classification, bug report | Draft |
| `coverage-agent` | Stagnation detection, proposals | Assist |

## 4. HITL Gates

Mandatory gates (user must approve):

- Before a full `FuzzRun` (after smoke).
- Before publishing / filing a bug report.
- Before writing a harness into the target project (vs. `fuzz_workspace/`).
- Before any action that the service-owned guardrail policy classifies as
  requiring approval. Guardrail policy is not currently user-editable.

## 5. Automotive Operations

An agent may propose offline capture analysis, deterministic mutations, state
interpretation, or a replay plan. It may not enable the automotive subsystem,
claim an unavailable adapter capability, choose an unallowlisted interface,
increase service-resolved limits, or manufacture approval evidence.

Offline planning remains `Draft`; virtual-CAN execution is at most
`Supervised`. Every physical-bench operation pauses for fresh human approval
after the exact protocol, replay-plan digest, interface, allowlists, rate, and
duration are known. Physical approval cannot be inherited from a prior plan or
granted by `Autonomous` mode. Dangerous diagnostic services remain denied when
the policy does not model an explicit approval path.
