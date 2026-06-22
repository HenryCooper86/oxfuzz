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
- Each sub-agent has a TOML definition in `config/agents/`.
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
- Before any action with risk score >= threshold (see `guardrails.toml`).