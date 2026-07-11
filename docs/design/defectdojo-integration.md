# DefectDojo Integration -- Design

## Goal

Push hobot_fuzz's triaged crashes to a [DefectDojo](https://www.defectdojo.org)
instance as findings, so fuzzing results flow into an org's existing
DevSecOps / vulnerability-management workflow with no manual re-entry.

## Approach

DefectDojo is a Django/Python server. We do **not** bundle or embed it. Instead
hobot_fuzz acts as a thin REST client that maps triaged crashes to DefectDojo's
**Generic Findings Import** JSON and POSTs them to the API. This reuses the
existing CWE + `security-severity` logic that already backs the SARIF exporter
(`hf-service/src/sarif.rs`), so a crash's classification is identical across
SARIF and DefectDojo.

Repeat pushes use **reimport-scan** (`/api/v2/reimport-scan/`) keyed on the
crash **stack signature** (`unique_id_from_tool`), so re-found crashes update in
place and crashes that no longer reproduce are closed -- instead of the
engagement filling with duplicates on every fuzzing iteration.

## Layering (AGENTS.md 2.9 -- all logic in hf-service)

| Layer | Location | Responsibility |
|-------|----------|----------------|
| Config | `config/defectdojo.toml` (+ `.example`), registered in `config.rs` `CONFIG_SECTIONS` | url, `api_token_env`, verify_tls, product/engagement, auto_create, reimport |
| Logic | `hf-service/src/defectdojo.rs` | `DefectDojoConfig`, `crashes_to_generic` mapper, `severity_bucket`, `DefectDojoClient` (import/reimport + test_connection) |
| Orchestration | `container.rs`: `push_to_defectdojo`, `defectdojo_test_connection`, `defectdojo_configured` | resolve crashes -> map -> POST |
| CLI | `hf-cli`: `defectdojo <project> [--target T] [--test]` | |
| Web | `hf-web`: `POST /defectdojo/push`, `GET /defectdojo/test`, `GET /defectdojo/configured` | |
| Tauri | `commands.rs`: `push_to_defectdojo`, `defectdojo_test_connection`, `defectdojo_configured` | |
| GUI | Settings > Integrations panel (URL/token + Test connection); "Push to DefectDojo" in Triage and Reports | |

## Secrets

The config stores only the **name** of an environment variable (`api_token_env`,
default `HF_DEFECTDOJO_TOKEN`); the token is read from the environment at call
time and never persisted or logged. This mirrors the provider `api_key_env`
convention. Errors redact the token and classify 401/403 -> Validation (user
action), 5xx -> Provider (transient/server).

## Crash -> Finding mapping

| DefectDojo field | Source |
|------------------|--------|
| `title` | `BugReport.title` -> `summary` -> `"{kind} crash"` |
| `severity` | `severity_bucket(security_severity(crash))` (Critical/High/Medium/Low) |
| `cvssv3_score` | `security_severity` (0-10) |
| `cwe` | `cwe_for(crash)` integer (omitted for `CWE-noinfo`) |
| `file_path` / `line` | parsed from CASR `crashline` |
| `description` | bug-report summary + repro + stack, else CASR stack |
| `mitigation` | `BugReport.suggested_fix` (the diff) |
| `impact` | `BugReport.root_cause` |
| `unique_id_from_tool` | `Crash.stack_signature` (dedup key) |
| `vuln_id_from_tool` | `Crash.id` |
| `active` / `verified` | `true` / `false` (machine-triaged, human-unconfirmed) |
| `dynamic_finding` | `true` (runtime finding) |

Product defaults to the project directory name; the test title is the target,
so repeat runs of a target land in the same DefectDojo test and dedup.

## Non-goals / behavior

- Never gate fuzzing on DefectDojo availability -- push is an explicit, separate
  action; failures surface as a toast/CLI error, and the local SARIF/report
  remain the record of fallback.
- No crash reproducer bytes are uploaded -- only metadata, stack, and locations.
