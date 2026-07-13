# DefectDojo Integration -- Design

## Goal

Push hobot_fuzz's triaged crashes to a [DefectDojo](https://www.defectdojo.org)
instance as findings, so fuzzing results flow into an org's existing
DevSecOps / vulnerability-management workflow with no manual re-entry.

## Approach

DefectDojo is a Django/Python server. We **ship no copy of it** -- no vendored
source, no compose file, no image. hobot_fuzz acts as a thin REST client that
maps triaged crashes to DefectDojo's **Generic Findings Import** JSON and POSTs
them to the API. This reuses the existing CWE + `security-severity` logic that
already backs the SARIF exporter (`hf-service/src/sarif.rs`), so a crash's
classification is identical across SARIF and DefectDojo.

Repeat pushes use **reimport-scan** (`/api/v2/reimport-scan/`) keyed on the
crash **stack signature** (`unique_id_from_tool`), so re-found crashes update in
place and crashes that no longer reproduce are closed -- instead of the
engagement filling with duplicates on every fuzzing iteration.

## Lifecycle of a local instance

Shipping no server is not the same as pretending none is running. The desktop app
embeds the DefectDojo web UI (a native child webview -- DefectDojo sends
`X-Frame-Options: DENY`, so an iframe is impossible), and a webview pointed at a
stopped server renders an empty grey rectangle that is indistinguishable from a
broken view. So hobot_fuzz **adopts and supervises** the DefectDojo compose
project the operator already installed, in `hf-service/src/defectdojo_lifecycle.rs`:

| Concern | Decision |
|---|---|
| Which instance | **Only a local one** (`localhost` / `127.0.0.1`). A remote DefectDojo is somebody else's server: probe it, never start or stop it. |
| Where it is | Discovered from Docker itself: the compose project's containers carry `com.docker.compose.project.config_files` / `.working_dir` labels, so a standard upstream install needs zero configuration. `[lifecycle] compose_files` overrides for a non-standard layout. |
| Which port | **The app owns it.** Upstream's compose publishes `${DD_PORT:-8080}`, so the port is derived from the configured `url` and passed in as `DD_PORT` -- the server cannot come up somewhere the app is not looking. |
| When | On launch, after Docker is up (it is a Docker stack too), if `[lifecycle] autostart` is set. Also on demand from the Health panel and the DefectDojo view. |
| Readiness | An **HTTP** probe, not a TCP connect: nginx accepts connections immediately but returns 5xx for the ~minute uwsgi takes to boot. `Starting` and `Ready` are different states, and the webview only attaches on `Ready`. |
| Failure | Reported as a state (`docker_down`, `not_installed`, `stopped`, ...) with a human-readable message, never an exception. Autostart is best-effort and never blocks launch. |

`system_status()` gains a `defectdojo` flag from the same probe, so the Health
panel, the REST `/system/status`, and the CLI agree on one answer.

## Layering (AGENTS.md 2.9 -- all logic in hf-service)

| Layer | Location | Responsibility |
|-------|----------|----------------|
| Config | `config/defectdojo.toml` (+ `.example`), registered in `config.rs` `CONFIG_SECTIONS` | url, `api_token_env`, verify_tls, product/engagement, auto_create, reimport, `[lifecycle]` |
| Lifecycle | `hf-service/src/defectdojo_lifecycle.rs` | `DefectDojoState`/`DefectDojoStatus`, compose discovery, `status`/`start`/`stop`/`autostart`, HTTP readiness probe |
| Logic | `hf-service/src/defectdojo.rs` | `DefectDojoConfig`, `crashes_to_generic` mapper, `severity_bucket`, `DefectDojoClient` (import/reimport + test_connection) |
| Orchestration | `container.rs`: `push_to_defectdojo`, `defectdojo_test_connection`, `defectdojo_configured` | resolve crashes -> map -> POST |
| CLI | `hf-cli`: `defectdojo <project> [--target T] [--test]` | |
| Web | `hf-web`: `POST /defectdojo/push`, `GET /defectdojo/test`, `GET /defectdojo/configured`, `GET /defectdojo/status`, `POST /defectdojo/start`, `POST /defectdojo/stop` | |
| Tauri | `commands.rs`: `push_to_defectdojo`, `defectdojo_test_connection`, `defectdojo_configured`, `defectdojo_status`/`_start`/`_stop`, `autostart_defectdojo` (from `setup()`) | |
| GUI | Settings > Integrations panel (URL/token + Test connection); "Push to DefectDojo" in Triage and Reports; DefectDojo row in Dashboard > Health; the embedded view gates on `Ready` and offers Start | |

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
  remain the record of fallback. Autostart is best-effort for the same reason: it
  runs in the background at launch and a failure is a reported state, not an error.
- No crash reproducer bytes are uploaded -- only metadata, stack, and locations.
