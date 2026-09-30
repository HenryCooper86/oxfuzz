# Web API Security and Run Transport Design

Status: **active**. Owner: `hf-web`.

## 1. Goal

`hf-web` is an untrusted network presentation boundary over `hf-service`. It
must not weaken the service's human-approval, sandbox, workspace, or persistence
contracts. HTTP handlers translate validated requests into service calls and
return redacted transport DTOs; they do not implement fuzzing business logic.

## 2. Exposure and Authentication

`oxfuzz serve` binds to `127.0.0.1` by default. A non-loopback bind is
rejected before opening a socket unless a non-empty `HF_WEB_TOKEN` is configured.
This is a startup invariant, not a warning.

All routes except `/health` are fail-closed unless either a bearer token is
configured or the operator explicitly sets `HF_WEB_TOKEN_OPTIONAL=1` for local
development. Bearer values are compared in constant time and are never written
to logs, URLs, error bodies, or tracing fields.

Browser cross-origin access is denied except for exact origins in
`HF_WEB_CORS_ORIGINS`. The default allowlist contains only the standard local
Vite origins. CORS permits `GET`, `POST`, `PATCH`, `DELETE`, and `OPTIONS`, plus
the `Authorization` and `Content-Type` headers; it never uses a wildcard origin. Actual requests
carrying an unlisted cross-origin `Origin` header are rejected before handler
execution, so CORS is not treated as response-only CSRF protection.

Every request body is limited to 1 MiB at the router before JSON extraction or
handler execution. Current APIs carry paths, settings, source snippets, and
bounded DTOs rather than bulk artifacts; captures and other large inputs are
staged in the managed workspace. A future bulk-upload route must declare its
own narrower authenticated streaming policy instead of raising this global
limit.

## 3. Host Filesystem Boundary

Network requests may refer only to projects below the canonical roots in
`HF_WEB_PROJECT_ROOTS`. When that variable is absent, a source checkout's
repository root is the sole allowed root; an installed server with no known
repository root denies project-path requests until roots are configured.

Project and document paths are canonicalized before use. Parent traversal,
outside-root paths, and symlink escapes fail closed. An ingested document must
also be a regular file below its approved project root. The policy is resolved
once when the router is built so a request cannot alter it through process
environment races.

REST project export requires an explicit approved project. An omitted project
must not select the service's all-project export mode, which is reserved for
trusted local presentation.
Run history, auto-revert audit, workbench dashboard, and harness review reads
likewise require an explicit approved project on the REST transport.
Persisted crash and corpus browse reads use the approved project's target IDs;
the desktop's browse-all service calls remain local-only.
The REST artifact clear operation requires an approved project and removes only
that project's persisted crashes and corpus entries. The desktop can retain its
trusted-local all-project clear operation.
The REST run-history clear operation likewise requires an approved project and
removes only that project's terminal runs and their retained evidence.
Deleting one crash through REST requires an approved project, and the service
checks the persisted crash, run, and target ownership before deleting its row.
REST corpus browse records carry their target ID so deletion can select one
stored entry by project, target ID, and digest. The server resolves the managed
path from storage; browser clients do not send a redacted path back as identity.

Schedule definition lists and create/update/delete responses include only projects
under the router's approved roots. Exact schedule deletion and enable/disable use
service methods that check stored project ownership under the scheduler mutation
admission lock before changing any definition or campaign state. Invalid persisted
project ownership fails with a bounded error; trusted local scheduler methods
retain their all-project access.

REST scheduler history reads and clearing authorize the project retained in each
execution's request parameters, including after its schedule definition is removed.
The service reads bounded pages and applies the requested visible count after
project filtering. Clearing compares the authorized stored JSON snapshot inside
the deletion transaction and fails if a selected record disappeared or changed;
nonterminal one-time occurrence receipts continue to protect their executions.
Missing or invalid retained project ownership produces a bounded error before
clearing begins. Trusted local history operations retain their all-project access.

## 4. Public Response DTOs

REST responses do not expose absolute host paths, provider credentials,
authorization headers, environment-variable secret names, or raw secret config
values. Path-bearing service records retain their shape where browser parity
requires it, but absolute path values are replaced by an explicit redaction
marker. Provider and raw-config reads clear secret fields. Desktop commands are
not changed in general; their trusted local presentation can continue to show
local paths. One-time recovery is stricter across every presentation: REST,
Tauri, and CLI use the service-owned bounded recovery error code and message,
never the underlying path-, SQL-, OS-, or stored-JSON-bearing cause.

DefectDojo and issue-tracker settings use dedicated typed GET/PATCH routes. Their
public DTOs replace secrets, secret environment names, and compose-file paths
with configured-state booleans. An omitted protected patch field means preserve;
replacement and clearing are explicit operations. The service performs the
merge, semantic validation, and atomic private-file write. Generic raw browser
writes are rejected for these sections, preventing a redacted read from becoming
a destructive write.

Potentially path-shaped Compose project and repository values use a public
`configured`/optional-`value` state. Absolute legacy values produce no value and
no redaction marker; clients must keep, explicitly replace, or explicitly clear
them. Same-directory patch transactions are serialized within one process.

`GET /config/fuzzing` returns the service-validated `FuzzingSettings` policy.
Presentation clients do not reconstruct this policy by parsing redacted raw
TOML and must propagate an invalid-policy error instead of substituting defaults.

## 5. Run Control and Events

Run status, start, and cancellation use service-owned run UUIDs. The web layer
never invents an execution id and never aborts a task as a substitute for
cooperative runtime cancellation. `POST /runs/start` validates the approved
project boundary, delegates reservation and launch to `hf-service`, and returns
`202 Accepted` only after the run row and recovery journal entry are durable and
the cancellation token is registered. Execution continues in a service-owned
task, so disconnecting the HTTP request does not orphan or implicitly cancel the
campaign. Status and cancellation resolve the durable row through service APIs;
missing and inactive runs remain distinct transport outcomes.

The network run-control surface is intentionally limited to harness-backed
user-space engines. Syzkaller remains a trusted-local Tauri workflow because it
accepts kernel, rootfs, SSH-key, and manager-config artifacts and may request
KVM device access; exposing that launch contract remotely would expand the web
threat model beyond approved project paths. Browser mode reports that boundary
explicitly. The REST API likewise exposes exact-id cancellation instead of a
blanket `cancel_all_runs` operation, preventing one client from stopping an
unrelated operator's campaign.

SSE uses a bounded broadcast channel. Oversized events are rejected before
enqueueing. A slow subscriber receives a `stream:lagged` event with the number
of dropped messages, then continues from the channel's current position. The
web transport exposes only channels with production producers: run progress,
run lifecycle, and stream lag. Run progress and lifecycle events always carry
the service-owned run id. The service emits `running` before execution and
exactly one terminal lifecycle event (`done`, `failed`, or `cancelled`) after
the background task returns.

Every `ClassifiedError` crosses the HTTP boundary through one mapping:
validation is `400`, harness/engine execution rejection is `422`, provider
failure is `502`, sandbox unavailability is `503`, timeout is `504`, and
storage/internal failure is `500`. Handlers do not choose a different status
for the same service error category.

One-time recovery uses its narrower service-owned public mapping:
`not_found` is `404`, `conflict` is `409`, `unavailable` is `503`, and
`internal` is `500`. Recovery error JSON includes that stable code and a
bounded message.

## 6. Validation

- Unit tests cover loopback/non-loopback bind decisions and bearer semantics.
- Router tests cover exact-origin preflight, unauthorized responses, and
  redacted config/path DTOs, typed integration preservation, explicit protected
  value updates, and fail-closed integration writes.
- Filesystem tests cover outside-root and symlink escape rejection.
- Run-route tests cover invalid ids, mapped preflight failures,
  missing/inactive runs, event-size bounds, and lag notification. Service tests
  prove a background start returns a queryable durable UUID before mocked
  execution, then exact cooperative cancellation reaches a terminal row.
- `hf-web` depends only on `hf-service`, never on domain/runtime crates.

## Browser event delivery

SSE parsing and subscriber delivery are separate operations. A throwing
subscriber is logged by event name without payload data, and remaining
subscribers and subsequent frames continue on the same connection. Subscriber
exceptions are never retried as raw JSON payloads or treated as transport loss.
