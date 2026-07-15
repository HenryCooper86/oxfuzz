# Web API Security and Run Transport Design

Status: **active**. Owner: `hf-web`.

## 1. Goal

`hf-web` is an untrusted network presentation boundary over `hf-service`. It
must not weaken the service's human-approval, sandbox, workspace, or persistence
contracts. HTTP handlers translate validated requests into service calls and
return redacted transport DTOs; they do not implement fuzzing business logic.

## 2. Exposure and Authentication

`hobot-fuzz serve` binds to `127.0.0.1` by default. A non-loopback bind is
rejected before opening a socket unless a non-empty `HF_WEB_TOKEN` is configured.
This is a startup invariant, not a warning.

All routes except `/health` are fail-closed unless either a bearer token is
configured or the operator explicitly sets `HF_WEB_TOKEN_OPTIONAL=1` for local
development. Bearer values are compared in constant time and are never written
to logs, URLs, error bodies, or tracing fields.

Browser cross-origin access is denied except for exact origins in
`HF_WEB_CORS_ORIGINS`. The default allowlist contains only the standard local
Vite origins. CORS permits the minimum methods and headers used by the API,
including `Authorization`; it never uses a wildcard origin. Actual requests
carrying an unlisted cross-origin `Origin` header are rejected before handler
execution, so CORS is not treated as response-only CSRF protection.

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

## 4. Public Response DTOs

REST responses do not expose absolute host paths, provider credentials,
authorization headers, environment-variable secret names, or raw secret config
values. Path-bearing service records retain their shape where browser parity
requires it, but absolute path values are replaced by an explicit redaction
marker. Provider and raw-config reads clear secret fields. Desktop commands are
not changed; their trusted local presentation can continue to show local paths.

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

SSE uses a bounded broadcast channel. Oversized events are rejected before
enqueueing. A slow subscriber receives a `stream:lagged` event with the number
of dropped messages, then continues from the channel's current position. Run
progress and lifecycle events always carry the service-owned run id. The
service emits `running` before execution and exactly one terminal lifecycle
event (`done`, `failed`, or `cancelled`) after the background task returns.

Every `ClassifiedError` crosses the HTTP boundary through one mapping:
validation is `400`, harness/engine execution rejection is `422`, provider
failure is `502`, sandbox unavailability is `503`, timeout is `504`, and
storage/internal failure is `500`. Handlers do not choose a different status
for the same service error category.

## 6. Validation

- Unit tests cover loopback/non-loopback bind decisions and bearer semantics.
- Router tests cover exact-origin preflight, unauthorized responses, and
  redacted config/path DTOs.
- Filesystem tests cover outside-root and symlink escape rejection.
- Run-route tests cover invalid ids, mapped preflight failures,
  missing/inactive runs, event-size bounds, and lag notification. Service tests
  prove a background start returns a queryable durable UUID before mocked
  execution, then exact cooperative cancellation reaches a terminal row.
- `hf-web` depends only on `hf-service`, never on domain/runtime crates.
