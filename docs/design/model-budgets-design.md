# Model spending budgets

Status: active implementation. Owner: hf-service, persistence: hf-storage.

The `model-budgets` feature adds a service-owned provider decorator to every
configured or environment-built pool. The decorator surrounds individual backend
requests, so pool retries and paid health probes each reserve their own allowance.
Streaming handshakes reserve before obtaining an upstream stream.

`oxfuzz.toml` exposes `[model_budget]`: explicit `scope_id`, optional `max_calls`,
`max_tokens`, `max_cost_microusd` (one dollar is 1000000), and
`max_output_tokens` (default 4096). No configured limits means disabled. A scope
identifies one campaign, benchmark trial, or multi-command workflow; use the same
scope and `HF_DB_PATH` throughout that workflow, including restarts. All model
operations in that configured service share the scope. This deliberate workflow
scope includes discovery and harness generation before a campaign run exists.
Unrelated concurrent workflows require separate service configurations/scopes.
The CLI's `--config <directory>` selector uses
these same settings; `oxfuzz model-budget` reports the retained accounting; presentations do not implement their own accounting.

SQLite stores immutable limits per scope plus attempts with provider/model,
reserved input/output tokens, integer cost, observed usage and completion state.
Atomic transactions charge one call and its worst-case usage before dispatch.
Concurrent processes cannot spend the same remaining allowance. Reopening a
scope with changed limits fails rather than resetting counters. Scope records
survive project evidence cleanup and restart. Denials persist the named exhausted
resource; callers receive a typed, nonretryable error without freezing a provider.

Input reservation uses the configured provider's full context window; output
uses the explicit request limit capped at `max_output_tokens`, which is also
written into the dispatched request. The context setting must accurately describe
the deployed model. Model overrides, arbitrary provider parameters, and image
requests are rejected when token or monetary limits are active because their
charges cannot be bounded by this text-token policy. Dollar limits require finite,
strictly positive input and output prices; zero means unknown, not free. Prices
must be an operator-supplied upper bound, including any applicable surcharges.
Integer microdollar charges round upward. Missing prices never become zero spend.

Successful responses with reported nonzero usage settle exactly once, refunding
unused tokens/cost. Failed requests, missing usage, incomplete streams, cancellation,
and process loss retain their entire reservation: the upstream might have billed
them. Recovery never refunds an unresolved attempt. An observed overrun blocks the
scope permanently and is retained as an accounting violation. No accounting layer
can enforce a dishonest upstream's billing or inaccurate configured prices.

Rejected alternatives: post-response checks admit concurrent overspend; in-memory
counters reset on restart; wrapping the pool misses internal retries; automatic
refunds after errors/crashes assume upstream requests were not billed.

Verification uses mock providers and real temporary SQLite databases: concurrent
admission, retry charging, restart retention, successful settlement, streaming drop,
unknown prices, immutable limits, disabled-feature settings, and terminal errors.
No live model, generated harness, or fuzzer executes in these tests.

## Operator example

Copy the normal configuration into a trial-specific directory, retain its provider
prices and credentials, and add the following to that directory's `oxfuzz.toml`:

```toml
[model_budget]
scope_id = "parser-a-trial-1"
max_calls = 30
max_tokens = 2000000
max_cost_microusd = 5000000
max_output_tokens = 4096
```

Run every discovery, harness, review, campaign, and triage command for that trial
with `HF_DB_PATH=/path/to/trial-accounting.db` and
`oxfuzz --config /path/to/trial-config <command>`. Inspect retained totals with
`oxfuzz --config /path/to/trial-config model-budget` using the same database.
This prints JSON with `scope_id`, `calls`, `tokens`, `cost_microusd`,
`terminal_reason`, and `blocked`; `null` means no reservation exists yet or no
budget is configured. Limits apply after provider reload or process restart.

Token and cost allowances must accommodate one full context-plus-output
reservation. They can therefore refuse a short prompt before the measured total
reaches its ceiling. This conservatism is deliberate. Settlements require
provider-reported positive input and output counts; missing, partial, or estimated
usage retains the maximum charge. No automatic reset/refund command is exposed.

## GUI configuration and retained usage

Settings Fuzzing edits `[model_budget]` within the existing shared configuration draft and Save Changes operation. The service validates the full configuration before writing. Limits and counters travel as decimal strings in settings JSON and the budget presentation response, preserving every integer through JavaScript. Raw TOML remains numeric. The backend alone parses and validates those strings.

Dashboard reads a service-owned view containing feature availability, configured policy and the retained snapshot for its workflow scope. A missing snapshot means the scope has no recorded provider reservations; it does not imply missing history was reset. Usage includes conservative outstanding reservations. Errors are displayed. Reading this view never dispatches a provider request. Policy changes require a new scope after the first reservation. Settings saves replace the provider pool immediately; direct disk edits require a provider reload or restart. This view describes the configured scope and durable ledger; already-running operations may still hold their earlier provider pool.

### Dollar presentation in the GUI

The cost limit editor accepts USD decimal amounts with at most six fractional digits and displays an explicit validation error for invalid amounts. Valid edits publish exact integer micro-USD strings into the existing shared config draft; invalid edits publish an invalid decimal string so backend conversion refuses Save Changes rather than saving a previous amount. An empty field removes the optional cost limit. This is presentation unit conversion only: backend limits and accounting remain authoritative.

Dashboard cost totals and limits display a dollar prefix and between two and six fractional digits. String/BigInt conversion preserves the full integer range without JavaScript floating-point rounding. Raw TOML and the service DTO continue using micro-USD integers/decimal strings.

### Applying saved runtime configuration

GUI runtime configuration writes call `ServiceContainer::save_config`. Runtime config validation and persistence precede provider reconstruction while the container's shared provider write lock is held; a successful save applies to the next provider-pool lookup across its clones. Reload takes the same lock before constructing providers, so concurrent reloads cannot publish an older policy after a newer save. Existing in-flight operations may finish against the pool and scope they already acquired. New wrappers reuse the durable ledger; reloading never resets an existing scope's allowance. Disk edits made outside this save operation still require an explicit provider reload or restart.

### Frontend delivery budget

Adding budget and harness evidence views must remain within existing application bundle limits. The shared extra translation table stores each message key once with English and optional Chinese text, reconstructing the same public dictionaries. Dictionary-level semantic regression checks preserve all keys, text and intentional omissions; this reduces duplicated key bytes without removing UI content or changing locale fallback.
