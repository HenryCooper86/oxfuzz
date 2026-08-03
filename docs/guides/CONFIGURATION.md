# Configuration Reference

[← Back to the README](../../README.md)

Only settings consumed by the production service are exposed as editable
configuration:

- `providers.toml` -- LLM provider pool (routing tags, failover, freeze/thaw).
- `oxfuzz.toml` -- enabled engines, run defaults/resource limits,
  coverage-stagnation, scheduling/session, coverage-regression policy, and the
  optional automotive sidecar policy.
- `defectdojo.toml` -- DefectDojo connection and lifecycle settings.
- `issue_tracker.toml` -- GitHub/GitLab crash issue integration.
- `agents/*.toml` -- Sub-agent definitions (discovery, harness, triage).

Mandatory sandbox/approval/network policy, storage internals, and tool-registry
policy use service-owned safe defaults rather than editable TOML. Runtime
locations are overridden with documented environment variables such as
`HF_WORKSPACE_DIR`, `HF_DB_PATH`, and `HF_CONFIG_DIR`; see `.env.example`.
Unsupported legacy section files are rejected by the config API instead of
being accepted as apparently editable settings.

The REST API binds to loopback by default and is **fail-closed**: set
`HF_WEB_TOKEN` to require a bearer token, or `HF_WEB_TOKEN_OPTIONAL=1` for
unauthenticated local development. A non-loopback `--host` is rejected unless a
token is configured. Browser origins are an exact allowlist in
`HF_WEB_CORS_ORIGINS`; project paths must be below `HF_WEB_PROJECT_ROOTS`. A
local web build sends the bearer value from `VITE_API_TOKEN` (set it to the same
value as `HF_WEB_TOKEN`).
