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

## Config directory resolution

Every entry point (CLI, web server, desktop app) resolves the config directory
in the same order, first match wins:

1. `--config <dir>` (CLI global flag),
2. the `HF_CONFIG_DIR` environment variable,
3. the per-user config dir, when it already holds at least one live
   `<section>.toml` -- macOS `~/Library/Application Support/oxfuzz/config`,
   Linux `$XDG_DATA_HOME/oxfuzz/config` or `~/.local/share/oxfuzz/config`,
   Windows `%APPDATA%\oxfuzz\config`. (A merely existing but empty directory
   does not win: bootstrap creates it on every run, and an empty directory must
   not shadow a source checkout.)
4. the nearest enclosing source tree containing both `Cargo.toml` and
   `config/`, walking up from the current directory and the executable path
   (the development flow). This binding prints a one-line stderr warning
   naming the resolved directory and the `HF_CONFIG_DIR` override; the same
   warning fires in reverse when a live per-user config shadows a discovered
   source tree. Without the warning, running the CLI inside an unrelated Rust
   project that happens to have a `config/` directory would silently bind that
   project's files.
5. the per-user config dir as the default (created on demand).

`oxfuzz init` writes into the resolved directory and prints it. An explicit
choice (`--config`/`HF_CONFIG_DIR`) naming an existing path that is not a
directory fails at startup rather than degrading into later I/O errors; a
directory that does not exist yet is created on demand. The desktop app pins
`HF_CONFIG_DIR` to the per-user directory at launch, so its Settings panel is
always the single source of truth for the app.

The REST API binds to loopback by default and is **fail-closed**: set
`HF_WEB_TOKEN` to require a bearer token, or `HF_WEB_TOKEN_OPTIONAL=1` for
unauthenticated local development. A non-loopback `--host` is rejected unless a
token is configured. Browser origins are an exact allowlist in
`HF_WEB_CORS_ORIGINS`; project paths must be below `HF_WEB_PROJECT_ROOTS`. A
local web build sends the bearer value from `VITE_API_TOKEN` (set it to the same
value as `HF_WEB_TOKEN`).
