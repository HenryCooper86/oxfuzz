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
- `agents/*.toml` -- optional user agent definitions that add to or override
  the built-in agents. No template is shipped and `oxfuzz init` does not create
  this directory; see [Agent definitions](#agent-definitions).

Contents of this page:

- [Choosing an LLM provider](#choosing-an-llm-provider)
- [Spending limits](#spending-limits)
- [`oxfuzz.toml` key reference](#oxfuzztoml-key-reference)
- [Agent definitions](#agent-definitions)
- [Config directory resolution](#config-directory-resolution)

Mandatory sandbox/approval/network policy, storage internals, and tool-registry
policy use service-owned safe defaults rather than editable TOML. Runtime
locations are overridden with documented environment variables such as
`HF_WORKSPACE_DIR`, `HF_DB_PATH`, and `HF_CONFIG_DIR`; see `.env.example`.
Unsupported legacy section files are rejected by the config API instead of
being accepted as apparently editable settings.

## Provider presets and credentials

Setup and **Settings -> Providers** share the same service/plan presets.
Kimi and GLM coding subscriptions use dedicated endpoints rather than their
pay-as-you-go API endpoints. The saved `provider_type` remains the supported
adapter (`openai-compat` for these services); the endpoint determines which
service/plan the Settings selector displays. Selecting a preset sets its
endpoint, model, and tool-calling mode without changing provider ID, routing
tags, or limits. Editing a custom endpoint does not rewrite it on reload.

A preset change clears the previous API key, environment-variable reference,
and custom headers. Enter credentials for the selected service before testing
or saving. Browser responses omit stored credentials; the service restores
those omitted values only when both `provider_type` and `base_url` are
unchanged. Editing the model or other metadata at the same endpoint retains
hidden credentials. Changing the endpoint or adapter does not silently reuse
them. Native desktop saves continue to write the explicitly edited values.

## Choosing an LLM provider

The model drafts and repairs harnesses, independently reviews each harness
before it runs, ranks targets (`discover --rank`), generates seeds and
dictionaries, and drafts bug reports. Everything except the pre-execution
review has a model-free fallback; see [Running without a model](#running-without-a-model).

### `providers.toml`

Each `[[providers]]` entry is one backend. The pool routes by `tags` and
fails over between entries. Main keys (`crates/hf-provider/src/config.rs`):

| Key | Default | Meaning |
| --- | --- | --- |
| `id` | required | Stable name, shown by `oxfuzz providers` |
| `provider_type` | required | Adapter; see the next table |
| `model` | required | Model name sent to the backend |
| `enabled` | `true` | `false` skips the entry |
| `tags` | `["general"]` | Routing tags, for example `reasoning`, `code` |
| `api_key_env` | none | Name of the environment variable holding the key |
| `api_key` | none | Inline key; wins over `api_key_env` when non-empty |
| `base_url` | per adapter | Endpoint override |
| `headers` | none | Extra HTTP headers |
| `max_concurrency` | `5` | Concurrent requests to this entry |
| `context_window` | `128000` | Tokens; also the input reservation for [spending limits](#spending-limits) |
| `cost_per_1k_input`, `cost_per_1k_output` | `0` | US dollars per 1,000 tokens; `0` means unknown |
| `tool_calling_mode` | per adapter | `native` or `prompt_based` |

Top-level pool keys (`default_freeze_duration_secs`, `max_freeze_duration_secs`,
`health_check_interval_secs`, `[response_body_limits]`,
`[response_stream_limits]`) are documented in
`config/providers.example.toml`.

Accepted `provider_type` values (`build_providers` in
`crates/hf-provider/src/pool.rs`); any other value is skipped with a warning:

| `provider_type` | Backend | Default `base_url` | Default tool calling |
| --- | --- | --- | --- |
| `openai` | OpenAI Chat Completions | `https://api.openai.com/v1` | native |
| `openai-compat`, `openai_compatible`, `custom` | Any OpenAI-compatible Chat Completions server (vLLM, llama.cpp server, gateways, Kimi/GLM plans) | `https://api.openai.com/v1`; set your server | prompt-based |
| `anthropic` | Anthropic Messages API | `https://api.anthropic.com/v1` | native |
| `gemini` | Google Gemini API | `https://generativelanguage.googleapis.com/v1beta` | native |
| `ollama` | Native Ollama API | `http://localhost:11434` | prompt-based |
| `ollama-cloud` | Hosted Ollama (needs an ollama.com key) | `https://ollama.com` | prompt-based |
| `azure` | Azure OpenAI (`azure_resource_name`, `azure_api_version`, `azure_use_deployment_urls`, `azure_auth_mode`) | from the Azure keys | native |
| `deepseek` | DeepSeek (OpenAI-compatible) | `https://api.deepseek.com/v1` | native |

### Credentials

For each entry the key is resolved as: a non-empty inline `api_key`, else the
non-empty value of the variable named by `api_key_env`. An entry that resolves
no key is skipped, and the only signal is a log line
(`Skipping provider: API key not found in environment`) that appears with
`RUST_LOG=warn`. Nothing loads `.env` automatically; export variables in the
shell or service that launches oxfuzz. Prefer `api_key_env` for real
secrets.

`HF_PROVIDER_API_KEY` is a single-provider fallback, not an addition. It is
used only when `providers.toml` yields no usable provider: the file is
missing or fails to parse, no entry is enabled, every entry was skipped, the
pool fails validation (including an invalid `[model_budget]`), or the config
directory fails its private-file check. The fallback is one
`openai-compat` provider with id `env`, tags `general`, `reasoning`, `code`,
model `HF_PROVIDER_MODEL` (default `gpt-4o`), and endpoint
`HF_PROVIDER_BASE_URL` (default `https://api.openai.com/v1`)
(`provider_pool_from_env` in `crates/hf-service/src/container/mod.rs`).

### Local models

Model calls are made by the oxfuzz process on the host, not from the sandbox,
so a server on `localhost` is reachable. Keyless servers still need a
placeholder key, because an entry without one is skipped:

```toml
[[providers]]
id = "ollama-local"
provider_type = "ollama"
model = "qwen2.5-coder:14b"
tags = ["general", "reasoning", "code"]
context_window = 32768
api_key = "not-needed"

[[providers]]
id = "vllm-local"
provider_type = "openai-compat"
model = "Qwen/Qwen2.5-Coder-32B-Instruct"
base_url = "http://localhost:8000/v1"
tags = ["general", "reasoning", "code"]
api_key = "not-needed"
```

Set `context_window` to what the server actually serves. Small local models
tend to need more repair rounds and fail review more often than hosted ones.

### Checking what was loaded

- `oxfuzz providers` lists the providers that were constructed, with their
  frozen/healthy state. A defined id that is missing was skipped; rerun with
  `RUST_LOG=warn` to see why.
- `oxfuzz doctor --engine libfuzzer --require-provider` confirms a pool can be
  built, without calling a model. It does not test credentials or
  connectivity.

### Running without a model

- `--ai off` on `discover --rank`, `harness`, `run`, `campaign`, `fuzz`,
  `triage`, and `ci` makes that command call no model, even if one is
  configured: heuristic ranking, template drafts, heuristic seeds, and
  crashes without bug-report drafts. `--ai require` does the opposite and
  fails instead of degrading.
- The pre-execution review of a harness has no model-free form. To smoke-test
  and promote without a model, pass `--no-llm-review` on `harness` or `fuzz`,
  or set `[harness] allow_unreviewed_smoke = true` for the deployment. Each
  bypass is recorded, and promotion still requires your approval. See
  [SAFETY_MODEL.md](SAFETY_MODEL.md).
- `oxfuzz agent` and chat need a provider.

A fully offline pipeline is therefore
`oxfuzz fuzz <project> --ai off --no-llm-review`.

## Spending limits

`[model_budget]` in `oxfuzz.toml` puts hard limits on model spending for one
named workflow (`crates/hf-service/src/model_budget.rs`; design in
[model-budgets-design.md](../design/model-budgets-design.md)). With no limit
set it is disabled.

| Key | Default | Meaning |
| --- | --- | --- |
| `scope_id` | none | Required when any limit is set: 1 to 128 ASCII letters, digits, or `-_.:` |
| `max_calls` | none | Upstream attempts, including retries and paid health probes |
| `max_tokens` | none | Input plus output tokens, including unresolved reservations |
| `max_cost_microusd` | none | Cost in millionths of a US dollar (`5000000` is $5.00) |
| `max_output_tokens` | `4096` | Output cap written into every request (1 to 1,000,000) |

How it is enforced:

- Every request reserves, before dispatch, one call plus the provider's full
  `context_window` as input tokens plus the output cap, and the matching cost.
  A successful response with reported usage refunds the unused part. Failed,
  cancelled, or interrupted requests keep their full reservation. Size
  `max_tokens` for at least one full reservation (for a 128,000-token context
  and the default output cap, 132,096 tokens per call).
- `max_cost_microusd` requires positive `cost_per_1k_input` and
  `cost_per_1k_output` on every provider; a provider with unknown prices is
  refused rather than treated as free.
- With `max_tokens` or `max_cost_microusd` set, requests whose cost cannot be
  bounded (model overrides, extra parameters, image requests) are refused.
- Accounting is stored in the database at `HF_DB_PATH`, per scope, and
  survives restarts. A scope's limits cannot change after its first
  reservation; use a new `scope_id` for a new workflow. Use the same config and
  `HF_DB_PATH` for every command in the workflow.
- Limits take effect on the next process start or provider reload.

`oxfuzz model-budget` prints the retained accounting for the configured scope
as JSON (`scope_id`, `calls`, `tokens`, `cost_microusd`, `terminal_reason`,
`blocked`), or `null` when no scope is configured or nothing has been
reserved yet:

```bash
HF_DB_PATH=/path/to/trial.db oxfuzz --config /path/to/trial-config model-budget
```

## `oxfuzz.toml` key reference

Defaults below are the values the service uses when a key is absent
(`crates/hf-service/src/config.rs`, `crates/hf-scheduler/src/config.rs`).
Every section rejects unknown keys and validates ranges, so a typo fails
loudly. The full annotated file, including `[campaign_health]`,
`[automotive]`, `[knowledge]`, `[session]`, `[git_diff]`, `[grep]`, and the
optional `[clang_analysis]`, is `config/oxfuzz.example.toml`.

Top level:

| Key | Default | Notes |
| --- | --- | --- |
| `coverage_stagnation_secs` | `120` | Env override `HF_COVERAGE_STAGNATION_SECS` |
| `coverage_stagnation_new_harness_windows` | `2` | Must satisfy 1 <= new_harness < stop |
| `coverage_stagnation_stop_windows` | `4` | |
| `auto_revert_enabled` | `false` | Env override `HF_AUTO_REVERT` |
| `auto_revert_threshold_pct` | `20.0` | Within (0, 100] |
| `auto_revert_notify_only` | `false` | Env override `HF_AUTO_REVERT_NOTIFY_ONLY` |

`[fuzzing]`:

| Key | Default | Notes |
| --- | --- | --- |
| `enabled_engines` | `["libfuzzer", "afl++", "honggfuzz", "syzkaller"]` | Canonical ids only; at least one |
| `default_engine` | `"libfuzzer"` | Must be enabled |
| `default_duration_secs` | `60` | Must not exceed `sandbox.max_duration_secs` |
| `default_timeout_ms` | `1000` | Per-input hang threshold, 1 to 3,600,000 |
| `default_resume` | `false` | AFL++ only |
| `default_sanitizer` | `"address"` | `address` or `undefined` |
| `collect_function_coverage` | `true` in builds with the `proof-carrying` feature (the default CLI build) | About 4% throughput cost |

`[fuzzing.sandbox]`:

| Key | Default | Notes |
| --- | --- | --- |
| `max_mem_mb` | `2048` | 1 to 65,536 |
| `max_cpus` | `1` | 1 to 64; also the engine worker count |
| `max_duration_secs` | `7200` | 1 to 604,800 (seven days) |

`[harness]`:

| Key | Default | Notes |
| --- | --- | --- |
| `allow_unreviewed_smoke` | `false` | Skips the model pre-execution review for every smoke run |
| `behavior_probe_timeout_secs` | `5` | 1 to 60 |

`[triage]`:

| Key | Default | Notes |
| --- | --- | --- |
| `confirmation_runs` | `3` | 2 to 10 replays per input after minimization |
| `replay_timeout_secs` | `10` | 1 to 30, per sandbox replay |

`[scheduler]`:

| Key | Default | Notes |
| --- | --- | --- |
| `max_event_cascade_depth` | `8` | `0` disables chaining |
| `max_concurrent_executions` | `10` | Must be greater than zero |
| `default_missed_policy` | `"skip"` | `catch_up`, `skip`, `backfill` |
| `default_concurrency_policy` | `"skip_if_running"` | `allow`, `skip_if_running`, `queue`, `cancel_previous` |
| `history_retention_limit` | `100` | `0` means unlimited |

`[build_profiles]`:

| Key | Default | Notes |
| --- | --- | --- |
| `allowed_cmake_options` | `["BUILD_SHARED_LIBS", "BUILD_TESTING"]` | Names a build profile's `--define` may use; nothing is injected |

`[model_budget]`: see [Spending limits](#spending-limits).

## Agent definitions

The agent loop (`oxfuzz agent`, chat in the GUI and web API) ships seven
built-in agents embedded in the binary (`crates/hf-agent/src/builtins/`:
`orchestrator`, `target-scout`, `harness-author`, `run-operator`,
`crash-triager`, `coverage-analyst`, `corpus-curator`). On load, every
`*.toml` file in `<config dir>/agents/` (except `*.example.toml`) is parsed as
one flat agent definition; a file whose `id` matches a built-in replaces it.
A file that fails to parse is skipped with a warning. There is no shipped
template; copying a built-in from `crates/hf-agent/src/builtins/` is the
easiest start. Fields (`crates/hf-agent/src/definition.rs`):

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | yes | Stable identifier (by convention the file stem) |
| `name`, `description` | yes | Display name and one-line summary |
| `role` | yes | `orchestrator`, `discovery`, `harness-author`, `run-operator`, `triage`, `coverage`, `corpus` |
| `system_prompt` | yes | Role prompt; oxfuzz wraps it with its fixed safety rules |
| `allowed_tools` | no | Subset of `discover`, `harness`, `refine`, `run`, `triage`, `corpus`, `delegate` |
| `skills` | no | Skill names injected into context |
| `model_tags` | no | Provider routing tags |
| `temperature` | no | 0 to 2 |
| `max_iterations` | no (12) | 1 to 50 |
| `autonomy` | no (`assist`) | `manual`, `assist`, `auto` |
| `capabilities`, `icon`, `user_callable` (true), `completion_requirement` | no | Presentation and loop details |

The ranges and the tool and skill names above are checked when a definition
is saved through the desktop app or API (`save_agent_definition` in
`crates/hf-service/src/agent.rs`); a hand-edited file is only parsed, so keep
its values in range. Agents act only through the service and its guardrails;
an agent cannot promote a harness.

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

In practice the per-user directory is what shadows a checkout: it becomes
live the first time `oxfuzz init` runs outside a source checkout, or the first
time the desktop app starts (on first launch the app also copies the
checkout's `providers.toml` into it). From then on the CLI run inside the
checkout reads the per-user files and prints, on every command except `init`:

```text
warning: config directory '<per-user dir>' (per-user) shadows the source tree config at '<checkout>/config'; set HF_CONFIG_DIR to pin one explicitly
```

To make the choice explicit, pass `--config <dir>` or export
`HF_CONFIG_DIR`; `oxfuzz --config <dir> init` fills in any missing files there
from the built-in templates. The config directory also locates `agents/` and
`skills/`. Note that `HF_DB_PATH` is resolved separately: the CLI default is
`data/oxfuzz.db` relative to the current directory, while the desktop app uses
`data/oxfuzz.db` under the per-user application directory (on macOS
`~/Library/Application Support/oxfuzz/data/oxfuzz.db`).

The REST API binds to loopback by default and is **fail-closed**: set
`HF_WEB_TOKEN` to require a bearer token, or `HF_WEB_TOKEN_OPTIONAL=1` for
unauthenticated local development. A non-loopback `--host` is rejected unless a
token is configured. Browser origins are an exact allowlist in
`HF_WEB_CORS_ORIGINS`; project paths must be below `HF_WEB_PROJECT_ROOTS`. A
local web build sends the bearer value from `VITE_API_TOKEN` (set it to the same
value as `HF_WEB_TOKEN`).
