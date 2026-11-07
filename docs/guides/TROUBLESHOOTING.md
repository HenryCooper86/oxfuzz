# Troubleshooting

[Back to the README](../../README.md)

Each entry is symptom, cause, fix. Two habits find most problems quickly:

- Run `oxfuzz doctor` first. It probes Docker, the sandbox image, and each
  engine without building or running anything.
- Read the warnings on stderr. With `RUST_LOG` unset the CLI prints warnings
  and errors (`oxfuzz tui` prints errors only), so skipped providers and
  ignored config files are named there. Set `RUST_LOG=info` for more, such as
  dropped compile flags.

Related: [INSTALL.md](INSTALL.md), [CONFIGURATION.md](CONFIGURATION.md),
[FUZZ_YOUR_PROJECT.md](FUZZ_YOUR_PROJECT.md),
[CLI_REFERENCE.md](CLI_REFERENCE.md).

## Sandbox and Docker

### `oxfuzz doctor` shows `MISSING  Docker daemon`

Symptom:

```text
oxfuzz sandbox readiness
MISSING  Docker daemon
UNKNOWN  sandbox image
UNKNOWN  libFuzzer
...
Docker not available: start Docker (`HF_USE_DOCKER=0` also turns it off), then run `oxfuzz doctor` again
Error: fuzzing is not ready: start Docker, build the sandbox image, and verify at least one engine
```

Other commands fail with `stub runtime: not implemented`.

Cause: the Docker daemon (OrbStack, Docker Desktop, or the Linux `docker`
service) is not running, or `HF_USE_DOCKER` is `0`/`false`. oxfuzz picks its
runtime when the process starts; with no daemon it uses a stub that refuses
every build and run rather than executing on the host. While Docker is down
the image and engines cannot be inspected, so they read `UNKNOWN`.

Fix: start OrbStack or Docker Desktop (on Linux, for example
`sudo systemctl start docker`), unset `HF_USE_DOCKER`, then run
`oxfuzz doctor` again in a new process. If the image line is still `MISSING`,
see the next entry.

### Sandbox image missing

Symptom: `doctor` shows `READY  Docker daemon` but `MISSING  sandbox image`;
a build or run fails with Docker output such as `pull access denied`.

Cause: the runtime always uses the image tag compiled into oxfuzz
(`SANDBOX_IMAGE` in `crates/hf-runtime/src/config.rs`, currently
`oxfuzz/fuzz-sandbox:0.2.1`), and it is not present locally. The runtime
never pulls it on its own.

Fix: from an oxfuzz source checkout run

```bash
./scripts/build-sandbox.sh
```

or `oxfuzz doctor --build-image` (the same build the desktop app runs; it
skips the script's post-build toolchain and Semgrep verification). Expect a
long first build and a large image: it compiles honggfuzz, syzkaller (with
its Go toolchain), and SymCC from source, installs Rust nightly and
cargo-fuzz, and needs network access while building. The local
`oxfuzz/fuzz-sandbox:0.2.1` image is about 7 GB on disk.

If a prebuilt image has been published for your version,
`./scripts/pull-sandbox.sh` downloads and verifies it instead; when none is
published it says so and points back to the build script.

### Image is present but out of date

Symptom: after updating oxfuzz, `doctor` reports the image missing even
though `docker image ls oxfuzz/fuzz-sandbox` lists older tags; or Build
Doctor reports a profile as `Stale`.

Cause: a new oxfuzz version can move `SANDBOX_IMAGE` to a new tag; older tags
are ignored. Separately, rebuilding the same tag gives it a new immutable
image ID, and saved build profiles record that ID.

Fix: rebuild with `./scripts/build-sandbox.sh`. Remove old tags you no
longer need with `docker image rm oxfuzz/fuzz-sandbox:<old tag>`. For a
project with a build profile, run `oxfuzz build diagnose <project>`, save the
profile again (`oxfuzz build profile set ...`), rerun `oxfuzz build run`, and
rebuild and requalify its harnesses.

### Wrong architecture (Apple Silicon or mixed hosts)

Symptom: builds are very slow, or a container fails with `exec format error`.

Cause: the image was built for a different architecture than the host.
`scripts/build-sandbox.sh` builds for Docker's default platform unless
`OXFUZZ_SANDBOX_PLATFORM` is set (for example `linux/amd64`).
`oxfuzz doctor --build-image` builds for the host platform (`linux/arm64` on
Apple Silicon, `linux/amd64` on x86_64). The desktop app compares the image
architecture with its Settings choice and, when it can find a source
checkout, rebuilds on a mismatch; the CLI `doctor` only checks that the tag
exists.

Fix: check with
`docker image inspect --format '{{.Architecture}}' oxfuzz/fuzz-sandbox:0.2.1`.
For userspace fuzzing, build for the native architecture: run
`./scripts/build-sandbox.sh` without `OXFUZZ_SANDBOX_PLATFORM`, or with
`OXFUZZ_SANDBOX_PLATFORM=linux/arm64` on Apple Silicon. Building a foreign
architecture requires emulation registered with Docker.

### A custom `OXFUZZ_SANDBOX_IMAGE` tag is not used

Symptom: you built `OXFUZZ_SANDBOX_IMAGE=myorg/sandbox:1 ./scripts/build-sandbox.sh`
and oxfuzz still reports the image missing.

Cause: `OXFUZZ_SANDBOX_IMAGE` only changes the tag the build script writes.
The runtime, `doctor`, and Build Doctor always use the fixed
`oxfuzz/fuzz-sandbox:<version>` tag; no environment variable or config key
overrides it.

Fix: build with the default tag, or retag your image:
`docker tag myorg/sandbox:1 oxfuzz/fuzz-sandbox:0.2.1`.

## Building oxfuzz

### macOS 27: `mis-aligned LINKEDIT string pool` while building `sqlx_macros`

Symptom: `cargo build --release` fails while loading a proc-macro dylib
(first seen with `sqlx_macros`) with a `mis-aligned LINKEDIT string pool`
error.

Cause: with Command Line Tools 27, Apple's `strip` leaves build-script and
proc-macro dylibs in a state dyld refuses to load, and the release profile
strips them.

Fix: this checkout sets `[profile.release.build-override] strip = false` in
the workspace `Cargo.toml`. On an older checkout, build with

```bash
CARGO_PROFILE_RELEASE_BUILD_OVERRIDE_STRIP=false cargo build --release
```

Shipped binaries are still stripped by the normal release profile.

### Linux: `cargo build --release` fails in `webkit2gtk-sys`, `soup3-sys`, or `gtk-sys`

Cause: the root `Cargo.toml` is a virtual workspace with no
`default-members`, so a plain build includes the desktop app crate
(`crates/hf-gui/src-tauri`), which links WebKitGTK and friends on Linux.

Fix: for the CLI only, build `cargo build --release -p hf-cli`; it does not
need those packages. For the whole workspace, install them first with
`scripts/ci/install-linux-deps.sh` (Debian/Ubuntu `apt-get` list).

## Configuration

### Edits to `config/*.toml` have no effect

Symptom: changes in your checkout's `config/` are ignored, and the CLI
prints a line like:

```text
warning: config directory '/Users/you/Library/Application Support/oxfuzz/config' (per-user) shadows the source tree config at '/path/to/oxfuzz/config'; set HF_CONFIG_DIR to pin one explicitly
```

Cause: the config directory is chosen in this order: `--config <dir>`,
`HF_CONFIG_DIR`, the per-user directory once it holds any live
`<section>.toml`, then the enclosing source tree's `config/`. The per-user
directory gains files when `oxfuzz init` runs outside a source checkout, or
when the desktop app starts (it pins the per-user directory and copies the
checkout's `providers.toml` there on first launch).

Fix: pin one directory with `--config <dir>` or `HF_CONFIG_DIR=<dir>`.
`oxfuzz --config <dir> init` fills any missing files there from the built-in
templates and prints the directory it used. Details:
[CONFIGURATION.md](CONFIGURATION.md#config-directory-resolution).

### `oxfuzz.toml` is rejected

Symptom: `doctor --engine ...` lists a problem, or commands fail, with
`invalid oxfuzz config: ... unknown field 'max_cpu', expected one of ...`
or a range message such as
`fuzzing.sandbox.max_cpus must be within 1..=64`.

Cause: every section is parsed with unknown fields denied and validated
ranges, so a typo or out-of-range value fails loudly instead of being
ignored.

Fix: correct the key or value named in the message. The key reference is in
[CONFIGURATION.md](CONFIGURATION.md#oxfuzztoml-key-reference).

### Your project's state seems to have disappeared

Symptom: `run`, `triage`, or `ci` cannot find a harness you promoted, or
`runs list` is empty.

Causes and fixes:

- The CLI opens `data/oxfuzz.db` relative to the current directory unless
  `HF_DB_PATH` is set (the desktop app uses `data/oxfuzz.db` under the
  per-user application directory, on macOS
  `~/Library/Application Support/oxfuzz/data/oxfuzz.db`). Export one absolute
  `HF_DB_PATH`.
- Targets are keyed by the exact spelling: `parse_value` and
  `src/parser.c::parse_value` are different workspaces. Use the spelling you
  promoted under (work orders always use the file-qualified one).
- Project identity is the canonical absolute path. A moved or re-cloned
  project starts fresh.
- `workspace ownership manifest does not identify <dir>`: a workspace root
  was moved or copied to a new path. Restore it at its original path.
  `workspace root is non-empty and has no ownership manifest`:
  `HF_WORKSPACE_DIR` points at an existing directory oxfuzz did not create;
  point it at a new or empty directory.

## Model providers

### The model is never used

Symptom: drafts come from the template, `--ai require` fails with
`no provider is configured`, or `oxfuzz providers` prints
`No providers configured.` or omits a provider you defined.

`oxfuzz providers` lists only the providers that were actually constructed,
so a missing id means it was skipped. The reason is a warning on stderr:

| Warning (stderr) | Cause | Fix |
| --- | --- | --- |
| `Skipping provider: API key not found in environment` | `api_key_env` names an unset or empty variable, or the provider has no key at all. Keyless local servers are skipped too | Export the variable in the launching shell (`.env` is not loaded automatically). For Ollama or another keyless server, set a placeholder `api_key = "not-needed"` |
| `Skipping provider: unsupported type` | `provider_type` is not one of `openai`, `openai-compat`, `openai_compatible`, `custom`, `anthropic`, `gemini`, `ollama`, `ollama-cloud`, `azure`, `deepseek` | Fix `provider_type` |
| `failed to parse .../providers.toml: TOML parse error ...` | Syntax error; the whole file is ignored | Fix the TOML |
| `failed to build provider pool from config: ...` | Invalid pool settings, every provider skipped (`no usable providers remain`), or an invalid `[model_budget]` | Fix the named setting |
| `ignoring file-based providers because private config validation failed` | A `*.toml` in the config directory is not a regular file (for example a symlink) | Replace it with a regular file |
| `provider is disabled, skipping` (info level) | `enabled = false` | Enable it |

When `providers.toml` yields no usable provider, oxfuzz falls back to a single
OpenAI-compatible provider built from `HF_PROVIDER_API_KEY` (with
`HF_PROVIDER_MODEL`, default `gpt-4o`, and `HF_PROVIDER_BASE_URL`, default
`https://api.openai.com/v1`). A leftover `HF_PROVIDER_API_KEY` can therefore
mask a broken `providers.toml`.

To check configuration without calling a model:
`oxfuzz doctor --engine libfuzzer --require-provider`. It confirms that a
provider pool can be built; it does not test credentials or connectivity.

### A provider is frozen

Symptom: `oxfuzz providers` shows `FROZEN  <id> ... (reason: ...)`, or
`--ai require` fails with `every configured provider is frozen`.

Cause: the pool freezes a provider after failures (for example an invalid key
or exhausted quota). Freeze state lives in the running process, so this
matters for long-lived processes (`oxfuzz serve`, the desktop app, a long
campaign); a new CLI process starts with every provider unfrozen. Frozen
providers are re-probed every `health_check_interval_secs` (default 30) in
`providers.toml`.

Fix: correct the cause, then `oxfuzz providers thaw <id>` (it thaws only
after a health check passes). The REST API exposes the same operation at
`POST /providers/{id}/thaw`.

### Smoke qualification fails with no model configured

Cause: before any generated harness runs, a separate model call reviews its
source. Without a provider (or with `--ai off`, which detaches the provider),
that review fails closed.

Fix: configure a provider, or opt out explicitly with `--no-llm-review` on
`harness` or `fuzz` (or `[harness] allow_unreviewed_smoke = true`). The bypass
is recorded and promotion still needs your approval. See
[SAFETY_MODEL.md](SAFETY_MODEL.md).

## Approvals

### Actions are denied in CI, scripts, or pipes

Symptom: an error beginning `guardrail denied:` when compiling, smoke
testing, promoting, or launching a fuzzer, with no prompt shown.

Cause: the CLI prompts only when both stdin and stderr are terminals. Without
a terminal, approval comes from the environment and defaults to deny.
`oxfuzz ci` and `oxfuzz serve` always use the environment, even on a terminal.

Fix: for a run you have already decided to trust, set `HF_AUTO_APPROVE=1`
(approves each high-risk action) or `HF_GUARDRAILS=permissive` (auto-approves
everything with an audit trail). Review past decisions with
`oxfuzz policy decisions`.

## Harness builds

### The harness does not compile

Symptom: `compile failed (exit N): ...` or
`harness for '<target>' failed to build after N repair attempt(s): ...`.

Where to look:

- The error itself carries the compiler's stderr (the repair-loop message
  keeps the first 600 characters).
- `RUST_LOG=info` also logs compile-database flags that were dropped.
- The generated source is kept in the target's workspace,
  `<workspace root>/<project name>-<hash>/<target>/` (for example
  `harness.c`), with the workspace root described in
  [FUZZ_YOUR_PROJECT.md](FUZZ_YOUR_PROJECT.md#before-you-start).
- For Build Doctor project builds, `oxfuzz build history <project>` keeps
  each run's bounded stdout and stderr.

Common causes, all explained in
[FUZZ_YOUR_PROJECT.md](FUZZ_YOUR_PROJECT.md#how-oxfuzz-builds-your-code):

- Header not found: no compile database, or include directories outside the
  project (dropped). Provide `compile_commands.json` or a build profile.
- Duplicate-symbol link errors (often for `main`): test, example, or tool
  sources were linked with the harness. Point oxfuzz at the library
  directory.
- Undefined references to a third-party library: dependencies are not linked
  or fetched.
- The container hit its 120-second compile limit on a large project.
- Generation stopped with a build profile state of `NeedsBuild`, `Stale`, or
  `Invalid`: run `oxfuzz build diagnose <project>` and follow its reasons.

`--repair N` on `oxfuzz harness` (two rounds are built into `oxfuzz fuzz`)
feeds compiler output back to the model; it cannot fix the project-level
causes above.

### A Rust harness does not build

Causes: a crates.io or git dependency (the sandbox is offline and vendors only
`libfuzzer-sys`); the project path is a virtual workspace root
(`could not find [package] name`); or the crate needs files other than `.rs`,
`Cargo.toml`, and `Cargo.lock`. Rust builds have a 600-second limit.

### Go or Python targets cannot be harnessed

That is current scope, not a fault: Go and Python are discovery-only, and
harness commands name the supported set (`c, cpp, rust`). See
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).
