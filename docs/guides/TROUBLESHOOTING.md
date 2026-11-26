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
`oxfuzz/fuzz-sandbox:0.2.4`), and it is not present locally. The runtime
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
`oxfuzz/fuzz-sandbox:0.2.4` image is about 7 GB on disk.

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
`docker image inspect --format '{{.Architecture}}' oxfuzz/fuzz-sandbox:0.2.4`.
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
`docker tag myorg/sandbox:1 oxfuzz/fuzz-sandbox:0.2.4`.

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

- Every entry point opens `data/oxfuzz.db` under the per-user application
  directory (on macOS `~/Library/Application Support/oxfuzz/data/oxfuzz.db`)
  unless `HF_DB_PATH` or `HF_APP_DIR` is set. Check that the shell running the
  CLI does not export a different `HF_DB_PATH`. Version 0.9.6 and earlier opened
  `data/oxfuzz.db` relative to the current directory; to read such a
  database, set `HF_DB_PATH` to its absolute path.
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

### A Bazel project build stops

`oxfuzz build history <project>` shows the message of the step.

- `this workspace carries no Bazel vendor directory`: the sandbox is offline
  and never downloads. Run
  `bazel vendor --vendor_dir=third_party/bazel //...` in the workspace on
  your machine and keep that directory with the project.
- `bazel aquery exited` after lines about a repository that could not be
  fetched: the vendor directory does not hold everything the targets need.
  Vendor again for `//...` after changing `MODULE.bazel`, and with the same
  Bazel major version that `.bazelversion` selects. A directory vendored on
  a different operating system or CPU is accepted; a repository that is
  missing from it is not.
- `the sandbox image carries Bazel 8 and Bazel 9`: `.bazelversion` asks for
  another version. Only those two major versions are available.
- `a Bazel profile needs MODULE.bazel`: the workspace uses `WORKSPACE` only.
  Vendor mode needs Bzlmod, so such a project is not supported; export a
  `compile_commands.json` yourself and place it in the project instead.
- The run stops before any step with a file-count or size reason: the
  project with its vendor directory is over the staging limits (20,000
  files, 512 MiB in total, 64 MiB per file).
- A harness then fails on a header that the Bazel build generates: the step
  compiles nothing, so generated headers do not exist. Generate them on
  your machine and keep them in the project, or fuzz a target that does not
  include them.

### A Rust harness does not build

Causes: a crates.io dependency the project does not carry (the sandbox is
offline and the image vendors only `libfuzzer-sys`); a git dependency; the
project path is a virtual workspace root (`could not find [package] name`); or
the crate needs files other than `.rs`, `Cargo.toml`, and `Cargo.lock`. Rust
builds have a 600-second limit.

For crates.io dependencies, run `cargo vendor` in the project on a machine
with network access and keep the `vendor/` directory it writes. oxfuzz stages
that tree whole and resolves from it together with the image's own crates;
the project's `.cargo/config.toml` is not needed and is not read. `no matching
package named ... found` then names a crate missing from `vendor/`, and `the
listed checksum of ... has changed` means a vendored file was edited or is a
symlink, which is not staged.

### A Python target is refused or its smoke fails

A Python target builds only for the `atheris` engine. Add `"atheris"` to
`[fuzzing] enabled_engines` and pass `--engine atheris`; any other engine is
refused before work starts. The harness path covers a top-level synchronous
function whose required parameters each take `bytes`, `str`, `int`, `float`
or `bool` (an unannotated parameter takes `bytes`); methods, `async`
functions, other parameter types, a parameter list that spans lines, and
files whose path is not importable (`my-tool/x.py`) are refused with the
reason. A `src/` directory is treated as the import root.

The harness is a generated script and is accepted only unchanged: an edited
Python harness fails lint with `python-fixed-template`.

`smoke fuzz: the Python harness exited 1 outside fuzzing` means the module
could not be imported in the sandbox, most often a third-party package. The
sandbox is offline and nothing is installed into it: besides the standard
library and the project's own modules, a run can import the pure-Python
packages the project carries under `vendor/python/` (for example
`pip install --target vendor/python --no-compile <package>` run beforehand on
a machine with network access). C extensions are outside the supported class.
A syntax error in
the selected module fails the build step instead, before anything is
imported. See [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

### A Java target is refused or its build fails

A Java target builds only for the `jazzer` engine. Add `"jazzer"` to
`[fuzzing] enabled_engines` and pass `--engine jazzer`; any other engine is
refused before work starts. The harness path covers a `public static` method
of a top-level class with one to eight parameters, each a `byte[]`, a
`String` or a primitive; instance methods, constructors, generic methods, and
other parameter types are refused with the reason.

The harness is a generated class and is accepted only unchanged: an edited
Java harness fails lint with `java-fixed-template`.

The build compiles every `.java` file of the project outside `test`
directories with `javac`, offline, against the jars directly inside the
project's `lib/` or `libs/` directory. `package ... does not exist` or
`cannot find symbol` for a class the project does not define means a
dependency jar is missing: nothing is resolved or downloaded, so copy the
jars a Maven or Gradle build would fetch into `lib/` first (for example
`mvn dependency:copy-dependencies -DoutputDirectory=lib`). Kotlin and Scala
sources and annotation processors are outside the supported class.

`smoke fuzz: the Java harness exited ... outside fuzzing` means the JVM or
Jazzer failed before or instead of fuzzing; the quoted output names the
cause. A run needs about 700 MiB of memory for the JVM. See
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

### A JavaScript target is refused or its module does not load

A JavaScript target builds only for the `jazzer-js` engine. Add `"jazzer-js"`
to `[fuzzing] enabled_engines` and pass `--engine jazzer-js`; any other engine
is refused before work starts. The harness path covers a function declared at
the top level of a `.js`, `.mjs` or `.cjs` file and exported under its own
name. Methods, classes, default exports, generators, and TypeScript are
outside it.

`does not document the type of '<name>'` means a required parameter has no
JSDoc type. JavaScript has no types to read, and calling the function with
the wrong kind of value would report an error the harness caused, so each
required parameter needs a line in the comment block directly above the
function: `@param {Buffer} data`, with `Buffer`, `Uint8Array`, `string`,
`number` or `boolean` as the type. Parameters with a default value and
parameters documented as optional are left out of the call.

`the project root has no package.json` means the directory given as
`<PROJECT>` is not the package root. Point the command at the directory that
holds `package.json`: the manifest decides whether a `.js` file is an ES
module and whether the package tree is staged.

The harness is a generated module and is accepted only unchanged: an edited
JavaScript harness fails lint with `js-fixed-template`.

`smoke fuzz: the JavaScript harness exited ... outside fuzzing` means Node.js
or Jazzer.js failed before or instead of fuzzing, and is never recorded as a
finding. `Cannot find module` or `Cannot find package` names a package the
staged project does not hold: nothing is installed in the sandbox, so run
`npm ci` (or `npm install`) in the project beforehand; `node_modules` is
staged as it is when the manifest declares dependencies. Symlinked package
layouts (pnpm, linked workspaces) are not staged, and a native addon built on
the host does not load in the Linux sandbox. See
[SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

### A binary-only session does not start or confirms nothing

`oxfuzz binary` refuses a file that is not a 64-bit little-endian ELF
executable, and a binary built for another CPU than the sandbox image's own
(both architectures are named): QEMU mode in the image emulates its own
architecture only.

`afl-fuzz -Q did not start fuzzing` quotes the fuzzer's last output. The
usual causes are a target that needs a shared object that was not supplied
(pass the directory with `--libs`), a target that crashes or times out on
every seed (supply seeds it accepts with `--seeds`, or raise `--timeout-ms`),
and the wrong input mode (the target reads standard input: pass `--stdin`;
the target is a server that accepts a connection: pass `--socket`).

With `--socket`, every seed timing out usually means the preload shim never
took effect: the binary is statically linked, or it connects out instead of
accepting or binding. A server that hands each connection to a forked child
runs, but a crash in the child is not seen. A UDP server is recognized when
it binds a datagram socket to an IPv4 or IPv6 address; one that registers the
socket with `epoll` before binding it will wait forever.

A stateful server that never reaches the interesting state with `--socket`
usually reads one request per `recv`: the whole input arrives in one read.
Use `--messages` and put the bytes `FF FE FD FC` between messages in the
seeds. What the server sends is discarded, so a step that must echo a value
the server chose (a nonce, a session id) is not reachable in either mode.

A finding with `confirmed: false` was saved by the fuzzer but its replay
ended differently. A finding with no `kind`, `signature`, or `frames` was
replayed without a crash report: the target is statically linked, or it
installs its own handlers for fatal signals. Such findings are never grouped
and their minimized input is checked by signal only. A confirmed finding
with no `minimized` entry could not be shrunk, or its shrunk form was a
different crash and was discarded. There is no sanitizer in this mode, so
memory errors that do not fault are not seen at all.

`--persistent` is refused with `--stdin`, `--socket`, or `--messages`, and
when the entry is not a defined function; the message lists functions that
exist. A stripped binary has none, so give a module offset such as `0x9d8`
from a crash frame instead. Stability below about 90% in persistent mode means
the loop entry leaves state behind between inputs: pass `--restore-memory`, or
choose an entry closer to where the input is read. A crash that depends on
such leftover state is not confirmed, because replay starts a fresh process.
`--continue-from` is refused for a session of a different binary.

In the desktop Binary view, **Draft seeds**, **Refine with AI**, and
**Explain with AI** need a configured provider; without one nothing is sent.
A finding with no frames in the target (a static binary, or no crash report)
is explained without disassembly.

`binary-issue` refuses a report that is not inside this project's own
session directory, and a `--finding` prefix shorter than eight hex digits or
matching more than one finding. See
`docs/design/binary-only-fuzzing-design.md`.

### A Go target is refused or its build fails

A Go target builds only for the `go-native` engine. Add `"go-native"` to
`[fuzzing] enabled_engines` and pass `--engine go-native`; any other engine is
refused before work starts. The harness path covers a package-level exported
function whose parameters are each `[]byte`, `string`, `bool`, an integer
type or a float type; methods, generic functions, functions in package
`main`, and parameters of any other type (structs, interfaces, slices of
anything but bytes) are refused with the reason.

The build runs offline (`GOPROXY=off`): a module that imports packages outside
the standard library must carry a `vendor/` tree, otherwise `go test -c` fails
naming the missing module. Project `_test.go` files are not staged, so the
harness binary holds only the generated fuzz test.

A smoke failure reading `the Go test binary exited 1 without saving a failing
input` is a failed run, not a finding; the quoted output names the cause.

### Crash scans are slow or CASR reports have no symbols

Use **Scan for Crashes** for classification. It does not call an AI provider or
minimize inputs. **Compose Report** and **Verify with AI** are separate actions.
The scan status shows the current phase, elapsed time, and completed input count
when available. **Stop scan** waits for sandbox teardown and keeps completed
findings; a stopped scan has not necessarily examined every input. Previously
saved AI reports and confirmed minimization evidence survive a rescan.

Rebuild (or pull) the sandbox if your image is older than
`oxfuzz/fuzz-sandbox:0.2.3`:

```sh
./scripts/build-sandbox.sh
```

Image 0.2.3 fixes a GDB output-pipe deadlock in CASR's timeout handling. The
service also stages honggfuzz crash names in the format CASR accepts. Earlier
versions could skip all honggfuzz inputs and silently fall back to basic replay,
then spend several minutes drafting AI reports. Scan the retained run again to
obtain symbolized CASR evidence. Existing historical findings remain retained.
