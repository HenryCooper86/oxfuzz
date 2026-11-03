# Fuzz Your Own Project

[Back to the README](../../README.md)

This guide is for fuzzing engineers who want to point oxfuzz at their own
C, C++, or Rust code and get triaged crashes out. It explains what oxfuzz
actually does to your source tree, what it supports today, and the two ways
to drive it. The command reference is in [CLI_REFERENCE.md](CLI_REFERENCE.md);
when something fails, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md).

## Before you start

1. Install the CLI (`cargo install --path crates/hf-cli --locked` from the
   oxfuzz checkout, or `cargo build --release -p hf-cli` for
   `target/release/oxfuzz`) and the sandbox image (`./scripts/build-sandbox.sh`).
   See [INSTALL.md](INSTALL.md).
2. Run `oxfuzz doctor`. It must report `READY` for `Docker daemon`,
   `sandbox image`, and the engine you plan to use.
3. Configure a model provider ([CONFIGURATION.md](CONFIGURATION.md#choosing-an-llm-provider)),
   or plan to run without one (`--ai off --no-llm-review`, described below).
4. Pin your state. Unless `HF_DB_PATH` is set, the CLI opens
   `data/oxfuzz.db` relative to the current directory, so running from a
   different directory sees a different database (and none of your promoted
   harnesses). Export `HF_DB_PATH` to one absolute path before you begin.
   Workspaces (harness binaries, corpora, crash files) default to the per-user
   directory (`~/Library/Application Support/oxfuzz/workspaces` on macOS,
   `$XDG_DATA_HOME/oxfuzz/workspaces` or `~/.local/share/oxfuzz/workspaces` on
   Linux); `HF_WORKSPACE_DIR` overrides it.

Every harness build and fuzz run executes inside the Docker sandbox with
networking disabled. Nothing generated is executed on your host, and every
high-risk step (compile, smoke run, fuzzer launch, project build) asks for
approval. See [SAFETY_MODEL.md](SAFETY_MODEL.md).

## What works today

From [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) and `TargetLanguage::harnessable`
in `crates/hf-core/src/target.rs`:

| Language (`--lang`) | Discovery | Harness build and campaigns | Engines |
| --- | --- | --- | --- |
| `c` | Tree-sitter scan of `.c`, `.h` | Yes | `libfuzzer`, `afl++`, `honggfuzz` |
| `cpp` (also `c++`, `cxx`) | Tree-sitter scan of `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh` | Yes | `libfuzzer`, `afl++`, `honggfuzz` |
| `rust` | Lexical scan for `pub fn` with parameters | Yes, through cargo-fuzz | `libfuzzer` only |
| `go`, `python` | Lexical scan | No. Candidates are marked `"harnessable": false` and harness commands refuse them | None |

Sanitizers: C and C++ build with `address` (default) or `undefined`; Rust is
AddressSanitizer only. Syzkaller is a separate kernel workflow and does not
apply to the userspace flow in this guide.

`--lang` matters: `discover` and `harness` scan or build only the language you
name. A C++ project whose API lives in `.h` headers is still found through its
`.cpp` definitions with `--lang cpp`. `oxfuzz fuzz` is the one command that
scans every supported language when `--lang` is omitted.

## How oxfuzz builds your code

Knowing this saves most first-run failures. For a C/C++ target, a harness
compile does the following (`crates/hf-service/src/container/harness_workspace.rs`,
`crates/hf-harness/src/generator.rs`):

- **Staging.** It copies every `.c`, `.h`, `.cc`, `.cpp`, `.cxx`, `.hpp`,
  `.hh`, and `.hxx` file under the project directory you pass into the
  target's workspace, preserving the directory layout. Directories named
  `.git`, `target`, `build`, and `node_modules` are skipped, symlinks are
  refused, and staging stops at 20,000 files. `.inc` and `.inl` files in the
  source tree are not staged; they are only picked up from a compile
  database's build directory.
- **One link.** It compiles the harness together with every staged
  translation unit (`.c`, `.cc`, `.cpp`, `.cxx`, up to 5,000) in a single
  compiler invocation inside the sandbox: 2 CPUs, 4096 MiB, 120 seconds, no
  network. Translation units under directories named `corpus`, `out`, `fuzz`,
  or `runs` are left out of that link.
- **Include paths.** The project root is always on the include path
  (`-I/work`). Anything else comes from a compile database (next section).

Consequences for a real project:

- Sources that define their own `main` (tests, examples, command-line tools),
  sources that only build on another OS, and sources that need a generated
  header will be part of that one link. There is no exclude option today. If
  they break the link, point oxfuzz at a directory that holds only the library
  (or a copy of it) instead of the repository root.
- A project with thousands of translation units may not finish inside the
  120-second compile limit.
- External libraries are not linked: `-l` and `-L` flags are never replayed,
  and include directories outside the project are dropped (see below).

For Rust, staging copies `Cargo.toml`, `Cargo.lock`, and every `.rs` file;
oxfuzz then scaffolds a cargo-fuzz project in `fuzz/` that depends on your
crate by path and runs `cargo fuzz build` (600-second limit). The sandbox's
Cargo is configured offline with a vendor directory that holds only
`libfuzzer-sys` and its dependencies (`docker/sandbox/Dockerfile`). In
practice that means:

- The project path must be a crate root whose `Cargo.toml` has a `[package]`
  table (a virtual workspace root fails with "could not find [package] name").
- Path dependencies inside the project work. Dependencies from crates.io or
  git cannot be resolved in the sandbox.
- Files other than `.rs`, `Cargo.toml`, and `Cargo.lock` (for example data
  pulled in with `include_bytes!`, or C sources compiled by a build script)
  are not staged.

## Give the compiler your include paths: compile_commands.json

Without a compile database, the model has to guess header paths and the
compile sees only `-I/work`. With one, oxfuzz replays the project's real
include directories, defines, and language standard.

For a project without a saved build profile, oxfuzz uses the first file that
exists of:

1. `compile_commands.json`
2. `build/compile_commands.json`
3. `out/compile_commands.json`
4. `.oxfuzz-build/compile_commands.json` (the conventional Build Doctor output)

You can generate one on your host with your normal build, for example
`cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` or
`bear -- make`. Host paths inside the project are rewritten to their
sandbox paths. Headers in the database's directory (and generated sources the
database references) are staged with the project, so generated headers in
`build/` resolve. Generate into `build/` (skipped by staging) or `out/` (left
out of the link). A host build tree written anywhere else, such as your own
CMake run into `.oxfuzz-build/`, would put CMake's compiler-probe sources
(each with its own `main`) into the harness link.

The database is untrusted input, so only an allowlist is replayed
(`crates/hf-discovery/src/build_context.rs`): `-I` directories that resolve
inside the project, `-D` with a C identifier name, one `-std=`, and a fixed
set of code-generation flags (`-fno-strict-aliasing`, `-fno-omit-frame-pointer`,
`-fPIC`, `-fPIE`, `-pthread`, `-fwrapv`, `-funsigned-char`, `-fno-common`).
Everything else (`-isystem`, `-include`, `-O`, `-W`, `-l`, include
directories outside the project) is dropped; run with `RUST_LOG=info` to see
the "flags outside the allowlist were not replayed" line.

## Build profiles (Build Doctor)

When you do not want to build on the host, or want oxfuzz to pin exactly which
database and component it uses, save a build profile and let oxfuzz generate
the database in the sandbox:

```bash
oxfuzz build diagnose <project>                # detect build systems, no execution
oxfuzz build profile set <project> \
  --component-root . --build-system cmake \
  --compile-database-path .oxfuzz-build/compile_commands.json
oxfuzz build profile show <project> --json     # note profile_sha256
oxfuzz build run <project> --expected-profile-sha256 <profile_sha256>
oxfuzz build history <project>                 # retained output of each run
oxfuzz build profile clear <project>           # back to the four-location search
```

Accepted `--build-system` values are `cmake`, `make`, `meson`, and
`autotools`. Detection reads marker files only (`CMakeLists.txt`,
`meson.build`, `configure.ac`/`configure.in`/`Makefile.am`,
`GNUmakefile`/`makefile`/`Makefile`). The reviewed plan runs, in the
sandbox with networking disabled:

| System | Steps |
| --- | --- |
| CMake | `cmake -S . -B <db dir> -DCMAKE_EXPORT_COMPILE_COMMANDS=ON <definitions>` (configure only) |
| Make | `mkdir -p -- <db dir>`, then `bear --output <db> -- make -B` |
| Meson | `meson setup <db dir>` (configure only) |
| Autotools | `autoreconf -i`, `./configure`, then `bear --output <db> -- make -B` |

Notes:

- `--define NAME=VALUE` is CMake-only, and `NAME` must be listed in
  `[build_profiles] allowed_cmake_options` in `oxfuzz.toml` (default:
  `BUILD_SHARED_LIBS`, `BUILD_TESTING`).
- `--dependency command:NAME` or `--dependency pkg_config:MODULE` adds a
  readiness probe. Probes check the sandbox image; nothing is installed.
- Saving a profile records the sandbox image's immutable ID, so Docker must be
  running. If you later rebuild the image, the profile reports `Stale` until
  you save it again, and harnesses built against it need a rebuild and
  requalification.
- While a profile is `NeedsBuild`, `Stale`, or `Invalid`, harness generation
  stops before any model call. A saved profile never falls back to the
  four-location search.
- Bazel is detected but unsupported. Custom Make targets, arbitrary
  environment variables, and dependency installation are unsupported.

The full specification is [build-doctor-design.md](../design/build-doctor-design.md).

## External dependencies

Fetching dependencies is unsupported ([SUPPORT_MATRIX.md](SUPPORT_MATRIX.md)).
Every build runs offline in the sandbox image, and the harness link adds no
libraries. A target that needs a third-party library to compile or link will
fail unless that code is inside the project directory. Practical options:
vendor the dependency's sources into the tree you point oxfuzz at, choose a
target below the dependency boundary, or stub the dependency for fuzzing. A
CMake `FetchContent`/`ExternalProject` step or a crates.io dependency will
fail for lack of network.

## Monorepos and components

There is no component option on `discover`, `harness`, or `fuzz`; the
`<PROJECT>` argument is the unit. `--component-root` exists only on
`oxfuzz build profile set`, where it selects which subdirectory's build
system to configure. The harness compile still stages the whole `<PROJECT>`
directory. So for a monorepo you choose between:

- Pass the repository root: sibling includes resolve and a component build
  profile works, but every translation unit in the repository joins the link.
- Pass the component directory: only that component is staged and linked, but
  headers outside it are not available.

Project identity is the canonical absolute path. Moving or re-cloning the
project to a different path starts it fresh (no targets, no promoted
harnesses).

## Discover targets

```bash
oxfuzz discover /path/to/project --lang c
oxfuzz discover /path/to/project --lang c --rank   # model-assisted ranking
```

On a terminal the result is a ranked table, best target first, ending with
the `oxfuzz fuzz` command for the top harnessable target. Piped output, or
`--json`, gives the full JSON inventory for scripts.

Plain discovery calls no model and builds nothing; it persists the
inventory in the database. `--rank --ai auto` keeps
the heuristic scores when no model is available. Each candidate carries a
`fit_score` and a `harnessable` flag. Targets are named by symbol
(`parse_value`) or by file-qualified selector (`src/parser.c::parse_value`).
Pick one spelling and keep using it: a harness promoted under one spelling
lives in a different workspace than the other.

## Flow 1: one command (`oxfuzz fuzz`)

```bash
oxfuzz fuzz /path/to/project --lang c --target parse_value \
  --engine libfuzzer --duration-secs 300 --iterations 3
```

Stages: discover, draft and compile a harness (with up to two automatic
repair rounds), independent model review, a 60-second smoke run, promotion
(asks you on a terminal), then the campaign (`--iterations` rounds of run and
triage). Omit `--target` to auto-pick the highest-fit harnessable candidate.
Re-running reuses an already promoted harness for that target and engine;
`--fresh` forces a new one. Useful options: `--sanitizer undefined`,
`--timeout-ms`, `--seed`, `--cmplog` and `--resume` (AFL++ only), `--json`.

Without any model: `oxfuzz fuzz ... --ai off --no-llm-review`. The harness is
then drafted from a template and the pre-execution review is skipped (recorded
as a bypass); you still approve promotion.

## Flow 2: reviewed work orders

When you want to write or review the harness yourself before anything runs,
use the work-order flow. Each step is retained and bound to exact digests:

```bash
oxfuzz work-order export /path/to/project --target parse_value \
  --lang c --engine libfuzzer --out work-order.md     # authoring packet
# Write harness.c from the packet (by hand or with another tool).
oxfuzz work-order import --work-order <work-order SHA-256> \
  --source harness.c --origin human                   # returns submission UUID
oxfuzz work-order qualify --submission <submission UUID>   # compile, review, smoke
# Inspect the returned source, lint, review, and smoke evidence.
oxfuzz work-order promote --attempt <attempt UUID>
oxfuzz run /path/to/project --target src/parser.c::parse_value \
  --engine libfuzzer --duration 60m
```

Use the complete file-qualified selector the work order prints for `run` and
the commands after it. To start from an oxfuzz draft instead of a blank file,
`oxfuzz harness <project> --target <sym> --engine <e> --draft-only --json`
returns the source to save and import. Details:
[CLI_REFERENCE.md](CLI_REFERENCE.md#harness-work-order-commands).

## Get crashes out

All of these take the same `<project>` and `--target` you fuzzed with:

| Command | Output |
| --- | --- |
| `oxfuzz triage <project> --target T` | Ingests, minimizes, and deduplicates crash artifacts; prints the unique count and bug-report drafts (`--ai off` skips the drafts) |
| `oxfuzz repro <project> --target T --engine E --out DIR` | A bundle with the harness, the crash input, the project translation units, and `REPRODUCE.md` (build and run commands). `--crash <id prefix>` picks a crash |
| `oxfuzz sarif <project> --target T --out f.sarif` | SARIF 2.1.0 for code scanning, from the latest run |
| `oxfuzz report <project> --target T --out report.md` | Markdown campaign report (`--report-lang en` or `zh`) |
| `oxfuzz regress <project> --target T` | Replays stored crashes against the current harness |
| `oxfuzz runs list --project <project>` | Run history and ids |

`repro` defaults to `--lang c`; pass `--lang cpp` or `--lang rust` for those
targets. (`triage` accepts `--lang` but works from the run's retained
workspace, so the value does not change its result.) A repro bundle is meant to be built outside
oxfuzz; running it executes a crashing input with no sandbox, so do that in a
disposable container or VM.

## Running in CI

`oxfuzz ci <project> --target T [--engine libfuzzer] [--duration 120s]
[--sarif oxfuzz.sarif] [--ai off]` runs a short campaign with an
already promoted harness, triages, writes SARIF, and exits non-zero if any
crash is found. It does not draft or promote a harness, and its `--lang`
flag is currently ignored. A starting template is
[`.github/workflows/fuzz.yml.example`](../../.github/workflows/fuzz.yml.example).
What the runner needs:

- Docker and the sandbox image. The example builds oxfuzz and the image from
  the checked-out repository, which only works when that repository is
  oxfuzz itself; for your project, check out oxfuzz separately (or use a
  prebuilt binary and image).
- The promoted harness's retained state: the database (`HF_DB_PATH`) and the
  workspace root (`HF_WORKSPACE_DIR`), restored at the same absolute paths,
  with your project checked out at the same absolute path it was promoted
  from. A moved workspace root is refused by its ownership manifest. A
  self-hosted runner with persistent state is the simplest arrangement.
- Non-interactive approval. `ci` always takes approval from the environment:
  set `HF_AUTO_APPROVE=1` or `HF_GUARDRAILS=permissive` (the example uses the
  latter). Without either, the fuzzer launch is denied.
- `--ai off` if the gate must not spend tokens.

If the gate fails before triage (no promoted harness, approval denied), no
SARIF file is written.

## Worked example: a small CMake library

`examples/cmake_tlv_lib` in this repository is a three-file CMake library
whose public header lives under `include/` and is included as
`"tlv/tlv.h"`. That include does not resolve from `-I/work`, so it needs a
compile database. With Docker running and `HF_DB_PATH` exported:

```bash
P=examples/cmake_tlv_lib
oxfuzz build diagnose $P                      # reports CMake from CMakeLists.txt
oxfuzz build profile set $P --component-root . --build-system cmake \
  --compile-database-path .oxfuzz-build/compile_commands.json --json
oxfuzz build run $P --expected-profile-sha256 <profile_sha256 from the output>
# Approve the project build when asked; it runs `cmake -S . -B .oxfuzz-build ...`
oxfuzz discover $P --lang c
oxfuzz fuzz $P --lang c --target tlv_decode --engine libfuzzer
# Approve compile, smoke, promotion, and the campaign when asked.
oxfuzz triage $P --target tlv_decode
oxfuzz repro $P --target tlv_decode --engine libfuzzer --out tlv-repro
oxfuzz sarif $P --target tlv_decode --out tlv.sarif
```

The expected finding is a one-byte heap-buffer-overflow write in
`decode_string`, reached through `tlv_decode`
([examples/cmake_tlv_lib/README.md](../../examples/cmake_tlv_lib/README.md)).
Alternatively, skip the profile and run
`cmake -S $P -B $P/build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON` on the host; the
four-location search then finds `build/compile_commands.json`.

## Worked example: a Rust crate

`examples/rust_varint` in this repository is a standalone library crate with
`pub fn decode(data: &[u8]) -> Result<(u64, usize), DecodeError>` in
`src/lib.rs` and no crates.io dependencies:

```bash
P=examples/rust_varint
oxfuzz discover $P --lang rust             # `decode` is listed as a Parser
oxfuzz fuzz $P --lang rust --target decode --engine libfuzzer \
  --duration-secs 120 --iterations 2
oxfuzz triage $P --lang rust --target decode
oxfuzz repro $P --lang rust --target decode --engine libfuzzer --out varint-repro
```

The expected finding is a shift-overflow panic on an over-long varint
([examples/rust_varint/README.md](../../examples/rust_varint/README.md)).
The harness is a `fuzz_target!` under `fuzz/fuzz_targets/` in the target's
workspace, built by `cargo fuzz build` with AddressSanitizer. If the
crate depended on, say, `thiserror` from crates.io, the sandbox build would
fail to resolve it (see "How oxfuzz builds your code"). A real two-crate
workspace with a path dependency is in `examples/qualification/rust`.

## Related guides

- [CLI_REFERENCE.md](CLI_REFERENCE.md) -- every command and flag
- [CONFIGURATION.md](CONFIGURATION.md) -- providers, budgets, `oxfuzz.toml`
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) -- symptoms and fixes
- [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md) -- what is qualified, and on which hosts
- [SAFETY_MODEL.md](SAFETY_MODEL.md) -- approvals and the sandbox boundary
