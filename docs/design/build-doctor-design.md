# Build Doctor

Status: **active implementation**. Phase 6 profile behavior below is the
implementation specification. Owner: `hf-service`, with typed records in
`hf-storage`, sandbox execution in `hf-runtime`, and authorization in
`hf-guardrails`.

## 1. Goal

Diagnose build requirements before drafting a harness, retain a reusable
optional project build profile, and show the exact sandbox build plan and its
terminal output. Profiles are optional: an unconfigured project keeps existing
C/C++ and Rust workflows. A saved profile selects the authoritative component,
compile database, configure definitions, dependencies, and sandbox image.

## 2. Feature and Ownership

The existing `build-doctor` feature enables diagnosis, profile save/clear,
project-build execution, and their CLI, REST, Tauri, and GUI surfaces. It uses
`build-context` for compile-database parsing. `hf-service` owns normalization,
readiness, hashes, dependency probes, plan construction, authorization, and
verification; presentations serialize requests and render service results.

Typed durable profile, diagnosis, and harness-input records remain available
in `hf-storage` without this feature. The small configured-input resolver and
checks, including their pure parsing dependencies, remain available to harness,
qualification, promotion, campaign, and corpus operations in feature-disabled
builds. Disabling `build-doctor` never makes a saved profile disappear or
silently restores legacy resolution. Diagnosis/profile mutation/build-plan
surfaces are unavailable when disabled; ordinary execution still enforces saved
inputs through its shared service checks.

## 3. Profile Selection and Validation

An unconfigured project searches for compile databases in this exact order:
`compile_commands.json`, `build/compile_commands.json`,
`out/compile_commands.json`, `.oxfuzz-build/compile_commands.json`. Existing
best-effort prompt context, strict compile-time parsing, and no-database Rust
or simple C/C++ behavior remain unchanged. Lack of a profile alone never blocks
Draft or Generate.

A configured project uses only its saved `component_root` and
`compile_database_path`; it never falls back to those four locations. Both
paths are normalized UTF-8 paths relative to the canonical project root, with
`.` denoting the root component. The database filename is exactly
`compile_commands.json`. Reject absolute paths, parent traversal, symlink
components, special files, and escape from the project. The component and
selected marker must exist. The database and its output ancestors may be absent:
validate every existing parent with `symlink_metadata` before accepting a
cold-start output path, then repeat containment checks when accessing it.
Include paths may refer to safe sibling directories inside the complete project.

Supported saved build systems are CMake and plain Make. Autotools, Meson, Bazel,
custom Make targets, arbitrary environment variables, and dependency installation
are unsupported in Phase 6. Reject CMake definitions on a Make profile rather
than saving ignored settings. Definitions are sorted by name and validated:

- Names match `[A-Z][A-Z0-9_]{0,63}` and occur in the validated
  `[build_profiles].allowed_cmake_options` configuration list.
- The default allowlist contains only `BUILD_SHARED_LIBS` and `BUILD_TESTING`.
  These are allowed names, not injected definitions or default values.
- Values are `ON`, `OFF`, or at most 128 ASCII characters from
  `[A-Za-z0-9_+.,:/-]`, and must not start with `-`.

Dependencies are typed `command:<name>` or `pkg_config:<module>` entries, with
1–64 ASCII characters matching `[A-Za-z0-9][A-Za-z0-9_.+-]*`. Normalize their
representation, deduplicate, and sort by kind/name without changing case.

Save resolves and persists the configured sandbox image tag and its immutable
image ID, the selected marker path and SHA-256, and `profile_sha256`. The
profile digest hashes versioned canonical serialization with named fields:
canonical project, normalized component/database paths, build system, sorted
definitions and dependencies, image tag/ID, and marker path/digest. Timestamps
are excluded so saving identical normalized assumptions keeps the same digest.
Every field controls selection, argv, probing, or staleness. Changed marker or
image assumptions require explicit review and save; diagnosis never rewrites
the saved profile. A store/read/image-resolution failure is an error, never an
unconfigured or ready result. Save also rejects profile/plan metadata that
cannot fit the retained diagnosis envelope; it cannot accept a plan whose
required evidence would exceed the persistence limit.

## 4. Detection and Diagnosis

Detection inspects marker files without executing project code. With no profile
it inspects the project root; with a profile it inspects the selected component.
Nested components are selected explicitly rather than inferred by traversal.

| Build system | Markers |
| --- | --- |
| CMake | `CMakeLists.txt` |
| Meson | `meson.build` |
| Autotools | `configure.ac`, `configure.in`, `Makefile.am` |
| Make | `Makefile`, `makefile`, `GNUmakefile` |
| Bazel | `WORKSPACE`, `WORKSPACE.bazel`, `MODULE.bazel`, `BUILD.bazel` |
| Cargo | `Cargo.toml` |

Report all matches in existing specificity order, with CMake above a generated
Makefile and Autotools above plain Make. For several Make markers use GNU Make's
selection order: `GNUmakefile`, `makefile`, `Makefile`. The selected marker is
part of saved identity; adding a higher-priority marker makes it stale. An
unsupported higher-level system is not silently downgraded to plain Make.
No markers gives `unknown`; source extensions are not build-system evidence.
Cargo retains `not_needed` because Rust harnesses use cargo-fuzz.

`ProjectBuildDiagnosis.profile_state` is separate from detected-system support:

| State | Meaning and admission |
| --- | --- |
| `Unconfigured` | No saved profile. Report legacy context availability; retain current Draft/Generate behavior. Saving a profile is optional. |
| `NeedsBuild` | Valid saved assumptions and dependencies, but the configured database has not been generated. Stop Draft/Generate and harness compile before provider use; keep the reviewed project-build plan runnable. |
| `Ready` | Saved assumptions and dependency probes match, and the exact configured database parses into a nonempty entry list with nonempty compiler invocations; all replayed flags pass the allowlist. A valid entry may require no extra flags. Generation may proceed. |
| `Stale` | Selected marker identity/bytes or resolved image tag/ID differs from saved assumptions. Stop generation/build and require explicit review/save. |
| `Invalid` | Unsafe/missing component or marker, unsupported system/options, malformed or zero-entry existing database, or named missing dependency. Stop generation/build and report the reason. |

Structural invalidity is checked first, changed saved assumptions next, then
dependency readiness and database readiness. Missing output alone is
`NeedsBuild`, not `Stale` or `Invalid`. Runtime failures are returned as errors;
a probe's absent command/module is a named dependency result. Diagnosis does
not call a provider, run project code, or install dependencies.

For configured diagnosis, probe service-required tools and the saved dependency
list in a unique empty managed workspace, with no project mounted, networking
disabled, and `SandboxOptions.image` set to the resolved immutable image ID.
Use fixed argv: `pkg-config --exists <module>` for modules. Command lookup uses
`/bin/sh -c 'command -v "$1" >/dev/null' oxfuzz-command-probe <name>`:
the script is constant, the validated name is a positional argument, and the
command being located is not executed. Do not interpolate a name into shell
source. CMake requires `cmake`; Make requires `mkdir`, `make`, and `bear`;
module probes additionally require `pkg-config`.

Phase 6 adds Bear to the pinned sandbox image alongside existing Make, CMake,
Ninja, and pkg-config. Release image checks cover `bear --version`,
`cmake --version`, `make --version`, and `pkg-config --version`. CMake and plain
Make plans are supported only when those required tools are available; other
build systems remain unsupported even if a particular image contains a tool.

## 5. Service API and Operator Flow

```rust
pub struct SaveBuildProfileRequest {
    pub project: String,
    pub component_root: String,
    pub build_system: ProfileBuildSystem, // CMake | Make
    pub compile_database_path: String,
    pub cmake_definitions: BTreeMap<String, String>,
    pub dependencies: Vec<BuildDependency>,
}

pub struct RunBuildPlanRequest {
    pub project: String,
    pub expected_profile_sha256: String,
}

pub enum BuildProfileState { Unconfigured, NeedsBuild, Ready, Stale, Invalid }

pub struct ProjectBuildDiagnosis {
    pub detected: Vec<BuildSystemDiagnosis>,
    pub profile: Option<BuildProfileView>,
    pub profile_state: BuildProfileState,
    pub dependency_statuses: Vec<BuildDependencyStatus>,
    pub reasons: Vec<String>,
    pub plan: Option<BuildPlan>,
    pub legacy_build_context_available: bool,
}

async fn diagnose_build(&self, project: &Path)
    -> Result<ProjectBuildDiagnosis, ClassifiedError>;
async fn save_build_profile(&self, req: SaveBuildProfileRequest)
    -> Result<BuildProfileView, ClassifiedError>;
async fn clear_build_profile(&self, project: &Path)
    -> Result<(), ClassifiedError>;
async fn run_build_plan(&self, req: RunBuildPlanRequest)
    -> Result<BuildPlanRunOutcome, ClassifiedError>;
async fn build_diagnosis_history(&self, project: &Path, limit: usize)
    -> Result<Vec<BuildDiagnosisRecord>, ClassifiedError>;
```

CLI, REST, Tauri, and GUI callers adopt these service requests coherently. Show
proactive diagnosis above Draft, an optional profile editor with Save and Clear,
exact argv/component/image/profile digest for review before explicit Run, and
retained output history. Labels and reason rendering have English and Chinese
translations. Build plans are offered for `NeedsBuild` and may be rerun when
`Ready`; `Unconfigured` can select/save a profile to prepare a reviewed plan.
No UI or agent action automatically approves a project build or a harness.
The shared draft service checks configured readiness before authorization,
discovery, or provider access; frontend disabling alone is not enforcement.
Provider-bearing generation and review must resolve the configured image tag
live before any provider call and report `Stale` if its immutable ID differs
from the saved profile, even when retained diagnosis and filesystem evidence
match. Read-only corpus availability alone uses retained image evidence without
runtime/image calls; final execution still rechecks live image freshness.

## 6. Reviewed Plan and Execution

A plan contains ordered fixed argument vectors, purposes, component working
directory, expected project-relative database path, exact profile digest, image
tag, and immutable image ID. The request's `expected_profile_sha256` must match
the current saved profile before authorization and before any build step.
CMake definitions are emitted as validated individual `-D<name>=<value>` tokens.

Stage the complete bounded project, then set runtime `cwd` to the staging root
so it mounts at `/work`. Set the existing `SandboxOptions.workdir` to
`/work/<component_root>` (or `/work` for `.`). Derive both CMake `-B` and Bear
output from the configured database path relative to that container working
directory. Derived sibling paths may contain `..` only as the result of this
validated in-project conversion; saved paths themselves cannot contain `..`.

For `component_root=components/parser` and
`compile_database_path=build/parser/compile_commands.json`, the steps are:

```text
cmake -S . -B ../../build/parser -DCMAKE_EXPORT_COMPILE_COMMANDS=ON <definitions>
```

or, for plain Make:

```text
mkdir -p -- ../../build/parser
bear --output ../../build/parser/compile_commands.json -- make -B
```

The CMake plan configures without compiling the whole project. Bear observes
the forced plain Make build. `<definitions>` denotes the sorted validated
argument tokens, never literal shell expansion. No plan step uses a shell.

Execution runs untrusted project code and requires `RunProjectBuild` at High
risk through the existing human authorization path. Hold the shared workspace
lease from staging through validation/publication and cleanup. Stage only
regular files, reject symlinks and special files, exclude version control and
known build output, and enforce 20,000 files, 64 MiB per file, and 512 MiB total.
All steps use `hf-runtime`, fixed argv, the captured immutable image ID, normal
resource limits, and disabled networking. The host never executes the build.
Validate the staged selected marker against the reviewed digest before dispatch.

A non-zero step, timeout, or cancellation stops the run. Retain the terminal
status, step index, exit code when meaningful, and bounded stdout/stderr. Zero
exit without a database is `artifact_missing`. Read the expected bounded
regular database at `staging/compile_database_path`, parse it, rewrite only
staging-root and `/work` prefixes to canonical project paths, then require a nonempty parsed entry list and validate replayed flags with the
existing allowlist. Empty argument vectors and empty compiler tokens are invalid.
Mapped path suffixes must be relative: reject an additional slash/backslash root,
UNC/verbatim prefix, or Windows drive designator after the execution prefix.
Ordinary relative suffixes are joined using native host path separators. A rejected
suffix makes the artifact invalid and preserves any previously published database.
The shared parser decodes command-form quotes and escapes without executing or
expanding shell content, following the [JSON Compilation Database format](https://clang.llvm.org/docs/JSONCompilationDatabase.html).
Publication converts those decoded tokens into an `arguments` array and removes
the old `command` field, so host paths containing spaces remain single tokens.
Other JSON fields are preserved. Normalized serialization uses the same 64 MiB
limit as the configured reader and stops before output exceeds that limit.
An `ArtifactInvalid` build operation records `Invalid` for that attempt and never
publishes its rejected database. Any prior valid host database remains intact;
a later independent diagnosis may still report that existing database `Ready`.
Zero additional flags is a valid configured result; preserve
the existing legacy no-flags-to-no-context behavior for unconfigured projects. Recheck the exact expected profile digest
immediately before atomic publication at `project/compile_database_path`; a
concurrent save/clear rejects publication and retains failure against the old
captured profile. Revalidate destination parents before replacement. No other
untrusted output is published to the project. Cleanup removes the unique staging
directory on every terminal path.

## 7. Retained Evidence and Harness Inputs

[DATABASE_SCHEMA.md](../standards/DATABASE_SCHEMA.md) specifies planned migration
`0031_build_profiles.sql`: one current `project_build_profiles` row, retained
`build_diagnosis_runs`, and immutable `harness_build_inputs`. Phase 5's delivered
migration 0030 remains unchanged. Both successful and failed diagnosis/build
outcomes retain the captured profile digest, reviewed plan/image, dependency
results, reasons, and bounded output in versioned diagnosis JSON of at most
65,536 UTF-8 bytes. Bound/truncate output with an explicit marker before encoding;
never truncate serialized JSON. History accepts only limits 1–100 and orders
by time then UUID newest first. Saving/clearing a profile does not relabel or
delete old diagnosis evidence. Missing matching retained diagnosis yields named
unavailable evidence in read-only capability views.

`clear_knowledge` preserves saved profiles as configuration, removes diagnosis
history as operation evidence, and removes build-input rows with their harnesses.
`delete_project` explicitly removes all three row families for its canonical
project in its transaction, including profiles/history without target rows.
No foreign key from historical evidence to the mutable current profile is used.

[Harness Generation Design](harness-generation-design.md) defines capture and
enforcement: read exact database bytes once, derive the actual staged flags,
and pin the actual compile image before each attempt. Successful compilation
atomically stores the new harness plus captured immutable inputs before the
active marker is published. Failed compilation stores no input row. Recompute
and compare at review, smoke, both promotion modes and the final promotion
reload, campaign admission before seed-provider use, and final fuzzer/corpus
executors. Configured stale or missing input evidence requires rebuild and
requalification. Historical unconfigured harnesses without a row retain the
existing source/binary approval behavior. Core Harness/approval types and Work
Order v2 wire fields do not change solely for profiles.

## 8. Rejected Alternatives

- Mandatory profiles would break existing simple projects without adding useful
  configuration; unconfigured resolution remains supported.
- Silent fallback from a saved profile would compile different inputs from the
  operator's selection; configured inputs are authoritative.
- Treating missing output as stale would prevent a valid cold-start build;
  `NeedsBuild` preserves the reviewed build action.
- Hardcoded root output or mounting only the component would lose configured
  output placement and sibling includes; stage the project and select workdir.
- A recorded image ID with tag-based dispatch would not identify the image used;
  dispatch the captured immutable reference.
- Independent harness/input writes could expose an untraceable active binary;
  commit them atomically before the marker.
- Runtime probes during corpus readiness would turn a read into execution;
  use retained evidence and return a named unavailable reason when absent.
- Arbitrary build scripts, installers, and additional build systems would exceed
  the validated Phase 6 configuration and require a separate design.

## 9. Verification Criteria

- Unconfigured C/C++ and Rust retain four-location/no-database behavior and do
  not require profiles; configured selection never falls back.
- Paths reject absolute/traversal/symlink/special/escape cases; missing output
  ancestors support cold-start `NeedsBuild` and a runnable plan.
- Nested components with sibling output and safe sibling includes use the full
  staged project, correct component workdir, exact argv, and exact publication.
- CMake option names/values and dependency identifiers validate at external and
  durable input reads; normalized saves have stable digests and consume fields.
- Marker/image changes require review/save; missing dependencies are named
  before a provider call. Probes have empty mounts, fixed argv, immutable image,
  no network, no project execution, and no installer/provider calls.
- CMake and Make/Bear produce validated context under fake runtime fixtures;
  real-image checks are separate sandbox validation, not inferred from mocks.
- Denial, non-zero exit, timeout, cancellation, missing/malformed output, and
  profile mutation before publication retain correctly attributed failure.
- Compile attempts dispatch the captured image; profile/database/image changes
  during awaited compilation never relabel the binary with newer inputs.
- Atomic persistence failure exposes neither a partial harness/input pair nor
  a new active marker; differing retries of an input UUID are rejected.
- Actual shared review/smoke/promotion/campaign/fuzzer/corpus executors deny
  stale configured inputs; promotion's final reload is covered. Rebuild and
  requalification restore eligibility; no new approval authority is introduced.
- A changed configured image tag with identical retained diagnosis, profile,
  marker, database, and flags reports `Stale` before generation/review provider
  calls; the review provider call count is zero. The same fixture's read-only
  corpus availability makes zero runtime/image calls, and final execution still
  rechecks live image freshness.
- Read-only corpus capabilities call neither runtime/image resolution nor a
  provider; missing matching retained diagnosis is named unavailable evidence.
- Feature-off/no-default and standalone-feature builds preserve durable reads
  and configured enforcement while hiding optional mutation/diagnosis surfaces.
- Cleanup preserves profiles for `clear_knowledge`, removes all project-owned
  rows for `delete_project`, and leaves Phase 5 schema and behavior unchanged.
