# Clang Harness Analysis

Status: **active; first milestone delivered**. Owner: `hf-service`, `hf-discovery`, and `hf-harness`.
Risk: **High**, because analysis changes model input and the harness pipeline.

## 1. Goal and First Milestone

Improve C/C++ harness generation with compiler-resolved function identities,
typed declarations, call sites, and graph paths. Existing discovery remains the
fast shortlist producer. Clang analyzes the selected build configuration and
provides advisory evidence for the shortlisted functions.

The first milestone does not implement symbolic feasibility, interprocedural
taint solving, automatic API lifecycle inference, or solver-generated seeds.
It must deliver an executable helper, bounded Rust parsing, durable service
operations, a CLI entry point, and persisted context used by harness drafting.
An extractor without a service-to-provider path does not finish this milestone.

Success means fewer symbol/type/setup guesses in generated harnesses, measured
by compilation, observed target entry, downstream function coverage, and cost.
No coverage improvement is assumed before measurement.

## 2. Existing Behavior

`hf-discovery::scanner` collects plain-identifier calls and merges graph entries
by function name. It excludes zero-parameter definitions before collecting
edges. `reachability::analyze` walks that graph and retains at most 64 reachable
names per candidate. `hf-prompt::render::target_block` renders at most 20 names.
These are useful ranking hints, not evidence that a particular input reaches
a callee.

`hf-analysis` remains a pure tree-sitter analysis crate. This feature does not
put subprocess management into that crate or replace native/Semgrep overlays.
Current candidate UUIDs and base scores remain unchanged. The semantic graph
has its own identities and is not projected back into the name-keyed graph.

## 3. Product Behavior

The optional `clang-analysis` Cargo feature is initially off by default and
forwarded by `hf-cli`, `hf-web`, and Tauri to `hf-service`. Service forwards it
to `hf-discovery` and enables `build-context`. Storage and inert `hf-core` types
remain available in feature-disabled builds so cleanup and history still work.

The initial user entry point is:

```text
oxfuzz discover PROJECT --lang c --clang
oxfuzz discover PROJECT --lang cpp --clang
```

The CLI invokes normal discovery, then requests analysis for the configured
number of highest-ranked candidates; ties use relative file, symbol, and UUID.
Combining `--clang` with `--rank`, `--ai`, or `--semgrep` is rejected initially
to avoid unspecified ordering between producers. Unsupported languages and
feature-disabled invocations fail explicitly. There is no new GUI or REST
endpoint in this milestone; their existing harness paths use the same service
context resolver when the feature is enabled and evidence is current.

Analysis never begins implicitly during discovery or harness drafting. A later
draft may consume a successful current result, but cannot start another scan.
No result means the existing draft behavior. A stale result is reported and
excluded; a storage read failure is an error, not absence. Analysis failure
returns a failing CLI outcome while retaining the ordinary discovery inventory.

## 4. Compilation Inputs and Snapshot

Reuse service-owned build-profile selection and the existing four-location
database search. A missing, empty, malformed, or unsupported database refuses
explicit Clang analysis; do not synthesize generic compiler flags. Selection
of a saved profile never falls back to another database.

Direct Clang/GCC/cc and C++ driver names, including numeric version suffixes,
are recognized; C++ driver language is made explicit before ordered arguments.
Wrappers and target-prefixed drivers are rejected because their implicit
configuration is unavailable. Source coordinates use physical expansion-file
positions so `#line` directives cannot replace discovery coordinates.

Compilation databases do not identify linked programs. An optional
`clang_analysis.scope_file` is a project-relative path to a strict version-1
JSON scope manifest. Its default is absent. A manifest contains `name`,
`compile_database_sha256`, and `units`, each selecting a relative `file` and
the SHA-256 of one normalized compiler invocation. It selects one intended
linked program/configuration, with at most one invocation per main source file.
All references must resolve uniquely in the captured database; stale digests,
duplicates, missing files, or selected targets outside the scope fail admission.
The service records manifest bytes/digest and treats the declared grouping as
an operator assumption, not proof that a linker produced that program.

Without a scope manifest, each unit is its own analysis scope and no external
USR join crosses units. The CLI reports this limitation explicitly. With a
manifest, index every unit it selects and join only within that named scope.
Do not infer grouping from shared flags, directories, the database filename,
or the saved profile's component path. The CLI result includes normalized
invocation digests so an operator can construct a manifest without guessing.

Read the database once and retain its digest. Process each compile entry with
its own working directory and ordered arguments. Never reuse the aggregate
`BuildContext` as semantic analysis input. Multiple commands for one source
are distinct build variants, identified by the normalized invocation digest.

A service-owned resolver replaces the executable with the bundled helper's
Clang toolchain and never executes the database's command string. It removes
known output/code-generation-only arguments and rejects plugins, response
files, arbitrary frontend passthrough, and unsupported semantic arguments.
It preserves supported `-D`, `-U`, language, standard, include, and forced-include
arguments in order, with project paths rewritten into the read-only snapshot.
Only image-owned system headers are available outside that snapshot. Rejection
names the unit and argument category, without reporting secrets or host paths.
Target/sysroot options require explicit supported image mapping; otherwise
they are rejected. No unreported argument dropping is allowed.

Stage a private immutable project snapshot containing all units, headers,
generated headers, and project-local include inputs needed by the selected
database. Refuse symlink escapes and inputs outside the canonical project.
Hash relative paths and exact staged bytes in deterministic order. This is a
separate snapshot builder: Semgrep's C-source-only snapshot is insufficient.
Source mutation during staging or freshness checking refuses publication/use;
the recorded digest always describes the exact retained staged bytes.

Index all compile entries in this selected scope, including low-scoring and
zero-parameter helpers. Shortlisting limits harness-context queries, not graph
membership. Configured unit/snapshot limits refuse oversized requests rather
than removing connecting functions. A cold index can cost as much as parsing
the selected project; do not promise that top-K selection avoids this cost.
Automatic index caching is deferred; immutable retained results can be reused
while their complete input fingerprints match.

## 5. Helper and Wire Evidence

Add `tools/clang-analysis`, a standalone C++ LibTooling executable named
`oxfuzz-clang-analyze`. The sandbox build uses LLVM 18 development packages;
the dispatched immutable image pins the actual package/toolchain bytes.
Record the full Clang version, helper executable SHA-256, and image content ID.
Other LLVM majors are unsupported for production until independently tested.
The Rust application does not link libclang or LLVM C++ libraries.

The fixed helper reads `/work/input/request.json`, parses staged project files
under `/work/source`, and writes `/work/output/index.json`. The version-1
request contains only validated per-unit argv, relative files/directories,
resource ceilings, and schema version. It has no arbitrary command, plugin,
environment, output path, or network field.

Version-1 response contains:

- Units: invocation digest and relative source path.
- Functions: unit-scoped USR identity, qualified name, definition and declaration
  locations, result type, ordered parameter types/names, variadic marker,
  linkage, method/static/access information, and definition availability.
- Calls: caller identity, call-site location, dispatch category, and optional
  declared callee identity. Categories are `direct`, `virtual`, `indirect`, and
  `unresolved`. Virtual calls are not treated as exact runtime dispatch.
- Toolchain identity and counts. Diagnostics are normalized bounded strings.

Within a unit, canonical declarations unify declarations and definitions. The
identity includes the invocation digest, so internal-linkage and build-variant
definitions never collide. A project-level index joins external declarations
to definitions by USR only within the explicitly declared linked build scope.
Missing or multiple definitions are explicit unresolved joins; do not
guess between configurations. Header-defined functions retain unit provenance.
This first milestone uses separate per-unit records instead of flattening
incompatible variants into one program.

Clang parse errors, incompatible helper versions, exceeded output/graph limits,
or malformed JSON fail the operation. An unresolved call is valid evidence and
does not itself fail parsing. Rust rejects unknown schema fields, dangling
identities, duplicate records with conflicting data, invalid coordinates,
non-project paths, and oversized collections at this foreign-data input.

## 6. Graph Queries and Harness Context

`hf-discovery::clang_analysis` owns pure normalization, graph queries, and
candidate association. Associate a candidate using language, defining relative
file, source position, and symbol/signature evidence. Zero or multiple matches
produce `unavailable` or `ambiguous`; a bare name is never sufficient.

Queries produce forward paths from a selected target and reverse paths to
possible project callers. Exact call edges and unresolved dispatch sites are
separate. A declared virtual target can appear as advisory metadata but does
not become a confirmed direct edge. Cycles terminate. Traversal exhaustion
means `unknown`, not unreachable. Paths contain source locations and identities.
External definitions are unknown leaves unless indexed in the selected scope.

The typed harness context contains the selected declaration, relevant project
headers, bounded direct caller/callee declarations and call-site locations,
shortest paths ordered deterministically, and explicit unresolved-call counts.
Include method receiver/access requirements visible in declarations. Do not
infer buffer/length relationships, ownership, initialization sequences, or
parameter ranges from names. Those need later data-flow analysis or citations
to retrieved source examples. Non-public/internal entry points carry access
limitations; the generator may propose an accessible caller without claiming
that caller has been proven usable.

The prompt labels every route as a potential static call route. It states that
no symbolic feasibility or observed execution was established. Render facts as
untrusted project data with the existing prompt-security delimiters. Do not
instruct the model to bypass validation or fix input fields to a single path.

## 7. Service Lifecycle, Safety, and Persistence

Use a service-owned asynchronous operation with `staging`, `analyzing`,
`validating`, `done`, `failed`, `cancelled`, and `interrupted` states. Admission
authorizes `Action::AnalyzeSource { analyzer: "clang" }` before staging/runtime
work and retains a reservation consistent with project cleanup. Cancellation
awaits runtime teardown; recovery marks abandoned operations interrupted and
never automatically restarts an unapproved operation. Terminal transitions use
compare-and-swap. Publication is atomic with the normalized index.

Run only through `hf-runtime` streaming options using an immutable image,
read-only input/source mounts, a separate writable output mount, no network,
no additional capabilities, no ptrace, and no ambient host environment. There
is no host fallback. Inspect `CommandTermination` before process exit status.
Bounds are enforced during collection as well as during Rust parsing.

Validated `[clang_analysis]` configuration initially defaults to:

| Setting | Default | Accepted range |
| --- | --- | --- |
| `max_targets` | 16 | 1..=64 |
| `max_translation_units` | 1024 | 1..=10000 |
| `max_snapshot_bytes` | 268435456 | 1..=1073741824 |
| `max_output_bytes` | 16777216 | 1..=67108864 |
| `max_functions` | 100000 | 1..=500000 |
| `max_calls` | 500000 | 1..=2000000 |
| `timeout_secs` | 600 | 1..=3600 |
| `memory_mb` | 2048 | 128..=16384 |
| `cpus` | 1 | 1..=8 |
| `max_context_bytes` | 16384 | 1024..=65536 |
| `image` | `oxfuzz/fuzz-sandbox:0.2.1` | nonempty image reference, at most 256 bytes |

String fields have fixed wire ceilings: IDs 1024 bytes, paths 4096 bytes,
names/types/diagnostics 4096 bytes; identifiers are encoded data, not commands.
The helper stops with a specific error when collection exceeds a ceiling.
Context truncation is allowed only at whole-record granularity and includes
omitted counts; it never changes an unknown result into a negative assertion.

Add durable `clang_analysis_operations`, `clang_analysis_results`, and
`harness_clang_contexts` records. Operations retain canonical project, language,
selected targets, resolved limits, timestamps, state, and failure category.
Results retain database/snapshot/invocation/toolchain/image digests and the
exact normalized index. Model context records retain target, result ID,
renderer version, and the exact rendered section before provider dispatch.
All records are versioned; immutable insertion accepts only identical retries.
Storage absence/failure prevents analysis or analysis-bearing provider calls.
Project deletion and knowledge cleanup remove the new evidence in dependency
order; feature-disabled builds retain that cleanup.

One shared context resolver serves ordinary and persistent drafts, direct draft
and generate/compile paths. It selects current matching evidence, associates
the target, renders and persists the exact section, then supplies it to the
provider. Freshness covers the selected profile, complete snapshot, database,
scope manifest, toolchain/image, and normalized invocations. Historical evidence remains
readable after it becomes stale. Unrelated compile/review/promotion guards
continue to apply unchanged. Analysis grants no execution approval.

## 8. Delivery and Verification

Deliver in five dependency-ordered implementation tasks: protocol/queries;
helper/toolchain; durable operations and sandbox executor; persisted harness
context; CLI/feature wiring and qualification. Each task uses test-first
development and ends with independently observable behavior.

Required fixtures include duplicate static function names across files,
overloads/namespaces, zero-parameter connecting helpers, macros with opposite
per-unit definitions, multiple build variants, recursive calls, virtual and
function-pointer calls, missing headers, private methods, and external leaves.
Service tests cover denial at the executor, timeout/cancellation, bad output,
stale headers/database/image, missing store, interrupted recovery, immutable
retry, cleanup, and persistence failure before provider dispatch. Both ordinary
and persistent prompts must be exercised through the real service call paths.

Compare baseline and enriched drafts on retained fixed C/C++ fixtures with the
same model/settings/budget. Report compile success, observed goal-function
entry, downstream coverage, executions per second, analysis seconds, and model
tokens separately. No generated harness runs on the host. Before release, the
LLVM 18 helper and the service must pass a real sandbox smoke test in addition
to mock-based Rust tests and repository quality gates.

### Local qualification (2026-10-20)

The five implementation tasks are delivered behind the optional feature.
Local verification on macOS passed formatting, fixing and verifying Clippy
(default, disabled defaults, and isolated Clang), workspace compilation,
3,963 tests, and documentation with warnings denied. The suite retained its
21 existing ignored tests; this change adds none. All 23 isolated product
feature builds and the feature-behavior gate passed. Script, dependency,
translation, performance-build/parser, and frontend gates passed, including
696 frontend tests, production bundle budgets, lint, and dependency audit.
Coverage collection/validation passed in diagnostic macOS mode; storage line
coverage was 92.18%. Linux baseline enforcement remains in CI.

Nine real LLVM 18 container fixtures cover compiler identities, macro/build
variants, zero-parameter helpers, dispatch, declarations, physical locations,
and rejected parses/collection limits. The minimal pinned Ubuntu qualification
image is built separately from the existing fuzz sandbox. A real CLI/runtime/
container pipeline with a local fixture HTTP provider exercises ordinary and
persistent drafts, exact retained provider input, rejection before dispatch on
context-write failure, C++ driver language for a `.c` file, and stale/deleted
source exclusion. No generated harness is built or executed by qualification.

The fixture provider verifies integration rather than model effectiveness.
Comparative harness compilation, observed target entry, downstream coverage,
throughput, and real model token/quality measurements remain unavailable.
These measurements require a separately approved sandbox harness campaign.

## 9. Rejected Alternatives and Later Work

- Replacing fast discovery: loses portability and makes every scan require a
  working build configuration.
- Linking LLVM into Rust: introduces C++ API/ABI coupling in the service.
- Parsing debug call-graph text: unsuitable as a versioned machine format.
- Treating stock analyzer warnings as a harness specification: omits successful
  paths and the declaration/call metadata needed by generation.
- Analyzing only shortlisted definitions: removes helper connections.
- Returning all variant definitions as resolved callees: combines mutually
  incompatible builds.
- Claiming unreachable from absent graph edges or empty diagnostics: unsupported.

Later designs can add CFG conditions, input-flow summaries, explicit library
models, whole-program indirect-call analysis, and bounded custom Static
Analyzer queries/CTU exploration. They must preserve `unknown` results and
validate useful path hypotheses with retained runtime coverage. Existing
concolic corpus enrichment remains a separate execution capability.

Upstream references: [LibTooling](https://clang.llvm.org/docs/Tooling.html),
[compilation databases](https://clang.llvm.org/docs/JSONCompilationDatabase.html),
[Static Analyzer](https://clang.llvm.org/docs/ClangStaticAnalyzer.html), and
[CTU analysis](https://clang.llvm.org/docs/analyzer/user-docs/CrossTranslationUnit.html).
