# Build Doctor

Status: **active implementation**. Owner: `hf-service`, with sandboxed execution
in `hf-runtime`, authorization in `hf-guardrails`, and rendering in `hf-gui`.

## 1. Goal

Turn "the harness will not build" into a specific, actionable answer: which
build system this project uses, whether oxfuzz can produce a compile database
for it in the current sandbox image, exactly what would run, and whether running
it worked.

Missing compile context is the largest source of first-draft harness build
failures. `hf-service::container::build_context` already consumes a
`compile_commands.json` when a project ships one, and records that generating
one "belongs behind `hf-runtime` and a guardrail action rather than here". This
subsystem is that path.

## 2. Feature and Ownership

The subsystem is enabled by the `build-doctor` feature in `hf-service`, which
depends on `build-context` for the compile-database vocabulary it produces and
consumes. `hf-service` owns detection, plan construction, authorization, and
result verification. REST and Tauri serialize service requests and views. React
renders the diagnosis and collects the execution approval; it never decides that
a build system is supported or that a plan succeeded.

## 3. Detection

Detection is read-only and evidence-citing. It looks only for marker files at
the project root, and reports which markers it found:

| Build system | Markers |
| --- | --- |
| CMake | `CMakeLists.txt` |
| Meson | `meson.build` |
| Autotools | `configure.ac`, `configure.in`, `Makefile.am` |
| Make | `Makefile`, `makefile`, `GNUmakefile` |
| Bazel | `WORKSPACE`, `WORKSPACE.bazel`, `MODULE.bazel`, `BUILD.bazel` |
| Cargo | `Cargo.toml` |

A project may match several. All matches are reported, ordered by how
specifically each generates compile context: a project with both `CMakeLists.txt`
and a `Makefile` is a CMake project whose `Makefile` is generated output, so
CMake ranks first. A project matching nothing is `unknown`. Detection never
guesses from source-file extensions: a wrong build system produces a plan that
wastes a sandbox run and misleads the operator.

Detection reads the project root only, not the whole tree. A marker in a
subdirectory belongs to a component, not to the project under test.

## 4. Diagnosis Vocabulary

Each detected build system carries one status:

- **`ready`** -- the project already ships a compile database that resolves to
  usable build context. No plan is needed and none is emitted.
- **`supported`** -- oxfuzz can produce a compile database for this build system
  with tools present in the pinned sandbox image. A plan is emitted.
- **`unsupported_in_image`** -- the build system was detected, but the tool that
  would generate a compile database is absent from the pinned image. The missing
  tool is named. No plan is emitted, because a plan that cannot run is worse
  than an honest refusal.
- **`not_needed`** -- the language path does not consume a compile database.
  Rust harnesses build through cargo-fuzz against the staged crate.
- **`unknown`** -- no marker matched.

The pinned image provides `clang`, `llvm`, `make`, `cmake`, `ninja-build`,
`git`, and `python3`. It does not provide `bear`, `meson`, or `bazel`.
Consequently CMake is `supported`; Make and Autotools are
`unsupported_in_image` (they need `bear` to observe a build); Meson and Bazel
are `unsupported_in_image` (their own tool is absent); Cargo is `not_needed`.

## 5. The Plan

A plan is an ordered list of steps. Each step carries the exact argument vector,
the working directory relative to the project root, and a human-readable purpose.
Arguments are a fixed vector: nothing is composed through a shell, and no value
is interpolated from project content. The plan also names the artifact it
expects to produce, relative to the project root.

For CMake the plan is one step:

```text
cmake -S . -B .oxfuzz-build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

producing `.oxfuzz-build/compile_commands.json`. It is a configure step only: it
generates the database without compiling the project.

The plan runs in the project directory, and `.oxfuzz-build/` is created there.
This is a visible side effect on the operator's own source tree, and it is part
of what the approval covers. The directory name is oxfuzz-owned and distinct
from any `build/` the project maintains, so a plan run never overwrites the
operator's build tree. Running in the project (rather than a workspace copy) is
required, not incidental: `BuildContext` include directories must resolve inside
the project root, so a database generated against a copy would be rejected by
the existing allowlist.

The plan is returned by diagnosis and rendered in full before anything runs.
Producing a plan executes nothing.

## 6. Execution

Running a plan runs the project's own build system, which is untrusted code. It
is therefore:

- gated by the `RunProjectBuild` guardrail action at `High` risk, authorized
  before the first step;
- executed step by step through `hf-runtime` with the pinned image, under the
  same resource limits and no network access as any other sandbox command; and
- never executed on the host.

A step that exits non-zero stops the run; later steps are not attempted, and the
failing step's index, exit code, and captured output are retained.

After the last step, the service verifies that the expected artifact exists and
resolves it through the existing compile-database path. A run whose steps all
exited zero but produced no readable database is reported as failed with
`artifact_missing`, not as success. Command success is not evidence that the
intended artifact appeared.

## 7. Rejected Alternatives

- **Guessing the build system from source extensions** -- produces a plan for a
  build system the project does not use, wasting a sandbox run and misleading
  the operator about why the harness will not build.
- **Emitting a plan for a build system the image cannot run** -- a plan that
  fails in the sandbox teaches the operator nothing about the actual gap.
- **Running the plan on the host** -- it is the untrusted project's own build
  system; the safety model puts every build in `hf-runtime`.
- **Composing plan steps as shell strings** -- project-derived content must
  never reach a shell; steps are fixed argument vectors.
- **Reusing the project's own `build/` directory** -- a plan run would clobber
  the operator's build tree; oxfuzz owns `.oxfuzz-build`.
- **Treating exit code zero as success** -- the artifact is the evidence, not
  the exit status.
- **Adding `bear`, `meson`, and `bazel` to the pinned image now** -- it would
  widen support to Make and Autotools projects, but changes the pinned image and
  forces every operator to rebuild it. Deliberately deferred, and the Doctor
  names the missing tool in the meantime.

## 8. Verification Criteria

- Each marker file is detected, several markers report several systems in
  specificity order, and no marker reports `unknown`.
- A marker in a subdirectory does not make the project that build system.
- A project that already resolves build context reports `ready` and emits no
  plan.
- Make, Autotools, Meson, and Bazel report `unsupported_in_image` naming the
  missing tool, and emit no plan.
- Rust reports `not_needed`.
- Diagnosis executes nothing.
- Execution is refused without guardrail authorization.
- A non-zero step stops the run and retains its index, exit code, and output.
- All steps exiting zero with no resulting database reports `artifact_missing`.
- No plan step runs on the host, and no step is composed through a shell.
- Feature-disabled builds compile and hide the surface.
