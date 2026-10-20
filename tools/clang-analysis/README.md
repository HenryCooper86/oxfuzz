# Clang semantic extractor

`oxfuzz-clang-analyze` parses C/C++ compiler invocations and emits version-1
JSON declarations and call sites. It does not execute target code or solve
path constraints. Production builds require LLVM 18; Rust uses bounded JSON
rather than linking LLVM libraries.

The service invokes the fixed executable in `hf-runtime` with read-only
`/work/input` and `/work/source` and a separate writable `/work/output`.
The helper reads `request.json` and writes `index.json`. A successful result
records the full compiler version and helper executable SHA-256.

Build the qualification image from a repository checkout:

```sh
docker build -f tools/clang-analysis/Dockerfile \
  -t oxfuzz/clang-analysis:test tools/clang-analysis
cargo build -p hf-cli --features clang-analysis
scripts/tests/gates.sh clang-analysis
```

The qualification Dockerfile defaults to the existing local fuzz sandbox for
fast development. CI selects the pinned Ubuntu base explicitly. The main
`docker/sandbox/Dockerfile` installs this executable in the production image.

Enable the optional Cargo feature and select the packaged image in
`[clang_analysis]` configuration, then run:

```sh
oxfuzz discover /path/to/project --lang c --clang
```

The ordinary compilation database is required. Each invocation retains its own
macros, working directory, standard, optimization/PIC semantics, and supported
include inputs. Unsupported semantic options are rejected. Source paths outside
the project and compiler plugins/response files are unsupported.
Direct `clang`, `gcc`, `cc`, `clang++`, `g++`, and `c++` driver names (with optional
numeric version suffixes) are supported. C++ drivers retain their language even
for `.c` files; a later explicit `-x` takes precedence. Compiler wrappers and
target-prefixed driver names require an explicit supported configuration and
are currently rejected. Locations use physical source coordinates, including
for generated code containing `#line` directives.

Without `scope_file`, cross-translation-unit definitions are unresolved. To
name one intended linked program, create a project-relative JSON manifest:

```json
{
  "schema_version": 1,
  "name": "parser-library",
  "compile_database_sha256": "SHA256_OF_DATABASE_BYTES",
  "units": [
    {"file": "src/parser.c", "invocation_sha256": "INVOCATION_ID_FROM_RESULT"}
  ]
}
```

Set `scope_file = "oxfuzz-clang-scope.json"` in `[clang_analysis]`. Every selected
invocation must exist exactly once in the captured database. A manifest groups
one invocation per main file; the grouping is an explicit build assumption.
Include helper translation units as well as target entry points.

The current extractor records explicit calls, declarations, and project header
locations. Implicit C++ constructors/destructors, runtime virtual overrides,
and arbitrary function-pointer destinations are not fully resolved. Context
labels static routes accordingly and retains unknown and omitted counts.
