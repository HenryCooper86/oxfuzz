# JavaScript Jazzer.js Fuzzing Design

Status: **first slice implemented, acceptance open** (2026-11-22). Owners:
`hf-service` for admission, staging and workflow, `hf-harness` for the
generated harness, `hf-engine` for the launcher and argv, `hf-discovery` for
candidates, `hf-crash` for report classification, and `hf-runtime` for every
process.

## Goal and admission

Fuzz a function that a Node.js module exports by name, through a Jazzer.js
fuzz function, inside the sandbox. `EngineKind::JazzerJs` (`jazzer-js`)
supports JavaScript only and stays outside the default enabled set: an
operator lists it under `[fuzzing] enabled_engines`. The `js-jazzer` feature
is part of the default feature set, following the `jvm-jazzer` and
`python-atheris` precedent: the runtime engine policy, not the build, keeps
the path off until an operator opts in. System status carries a `jazzer_js`
flag, true only when the image has the `jazzer-js` launcher. JavaScript is
not advertised as libFuzzer support because Jazzer.js embeds libFuzzer: the
counters are edges Jazzer.js instruments in JavaScript source, and a finding
is an uncaught exception, a rejected promise, or a bug-detector report.

Jazzer.js is selected because it is the maintained coverage-guided fuzzer for
Node.js (4.0.0, April 2026, Apache-2.0) and ships its native fuzzer module
prebuilt for linux/arm64 and linux/x64, so the image builds nothing native.

## Supported target class

A function declared at the top level of a `.js`, `.mjs` or `.cjs` file and
exported under its own name, each of whose required parameters is documented
in the JSDoc block directly above the function as `Buffer`, `Uint8Array`,
`string`, `number` or `boolean`.

- **Why documentation is required.** JavaScript has no types to read. Handing
  a `Buffer` to a function that expects a string makes the first input throw
  a `TypeError` that the harness caused, and reporting that as a finding
  would be wrong. An undocumented required parameter is therefore refused,
  and the refusal names the `@param {type} name` line to add.
- **Optional parameters.** A parameter with a default value, a parameter
  JSDoc marks optional (`[name]` or `{type=}`), and a rest parameter are left
  out of the call. A required parameter after an optional one is refused,
  because arguments are positional. At most eight required parameters.
- **Module kinds.** CommonJS and ES modules. Discovery reads
  `exports.name = ...`, `module.exports.name = ...`, `module.exports = { name }`,
  `export function`, `export const name = ...` and `export { name }`.
  Function declarations, function expressions and arrow functions are
  candidates, `async` or not.
- **Outside the class.** Methods and classes (they need an object the harness
  cannot construct), default exports, renamed exports, generators,
  destructured parameters, object and array parameters, TypeScript, code
  that needs a browser, native addons, and declarations that are indented
  (inside a wrapper function or a UMD prelude).

## Toolchain

The image carries Node.js 24.22.3 at `/opt/node`, verified against the
release digest of its architecture, and Jazzer.js 4.0.0 at `/opt/jazzerjs`,
installed with `npm ci --ignore-scripts` from the committed
`docker/sandbox/jazzerjs/package-lock.json`. The lockfile pins all 105
packages by integrity hash; none declares an install script, and every one
carries a permissive license (MIT, ISC, Apache-2.0, BSD, BlueOak, CC-BY-4.0).
`/usr/local/bin/jazzer-js` starts the pinned Node.js on the pinned Jazzer.js
command line. Nothing is installed or downloaded at run time.

## Project staging and dependencies

The project root must hold `package.json`; a draft for a project without one
is refused with that reason. Staging copies the manifest, every `.js`,
`.mjs`, `.cjs` and `.json` file (the manifest decides whether a `.js` file is
an ES module, and modules read JSON data), and, when the manifest declares
`dependencies`, `optionalDependencies` or `peerDependencies`, the whole
`node_modules` tree as it is. Development-only packages do not cause the
tree to be staged. Symlinks are refused, so a symlinked layout (pnpm, linked
workspaces) is not staged and a module that needs it fails to load. A
package that ships a native addon built for the host will not load in the
Linux sandbox. Files under `node_modules`, test directories, and `*.test.*`,
`*.spec.*`, `*.min.*` and `*.config.*` files are not discovery candidates.

## Harness

`hf_harness::js_jazzer` renders one fixed file from the selected function
(module path, export name, and the type of each required parameter) and
records them in a `// oxfuzz:js-target` line. There is no model draft and no
repair: lint accepts only the generated text for the recorded target, and
the service additionally requires the recorded function to be the selected
one. A JavaScript harness runs with Node.js's full power the moment it is
loaded, so there is no reviewed subset of edits to allow yet.

The artifact is one executable file that is a shell script and an ES module
at once. Its second line is a comment to JavaScript and a command to the
shell: it writes the module text to `/tmp/oxfuzz-harness.mjs`, restates
libFuzzer's `-timeout=<seconds>` as Jazzer.js's `--timeout <milliseconds>`
(which would otherwise override it with its default), and starts
`jazzer-js` on the copy with the artifact's own directory in
`OXFUZZ_HARNESS_DIR`. The copy leaves out the two launcher lines because
Jazzer.js's ES module instrumentation does not accept an interpreter line.

The module is an ES module because it has to `import()` the selected module:

- Jazzer.js instruments an ES module only when it is imported. A CommonJS
  harness that `require`s an ES module runs it uninstrumented, which a
  probe showed as a run with no coverage growth and no finding.
- A CommonJS module is instrumented either way, and its exports arrive as
  the default export when Node.js cannot name them, so the harness looks
  for the function on the namespace and then on the default export.
- A module that does not export the function throws while the harness
  loads, which is a failed run and not a finding.

One `Buffer` or `string` parameter receives the input as it is (the string
decoded as UTF-8). Any other list is filled in order from Jazzer.js's
`FuzzedDataProvider`, loaded from the image's pinned tree by absolute path so
a copy the project carries cannot replace it; the last `Buffer` or `string`
takes the remaining input.

The fuzz function returns what the selected function returns, and Jazzer.js
is not put in its synchronous mode. A promise is therefore awaited and its
rejection is a finding, whether or not the function is declared `async`. In
synchronous mode a function that returns a promise without being declared
`async` crashes the process outside any report. The cost is one turn of the
event loop per input: about half the throughput on a trivial function
(109,881 against 52,426 executions per second in the probe).

## Build and execution

The build is one fixed shell command: the image's Node.js parses the harness
and the selected module with `node --check` and installs the harness as the
executable artifact. Nothing is loaded before the smoke approval. Smoke,
campaign and replay start the artifact directly, the way they start a
compiled harness. The argv is fixed libFuzzer flags built in
`hf_engine::jazzerjs`; fork and job flags are refused. A run is one Node.js
process whatever the CPU allocation. No sanitizer applies and any other
choice is refused.

## Retained sources

The staged project (manifest, modules, JSON files, and the package tree) is
captured into each run's `input/source-context`. A staged run's harness
loads the module from that directory, so the run and its historical replay
execute the sources and packages captured at run start even when the
workspace has changed since. Smoke and triage replay load the workspace
copy. A run of a project with a large package tree keeps a copy of it.

## Findings

An uncaught exception or a rejected promise exits 77 and writes
`crash-<sha1>`; a per-input timeout exits 70 and writes `timeout-<sha1>`.
Ingestion collects both like libFuzzer artifacts. Jazzer.js reports a finding
as `==<pid>== Uncaught Exception: <name>: <message>` followed by `at` frames,
and a bug-detector finding (command injection, path traversal, prototype
pollution and the others it loads) as `==<pid>== <title>` with the call on
the next line. libFuzzer's own lines carry the same process mark and are told
apart by their `ERROR:` or `libFuzzer:` label. Classification names the
exception (or the detector's title and call) and signs the frames of the
code under test as `function (file)`: the file is the module's path below
the project whether a run loaded it from its retained sources or a replay
from the workspace, and whether Node.js printed a path or a `file://` URL;
positions are left out because an instrumented ES module reports its own.
Frames of the harness, of Jazzer.js and of Node.js internals are skipped. An
exit other than 0, 70 or 77 (a module that fails to load) fails the smoke as
such and is never a finding.

## Evidence

Jazzer.js 4.0.0 on Node.js 24.22.3 in `oxfuzz/fuzz-sandbox:0.2.3`
(linux/arm64), 2026-11-22, through the live tests
`live_jazzer_js_finds_replays_and_classifies_a_planted_exception` (a
CommonJS module that loads a package the project carries: found, collected,
replayed with exit 77, classified, replayed from the run's retained sources
after the workspace was corrected, clean on the corrected function, and a
module that cannot load or does not parse failing as such) and
`live_jazzer_js_fuzzes_an_async_es_module_function_with_typed_parameters`
(an `async` ES module function of a `number` and a `string`, whose rejected
promise is found and classified).

## Not implemented

Selected-function entry evidence, coverage reports, minimization, CASR,
expected-rejection predicates, a way to state parameter types without
editing the source, methods and classes, TypeScript, symlinked package
layouts, installing packages, and driving the engine from the desktop app
(JavaScript targets are discoverable there and fuzzed from the CLI, like Go,
Python and Java). A full review, promotion, campaign and Stop cycle through
the commands has not been exercised.
