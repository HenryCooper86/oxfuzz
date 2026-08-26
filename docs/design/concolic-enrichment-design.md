# Concolic Corpus Enrichment

Status: **active implementation**. Owner: `hf-service`, over a SymCC-instrumented
build produced and executed by `hf-runtime`.

## 1. Goal

Mutation cannot guess a value it has to match. A parser that checks four magic
bytes, a length field, or a checksum presents a branch that random mutation
reaches only by accident, and coverage stops at that comparison no matter how
long a campaign runs. `coverage-blocker-design.md` names such a function as a
blocker; it does not produce an input that gets past it.

Concolic execution does. It runs a real input while recording the path
constraints the program tests, negates one, and asks a solver for an input that
takes the other branch.

This subsystem runs the retained corpus through a concolically instrumented
build and folds the solved inputs back into the corpus. A later campaign starts
from the enriched corpus. It grows a corpus; it does not fuzz, and it starts no
campaign.

## 2. Naming

The subsystem is *concolic enrichment*. SymCC is its current implementation and
is named only where the toolchain is discussed. Naming the capability rather
than the tool keeps the service API stable if the implementation changes, and
this is a field where implementations change: SymCC, SymQEMU, and Fuzzolic all
produce the same artifact from the same input.

## 3. Feature and Ownership

Enabled by the `concolic-enrichment` feature in `hf-service`. The sandbox image
owns the toolchain; `hf-service` owns the operation; the CLI and REST render the
result and never decide any part of it.

The surface is `oxfuzz corpus <project> --target <sym> --op concolic`, beside
`seed`, `grow`, `prune`, `minimize`, `absorb`, and `list`. The observable
outcome is corpus growth, so that is where an operator looks for it. `minimize`
and `absorb` already execute the target, so an operation that builds and runs is
not a new kind of thing on that surface.

## 4. The Operation

Four steps, each through `hf-runtime` (AGENTS.md 2.12). Nothing runs on the
host.

1. **Build.** Compile the target's promoted harness and the staged target with
   the SymCC compiler wrapper in place of `clang`, producing a binary that
   records path constraints as it executes. This reuses the existing staging and
   build path; only the compiler and its flags differ. A target with no promoted
   harness has nothing to instrument, and the pass reports that rather than
   instrumenting a draft: human promotion stays bound to the exact harness
   revision, and a concolic pass is not a way around it.
2. **Explore.** Run each selected corpus input under that binary with
   `SYMCC_OUTPUT_DIR` naming a staged output directory, and with
   `SYMCC_INPUT_FILE` naming the input. The runtime writes solved inputs to the
   output directory.

   `SYMCC_INPUT_FILE` is not optional for a file-reading harness, and omitting
   it is the subsystem's sharpest failure mode: SymCC treats only stdin as
   symbolic by default, so a file-based harness run without it marks nothing
   symbolic, solves nothing, writes nothing, and exits zero. Measured: the same
   harness and input yield one solved input with the variable set and none
   without it, with no diagnostic in either case. oxfuzz's generated harnesses
   read a file, so this is the default path rather than an edge case, and the
   run step sets the variable rather than trusting a caller to.
3. **Collect.** Read the produced inputs, discard those already present in the
   corpus by content digest, and count what remains.
4. **Fold.** Add the novel inputs to the retained corpus through the existing
   corpus persistence, so they are indistinguishable from any other corpus
   entry to every later consumer.

Step 4 is deliberately the existing path rather than a parallel store. A solved
input is a corpus input; giving it a second home would mean every consumer of
the corpus had to learn about concolic enrichment (AGENTS.md 2.18).

## 5. Bounding

Path explosion is concolic execution's normal failure mode, not its exceptional
one: a loop over input bytes can fork a constraint per iteration, and a solver
call is orders of magnitude slower than a fuzz execution. An unbounded pass
would consume a machine and produce nothing an operator asked for.

Four validated configuration fields bound it, under a `concolic` section:

- **`max_inputs`** -- corpus inputs explored in one pass.
- **`per_input_timeout_secs`** -- wall-clock for one input's exploration.
- **`max_solved_inputs`** -- solved inputs retained from one pass.
- **`total_timeout_secs`** -- wall-clock for the whole pass.

These are configuration and not constants (AGENTS.md 2.15). A deployment
enriching a small binary parser and one enriching a protocol stack do not share
a per-input timeout, and a `DEFAULT_*` constant would make that a code change.
Validation rejects a zero in any field: a zero bound is not "unlimited" here,
it is a pass that does nothing while reporting success.

Inputs beyond `max_inputs` are reported as skipped with the bound that skipped
them, never silently dropped.

## 6. Result

One view per pass:

- **`inputs_explored`** and **`inputs_skipped`**, with one typed reason per
  pass naming which bound in section 5 stopped it. A pass stops on the first
  bound it reaches, so the reason is singular rather than a set.
- **`inputs_solved`** -- what the solver produced.
- **`inputs_novel`** -- how many of those were not already in the corpus.
- **`corpus_size_before`** and **`corpus_size_after`**.

`inputs_novel` is the number that matters and is reported separately from
`inputs_solved` on purpose. A solver that returns fifty inputs the corpus
already contains has enriched nothing, and a result that reported only
`inputs_solved` would present that as a success.

## 7. Availability

The toolchain is optional. Where it is absent the operation returns
`Unavailable` with a reason code and changes no corpus. That is distinct from a
pass that ran and solved nothing, which is a real and common outcome.

Availability is a bounded probe in the sandbox -- the image is present and the
wrapper answers a version query -- surfaced through `oxfuzz doctor` alongside
the engine checks. The probe never runs a target.

## 8. Toolchain

SymCC compiles the target with an LLVM pass that emits calls into a runtime
recording symbolic constraints, then solves them with Z3. It is added to the
sandbox image as its own layer, pinned by commit and verified at image build
time, matching how honggfuzz, syzkaller, CASR, and cargo-fuzz are already
handled there.

Four properties of the tool constrain the layer. Each was read from SymCC's own
build files rather than assumed, because each one silently produces a broken or
absent capability when guessed wrong.

- **LLVM 17, not the image default.** SymCC's `CMakeLists.txt` warns that it
  targets LLVM 8 through 17 and is "unlikely to work" outside that range. The
  sandbox image is Ubuntu 24.04, whose default is LLVM 18, so the layer installs
  and builds against the distribution's LLVM 17 explicitly rather than
  inheriting the default. Building against 18 is not a supported configuration
  and the layer must not silently attempt it.
- **The runtime is a submodule.** SymCC's runtime lives in a separate
  repository (`symcc-rt`) wired in as a git submodule, with the qsym backend
  nested inside it as a further submodule. A plain clone yields an empty
  `runtime/` directory and a cmake failure that names the directory rather than
  the cause.
- **Backend selection is `SYMCC_RT_BACKEND`, and it must be `qsym`.** The
  runtime accepts `simple` or `qsym` and defaults to `qsym`. Only `qsym`
  writes solved inputs to `SYMCC_OUTPUT_DIR`. The `simple` backend solves the
  constraint and prints the diverging assignment to stdout without writing a
  file; SymCC itself prints "for anything but debugging SymCC itself, you will
  want to use the QSYM backend instead" when it starts. A layer built on
  `simple` would produce a subsystem that never enriches anything, and would
  report empty passes indefinitely without erroring.

  `qsym` is commonly described as x86-centric. Measured on this workspace's
  own arm64 image it builds and solves correctly, so the layer selects it on
  every architecture rather than branching. Note that `QSYM_BACKEND` is not an
  option in current SymCC; passing it does nothing and leaves the default in
  place.
- **LLVM's cmake exports need zlib and zstd.** LLVM's exported targets reference
  `ZLIB::ZLIB`, so the dev packages must be present or `find_package(LLVM)`
  fails while configuring the runtime.

## 9. Rejected Alternatives

- **Registering SymCC as an `EngineKind`** -- it is not a fuzzer. `EngineAdapter`
  is `kind()` plus `build_run_args()`, which does not describe building an
  instrumented binary and folding solved inputs into a corpus, and every
  consumer that enumerates engines would be told there is a fuzzer here.
- **Running `symcc_fuzzing_helper` concurrently beside a live AFL++ campaign** --
  this is SymCC's upstream model and produces better results, because the solver
  reacts to queue entries the fuzzer finds during the run rather than only
  between runs. It needs an execution model oxfuzz does not have:
  `RuntimeAdapter` is `run_command`, one bounded command per invocation, with no
  `spawn`. Two cooperating long-lived processes sharing an output directory
  would either need that trait extended or a wrapper script running both inside
  one invocation, and in both cases the per-process resource limits AGENTS.md
  2.12 relies on stop describing what actually runs. Recorded here as a possible
  later phase so this design does not have to be redone if that model is added.
- **The `simple` runtime backend** -- section 8. It was chosen in an earlier
  revision of this design on the assumption that both backends produce the same
  artifact and differ only in speed. They do not: `simple` writes no solved
  inputs at all. The assumption was corrected by building both and running
  them, not by reading about them.
- **Running SymCC on the host** -- every build and every execution of an
  instrumented target goes through `hf-runtime` (AGENTS.md 2.12). An
  instrumented build of an untrusted project is untrusted code.
- **Unbounded exploration** -- section 5.
- **A separate store for solved inputs** -- section 4.
- **Reporting `inputs_solved` as the headline number** -- section 6.
- **Falling back to an uninstrumented build when the toolchain is missing** --
  it would run the corpus through a binary that cannot solve anything and report
  a completed pass, which is a pass that did nothing dressed as one that worked.

## 10. Verification Criteria

- The SymCC layer builds in the sandbox image against LLVM 17, with the runtime
  submodule checked out and the `qsym` backend selected (section 8: only `qsym`
  writes solved inputs), and the image build fails loudly if the wrapper is
  absent, matching the existing toolchain verification step.
- The layer's compiler wrapper instruments a trivial program with a
  magic-value branch, and running it writes at least one solved input file. An
  image whose wrapper builds but solves nothing is a layer that will report
  empty passes forever, and the image build is where that is cheapest to catch.
  Checking that the wrapper compiles is not sufficient: both backends compile,
  and only one writes a file.
- A file-reading harness explored without `SYMCC_INPUT_FILE` produces no solved
  inputs, so the run step sets it and a test asserts it is set.
- An absent toolchain yields `Unavailable` with a reason code and leaves the
  corpus byte-identical.
- Every bound in section 5 is enforced, and a pass that hits one reports which.
- A zero in any bound is rejected at configuration load.
- A solved input already present in the corpus is counted in `inputs_solved` and
  not in `inputs_novel`.
- A pass that solves nothing is a success with `inputs_novel` zero, not a
  failure.
- No step executes outside `hf-runtime`.
- The corpus after a pass contains every entry it contained before.
