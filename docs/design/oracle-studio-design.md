# Oracle Studio

Status: **active implementation**. Owner: `hf-service`, with the scaffold built
and run through the existing `hf-harness` and campaign paths, and rendering in
`hf-gui`.

## 1. Goal

A sanitizer finds memory-safety faults. It does not find a decoder that returns
the wrong answer, a round-trip that loses data, or an invariant that quietly
stops holding. Those defects do not crash, so nothing currently reports them.

An oracle is a property, stated by a human, checked on every input. This
subsystem lets an operator state such a property as a typed specification, see
exactly what harness it produces before anything is built, and have a resulting
finding identified as a violation of that named property.

Six kinds are supported. Differential, round-trip, and invariant are stateless:
one input, one check. Metamorphic relates the result of one input to the result
of a transformed input. Stateful drives a sequence of operations derived from the
input and checks after each. Resource watches a reported measurement across a
call rather than the value returned.

## 2. Feature and Ownership

The subsystem is enabled by the `oracle-studio` feature in `hf-service`.
`hf-service` owns the specification vocabulary, validation, scaffold rendering,
and violation classification. Building and running an oracle harness use the
existing approved compile, smoke, and campaign paths; the studio adds no
execution route. REST and Tauri serialize the service view, and React renders it
without deciding whether a property was violated.

## 3. Specification

A specification names the target and one property:

- **Differential** -- `target(data, size)` and a `reference(data, size)` must
  agree on every input. The classic oracle for a reimplementation or an
  optimized path against a known-good one.
- **Round-trip** -- `decode(encode(x))` must reproduce `x`. Catches loss and
  corruption that never touch invalid memory.
- **Invariant** -- a `predicate()` must hold after every call to the target.
  Catches state that degrades over a campaign rather than failing at once.
- **Metamorphic** -- transforming an input must relate its result to the
  original's in a stated way. The relation is one of `equal`, `not_less`, or
  `not_greater`: a transformation that adds data must not shrink a count, one
  that removes data must not grow it, and one that should not matter must not
  change it. Catches wrong answers where no reference implementation exists to
  compare against.
- **Stateful** -- a sequence of operations derived from the input, with a check
  after every step. The input's first byte selects an operation and the next
  bytes are its payload, repeatedly, up to a bounded step count. Catches defects
  that need a particular order of calls rather than a particular input.
- **Resource** -- a reported measurement must not grow by more than a stated
  amount across one call. Catches leaks and blowups, which return correct
  answers and never touch invalid memory.

Every symbol in a specification is interpolated into generated C source, so each
must be a plain identifier: a leading letter or underscore, then letters,
digits, or underscores, bounded in length. Anything else -- a call, an operator,
a comment sequence, whitespace, a newline -- is rejected before rendering. This
is the injection boundary of the subsystem and it fails closed.

A specification also carries a human-written description of the property. It is
retained with the oracle so a later reader knows what was actually being
claimed, not merely which symbols were compared.

## 4. Signature Contracts

Each scaffold assumes a documented signature for the symbols it calls, and the
design records them:

| Kind | Required signatures |
| --- | --- |
| Differential | `int target(const uint8_t *, size_t)`, `int reference(const uint8_t *, size_t)` |
| Round-trip | `int encode(const uint8_t *, size_t, uint8_t *, size_t *)`, `int decode(const uint8_t *, size_t, uint8_t *, size_t *)` |
| Invariant | `int target(const uint8_t *, size_t)`, `int predicate(void)` |
| Metamorphic | `int target(const uint8_t *, size_t)`, `int transform(const uint8_t *, size_t, uint8_t *, size_t *)` |
| Stateful | `int apply(uint8_t, const uint8_t *, size_t)`, `int check(void)` |
| Resource | `int target(const uint8_t *, size_t)`, `unsigned long measure(void)` |

oxfuzz does not parse C, so a mismatch is caught by the compiler rather than by
validation. That is deliberate. A build failure naming the symbol is visible and
actionable; a scaffold that silently accepted a wrong signature would compile
into an oracle that tests nothing, which is worse than not having one.

## 5. Scaffold

Rendering is deterministic: the same specification always produces the same
source, so a reviewer who approved a scaffold approved exactly what gets built.
The scaffold is shown in full before anything is built.

Each scaffold states its property in a comment, performs the check, and on
violation writes a marker to stderr and terminates.

## 6. The Lint Exception

`hf-harness`'s `no-process-exit` rule blocks `exit`, `_exit`, and `abort` as
build failures, because a harness that terminates while handling input makes
every input look like a crash.

An oracle must terminate: that is how it signals the finding. The scaffold
writes its marker, flushes, and calls `__builtin_trap()`. This is chosen for two
reasons, not to slip past the rule:

- `assert` is removed by `NDEBUG`, so an oracle built with it could silently
  check nothing; `__builtin_trap()` is unconditional.
- it is the primitive sanitizer checks themselves use for a failed check.

This is the one sanctioned place a harness deliberately terminates. The rule
stays in force everywhere else, and every rendered scaffold is checked against
the existing lint as part of the test suite.

## 7. Violation Identity

On violation the scaffold writes one line:

```text
OXFUZZ_ORACLE_VIOLATION <oracle-id> <kind> [detail]
```

The optional detail is one whitespace-free token carrying the evidence that
distinguishes one violation of a kind from another: `step=3` for the operation
index a stateful sequence failed at, `growth=4096` for the amount a resource
measurement grew. The stateless kinds carry no detail, because the input alone
identifies the violation. A detail that is absent or unparseable does not stop
the line from classifying: the oracle and kind are what make it a violation.

The service classifies a finding as an oracle violation by finding that marker
in the finding's retained output. No `CrashKind` variant is added: that would
modify a core contract the protocol says to extend rather than change, break
exhaustive matches across the workspace, and leave every persisted crash to
migrate. The marker is retained evidence, so the classification is
reconstructable from what was stored.

The marker is read from the report text ingest retains beside the crash input,
under the same `log-<stem>.txt` convention ingest uses. It is read without
ingest's "does this look like a sanitizer report" filter, which is the right
test for classifying a crash and the wrong one here: a trap-only oracle log need
not mention a sanitizer at all, and filtering on that would silently lose the
marker.

Two consequences are stated deliberately:

- **A crash in an oracle harness is not automatically an oracle violation.** An
  oracle harness can also dereference a null pointer, and that is a
  memory-safety finding, not a violated property. Only the marker makes it an
  oracle violation.
- **Absence of a marker is not evidence that the property holds.** It means no
  violation was recorded, which is what the view says.

## 8. Bounds

A stateful oracle consumes its input as a sequence, so it needs a step ceiling:
without one a large input becomes an unbounded loop inside a single fuzzer
iteration, which stalls the campaign rather than finding anything. A resource
oracle needs a growth allowance, since no real function grows nothing. Both are
part of the reviewed specification and both are validated to a bounded range, so
a specification cannot ask for a step count that never terminates.

## 9. Rejected Alternatives

- **Adding `CrashKind::OracleViolation`** -- modifies a core contract, breaks
  exhaustive matches, and requires migrating persisted crashes, to express
  something a retained marker already carries.
- **Having a model author the oracle body** -- the property decides whether a
  finding is real; that must come from a reviewed specification.
- **Validating signatures by parsing C** -- oxfuzz has no C parser, and a
  half-correct one would accept wrong signatures silently. The compiler is the
  honest check.
- **Using `assert` for the failure path** -- `NDEBUG` would remove the check and
  leave an oracle that silently tests nothing.
- **Relaxing `no-process-exit` generally** -- the rule catches a real and common
  harness defect; the exception is one rendered failure path, not a licence.
- **Treating any crash in an oracle harness as a violation** -- it would report
  memory-safety findings as property violations and misdirect the fix.
- **Reusing ingest's sanitizer-report pairing unchanged** -- its filter accepts
  text only when it looks like a sanitizer report. An oracle log that traps
  without sanitizer output would be discarded before the marker was ever seen.
- **Running the oracle harness from the studio** -- compile, smoke, and campaign
  already have approved paths.
- **An open-ended metamorphic relation expression** -- it would be code supplied
  as a string and interpolated into the harness, which is exactly what the symbol
  validation exists to prevent. A closed relation vocabulary is checkable.
- **Deriving a stateful operation alphabet automatically** -- which calls are
  legal in which order is domain knowledge; guessing it would produce sequences
  that fail for reasons that are not defects.
- **Measuring resources from outside the harness** -- process-level memory
  includes the fuzzer, the sanitizer, and the corpus, so a target-reported
  measurement is the only one attributable to the target.

## 10. Verification Criteria

- A symbol that is not a plain identifier is rejected before rendering, and the
  rejection names the offending symbol.
- Each kind renders a scaffold that states its property, calls the specified
  symbols, emits the marker, and terminates through `__builtin_trap()`.
- Every rendered scaffold passes `lint_harness_source` with no blocking finding.
- Rendering is deterministic for a given specification.
- The marker classifies a violation and names the oracle and kind.
- Output without a marker yields no violation.
- A memory-safety crash in an oracle harness is not an oracle violation.
- A retained log carrying the marker classifies even when it contains no
  sanitizer output.
- A stateful violation carries the step index and a resource violation the
  observed growth; a marker without detail still classifies.
- A step ceiling or growth allowance outside its bounded range is refused.
- A metamorphic relation is drawn from the closed vocabulary, never supplied as
  an expression.
- The studio executes nothing.
- Feature-disabled builds compile and hide the surface.
