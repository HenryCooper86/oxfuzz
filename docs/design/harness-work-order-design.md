# Harness Work Order Export

Status: **planned**. Owner: `hf-service`, over `hf-discovery` candidates and the
resolved build context.

## 1. Goal

Every harness-authoring path in oxfuzz requires a configured LLM provider. That
excludes two real cases: an operator who wants to write the harness themselves,
and an environment where no provider credential may be present.

A work order is a self-contained directory holding everything needed to author
one harness for one candidate, with no provider involved at any point.

## 2. Feature and Ownership

Enabled by the `harness-work-order` feature in `hf-service`, which implies
`build-context`. Export composes retained discovery and build-context state and
calls no provider.

## 3. Contents

For one candidate:

- the candidate record: function, signature, source location, and the discovery
  evidence that ranked it;
- a bounded excerpt of the function's source and its declaration;
- the resolved compile context for its translation unit -- include directories,
  defines, language standard, and compile flags, as `hf-discovery`'s build
  context already extracts them;
- the harness rules from `docs/standards/HARNESS_STANDARD.md` that the lint
  enforces, so an author sees the constraints before writing rather than as
  compile failures afterward;
- seed suggestions drawn from retained corpus entries and repository fixtures;
  and
- the exact oxfuzz commands that validate the result.

## 4. Determinism And Safety

The export is deterministic: the same retained state produces a
byte-identical packet, so two exports can be diffed.

Nothing secret is written. Provider credentials, tokens, and the environment are
never read by this path, because no part of it needs them. Source excerpts come
from the project under test and are bounded in size; the packet is data for a
person to read, and the export performs no build and executes nothing.

## 5. Rejected Alternatives

- **Emitting a filled prompt template** -- fuzzctl writes model-ready prompt
  packets. A prompt is one consumer's format; the work order holds the evidence
  and lets a person or any tool decide how to use it.
- **Including the whole source file** -- unbounded, and the candidate's
  declaration plus body is what an author needs.
- **Generating a draft harness in the packet** -- drafting is a provider path
  with a review gate; a draft in a provider-free export would arrive without one.
- **Writing the packet inside the project under test** -- the project is
  untrusted input; exports land in the workspace.

## 6. Verification Criteria

- Export succeeds with no provider configured.
- The same retained state exports byte-identical packets.
- The packet carries compile context matching the candidate's translation unit.
- No environment variable, credential, or token appears in the output.
- Export performs no build and starts no process.
