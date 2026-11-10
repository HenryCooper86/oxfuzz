# corpus-curation

Keep a target's fuzzing corpus small, diverse, and effective.

## When to use

- Before a campaign, to seed the corpus with good starting inputs.
- During a campaign, to grow it from new coverage-increasing inputs.
- When the corpus has grown large or redundant and needs pruning.

## Principles

- A good seed exercises a distinct, valid code path -- not random bytes.
- Diversity beats volume: many near-duplicate inputs waste fuzzer cycles.
- Every retained input should justify itself by unique coverage.

## Procedure

1. **Seed**: derive starting inputs from the target's expected format
   (valid examples, boundary values, known tricky cases). For a JSON parser:
   `{}`, `[]`, nested objects, deep arrays, unicode escapes, truncated inputs.
2. **Grow**: after a run, fold coverage-increasing inputs the engine found
   back into the corpus.
3. **Prune byte duplicates**: the `corpus` tool's `prune` operation removes
   byte-identical inputs. It does not measure coverage or prove a minimal corpus.
   Coverage-based reduction is a separate engine-backed operation in Corpus
   Management and requires the matching qualified, approved harness.
4. **Report** the corpus size before/after and what changed.

## Operations (corpus tool)

- `seed`  -> write starting inputs
- `grow`  -> import findings from the run output
- `prune` -> remove byte-identical inputs
- `list`  -> current corpus size

## Anti-patterns

- Seeding with thousands of random blobs (slows the fuzzer, no signal).
- Never pruning (corpus bloat degrades exec/s over time).
