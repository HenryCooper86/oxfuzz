# coverage-analysis

Judge whether a fuzzing campaign is making progress and recommend the next move.

## When to use

- During or after a run, to decide if the campaign is healthy.
- When edge growth has flattened or exec/s is low.

## Signals to read

- **Edges covered** over time: still climbing, or flat?
- **Executions per second**: high (good harness) or low (heavy setup / I/O)?
- **Corpus growth**: new inputs still being found, or dried up?
- **Time since last new edge**: the stagnation clock.

## Diagnosis -> action

- Flat edges + healthy exec/s -> the fuzzer can't reach new code. Likely a
  guarded path (magic bytes, checksum, length field). Add a targeted seed or
  a dictionary, or split the harness to start past the guard.
- Low exec/s -> the harness does too much per iteration (allocation, I/O,
  global setup). Trim it; move setup out of the hot path.
- Corpus stopped growing early -> seeds too narrow; add diverse seeds.
- Crashes found -> hand off to crash-triage; keep fuzzing for more.

## Output

State the verdict (progressing / stalled), the evidence (the numbers), and one
concrete next step (a seed, a harness change, a different target).
