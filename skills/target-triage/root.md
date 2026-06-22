# target-triage

Rank functions in a codebase by their suitability for fuzzing.

## When to use

- The user asks "what should I fuzz in this project?"
- `hf-discovery` produces a raw candidate list that needs scoring.

## Procedure

1. Receive the candidate list (symbol, file, line, signature, complexity).
2. For each candidate, evaluate:
   - Does it accept untrusted input? (+0.3)
   - Is it a parser/deserializer? (+0.3)
   - High cyclomatic complexity? (+0.2)
   - No existing harness in the project? (+0.1)
   - Uses raw pointers / unsafe / FFI? (+0.1)
3. Emit a JSON array with `fit_score` (0.0-1.0) and `rationale` per candidate.
4. Sort descending by `fit_score`.

## Output format

```json
[
  {
    "symbol": "parse_value",
    "file": "src/json/parser.c",
    "line": 42,
    "kind": "Parser",
    "input_surface": "Bytes",
    "complexity": 78,
    "fit_score": 0.92,
    "rationale": "Top-level JSON parser taking raw bytes; high complexity."
  }
]
```

## Anti-patterns (reject)

- Pure formatting wrappers (e.g. `printf` wrappers).
- Functions that only read from config files.
- Functions with no input parameters.