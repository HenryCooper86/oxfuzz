# crash-triage

Classify a crash and draft a bug report.

## When to use

- After a fuzz run produces crash artifacts.
- When the user asks "triage this crash".

## Procedure

1. Read the sanitizer log (ASan / UBSan / MSan / TSan) or engine log.
2. Identify the crash kind:
   - heap-buffer-overflow -> `Asan`
   - stack-buffer-overflow -> `Asan`
   - use-after-free -> `Asan`
   - integer-overflow -> `Ubsan`
   - SIGSEGV -> `Segv`
   - SIGABRT -> `Abort`
   - timeout -> `Timeout`
3. Extract the top-N stack frames; compute a stack signature (sha256 of
   top-3 frames).
4. Read the minimized crash input.
5. Draft a bug report:
   - title: concise, e.g. "heap-buffer-overflow in parse_value"
   - summary: 1-2 sentences.
   - repro_steps: build flags + fuzzer invocation + crash input path.
   - stack: top frames.
   - severity_guess: one of {low, medium, high, critical} with justification.

## Output format

```json
{
  "title": "heap-buffer-overflow in parse_value",
  "summary": "parse_value reads past buffer end on truncated UTF-8.",
  "repro_steps": "...",
  "stack": "...",
  "severity_guess": "high"
}
```

## Rules

- Do not exaggerate severity. If uncertain, say "uncertain" in the summary.
- Never auto-publish; HITL gate is mandatory.