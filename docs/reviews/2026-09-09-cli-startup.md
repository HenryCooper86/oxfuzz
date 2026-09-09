# CLI startup on small process stacks

## Reproduced problem

The debug CLI aborted before printing `--version` when launched with a 1 MiB
process stack. A subprocess regression reproduced `SIGABRT` and the Rust stack
overflow message. A macOS crash trace located the overflow in Clap's generated
`Commands::augment_subcommands` / `BuildCommand::augment_subcommands` path.
This is evidence of a local portability defect; it does not by itself identify
the earlier Windows CI failure.

Boxing the asynchronous dispatcher, and then its selected futures, did not make
the regression pass. Those changes were removed. The command enum now delegates
to 33 separate `clap::Args` structs, reducing the generated argument builder's
stack usage. Draft-output flags are a flattened argument group. Command names,
flags, defaults and service calls remain the same; internal match patterns and
their existing tests follow the new structs. No stack-size override or extra
worker thread was introduced.

## Verification

The new subprocess tests cover version startup without configuration, version
startup on a 1 MiB Unix process stack, and validation of run/campaign commands
on that same small stack without creating workspace state. The existing CLI
unit, JSON-output and run-policy tests pass after the refactor.

Full workspace tests passed: 3,247 passed, zero failed, seven ignored across
180 summaries. Formatting, fixing and strict workspace Clippy, compilation,
documentation, all-target Clippy and all-target Clippy with default features
disabled passed. The frontend passed 518 tests in 72 files, production build and
bundle budgets, and lint; all 93 script tests, translation pairing, dependency
checks and domain coverage passed (91.12% aggregate line coverage).

Raw local logs are `/tmp/oxfuzz-cli-startup-*.log`. The Windows job
for the earlier admission commit was superseded before it finished; no Windows
pass is inferred from its cancellation. A completed hosted run of this fix is
still required.
