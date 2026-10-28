# Changelog

Notable user-facing changes, newest first. Entries are written when a change
lands rather than at release time: section 1 of `docs/guides/RELEASE_CHECKLIST.md`
asks the releaser to review user-facing changes, migrations, and configuration
compatibility, and this is what that review reads from.

Versions match the release commits that bump `Cargo.toml`.

## Unreleased

### Added

- The Patch-to-Proof panel offers the reviewed bug report's suggested fix as
  a one-click starting patch for the draft editor; the operator still reviews
  and can edit it before creating, approving, or running a verification.
- LLM dictionary drafts are targeted and durable: the prompt carries the
  target's own definition and the static dictionary's existing tokens, and
  each prompt and response is retained (migration 0047,
  `dictionary_llm_drafts`). Repeated runs on unchanged sources reuse the
  retained tokens without a model call.

- Crash verification is durable and evidence-based: each verification prompt
  is retained before dispatch and completed with the provider's reply
  (migration 0048, `crash_verify_drafts`), and the web/Tauri/desktop verify
  action identifies the persisted crash by project, run, and crash id. The
  REST `POST /crash/verify` request no longer accepts a client-supplied
  crash body.

## 0.8.1 - 2026-10-25

The v0.8.0 tag was never published: its Windows tests failed on the
prompt-path separator fixed below.

### Added

- Harness drafts show the model the target's own definition, read from inside
  the project, bounded, and retained before dispatch (migration 0045,
  `harness_target_sources`). Every draft path, including a plain
  `oxfuzz harness`, also carries the project's promoted harnesses.
- Smoke-failure repair: a smoke run in which the fuzzer never reached the
  harness, or the harness hung, is fed back to the model and the rewrite is
  compiled and qualified again, with a new review and human approval. Used by
  `oxfuzz fuzz` and `oxfuzz harness --repair N`; crashes are never repaired.
- `oxfuzz harness --adopt <harness-id>` recompiles a stored revision, such as
  a campaign's coverage-plateau refine proposal, as the active revision for
  normal qualification and promotion.
- `examples/honggfuzz_upstream/`: unmodified upstream honggfuzz examples
  (Apache-2.0) and reference harnesses, with `fetch-libs.sh` for the pinned
  library sources.

### Changed

- Coverage-plateau refine proposals compile in a separate proposal workspace;
  the promoted revision stays active, so the next campaign is no longer
  blocked by an unqualified revision.
- `oxfuzz run` seeds with LLM seeds when a provider is configured, with the
  heuristic seeds as fallback.
- Bug reports are drafted from the code under test: the target definition and
  the lines around the faulting line, CASR frames and crashline, and the
  harness labelled as the driver. Each prompt and response is retained
  (migration 0046, `crash_report_drafts`).

### Fixed

- honggfuzz harness prompts no longer ask for `HF_ITER`; C/C++ prompts state
  the engine rules (no harness `main`, return 0, per-input state reset for
  honggfuzz's persistent process).
- The bug-report prompt labelled the harness as target source and sent the
  dedup hash as the stack.
- The harness lint gate no longer requests a model repair after the repair
  budget is spent.
- Target-definition and crash-site prompt sections name their file with `/`
  on every host, including Windows.

## 0.7.2 - 2026-10-25

### Fixed

- CLI `harness --repair/--refine` rejects an explicit `--ai off/require`
  (those paths always use a configured model), `corpus --op llmseed/regen`
  take `--lang` instead of hardcoding C, and `run --replay` rejects
  `--duration`, `--cpus`, and an explicit `--lang` it would silently drop.
  `discover --clang` now honors Ctrl-C and a bounded wait derived from the
  analysis budget instead of polling forever.
- REST scheduler mutations (create/delete/set-enabled/concurrency) return
  503 when no scheduler is attached instead of an empty success; the
  coverage-experiment replay review maps infrastructure failures to 5xx
  instead of 400; response serialization failures return 500 instead of a
  null 200 body, and the coverage series response passes the same redaction
  as every other public endpoint. Saving providers that leave enabled
  providers unloaded reports an error, mirroring the CLI/GUI config path.
- Skills: an unreadable `root.md` is skipped with a warning instead of
  registering an empty playbook, the manifest no longer rewrites
  `max_input_tokens` to a hidden default or writes unread bookkeeping
  sections, and an agent referencing an unknown skill fails loud at prompt
  assembly instead of running without its playbook.
- Runtime: unknown sandbox architectures are rejected at the config/IPC
  boundary instead of being coerced to the host arch, a failed engine probe
  is logged and reported distinctly from "no engines", and the config no
  longer carries memory/cpu/duration/ptrace defaults the runtime never read
  (config-wide env defaults remain).
- Web auth: `/health` no longer resets the brute-force lockout window, a
  correct bearer token is now admitted even while the lockout throttles
  failing attempts, and `oxfuzz serve` fails startup on an explicitly
  configured but weak `HF_WEB_TOKEN` instead of serving every request a 401.
  A token-gated `POST /automotive/approval/mint` route (with a matching
  desktop command) mints keyed physical-bench approval evidence to feed
  `/automotive/replay`.
- Campaigns and discovery: a bare namespaced C++ symbol (`ns::Class::method`)
  now matches its file-qualified emitted selector, so `campaign --target`
  admits a harness promoted under the qualified spelling; campaign admission
  resolves the target spelling exactly like a direct run; legacy campaign
  schedules whose trigger interval differs no longer share one state
  identity; and legacy run-history crash counts dedupe per run rather than
  across runs.
- Corpus/seed provenance: seed-generation APIs report only the seeds they
  wrote (never the pre-existing inventory), first-time seeds persist with
  their `Seed` source, and an empty dead-seed set reports zero requested
  replacements.
- Issue filing: a pending dedup claim whose remote create never completed is
  reclaimed after a bounded TTL instead of wedging the key forever.
- Reports: the deterministic reproduction bullet carries the crash id, so
  identically-assessed crashes no longer suppress each other's re-injection;
  managed-mutator review rejects the same plugin-environment keys launch
  does; and enrichment treats a candidate's recorded span end as exclusive.

### Removed

- The unused prompt section/template/store subsystem of `hf-prompt` and the
  documented-but-inert prompt override format
  (`config/prompts/prompts.example.toml`); prompts are compile-time sections
  of the binary. The dead `truncate_tool_result`, `hf_discovery::rank`, and
  `render_discovery_prompt` APIs were removed with it.

## 0.7.0 - 2026-10-23

### Added

- Harness and History show retained AFL++ behavioral qualification evidence,
  including input sensitivity, repeatability, and persistent sequence checks.
  Unsupported or unavailable measurements remain explicit.
- Harness imports native C/C++ custom mutators through upstream AFL++ and
  libFuzzer APIs. New revisions retain reviewed source, sandbox image, native
  artifact identity and bounded callback observations; campaigns and retained
  replay verify the staged artifacts before loading them.
- Settings configures durable workflow call, token and USD limits. Dashboard
  shows exact usage and denials. Provider retries and streams reserve allowance
  before dispatch; restart retains unresolved charges, and Settings changes
  apply to new provider operations without restarting the application.
- Coverage experiments guide a reviewed change into an approved campaign,
  associate its run atomically, and attach the terminal comparison. Restart
  recovers abandoned admissions while preserving live process ownership and
  unsuccessful attempts.
- Prepared-source onboarding and schema-2 benchmark cohorts bind each trial to
  exact reviewed harness bytes and staged-source identity. The runner installs
  runtime spending limits and validates output identifiers and source files.

### Fixed

- Updated Tokio to 1.53.3 for the RUSTSEC-2026-0386 I/O-safety advisory.
- Crash minimization independently confirms the original and smaller input
  against the retained executable and image. Reports and proof views recompute
  observed same-failure counts; clean, changed, incomplete or intermittent
  outcomes preserve the original input and evidence.
- Optional behavioral probe runtime failures retain bounded unavailable
  evidence without hiding artifact, image, or storage failures.
- Shared translation keys reduce application JavaScript by 48 KB while
  preserving all English and Chinese text and existing locale fallbacks.
- Translation confirmations select exact repository-relative file paths,
  preserving unrelated records for documents with the same filename.

### Qualification

- Real-project effectiveness results and native-mutator benefit measurements
  remain pending manual qualification. Passing controlled tests does not supply
  those measurements. See `docs/guides/MANUAL_QUALIFICATION.md` and
  `docs/guides/MANAGED_MUTATORS.md`.

## 0.6.10 - 2026-10-23

### Fixed

- Change-review REST operations enforce approved project roots for supplied
  patches, revision inspection, and both retained runs in comparisons and
  publication requests.
- Git revision inspection disables executable diff/textconv helpers, captures
  output asynchronously with a 4 MiB ceiling, and terminates stalled children.
  The new `[git_diff].timeout_secs` setting defaults to 30 and accepts 1–300.
- Source inspection rejects special files and replacement symlinks, validates
  and reads the same open file, resolves parent components after symlinks, and
  bounds both small-file and streaming reads against admitted file size.
- Dictionary extraction uses confined, bounded source reads, preserves complete
  UTF-8 prefixes, and accounts for bytes consumed before read failures.
- Invalid provider proxy settings fail client construction instead of silently
  connecting directly. Proxy errors no longer include embedded credentials.
- PDF and DOCX export rejects images and raw HTML before tool discovery, renders
  the validated Markdown tree to HTML, and enables Pandoc's sandbox. This prevents
  local-file embedding and avoids interpreting report text as converter-specific
  YAML or TeX instructions. Markdown export retains the original source.
- UDS scans enforce event, payload, rate, and elapsed-time limits through the
  sidecar executor, validate reply sizes, and retain measured event timestamps.
  Offline packet-test fixtures use explicit synthetic addresses without routing
  lookups. Physical CAN qualification remains separate acceptance work.

## 0.6.9 - 2026-10-22

### Fixed

- Spill retention ignores directory and file symlinks instead of traversing
  linked directories and deleting unrelated files. Spill saves also reject
  symlinked root and owner directories rather than writing through them.
- OpenAI-compatible streams reassemble tool-call fragments that omit `index`,
  including repeated call IDs, without duplicating calls or losing arguments.
  Azure streaming no longer allocates an unused provider ID for every chunk.
- Recovered transcript counts now skip malformed JSONL records consistently
  with reads, so checkpoint positions do not preserve messages from a rolled-back
  turn. Reading recent messages no longer lets a torn record displace valid
  history.
- Updated Vitest to 4.1.12 to clear the development-dependency audit findings for
  [manual mock registration](https://github.com/advisories/GHSA-qxg6-89mg-rqv8)
  and [Windows redirect traversal](https://github.com/advisories/GHSA-xp26-3454-mjgp).
- Scheduler event publication no longer deadlocks store reads and execution when
  the trigger queue is full. Historical backfill reservations now consume the
  hourly admission limit, and shutdown cancels interrupted recurring admissions
  without bypassing one-time receipt handling after schedule removal.

## 0.6.8 - 2026-10-21

### Added

- Shared getting-started and Settings provider presets for DeepSeek, Kimi API
  and Coding subscriptions, and GLM API and Coding Plans on BigModel.cn and Z.AI.
  Dedicated coding endpoints, editable models, and English/Chinese credential
  guidance distinguish subscriptions from pay-as-you-go API accounts.

- Source builds enabling `clang-analysis` can explicitly collect sandboxed
  LLVM 18 declarations, call graphs, CFGs and bounded modeled path evidence.
  Current evidence is retained before harness drafting; the feature remains
  opt-in and does not weaken source review or human execution approval.

- Clang harness context now renders compactly for modeled exploration: each
  unit-qualified declaration identity is stated once behind prompt-local symbol
  indices, exact-duplicate call and branch observations are coalesced, and
  distinct guard observations are retained ahead of repeated call/CFG records.
  On the retained effectiveness cohort this reduced provider-section bytes by
  51.1% and restored the decoder trial's 32 distinct guard observations that
  repetition had previously crowded out. Graph-only context is unchanged.

### Fixed

- Coverage qualification clears cached workspace instrumentation before measuring,
  preventing earlier feature selections and counters from entering current
  reports without changing the checked-in baseline.

- Allocation-dispatch qualification now shares the workspace configuration lock
  with concurrent fixtures, keeping proposal writes and denial checks in the
  same test workspace.

- Clang analysis runs as its staged workspace owner on Unix, allowing private
  Linux input and output directories to work with capabilities dropped and
  without broadening filesystem permissions.

- Updated Vite to 7.3.7 to address the editor-launch command-injection
  advisories and restore the frontend dependency-audit gate.

- Settings now includes the Kimi and GLM provider choices previously offered
  only in setup. Saved compatible providers recover their branded selection
  from the endpoint without changing custom models or URLs.
- Changing a provider preset clears its prior credentials and headers. Browser
  saves preserve hidden credentials only when provider type and base URL are
  unchanged, preventing implicit reuse against a different service.

- Harness controls keep long qualified targets inside their selector and align
  engine, generator, and language fields at narrow panel widths. Truncated
  selections retain their full text in tooltips and the dropdown.

## 0.6.7 - 2026-10-19

### Fixed

- The command palette keeps keyboard focus inside its dialog, restores the
  opening control on dismissal, and scrolls keyboard-selected results into view.
  Change Review is included, and Enter on a tab-focused result opens that result
  rather than the separate search highlight.
- Removed obsolete browser-native file-dialog and silent report-save transport
  fallbacks. Browser path selection uses the server-path picker; unsupported
  native commands now report their absence instead of pretending to succeed.
- Settings saves persist the clicked snapshot without reloading over newer
  in-flight edits. Those edits remain visible and unsaved until the next Save.
- Provider connection-test results disappear when their configuration changes;
  late success and failure replies no longer describe an edited provider.
- Report saves preserve newer editor changes and selections while pending,
  retain the first saved ID, and exclude duplicate requests from one editor.
- FORM/RAW settings conversions no longer replace edits made while conversion
  is pending or switch the operator into a stale editor.
- Run progress is recorded against the launched project's identity, even when
  another project was previously selected or becomes active before completion.
- Browser report updates preserve the saved owner, including its original path
  spelling, unless an explicit replacement is approved. Content edits cannot
  save a redaction marker as ownership or take over a report outside approved
  project roots.
- Concurrent report saves use independent, exclusively owned staging files
  before atomic replacement; failed writes remove their own staging files.
  Public storage errors expose only the I/O category, with private paths kept
  in diagnostic logs.
- Native file dialogs and external links remain native when a desktop host uses
  the HTTP backend; report editing follows the selected backend's owner policy.
- Standalone Harness registers the project it actually qualifies or hydrates,
  preserving its project-scoped progress. Passive late replies do not restore
  removed recents, and hydration admission no longer loops on rerender.

## 0.6.6 - 2026-10-15

### Fixed

- Sandbox timeout and cancellation now stop and reap the Docker client before
  verified removal of its owned container, including a container that has been
  created but not started. An unresolved create request retains its ownership
  record and blocks further work rather than being forgotten after a delay.
- Creation acknowledgment no longer rewrites the locked recovery identity.
  Interrupted cleanup keeps recoverable ownership evidence, and a partial
  Docker ID file cannot block independently verified owned-container removal.
- Includes the seed and crash-reporting enhancements documented under 0.6.5.
  That candidate remains unpublished after live isolation qualification exposed
  the timeout cleanup defect.

## 0.6.5 - 2026-10-15

### Added

- `run`, `campaign`, and `fuzz` accept an explicit `--seed <u64>` for new
  userspace campaigns. The selected value is retained in execution inputs and
  evidence; campaign iterations reuse it, while replay preserves its original
  seed. libFuzzer rejects seeds whose low 32 bits are zero because its
  truncated value requests randomization.
  The effectiveness runner now passes each frozen trial seed and checks it
  against retained settings and exported evidence.
- Campaign evidence schema 3 includes each crash's retained origin.
  Effectiveness reports count distinct stack signatures and separate target,
  harness, runtime, unknown, and ambiguous attribution without claiming
  confirmed independent bugs. Conflicting attribution never increases the
  target count; absent timing or independent replay evidence remains
  unavailable. Older manifest schemas are refused rather than silently
  acquiring origin data.

## 0.6.4 - 2026-10-15

### Fixed

- Browser event streams close oversized incomplete responses before reconnecting,
  and delayed responses from unsubscribed connections no longer announce
  connections to replacement subscribers.
- Project deletion and knowledge clearing reject active workspace operations;
  discovery and ranking retain that protection through their final writes.
  Cleanup also removes retained AI discovery results and their prompts, without
  deleting source projects or another project's records.
- Desktop Run History clearing respects the selected project instead of clearing
  every project's runs. The unselected desktop view retains its all-projects
  operation.
- Invalid saved workflow progress no longer crashes the GUI or marks unknown
  stages complete. Superseded and unmounted confirmation dialogs cancel their
  pending callers instead of leaving them waiting indefinitely.
- Streaming run logs and health updates no longer repeatedly serialize the full
  retained-run summary when its persisted fields have not changed.
- Report and run deletion controls exclude duplicate destructive requests, and
  successful report deletion refreshes other report listings. Harness comparison
  read failures now show their cause instead of silently closing the comparison.
- Reports, triage, and automotive previews offer Markdown downloads in browser
  mode instead of advertising native-only export formats. Desktop previews retain
  the formats supported by the service.
- Saved-report DefectDojo publication resolves the stored report by ID on both
  hosts instead of sending a redacted browser project path back to the server.
  Authorization and execution use the same owner/target snapshot; editing the
  draft cannot switch projects after approval. Publication controls also exclude
  duplicate requests while an import is pending.
- Release verification waits for lazy report-preview imports before checking
  export actions, avoiding timing-dependent frontend CI failures.

## 0.6.3 - 2026-10-13

### Fixed

- Release verification isolates Semgrep workspace fixtures from concurrent tests
  that change the workspace directory. Disposable Git fixtures disable automatic
  maintenance so strict cleanup cannot race a background Git process.
- Includes the desktop approval, target identity, and submission fixes documented
  under 0.6.2; both earlier 0.6.x candidates remained unpublished.

## 0.6.2 - 2026-10-13

### Fixed

- Explicit desktop actions now pass the selected operation's approval to the
  service, including harness qualification and promotion, corpus tools, builds,
  tournaments, publication, remediation verification, and virtual CAN tools.
  Existing workflow and assistant approvals retain configured policies and deny
  guards. Smoke consent does not approve campaign promotion or unrelated actions.
- File-qualified targets keep the same harness filename and target lease through
  generation, refinement, tournament compilation, and smoke qualification.
- Work-order promotion reports policy refusals as `promotion_denied`, preserving
  the refusal reason instead of incorrectly reporting stale harness evidence.
- Human-authored work-order submissions no longer display an external-tool name
  requirement. External-tool submissions still require that provenance.

## 0.6.1 - 2026-10-13

### Added

- AFL++ persistent-mode harness flavor for stateful or slow-to-initialize
  targets. `oxfuzz harness --target <sym> --engine afl++ --persistent` drafts
  a harness that owns `main` and the forkserver loop: `__AFL_FUZZ_INIT()`
  shared-memory input, one-time setup before `__AFL_INIT()` (the deferred
  forkserver clones the post-setup state), a `while (__AFL_LOOP(N))` loop
  (N defaults to 1000, AFL++'s recommended starting point, and honors the
  `AFL_FUZZER_LOOPCOUNT` override the function-coverage proof path sets to
  100 on profiled campaigns), an explicit per-iteration reset section (the
  discipline that keeps persistent findings reproducible), and a standalone
  branch that replays each file argument once so crash replay, afl-showmap,
  and afl-cmin keep working unchanged. The build derives from the source's
  structure: a persistent source compiles with afl-clang-fast but without
  `-fsanitize=fuzzer` (its `__AFL_FUZZ_INIT()` and the libFuzzer driver both
  define `__afl_sharedmem_fuzzing` strongly and cannot link), on every
  compile surface -- CLI, GUI/REST source upload, and work-order import --
  with the wrong pairings refused with the fix named. The lint gains three
  warning-tier structural rules for persistent sources
  (`persistent-loop-without-shm-init`, `persistent-shm-init-without-loop`,
  `persistent-mutable-global`, the state-reset obligation); smoke,
  independent review, and promotion gates are unchanged. The flavor is AFL++
  + C/C++ only, opt-in per invocation with no `[fuzzing]` default, and does
  not combine with `--refine` (refinement keeps the active revision's shape).
  `oxfuzz fuzz` deliberately has no `--persistent`: the one-command pipeline
  keeps the stock driver shape. Shared-memory input needed no work: the stock
  driver build already receives it (afl-fuzz switches delivery on the
  forkserver handshake), which is why the run argv is identical for both
  shapes. See `docs/standards/HARNESS_STANDARD.md` section 7 and
  `docs/standards/ENGINE_ADAPTER_STANDARD.md` 3.8.
- Batch corpus distillation for AFL++ targets: `oxfuzz corpus --op afl-cmin`
  runs one sandboxed `afl-cmin` invocation that reduces the whole corpus to a
  minimum covering set (parallel `-T` follows the sandbox CPU ceiling, `-t`
  the configured per-input timeout, `-m none` for sanitizer builds), bounded
  by the same 10-minute budget coverage pruning gets. This is the scale tier
  next to `--op cprune`'s one-container-spawn-per-input fingerprinting (capped
  at 10,000 inputs); it is explicit and never auto-selected because the two
  reductions answer different questions. The op is spelled `afl-cmin` since
  `cmin` is already the libFuzzer `minimize` alias. The distilled tree is
  validated on the host before adoption (non-empty, every survivor
  byte-identical to a pre-run corpus entry), and a failed or garbage run
  keeps the retained corpus untouched. Requires an exact promoted,
  smoke-qualified AFL++ harness; audit goes through the existing
  corpus-operation and run-fuzzer approvals. See
  `docs/standards/ENGINE_ADAPTER_STANDARD.md` 3.7.
- AFL++ CmpLog/redqueen support for magic-byte and multi-byte comparison
  targets. `oxfuzz harness --target <sym> --engine afl++ --cmplog` builds a
  CmpLog companion binary (same source, driver, and sanitizer flags, compiled
  with `AFL_LLVM_CMPLOG=1`, written as `<main>.cmplog`) and records the build
  plus the companion's SHA-256 on the harness revision; `oxfuzz run
  --cmplog`, `campaign --cmplog`, and `fuzz --cmplog` drive it via
  `afl-fuzz -c`. An opted-in run against a companion-less (or
  digest-mismatched) revision fails before any engine starts, naming the
  build that produces the companion; `--cmplog` on a non-AFL++ engine fails
  at policy resolution. In a multi-CPU run the `-M` primary fuzzes the plain
  build and every `-S` secondary carries `-c` (per AFL++ 4.09c's multi-core
  guidance). The companion is staged into the run's retained inputs, so
  replay re-executes with the identical binary, and CmpLog runs form their
  own comparison group for auto-revert and run comparison. The run summary
  and journal note when CmpLog was active (its throughput is not comparable
  with a plain run's). There is deliberately no `[fuzzing] default_cmplog`;
  opt-in is per invocation. `AFL_CMPLOG_ONLY_NEW` and the `-l` CmpLog level
  knob are deliberately not set/emitted. See
  `docs/standards/ENGINE_ADAPTER_STANDARD.md` 3.6.
- Edge-set diff between runs. A terminal AFL++ campaign now retains its
  covered edge set — the union of AFL coverage-map offsets its run-local
  corpus exercises, replayed through `afl-showmap` against the run's exact
  staged binary under its recorded sandbox image — as an immutable 64 KiB
  bitmap (migration 0038), captured best-effort at run end and as the new
  `edge_set` closeout step. `oxfuzz runs diff <run-a> <run-b>` answers
  "run B lost which edges that run A had" with exact only/lost, gained,
  common, and union counts plus capped id samples (`--json` for the full
  capped report), and flags cross-binary diffs, where per-build edge id
  assignment makes id samples advisory. `oxfuzz runs capture-edges <run-id>`
  captures a set on demand while the run's retained corpus and binary are
  still staged; a run that already retains one is reported without
  re-measurement. libFuzzer, honggfuzz, and Rust runs carry no AFL map, so
  capture skips them with the reason named.
- Interactive CLI approval gate. On a terminal (stdin and stderr both TTYs),
  a high-risk action now prompts `[y]es/[n]o/[a]lways` -- approve once, deny,
  or allow that action kind for the rest of the process -- instead of
  requiring `HF_AUTO_APPROVE=1` exported up front. Empty, unrecognized, or
  missing input denies (fail closed); every outcome is echoed to the
  transcript and persisted in the policy audit trail. Piped/CI/headless runs
  never prompt and never block on input: they keep the environment policy
  (`HF_AUTO_APPROVE`, `HF_GUARDRAILS=permissive`), which also still approves
  without prompting on a terminal. `oxfuzz serve` is unchanged.
- Go native fuzzing engine foundation: an admission-gated `go-native`
  engine kind (valid in `enabled_engines` policy lists, never enabled by
  default), the compiled-test-binary run adapter matching the qualified
  direct-binary control, and Go native fuzzer status/failure parsing.
  The Go service workflow (harness generation, staging, build, campaigns)
  is not implemented yet; the support matrix keeps Go at discovery-only
  until that lands and is qualified.
- libFuzzer fork-mode run summaries report the campaign's aggregate
  throughput (cumulative counter over elapsed time) instead of only the
  parent's current-window rate, which dipped between child restarts;
  verified live at 2.32M execs/s where the window rate read ~0.7M.
- First live Rust cargo-fuzz campaign qualification: one complete cycle
  (sandboxed offline build via the vendored dependency, provider review,
  smoke, promotion, campaign with a 644 ms addressed Stop, and retained-input
  replay) passed on macOS arm64; see the acceptance record.
- Generated build inputs reach harness compiles. A successful configured
  build publishes the build tree's generated headers (by suffix) and the
  database-referenced generated sources alongside the compile database, and
  harness workspace staging carries them into the sandbox at their
  project-relative layout, where the database's own include flags resolve
  them. Unreferenced build-dir sources (build-system probe files with their
  own `main`) are deliberately never staged. Verified live: a Meson project
  whose target includes a `configure_file`-generated header now compiles a
  harness; previously the compile failed with a missing include.
- Meson and Autotools build profiles. A component with `meson.build` or
  autotools markers (`configure.ac`, `configure.in`, `Makefile.am`) can now
  save, diagnose, and execute a configured build profile like CMake and
  plain Make: `meson setup` writes the compile database; `autoreconf -i`,
  `./configure`, and a Bear-recorded forced Make build produce it. Both
  plans were verified live in the rebuilt sandbox image.
- AFL++ intra-target parallel fuzzing. A CPU allocation above one now runs a
  sandboxed primary/secondary coordinator (one `-M main` and N-1 `-S`
  instances sharing the run output tree); terminal statistics aggregate every
  instance's `fuzzer_stats` (throughput and saved crashes summed, edges
  maximized). Single-CPU allocations keep the previous single-instance argv.

### Changed

- The fuzzing sandbox image is now `oxfuzz/fuzz-sandbox:0.2.1` (0.2.0 added
  meson, autoconf, automake, libtool; 0.2.1 vendors `libfuzzer-sys` with a
  crates.io source replacement so cargo-fuzz harness builds resolve their
  fuzzing dependency fully offline). Rebuild it with
  `./scripts/build-sandbox.sh`; image overrides must also move to 0.2.1.
- Migration `0037_build_profile_systems.sql` widens the saved build-system
  constraint to Meson and Autotools; existing profiles keep their identities
  and digests.

### Upgrade notes and limitations

- Staged generated build inputs are part of the workspace's C/C++ build
  inputs, so run source-revision digests cover them from this version on.
  Patch-to-Proof replays of runs retained before this change may fail the
  staged-source pre-flight for projects whose build directory holds such
  files; re-run the campaign to refresh the retained digest. A working LLM
  review provider remains mandatory for harness qualification.

### Fixed

- Docker workspace mounts preserve Windows drive-letter paths and literal
  colons without rewriting matching command arguments. Mount-option delimiters
  remain rejected, quoted names remain valid, and read-only workspace
  restrictions remain enforced. AFL++ resume copies meter actual file bytes,
  refuse to overwrite destinations, and exclude NTFS alternate data streams.
- Cross-platform regression checks compare resolved config directories, use
  portable AFL session fixtures, and measure scheduler budgets with a controlled
  clock. Campaign tests directly check workspace lease ownership instead of
  imposing a machine-dependent deadline on database and filesystem work.
- GUI requests retain their project, target, and harness revision ownership:
  delayed responses cannot restore deleted project state, replace current
  artifact inventories, or approve a regenerated harness. Change-review
  publication uses the comparison the operator reviewed.
- Native startup delivers retained campaign-health events. Browser workflows
  now expose the missing coverage and known-findings routes, send the expected
  change-impact and remediation request fields, and explain desktop-only
  storage and global knowledge controls.
- Discovery and retained runs preserve the selected workspace for both unique
  and duplicate symbols. Failed coverage reads remain retryable, desktop
  artifact inventories avoid redundant scans, and corrected diagrams recover
  from rendering errors. Updated diagram dependencies resolve their reported
  security advisories.
- libFuzzer fork-mode runs no longer report phantom leaks: fork children
  misreport the forked snapshot of the parent's heap as leaked, so fork runs
  now pass `-detect_leaks=0` and set `ASAN_OPTIONS=detect_leaks=0` (an
  operator-provided `ASAN_OPTIONS` wins outright). Single-process runs keep
  leak detection on and `leak-*` artifacts remain ingested findings.
- Harness compiles no longer link the source-context copies retained under
  `runs/` in the target workspace, which duplicated every target symbol and
  failed every harness rebuild after the workspace's first campaign.
- Harness smoke qualification stays single-instance regardless of the
  operator CPU ceiling, so raising `fuzzing.sandbox.max_cpus` (which puts
  campaign libFuzzer runs into fork mode and orchestrates AFL++ instances)
  no longer changes the qualification argv or its exit-code evidence.
- Coverage-regression auto-revert fires again with
  `fuzzing.collect_function_coverage = true`. The comparability check and the
  run-history comparison key compared the persisted run environment verbatim,
  and the service injects a per-run `LLVM_PROFILE_FILE` profile destination
  into it, so no two runs ever compared equal and the policy silently never
  fired. The comparison now excludes service-assigned run-scoped environment
  destinations (and documents why the per-run seed was never part of it);
  the persisted run config keeps them verbatim.
- Discovery no longer reads as harnessable for languages without a harness
  build path. `oxfuzz discover --lang go|python` still scans and persists its
  inventory, but every candidate carries a derived `harnessable` flag and
  stderr names the supported set (`c, cpp, rust`). Harness
  draft/compile/generate/refine, `oxfuzz fuzz` target auto-selection (which
  previously could pick a Go target when the admission-gated `go-native`
  engine was enabled, failing later at the unimplemented build), and
  `oxfuzz campaign` all enforce the single `TargetLanguage::harnessable`
  predicate with one message naming the language and the supported set.

## 0.6.0 - 2026-10-07

### Added

- Intra-target parallel fuzzing through the run CPU allocation. An allocation
  above one runs libFuzzer fork mode (`-fork=N`); honggfuzz continues to map
  it to `--threads`. `oxfuzz run --cpus N` requests a per-run allocation
  validated against `fuzzing.sandbox.max_cpus`, and an omitted request keeps
  the configured allocation. AFL++ still runs a single instance per run.

### Improved

- The terminal quick start works as documented: the CLI guides now state that
  harness smoke runs and fuzzer launches read their approval consent from
  `HF_AUTO_APPROVE` / `HF_GUARDRAILS` (Safety Model, Getting Started, CLI
  Reference, both READMEs). The desktop app continues to approve through its
  dialog.
- The CLI reference documents `repro`, `arm`, `providers`, `policy`, `trust`,
  `unreached`, and `attribution`, matches the actual `agent`, `ingest`, and
  `session` signatures, and no longer lists `session list` or implies CLI
  syzkaller campaigns. `oxfuzz init` is no longer described as creating
  `.env`.
- The example PR fuzz workflow states that the CI gate requires an already
  promoted harness and its retained database/workspace state on the runner;
  it does not draft a harness.

### Upgrade notes and limitations

- A deployment that raises `fuzzing.sandbox.max_cpus` above one now runs
  libFuzzer campaigns in fork mode, which continues after crashes and exits
  at the time budget. Single-CPU allocations keep the previous
  single-process behavior and argv. Replays restore the CPU allocation
  recorded with the original run, subject to current policy ceilings.
- No persisted-format or configuration migration is required; historical run
  rows replay unchanged.

## 0.5.1 - 2026-09-15

### Improved

- Browser project selection validates an approved server directory before opening
  it. Native desktop file dialogs remain available.
- Discovery keeps ranked results available and lets users explicitly select a
  target before continuing. Harness setup puts the required steps first and
  groups specialist tools under Advanced tools.
- Setup includes API-key and model guidance. Empty findings and reports explain
  the next action, and report export options match platform capabilities.
- Keyboard labels, workflow focus, and compact help navigation improve access
  for first-time users and smaller windows.

### Fixed

- Readiness indicators now show disconnected/unknown status when the service
  stops responding and recover on reconnection. Checking status no longer
  starts Docker or prepares a sandbox implicitly.
- New project entry consistently opens the guided workflow. Browser settings
  omit unusable native-only controls and redacted-path copy actions.
- Campaign replay, run-owned coverage evidence, and schedule budget handling
  retain and validate the evidence used by each operation.
- Documentation checks skip excluded directories, and a repeatable userspace
  engine qualification runner exercises the supported deterministic fixtures.

### Upgrade notes and limitations

- Back up the runtime database and configuration before upgrading. Migration
  `0034_run_function_coverage.sql` adds retained per-run function-coverage
  evidence. Existing rows remain readable; missing evidence is unavailable,
  not zero coverage or a claim of exact historical replay.
- Browser users need an approved project path from the server administrator;
  selecting a server path does not upload a local project.
- Desktop installers remain unsigned/not notarized. Patch-to-Proof remains
  unavailable on Windows, and syzkaller needs a configured kernel/VM environment.
- Docker sandboxing, source review, and exact-revision human approval remain
  required for full campaigns.

## 0.5.0 - 2026-09-10

### Added

- Guided desktop setup with verified provider connections and readiness checks.
- Reviewed campaign replay from run history, with launch details, durable run
  tracking, and controls for interrupted runs.
- Run results linked directly to findings for the selected project and run,
  alongside retained coverage evidence and clearer comparison explanations.
- Schedule previews showing upcoming opportunities and remaining budgets.
- Reviewed project allocation quotas for campaigns and incremental refresh of
  changed knowledge entries.

### Improved

- Desktop navigation focuses on the guided campaign workflow. Workflow and
  settings modules load when needed, reducing the initial frontend bundle.
- Campaign approval, recovery, coverage errors, and small-window layouts give
  operators clearer next steps.
- Scheduling reports failed worker loops and enforces campaign allowances;
  startup failures retain recoverable state.
- Launch-time source context and starting corpus are retained with bounded
  staging and hashes computed from the captured inputs.
- Project knowledge and event subscribers are isolated so one project or slow
  subscriber does not interfere with another.
- Project documentation is reorganized, with a focused backlog and capability
  acceptance checklist.

### Fixed

- CLI startup stack overflow on small process stacks and overflowing duration
  conversions.
- Empty provider configuration and campaign requests exceeding configured limits
  now fail before execution.
- The demo promotes the exact retained harness attempt and checks readiness for
  the selected campaign before authoring.
- A clean regression replay is described as an observation rather than proof
  that a bug is fixed.
- Updated the frontend test dependencies past the Vitest mocker advisory.

### Upgrade notes and limitations

- Back up the runtime database and configuration before upgrading. This release
  adds no database migrations and retains existing configuration.
- Reviewed replay launches a new campaign using current workspace inputs. It
  does not provide exact historical reproduction. Aggregate coverage does not
  establish target-function entry by the original run.
- Build Doctor configures CMake and plain Make projects. Go/Python discovery
  does not imply complete harness support.
- Desktop downloads are unsigned. Patch-to-Proof remains unavailable on
  Windows, and syzkaller requires a separately configured kernel/VM environment.
- Docker sandboxing, source review, and human approval remain required for
  generated harness execution.

## 0.4.0 - 2026-09-08

### Added

- **Retained daily-work workflows.** The desktop app now connects external
  Harness Work Orders, exact-attempt qualification and human approval, resumable
  run closeout, historical findings, and retained coverage experiments.
- **Actionable historical findings.** The finding queue preserves exact run and
  crash selection for review, reproduction, reports, and publication.
- **Campaign Health and build readiness.** Retained cumulative telemetry,
  request-scoped run admission, isolated run output, configurable CMake/plain-Make
  profiles, and immutable build inputs support repeatable operator workflows.
- **Qualified corpus and experiment tools.** Desktop corpus import reports exact
  accounting; survival and reduction use the selected target; experiments retain
  proposals, matched settings, run references, and descriptive comparison results.
- **The approval gate now shows its evidence.** Every harness review item
  carries the qualification evidence an approval attests to: the independent
  LLM review verdict and reasons bound to the exact source and binary, the
  SHA-256 digest binding, the lexical lint findings recomputed for that exact
  source, and the smoke statistics. The GUI's human-approval step renders it
  all in one glance beside the promote action, and missing evidence is stated
  ("no independent review persisted"), never implied.
- **The 90-second CVE-pattern rediscovery demo.**
  `scripts/demo-cve-rediscovery.sh` runs the full pipeline against a
  deliberately vulnerable example target -- discovery, harness qualification,
  the human promotion gate (the script stops and waits), a bounded fuzz run,
  and triage -- ending in the rediscovery of a planted length-field-trust
  bug, the pattern behind a long line of real parser CVEs. Honest by design:
  the fixture is modeled on the CVE class, never claimed as a specific
  historical CVE. `--preflight-only` checks readiness side-effect-free.
- **External corpora can be imported.** `oxfuzz corpus import --project ...
  --target ... --from <dir>` brings an OSS-Fuzz corpus checkout (or any flat
  corpus directory) into the target's corpus: bounded, hash-deduplicated,
  content-addressed, and idempotent -- re-importing adds nothing. A source
  path that is not a regular directory fails loudly.
- **Coverage attribution ranks the whole inventory for the next harness.**
  `oxfuzz attribution <project>` attributes every discovered target against
  the union of retained coverage -- untouched, partial (the stall frontier),
  or saturated -- and orders the list untouched-first, saturated-last, with
  discovery's own order preserved inside each tier and no score rewritten.
  Saturated targets stop headlining the next-harness list even when their
  static score is the project's highest.
- **Dying seeds can now be regenerated.** `oxfuzz corpus regen <project>
  <target>` runs one bounded pass: remove the generated seeds the survival
  metric flags as dying at entry, request that many replacements from the
  provider, write them, and re-measure so the outcome reports how the
  replacements fared. Only entries in the reserved generated-seed name
  namespace (`seed_`, `llmseed_`, `regen_`) are eligible; earned inputs are
  never removed.
- **Seed survival is now measured.** `oxfuzz corpus survival <project>
  <target>` runs each corpus seed once through `afl-showmap` on the promoted
  AFL++ harness and classifies it against the empty input's edge coverage:
  seeds that reach past the harness's entry validation, seeds that die at it
  (the most common reason a seed corpus finds nothing), and seeds that could
  not be measured are counted separately, with a survival ratio. Read-only
  and advisory: it tells the operator which seeds to regenerate.
- **Harness drafts learn from accepted harnesses.** The draft prompt is
  conditioned on the project's previously promoted harnesses (accepted
  examples): house style, entry-point shape, and working include paths, read
  from the persisted harness records -- at most two, same language as the
  target, each source bounded. Projects without promotions draft exactly as
  before.
- **Harness lint now covers Rust and Python harnesses.** Lexical rules are
  scoped per language: Rust (cargo-fuzz) harnesses are checked for
  `std::process::exit`, `Command::new`, `thread::sleep`, socket use, and
  `catch_unwind`; Python (Atheris) harnesses for `sys.exit`, `subprocess`,
  `time.sleep`, socket use, `random`, and bare `except:`. Go still returns no
  findings (unchecked rather than clean). Harness Work Order packets now carry
  exactly the rules that apply to the target's language instead of the C table
  for every language.
- **Repair prompts now receive summarized compiler diagnostics.** Distinct
  diagnostic lines (clang/GCC and rustc formats) are extracted, deduplicated,
  and bounded before reaching the model, instead of a raw head-truncated dump
  that could spend the whole budget on build noise before the first error.
- **A coverage gate measures the TEST_STRATEGY targets.** `scripts/tests/gates.sh
  coverage` reports per-crate line coverage for the four domain crates via
  cargo-llvm-cov, and CI records it on every push; thresholds are not enforced
  until a trusted baseline exists.

### Changed

- Cross-revision findings and coverage comparisons now explicitly distinguish
  observations from causal claims and require matched retained settings.
- Finding queues resolve latest-run evidence in batches. File-qualified target
  identity is preserved through Work Orders, campaigns, findings, reproduction
  bundles, corpus actions, and evidence deletion.
- Selected SQLite writes acquire immediate write intent to avoid deferred
  transaction upgrade failures under contention.
- Windows Work Order export binds reads to the selected project root; native
  manifest and build-path handling corrections are included.
- Corrected stale documentation references: the repository layout no longer
  lists nonexistent `config/agents/` and `skills/` directories, the harness
  prompt template location now names the real renderer, and the design
  overview's dead "y-agent" rows name their actual owners.

## 0.3.0 - 2026-08-31

### Added

- **Native C/C++ analysis now complements optional Semgrep enrichment.** The
  bounded tree-sitter analyzer reports deterministic memory, lifetime,
  arithmetic, and dangerous-API signals, with measured benchmark recall and
  no observed false positives on the retained evaluation corpus.
- **Harness generation now consumes real project build context.** Nested C/C++
  sources retain their layout, compile databases supply allowlisted include
  paths, definitions, and language standards, generated source is linted
  before sandbox compilation, and crash reports distinguish harness defects
  from target findings.
- **Bounded concolic corpus enrichment is available through CLI and REST.**
  SymCC with the QSym backend runs only through the sandbox, enforces input and
  time limits, and promotes solver-produced inputs only when their content is
  novel.
- **Harness Work Order v2 provides durable provider-free authoring.** Operators
  can export content-addressed target evidence, import immutable external
  candidates, qualify them through sandbox compile, independent review, and
  smoke stages, rank retained attempts, and explicitly promote one exact
  qualified revision.
- **Evidence-backed professional workflows cover the campaign lifecycle.**
  Finding proof cards, sandboxed patch verification, change-aware comparison,
  build diagnosis, non-crash oracles, coverage-blocker ranking, crash
  disposition, campaign trust and health, unreached-surface reporting, and
  resumable run closeout are available through service-owned operations.
- **Automotive workflows now include responder modeling, state-sequence
  planning, state coverage, and approved state-corpus promotion** across CLI,
  REST, and desktop surfaces.
- **Syzkaller campaigns persist runs and ingest kernel crash evidence** through
  the existing sandboxed campaign and triage path.

### Changed

- Existing SQLite stores migrate automatically on first open. Work-order,
  campaign-evidence, automotive, and run-closeout records are retained as
  durable service evidence.

- **The campaign scheduler starts disarmed, and missed occurrences are held
  until it is armed.** A schedule with a `catch_up` or `backfill` missed policy
  used to replay everything it missed as soon as the process came back up.
  Recovery still restores that work, but it now waits for an explicit decision:
  `POST /schedule/arm`, or `oxfuzz arm` for a headless server (`--status` to
  check, `--off` to withdraw). A restart on its own is no longer treated as
  consent to resume a campaign that may be hours stale and pointed at a project
  which has changed in the meantime.

  **If you rely on catch-up firing automatically after a restart, you must now
  arm the server.** Nothing fires until you do, and held work is discarded on
  shutdown.

- **Oversized tool results are written to disk and replaced with a preview plus
  a locator**, instead of being truncated to a head and tail with the middle
  discarded. Artifacts live under the app's private state directory beside the
  run journal, not in your project. The store bounds itself at roughly 256 MiB,
  evicting the oldest artifacts as new ones arrive.

### Security

- **Windows Harness Work Order exports now use handle-relative project reads.**
  Ordinary project files work on Windows while link-like parent and leaf
  components remain rejected; source metadata, size validation, and bounded
  reads use one opened handle.

  **Known Windows limitation:** the project-root pathname is reopened after
  canonicalization. Another local process that can rename that selected root
  and create a directory junction in its parent could redirect the confined
  read. Until root-handle hardening lands, keep the selected project parent
  trusted and immutable during export, or avoid Harness Work Order export on
  Windows.

- **Patch-to-Proof is unavailable on Windows in this release.** The service
  fails closed before creating a remediation draft because secure
  handle-relative reads of retained crash evidence are not implemented there.
  Use Patch-to-Proof on Linux or macOS; Windows does not fall back to a
  canonicalize-then-open read.

- **Processes oxfuzz spawns on the host no longer inherit its environment.**
  The `docker` CLI, `git`, `pandoc`, the DefectDojo lifecycle commands, and the
  daemon-start helpers now start from a scrubbed copy: variables whose names
  contain `KEY`, `SECRET`, `TOKEN`, or `PASSWORD`, plus everything prefixed
  `HF_`, are dropped. `PATH`, `HOME`, locale, and proxy settings survive. If a
  helper on your system needed one of the dropped variables, it will no longer
  see it.
