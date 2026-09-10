# Capability acceptance checklist

Use this checklist for release qualification and product measurements. These are
acceptance criteria, not completed certifications. Record the tested commit,
target and image revisions, configuration, budgets, observed outcome, and links
to non-secret retained evidence for each result. Record unsupported operations
and failures explicitly. The [project backlog](../../TODO.md) lists prerequisites
and remaining implementation work.

Run generated harnesses and engines through `hf-runtime`, with source review and
human approval. Use dedicated environments for fault injection, kernel VMs and
physical interfaces, and approved test destinations for external publication.

## Capability checks

| Capability | Acceptance criterion |
| --- | --- |
| Installation, initialization, readiness | Clean-machine CLI/native install and provider connectivity. |
| Configuration and execution policy | Timed first setup, invalid config recovery, and parity across installed clients. |
| Project selection and target identity | Large monorepo navigation and renamed/deleted project walkthroughs. |
| C/C++ discovery and ranking | Precision/recall and top-ranked target usefulness on held-out projects. |
| Rust, Go, Python discovery | Publish and verify a language-by-operation support table; do not equate lexical discovery with an end-to-end campaign. |
| Native static analysis | Refreshed labeled-corpus accuracy and ranking benefit. |
| Semgrep enrichment | Actual image smoke and incremental engineer value beyond native analysis. |
| Build context and Build Doctor | Representative dependencies, generated headers, static libraries, and third-party project success rates. |
| AI and heuristic harness authoring | Compile success, actual target entry, repair cost, and harness-caused crash rate across projects/providers. |
| Harness review, smoke, promotion | Real bounded qualification for each userspace engine. |
| External Work Orders | Operator walkthrough from exported packet to first useful real campaign. |
| Harness tournaments | Show winner usefulness on held-out seeds, not merely its qualification score. |
| libFuzzer campaigns | Real fault rediscovery, cancellation, corpus growth, replay and minimization on pinned projects. |
| AFL++ campaigns | Actual persistent-mode throughput and crash/queue ingestion; add/review intra-target worker configuration and compare multi-core efficiency with native AFL++. |
| honggfuzz campaigns | Real wrapper compatibility, worker behavior, crash ingestion and reproducibility. |
| syzkaller campaigns | Linux/KVM qualification, VM failure recovery, kernel reproduction and minimization. Not userspace parity. |
| Progress, cancellation, run ownership | Real per-run Stop latency and container cleanup under engine failure. |
| Campaign Health and morning queue | Overnight soak with disk pressure, worker loss, restart and multiple campaigns. |
| Scheduling and portfolio rotation | Multi-day timezone/restart tests with real worker lifecycle; acknowledgement does not establish orphan termination. |
| Crash collection, deduplication, classification | Measured duplicate rate, harness-artifact discrimination and reproduction rate on real crashes. |
| Crash minimization | Actual minimized artifact preserves the same failure for each supported minimizer. |
| Historical finding review and proof cards | Cold-store and large-history task latency, including measured P95. |
| Corpus import, sharing, deduplication | Large real corpora and cross-engine compatibility with measured retention. |
| Corpus survival and reduction | Quality and cost versus native reduction. |
| Coverage tracking and unreached surface | Exact source/function coverage per run and build; do not use edge counts as function-entry evidence. |
| Coverage experiments | Useful experiments on real targets and selected-function entry evidence. |
| Dictionaries and seed generation | Branch reach gained per model dollar versus static-only seeds/dictionaries. |
| Concolic enrichment | Real solver output and incremental coverage on representative comparison barriers. |
| Oracle Studio | Actual qualification and known property violations per kind, including state reset and false-positive controls. |
| Change-aware comparisons and Patch-to-Proof | Real original/patch/reproducer chain; Windows and syzkaller unavailable for Patch-to-Proof. |
| Run closeout and recovery | Real process interruption at each step, reliable re-opening and no repeated external side effects. |
| Reports, SARIF and evidence exports | Clean recipient reproduces a selected finding using only the exported evidence and documented prerequisites. |
| GitHub/GitLab and DefectDojo | Disposable integration-server workflows including retry, dedup, auth expiry and partial failure. |
| AI assistant, providers and skills | Live provider compatibility, tool-call reliability, interruption and recoverable retained context under a fixed cost budget. |
| Automotive protocols and stateful lab | Separately scoped virtual-lab qualification; physical bench needs approved interface/target scope. Protocol novelty is not source coverage. |
| CLI/TUI, REST/SSE and native/web UI | Actual packaged application walkthroughs, keyboard efficiency, disconnect/reconnect and two concurrent sessions. |
| Storage, recoverability and diagnostics | Crash/restart/backup restore across a release migration and measured dispatch P95. |
| Sandbox and guardrails | Actual resource/network/filesystem isolation and cleanup across supported Docker platforms. No host fuzzing fallback is acceptable. |

## Evaluation method

- Separate unit, fixture, mocked-runtime, live sandbox, installed application,
  and physical-lab evidence.
- For comparisons, pin projects and versions, use equal budgets, and report
  variance, task completion, failure rates, cost, and median/P95 timings.
- Preserve exact harness attempts, run configurations, logs, and artifact
  identities. Temporary local files are not durable release evidence.
- Do not count a replay as a verified fix, aggregate edges as function entry,
  or a successful bounded run as proof that a target is safe.
