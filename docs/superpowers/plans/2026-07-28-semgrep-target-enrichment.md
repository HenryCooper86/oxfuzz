# Semgrep Target Enrichment Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add explicit, sandboxed Semgrep enrichment for persisted C/C++ target inventories, using a pinned `0xdea/semgrep-rules` snapshot to apply deterministic score overlays without changing base discovery scores.

**Architecture:** `hf-discovery` parses, validates, maps, and scores Semgrep JSON as pure domain logic. `hf-service` owns bounded source snapshots, the typed runtime request, asynchronous lifecycle, recovery, atomic publication, stale-overlay checks, and effective-ranking DTOs; `hf-storage` supplies the three-table transaction boundary, while CLI, REST, Tauri, and React remain thin transports. Semgrep and its bundled rules execute only in the existing Docker sandbox through `RuntimeAdapter`.

**Tech Stack:** Rust 2021, Tokio, serde/serde_json, SHA-256 (`sha2`), SQLx/SQLite, tree-sitter C/C++, `ignore`, Docker, Semgrep CE `1.169.0`, `0xdea/semgrep-rules` commit `4d66ecf30bfb1809a984085f2c86a8c3915bfc71`, Axum, Clap, Tauri 2, React 19, TypeScript, Vitest.

## Global Constraints

- The approved design is `docs/superpowers/specs/2026-07-28-semgrep-target-enrichment-design.md`; update it first if implementation proves a requirement impractical.
- The first release supports only `TargetLanguage::C` and `TargetLanguage::Cpp`.
- Normal discovery never starts Semgrep. Every scan starts from an explicit CLI, REST, or GUI request.
- `semgrep-enrichment` is enabled by default in normal product crates and removed by `--no-default-features`.
- Semgrep is not an agent tool or scheduler action. Existing ranking consumers may use a previously completed, current overlay but may not start a scan.
- Pin Semgrep CE to `1.169.0` and rules to commit `4d66ecf30bfb1809a984085f2c86a8c3915bfc71`, limited to `rules/c`.
- The sandbox is offline, capability-free, `no-new-privileges`, 2 CPUs, 4 GiB RAM, 128 PIDs, 10 minutes, and a 64 MiB output-file ceiling.
- Snapshot limits are 25,000 files, 2 MiB per file, 512 MiB aggregate bytes, and 4,096 bytes per normalized relative path.
- Result limits are 50,000 findings, 512 bytes per rule identifier, and 4,096 bytes per message.
- Score weights are Error `0.10`, Warning `0.05`, and Info `0.01`; deduplicate by `(candidate_id, rule_id)`, cap the Semgrep boost at `0.20`, and cap effective score at `1.0`.
- Never mutate `TargetCandidate.fit_score`; it remains the base score.
- Any staging, execution, validation, mapping, revision, persistence,
  confirmed journal, or cleanup failure is atomic and publishes no findings or
  score overlay. An indeterminate terminal journal append remains invisible
  until restart replay proves a successful close or triggers repair.
- A live scan owns the shared workspace lease before its first database or
  journal write and retains it through terminal journal persistence. Recovery
  owns the matching exclusive lease and never inspects a journal when that
  lease is unavailable.
- One project owns an exclusive cross-process lease through cleanup and close.
  A database `done` row is exposed as `persisting` until successful journal
  closure is verifiable.
- Persistent journal transactions use a securely descriptor-opened advisory
  lock. The lock order is workspace lease -> project lease -> journal lock ->
  database transaction.
- No raw snippets, metavariables, upstream fingerprints, credentials, absolute host paths, or arbitrary Semgrep JSON are persisted or returned.
- No generated harness or real fuzzer is run on the host. Normal tests use fake/recording runtimes; the real Semgrep smoke gate runs only inside Docker.
- All Rust production changes follow Red -> Green -> Refactor and contain no inline lint suppression.
- Every `cargo test` command in this plan uses the repository-mandated filtered output form.
- Execute shell blocks containing a `cargo test` pipeline with `set -o pipefail` enabled. Wrap the filter as `{ grep -v '…' || true; }` so an empty clean-output stream succeeds while Cargo failures still propagate through the pipeline.
- Each task ends in one English commit containing only that task's concern.

## File and Interface Map

| Area | Files | Responsibility |
| --- | --- | --- |
| Design alignment | `docs/design/DESIGN_OVERVIEW.md`, `docs/design/target-discovery-design.md`, `docs/design/runtime-design.md`, `docs/design/service-orchestration-design.md`, `docs/standards/DATABASE_SCHEMA.md` | Make the approved Semgrep contract part of the canonical architecture before production code changes. |
| Core spans | `crates/hf-core/src/target.rs`, `crates/hf-discovery/src/scanner.rs`, `crates/hf-discovery/src/reachability.rs` | Backward-compatible end coordinates and complete C/C++ function spans. |
| Pure Semgrep domain | `crates/hf-discovery/src/semgrep.rs`, `crates/hf-discovery/tests/fixtures/semgrep/*.json` | Strict JSON normalization, fingerprints, mapping, deduplication, scoring, and deterministic ordering inputs. |
| Runtime profile | `crates/hf-core/src/runtime.rs`, `crates/hf-runtime/src/docker.rs` | Per-operation PIDs tightening in the existing structured sandbox options. |
| Bundled toolchain | `third_party/semgrep-rules/**`, `docker/sandbox/semgrep/scan.sh`, `scripts/update-semgrep-rules.sh`, `scripts/semgrep-tree-digest.py`, `docker/sandbox/Dockerfile`, `scripts/build-sandbox.sh` | Reviewed rule snapshot, license provenance, fixed command wrapper, image build verification, and container-only smoke gate. |
| Storage | `crates/hf-storage/migrations/0022_semgrep_enrichment.sql`, `crates/hf-storage/src/store.rs`, `crates/hf-storage/src/lib.rs`, `crates/hf-storage/tests/store.rs` | Durable operation records, findings, scores, atomic publish/compensation, and latest-overlay reads. |
| Recovery | `crates/hf-service/src/semgrep_recovery.rs` | Cross-process-locked, synced per-operation JSONL journal with open, ready-to-commit, successful-close, and terminal-abort records. |
| Service | `crates/hf-service/src/semgrep.rs`, `crates/hf-service/src/container.rs`, `crates/hf-service/src/lib.rs`, `crates/hf-service/src/agent.rs`, `crates/hf-service/src/scheduler.rs`, `crates/hf-service/src/workbench.rs` | Admission, staging, runtime invocation, cancellation, atomic completion, recovery, staleness, DTOs, and all effective-ranking consumers. |
| Feature wiring | `crates/hf-discovery/Cargo.toml`, `crates/hf-service/Cargo.toml`, `crates/hf-cli/Cargo.toml`, `crates/hf-web/Cargo.toml`, `crates/hf-gui/src-tauri/Cargo.toml` | Compile-time inclusion in normal products and exclusion from no-default builds. |
| Presentations | `crates/hf-cli/src/main.rs`, `crates/hf-web/src/router.rs`, `crates/hf-web/tests/api.rs`, `crates/hf-gui/src-tauri/src/commands.rs`, `crates/hf-gui/src-tauri/src/lib.rs`, `crates/hf-gui/src/lib/httpTransport.ts`, `crates/hf-gui/src/types/index.ts`, `crates/hf-gui/src/views/DiscoverView.tsx` | Explicit start/status/cancel/result transport and advisory rendering without scoring logic. |
| Release/docs | `scripts/test-semgrep-sandbox.sh`, `scripts/build-release.sh`, `docs/guides/GETTING_STARTED.md`, `docs/guides/RELEASE_CHECKLIST.md`, `README.md` | Operator instructions, licensing, and reproducible release verification. |

---

### Task 1: Align the Canonical Design Documents

**Files:**
- Modify: `docs/design/DESIGN_OVERVIEW.md`
- Modify: `docs/design/target-discovery-design.md`
- Modify: `docs/design/runtime-design.md`
- Modify: `docs/design/service-orchestration-design.md`
- Modify: `docs/standards/DATABASE_SCHEMA.md`

**Interfaces:**
- Consumes: the approved design specification named in Global Constraints.
- Produces: canonical ownership, flow, failure, and schema text that every implementation task must follow.

- [ ] **Step 1: Add a failing documentation-contract check**

Run:

```bash
for file in \
  docs/design/DESIGN_OVERVIEW.md \
  docs/design/target-discovery-design.md \
  docs/design/runtime-design.md \
  docs/design/service-orchestration-design.md \
  docs/standards/DATABASE_SCHEMA.md
do
  rg -q 'Semgrep' "$file" || { echo "missing Semgrep contract: $file"; exit 1; }
done
```

Expected: FAIL on the first canonical document that does not mention Semgrep.

- [ ] **Step 2: Add the exact architecture contract**

Add this ownership row to the `DESIGN_OVERVIEW.md` alignment table:

```markdown
| Semgrep target enrichment | hf-discovery + hf-service | `SemgrepFinding`, `SemgrepTargetScore`, `SemgrepInventoryView` | target-discovery-design.md + service-orchestration-design.md |
```

Document these points in the owning files:

```text
target-discovery-design.md:
  optional C/C++ function end spans; pure Semgrep normalization/mapping/scoring;
  base scores remain immutable; Error/Warning/Info weights and both caps.

runtime-design.md:
  fixed in-image wrapper; local bundled rules only; no network; read-only source;
  writable bounded output; 2 CPUs/4 GiB/128 PIDs/600 seconds/64 MiB fsize.

service-orchestration-design.md:
  explicit asynchronous start/status/cancel/result; one active scan per project;
  source snapshot bounds; WAL open -> ready_to_commit -> DB publish -> WAL close;
  compensation and startup recovery; current/stale effective-inventory rules.

DATABASE_SCHEMA.md:
  migration 0022 and all columns, checks, foreign keys, indexes, atomic success
  transaction, failed/cancelled child-row prohibition, and project deletion order.
```

- [ ] **Step 3: Re-run the documentation-contract check**

Run the command from Step 1.

Expected: PASS with no output.

- [ ] **Step 4: Review terminology**

Run:

```bash
rg -n -i 'confirmed vulnerability|confirmed crash|CVE Binary Tool|registry rules' \
  docs/design docs/standards/DATABASE_SCHEMA.md
```

Expected: no new text describes Semgrep findings as confirmed vulnerabilities/crashes, no CVE Binary Tool scope is introduced, and any registry-rules occurrence says registry access is forbidden.

- [ ] **Step 5: Commit**

```bash
git add docs/design/DESIGN_OVERVIEW.md docs/design/target-discovery-design.md \
  docs/design/runtime-design.md docs/design/service-orchestration-design.md \
  docs/standards/DATABASE_SCHEMA.md
git commit -m "docs: align Semgrep enrichment architecture"
```

---

### Task 2: Add Backward-Compatible Function End Spans

**Files:**
- Modify: `crates/hf-core/src/target.rs`
- Modify: `crates/hf-discovery/src/scanner.rs`
- Modify: `crates/hf-discovery/src/reachability.rs`
- Test: `crates/hf-core/src/target.rs`
- Test: `crates/hf-discovery/src/scanner.rs`

**Interfaces:**
- Consumes: existing `SourceLocation`, tree-sitter `function_definition` nodes.
- Produces:

```rust
pub struct SourceLocation {
    pub file: PathBuf,
    pub line: u32,
    pub col: u32,
    #[serde(default)]
    pub end_line: Option<u32>,
    #[serde(default)]
    pub end_col: Option<u32>,
}
```

- [ ] **Step 1: Write the failing compatibility and C-span tests**

Add these assertions:

```rust
#[test]
fn source_location_reads_legacy_json_without_end_coordinates() {
    let location: SourceLocation =
        serde_json::from_str(r#"{"file":"src/parser.c","line":4,"col":1}"#).unwrap();
    assert_eq!(location.end_line, None);
    assert_eq!(location.end_col, None);
}

#[test]
fn c_candidate_span_covers_the_complete_definition() {
    let candidates = c_candidates(
        "int parse_packet(const unsigned char *data) {\n\
             if (data[0]) { return 1; }\n\
             return 0;\n\
         }\n",
    );
    let span = &candidates[0].location;
    assert_eq!((span.line, span.col), (1, 1));
    assert_eq!((span.end_line, span.end_col), (Some(4), Some(2)));
}
```

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```bash
cargo test -p hf-core source_location_reads_legacy_json_without_end_coordinates 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-discovery c_candidate_span_covers_the_complete_definition 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because the end fields do not exist and the C scanner records only the identifier start.

- [ ] **Step 3: Implement the span fields and populate every constructor**

For C/C++, use the function node, not the identifier node:

```rust
let start = node.start_position();
let end = node.end_position();
let location = SourceLocation {
    file: path.to_path_buf(),
    line: u32::try_from(start.row + 1).unwrap_or(u32::MAX),
    col: u32::try_from(start.column + 1).unwrap_or(u32::MAX),
    end_line: Some(u32::try_from(end.row + 1).unwrap_or(u32::MAX)),
    end_col: Some(u32::try_from(end.column + 1).unwrap_or(u32::MAX)),
};
```

Set `end_line: None, end_col: None` in Rust, Go, Python, reachability, core, service, knowledge, and test constructors. Do not synthesize incomplete lexical-language spans.

- [ ] **Step 4: Run the crate tests**

Run:

```bash
cargo test -p hf-core 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-discovery 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-core/src/target.rs crates/hf-discovery/src/scanner.rs \
  crates/hf-discovery/src/reachability.rs crates/hf-service/src/container.rs \
  crates/hf-service/src/knowledge.rs
git commit -m "feat: record complete C and C++ target spans"
```

---

### Task 3: Add Feature Gates and Strict Semgrep JSON Normalization

**Files:**
- Modify: `crates/hf-discovery/Cargo.toml`
- Modify: `crates/hf-discovery/src/lib.rs`
- Create: `crates/hf-discovery/src/semgrep.rs`
- Create: `crates/hf-discovery/tests/fixtures/semgrep/valid.json`
- Create: `crates/hf-discovery/tests/fixtures/semgrep/unknown_severity.json`
- Create: `crates/hf-discovery/tests/fixtures/semgrep/skipped.json`
- Create: `crates/hf-discovery/tests/fixtures/semgrep/errors.json`

**Interfaces:**
- Consumes: Semgrep CE JSON bytes and the staged normalized path manifest.
- Produces:

```rust
pub const MAX_FINDINGS: usize = 50_000;
pub const MAX_RULE_ID_BYTES: usize = 512;
pub const MAX_MESSAGE_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SemgrepSeverity { Info, Warning, Error }

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemgrepRange {
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepFinding {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: SemgrepSeverity,
    pub message: String,
    pub relative_path: PathBuf,
    pub range: SemgrepRange,
    pub matched_target_id: Option<Uuid>,
    pub nominal_weight: f64,
}

#[derive(Debug, thiserror::Error)]
pub enum SemgrepValidationError {
    #[error("invalid Semgrep JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unsupported Semgrep output version: {0}")]
    UnsupportedVersion(String),
    #[error("Semgrep analysis is incomplete: {0}")]
    Incomplete(String),
    #[error("Semgrep result limit exceeded: {0}")]
    Limit(String),
    #[error("unsafe Semgrep finding: {0}")]
    UnsafeFinding(String),
    #[error("Semgrep finding fingerprint collision: {0}")]
    FingerprintCollision(String),
}

pub fn parse_findings(
    bytes: &[u8],
    staged_paths: &BTreeSet<PathBuf>,
) -> Result<Vec<SemgrepFinding>, SemgrepValidationError>;
```

- [ ] **Step 1: Add the feature and failing parser tests**

Use this feature boundary:

```toml
[features]
default = []
semgrep-enrichment = []
```

Expose only:

```rust
#[cfg(feature = "semgrep-enrichment")]
pub mod semgrep;
```

Tests must cover valid Error/Warning/Info normalization; malformed JSON; missing `results`, `errors`, or `paths`; unknown severity; zero/reversed coordinates; absolute and `..` paths; paths absent from the manifest; non-empty `errors`; non-empty `paths.skipped`; rule/message byte limits; more than 50,000 findings; identical duplicates; and a forced fingerprint collision with different normalized content.

The valid fixture shape is:

```json
{
  "version": "1.169.0",
  "results": [{
    "check_id": "c.lang.security.audit.dangerous-function-usage",
    "path": "src/parser.c",
    "start": {"line": 8, "col": 5, "offset": 90},
    "end": {"line": 8, "col": 17, "offset": 102},
    "extra": {"message": "dangerous copy", "severity": "ERROR"}
  }],
  "errors": [],
  "paths": {"scanned": ["src/parser.c"], "skipped": []}
}
```

- [ ] **Step 2: Run the parser tests and verify red**

Run:

```bash
cargo test -p hf-discovery --features semgrep-enrichment semgrep::tests::parse_ 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because `hf_discovery::semgrep` does not exist.

- [ ] **Step 3: Implement strict raw DTOs and normalization**

Deserialize only the required supported fields:

```rust
#[derive(Deserialize)]
struct RawOutput {
    version: String,
    results: Vec<RawResult>,
    errors: Vec<serde_json::Value>,
    paths: RawPaths,
}

#[derive(Deserialize)]
struct RawResult {
    check_id: String,
    path: String,
    start: RawPosition,
    end: RawPosition,
    extra: RawExtra,
}

#[derive(Deserialize)]
struct RawPosition { line: u32, col: u32 }

#[derive(Deserialize)]
struct RawExtra { message: String, severity: String }

#[derive(Deserialize)]
struct RawPaths {
    scanned: Vec<String>,
    skipped: Vec<serde_json::Value>,
}
```

Require `version == "1.169.0"`, empty errors/skips, safe normalized relative paths, positive ordered ranges, staged-manifest membership, exact equality between normalized `paths.scanned` and the staged manifest, and exact byte ceilings. Normalization accepts only an optional leading `./`, converts platform separators to `/`, and rejects absolute paths, prefixes, empty components, `.` elsewhere, and `..`; the fixed wrapper runs from `/work/source`, so no host or container-root prefix is accepted. Ignore unknown JSON fields for forward-compatible telemetry, but never persist them.

Use one canonical length-prefix helper:

```rust
fn hash_field(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(value);
}
```

Fingerprint with a leading `0x01` byte, then length-prefixed rule id, lowercase severity, slash-normalized path, each coordinate as four big-endian bytes, and message. Deduplicate identical fingerprints. Maintain a `HashMap<String, SemgrepFinding>` and fail if an occupied fingerprint differs; exercise that branch through a private `parse_findings_with_fingerprint` test helper.

- [ ] **Step 4: Run feature-on and feature-off checks**

Run:

```bash
cargo test -p hf-discovery --features semgrep-enrichment semgrep::tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo check -p hf-discovery --no-default-features
```

Expected: tests PASS and the feature-off crate compiles without the Semgrep module.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-discovery/Cargo.toml crates/hf-discovery/src/lib.rs \
  crates/hf-discovery/src/semgrep.rs crates/hf-discovery/tests/fixtures/semgrep
git commit -m "feat: normalize bounded Semgrep findings"
```

---

### Task 4: Map Findings and Calculate Deterministic Score Overlays

**Files:**
- Modify: `crates/hf-discovery/src/semgrep.rs`

**Interfaces:**
- Consumes: `TargetInventory`, normalized `Vec<SemgrepFinding>`.
- Produces:

```rust
#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepTargetScore {
    pub target_id: Uuid,
    pub base_score: f64,
    pub boost: f64,
    pub effective_score: f64,
    pub matched_rule_count: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SemgrepAnalysis {
    pub findings: Vec<SemgrepFinding>,
    pub scores: Vec<SemgrepTargetScore>,
    pub matched_candidate_count: u32,
}

pub fn map_and_score(
    inventory: &TargetInventory,
    findings: Vec<SemgrepFinding>,
) -> Result<SemgrepAnalysis, SemgrepValidationError>;
```

- [ ] **Step 1: Write failing mapping and scoring tests**

Create candidates in one file whose spans prove all boundary cases. Tests must assert:

```rust
assert_eq!(analysis.findings[0].matched_target_id, Some(parse_packet_id));
assert_eq!(analysis.findings[file_level].matched_target_id, None);
assert_eq!(analysis.findings[ambiguous].matched_target_id, None);
assert_eq!(score.matched_rule_count, 3);
assert_eq!(score.boost, 0.16); // Error + Warning + Info
assert_eq!(capped.boost, 0.20);
assert_eq!(ceiling.effective_score, 1.0);
```

Also prove:

- exact normalized relative-path equality is required;
- a finding start coordinate at the candidate start/end is contained;
- incomplete spans make the inventory ineligible;
- repeated locations for one rule count once;
- one rule with multiple severities uses the highest severity;
- every candidate receives a score row, including zero-boost candidates;
- repeated calls start from `fit_score`, never a prior effective score; and
- score output is sorted by target UUID for deterministic persistence.

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```bash
cargo test -p hf-discovery --features semgrep-enrichment semgrep::tests::map_ 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-discovery --features semgrep-enrichment semgrep::tests::score_ 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because mapping/scoring interfaces do not exist.

- [ ] **Step 3: Implement unique containment and capped scoring**

Use lexicographic coordinate comparison:

```rust
fn contains_start(candidate: &TargetCandidate, finding: &SemgrepFinding) -> bool {
    let Some(end_line) = candidate.location.end_line else { return false };
    let Some(end_col) = candidate.location.end_col else { return false };
    let start = (candidate.location.line, candidate.location.col);
    let end = (end_line, end_col);
    let point = (finding.range.start_line, finding.range.start_col);
    start <= point && point <= end
}
```

Map only if exactly one same-path candidate contains the point. Aggregate a `BTreeMap<(Uuid, String), SemgrepSeverity>`, retaining the maximum severity, then compute:

```rust
let boost = rule_severities
    .values()
    .map(|severity| severity.weight())
    .sum::<f64>()
    .min(0.20);
let effective_score = (candidate.fit_score + boost).min(1.0);
```

Reject non-C/C++ candidates, mixed project roots, any incomplete candidate span, non-finite/out-of-range base scores, and duplicate candidate IDs.

- [ ] **Step 4: Run all discovery tests**

Run:

```bash
cargo test -p hf-discovery --features semgrep-enrichment 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-discovery/src/semgrep.rs
git commit -m "feat: map Semgrep signals to capped target scores"
```

---

### Task 5: Allow a Specialized Runtime Profile to Tighten the PID Limit

**Files:**
- Modify: `crates/hf-core/src/runtime.rs`
- Modify: `crates/hf-runtime/src/docker.rs`

**Interfaces:**
- Consumes: `RuntimeConfig.max_pids`, existing `SandboxOptions`.
- Produces:

```rust
pub struct SandboxOptions {
    // existing fields
    pub max_pids: Option<u32>,
}
```

`Some(n)` is valid only for `1 <= n <= RuntimeConfig.max_pids`; it is a tighten-only override.

- [ ] **Step 1: Write failing Docker-argument and validation tests**

```rust
#[test]
fn specialized_profile_can_tighten_but_not_expand_pid_limit() {
    let cfg = RuntimeConfig { max_pids: 512, ..RuntimeConfig::default() };
    let opts = SandboxOptions { max_pids: Some(128), ..SandboxOptions::default() };
    let args = build_exec_args_with(&cfg, &ResourceLimits::default(), &["true".into()], &opts);
    assert!(args.contains(&"--pids-limit=128".to_owned()));
}
```

Add validation cases for `Some(0)` and `Some(513)` returning `ClassifiedError::Sandbox`.

- [ ] **Step 2: Run the focused test and verify red**

Run:

```bash
cargo test -p hf-runtime specialized_profile_can_tighten_but_not_expand_pid_limit 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because `SandboxOptions.max_pids` does not exist.

- [ ] **Step 3: Implement the tighten-only override**

In option validation:

```rust
if let Some(max_pids) = opts.max_pids {
    if max_pids == 0 || max_pids > self.cfg.max_pids {
        return Err(ClassifiedError::Sandbox(format!(
            "sandbox PID limit must be between 1 and {}",
            self.cfg.max_pids
        )));
    }
}
```

In Docker argument construction:

```rust
args.push(format!(
    "--pids-limit={}",
    opts.max_pids.unwrap_or(cfg.max_pids)
));
```

Update every explicit `SandboxOptions` literal with `..SandboxOptions::default()` or `max_pids: None`.

- [ ] **Step 4: Run runtime tests**

Run:

```bash
cargo test -p hf-runtime 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-core/src/runtime.rs crates/hf-runtime/src/docker.rs
git commit -m "feat: support tighten-only sandbox PID limits"
```

---

### Task 6: Vendor and Verify the Pinned Rules and Semgrep CLI

**Files:**
- Create: `third_party/semgrep-rules/COMMIT`
- Create: `third_party/semgrep-rules/RULES_SHA256`
- Create: `third_party/semgrep-rules/LICENSE`
- Create: `third_party/semgrep-rules/UPSTREAM.md`
- Create: `third_party/semgrep-rules/rules/c/**`
- Create: `third_party/semgrep/LICENSE`
- Create: `third_party/semgrep/UPSTREAM.md`
- Create: `scripts/semgrep-tree-digest.py`
- Create: `scripts/update-semgrep-rules.sh`
- Create: `docker/sandbox/semgrep/scan.sh`
- Create: `docker/sandbox/semgrep/fixtures/vulnerable.c`
- Create: `docker/sandbox/semgrep/fixtures/clean.c`
- Modify: `docker/sandbox/Dockerfile`
- Modify: `scripts/build-sandbox.sh`

**Interfaces:**
- Consumes: exact upstream commit and Semgrep version from Global Constraints.
- Produces:
  - `/opt/oxfuzz/semgrep-rules/rules/c` in the sandbox image;
  - `/usr/local/bin/oxfuzz-semgrep-scan`, which accepts no arguments;
  - `/work/output/semgrep.json`;
  - committed `RULES_SHA256` using 8-byte big-endian path length + path bytes + 8-byte big-endian file length + file bytes, in lexicographic path order.

- [ ] **Step 1: Write the failing repository provenance check**

Run:

```bash
test "$(cat third_party/semgrep-rules/COMMIT 2>/dev/null)" = \
  "4d66ecf30bfb1809a984085f2c86a8c3915bfc71" &&
test -s third_party/semgrep-rules/RULES_SHA256 &&
test -s third_party/semgrep-rules/LICENSE &&
test -s third_party/semgrep/LICENSE &&
test -d third_party/semgrep-rules/rules/c
```

Expected: FAIL because the pinned snapshot is not present.

- [ ] **Step 2: Add the deterministic tree-digest utility**

The complete digest loop is:

```python
#!/usr/bin/env python3
import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
digest = hashlib.sha256()
files = sorted(path for path in root.rglob("*") if path.is_file() and not path.is_symlink())
for path in files:
    relative = path.relative_to(root).as_posix().encode("utf-8")
    content = path.read_bytes()
    digest.update(len(relative).to_bytes(8, "big"))
    digest.update(relative)
    digest.update(len(content).to_bytes(8, "big"))
    digest.update(content)
print(digest.hexdigest())
```

The updater script must fetch only the exact rules commit into `mktemp -d`, verify `git rev-parse HEAD`, replace only `third_party/semgrep-rules/rules/c`, copy upstream `LICENSE`, write the literal commit to `COMMIT`, run the digest utility into `RULES_SHA256`, and write the repository URL plus commit to `UPSTREAM.md`. It must also fetch the Semgrep `v1.169.0` tag into a second temporary repository, verify that tag resolves to the fetched commit, copy its LGPL-2.1 `LICENSE` to `third_party/semgrep/LICENSE`, and record the tag, resolved commit, and source URL in `third_party/semgrep/UPSTREAM.md`.

- [ ] **Step 3: Run the updater and inspect the vendored scope**

Run:

```bash
./scripts/update-semgrep-rules.sh
test "$(find third_party/semgrep-rules/rules -mindepth 1 -maxdepth 1 -type d -print)" = \
  "third_party/semgrep-rules/rules/c"
test "$(scripts/semgrep-tree-digest.py third_party/semgrep-rules/rules/c)" = \
  "$(cat third_party/semgrep-rules/RULES_SHA256)"
```

Expected: PASS, and only `rules/c` is vendored. This step needs network approval at execution time.

- [ ] **Step 4: Add the fixed no-argument scan wrapper**

`docker/sandbox/semgrep/scan.sh` must reject arguments and use only fixed paths:

```bash
#!/usr/bin/env bash
set -euo pipefail
[[ "$#" -eq 0 ]] || { echo "oxfuzz-semgrep-scan accepts no arguments" >&2; exit 64; }
[[ "$(semgrep --version)" == "1.169.0" ]]
[[ "$(python3 /opt/oxfuzz/semgrep-tree-digest.py /opt/oxfuzz/semgrep-rules/rules/c)" == \
   "$(cat /opt/oxfuzz/semgrep-rules/RULES_SHA256)" ]]
unset SEMGREP_APP_TOKEN
export SEMGREP_SEND_METRICS=off
rm -f /work/output/semgrep.json
cd /work/source
exec semgrep scan \
  --config /opt/oxfuzz/semgrep-rules/rules/c \
  --json \
  --json-output /work/output/semgrep.json \
  --metrics off \
  --disable-version-check \
  --no-rewrite-rule-ids \
  --jobs 2 \
  --max-target-bytes 2097152 \
  --timeout 30 \
  --timeout-threshold 1 \
  .
```

The wrapper contains no autofix flag, registry config, token, user environment, or caller-controlled path/flag.

Use this vulnerable fixture:

```c
#include <stdio.h>

int parse_line(char *output) {
    return gets(output) == NULL ? -1 : 0;
}
```

The clean fixture uses bounded `fgets(output, 32, stdin)` instead. Build and release verification must assert exactly one `raptor-insecure-api-gets` finding in `vulnerable.c` and none in `clean.c`; it must not accept an arbitrary non-empty result set.

- [ ] **Step 5: Install and build-verify the pinned toolchain**

Add to `docker/sandbox/Dockerfile`:

```dockerfile
ARG SEMGREP_VERSION=1.169.0
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    "semgrep==${SEMGREP_VERSION}"
COPY third_party/semgrep-rules /opt/oxfuzz/semgrep-rules
COPY scripts/semgrep-tree-digest.py /opt/oxfuzz/semgrep-tree-digest.py
COPY docker/sandbox/semgrep/scan.sh /usr/local/bin/oxfuzz-semgrep-scan
RUN chmod 0755 /usr/local/bin/oxfuzz-semgrep-scan /opt/oxfuzz/semgrep-tree-digest.py \
    && test "$(semgrep --version)" = "${SEMGREP_VERSION}" \
    && test "$(python3 /opt/oxfuzz/semgrep-tree-digest.py /opt/oxfuzz/semgrep-rules/rules/c)" = \
       "$(cat /opt/oxfuzz/semgrep-rules/RULES_SHA256)"
```

Semgrep CE `1.169.0`'s dedicated `scan --validate` path must not be used: it
unconditionally fetches the registry-hosted `p/semgrep-rule-lints` pack.
Extend `scripts/build-sandbox.sh` to assert the version and tree digest, then
validate the complete bundled configuration by running the fixed wrapper
inside a `docker run --network none --read-only` container with read-only
source and writable output mounts. Successful loading/execution of all local
rules plus the exact `raptor-insecure-api-gets` vulnerable/clean fixture
assertion is the offline validation gate.

- [ ] **Step 6: Build and run the container-only verification**

Run:

```bash
./scripts/build-sandbox.sh
```

Expected: PASS; output confirms Semgrep `1.169.0`, exact tree digest, complete
local-configuration loading/execution, networking disabled, and expected
vulnerable/clean fixture identifiers. No host Semgrep command or registry
validation path is run.

- [ ] **Step 7: Commit**

```bash
git add third_party/semgrep-rules third_party/semgrep scripts/semgrep-tree-digest.py \
  scripts/update-semgrep-rules.sh docker/sandbox/semgrep docker/sandbox/Dockerfile \
  scripts/build-sandbox.sh
git commit -m "build: bundle pinned Semgrep rules and scanner"
```

---

### Task 7: Add Atomic Semgrep Storage Records

**Files:**
- Create: `crates/hf-storage/migrations/0022_semgrep_enrichment.sql`
- Modify: `crates/hf-storage/src/store.rs`
- Modify: `crates/hf-storage/src/lib.rs`
- Modify: `crates/hf-storage/tests/store.rs`

**Interfaces:**
- Consumes: service-mapped run, finding, and score records.
- Produces:

```rust
pub enum SemgrepRunStatus {
    Staging, Scanning, Validating, Persisting, Done, Failed, Cancelled,
}

pub struct SemgrepRunRecord { /* every typed migration column */ }
pub struct SemgrepFindingRecord { /* normalized fields only */ }
pub struct SemgrepTargetScoreRecord { /* base, boost, effective, rule count */ }
pub struct SemgrepPublication {
    pub run: SemgrepRunRecord,
    pub findings: Vec<SemgrepFindingRecord>,
    pub scores: Vec<SemgrepTargetScoreRecord>,
}

pub async fn insert_semgrep_run(&self, run: &SemgrepRunRecord) -> Result<(), StorageError>;
pub async fn set_semgrep_phase(
    &self,
    id: Uuid,
    expected: SemgrepRunStatus,
    next: SemgrepRunStatus,
    source_sha256: Option<&str>,
) -> Result<(), StorageError>;
pub async fn publish_semgrep_run(
    &self,
    publication: &SemgrepPublication,
) -> Result<(), StorageError>;
pub async fn fail_semgrep_run(
    &self,
    id: Uuid,
    status: SemgrepRunStatus,
    failure_code: &str,
    failure_message: &str,
    ended_at: DateTime<Utc>,
) -> Result<(), StorageError>;
pub async fn compensate_semgrep_publication(
    &self,
    id: Uuid,
    failure_code: &str,
    failure_message: &str,
    ended_at: DateTime<Utc>,
) -> Result<(), StorageError>;
pub async fn semgrep_run(&self, id: Uuid) -> Result<Option<SemgrepRunRecord>, StorageError>;
pub async fn semgrep_publication(
    &self,
    id: Uuid,
) -> Result<Option<SemgrepPublication>, StorageError>;
pub async fn latest_semgrep_publication(
    &self,
    project_root: &str,
    language: &str,
) -> Result<Option<SemgrepPublication>, StorageError>;
```

- [ ] **Step 1: Write failing migration and transaction tests**

Add tests that:

- insert a staging row and enforce valid phase transitions;
- reject two active rows for one canonical project using a partial unique index;
- publish findings, all candidate score rows, counts, digests, duration, and `done` in one transaction;
- inject a trigger failure on the second finding and prove zero finding/score rows plus non-done parent state;
- compensate a published row and prove children are deleted and status is `failed`;
- ensure `failed` and `cancelled` rows have no child rows;
- return the newest `done` publication for project/language;
- delete Semgrep children/runs in `delete_project` and `clear_knowledge`; and
- reject malformed persisted enums, UUIDs, timestamps, hashes, coordinates, weights, and counts.

- [ ] **Step 2: Run the focused storage tests and verify red**

Run:

```bash
cargo test -p hf-storage semgrep_ 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because migration 0022 and Semgrep store methods do not exist.

- [ ] **Step 3: Implement migration 0022**

Use these tables and constraints:

```sql
CREATE TABLE semgrep_enrichment_runs (
    id TEXT PRIMARY KEY,
    project_root TEXT NOT NULL,
    language TEXT NOT NULL CHECK (language IN ('c', 'cpp')),
    source_sha256 TEXT,
    sandbox_image TEXT NOT NULL,
    sandbox_image_sha256 TEXT NOT NULL,
    semgrep_version TEXT NOT NULL,
    rules_commit TEXT NOT NULL,
    rules_tree_sha256 TEXT NOT NULL,
    command_schema_version INTEGER NOT NULL CHECK (command_schema_version = 1),
    status TEXT NOT NULL CHECK (
        status IN ('staging','scanning','validating','persisting','done','failed','cancelled')
    ),
    started_at TEXT NOT NULL,
    ended_at TEXT,
    output_sha256 TEXT,
    finding_count INTEGER,
    matched_candidate_count INTEGER,
    duration_ms INTEGER,
    failure_code TEXT,
    failure_message TEXT,
    CHECK (
        status <> 'done' OR (
            source_sha256 IS NOT NULL AND ended_at IS NOT NULL AND
            output_sha256 IS NOT NULL AND finding_count IS NOT NULL AND
            matched_candidate_count IS NOT NULL AND duration_ms IS NOT NULL
        )
    )
);

CREATE UNIQUE INDEX idx_semgrep_one_active_project
ON semgrep_enrichment_runs(project_root)
WHERE status IN ('staging','scanning','validating','persisting');

CREATE INDEX idx_semgrep_latest_project_language
ON semgrep_enrichment_runs(project_root, language, ended_at DESC)
WHERE status = 'done';

CREATE TABLE semgrep_findings (
    scan_id TEXT NOT NULL REFERENCES semgrep_enrichment_runs(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('error','warning','info')),
    message TEXT NOT NULL,
    relative_file TEXT NOT NULL,
    start_line INTEGER NOT NULL CHECK (start_line > 0),
    start_col INTEGER NOT NULL CHECK (start_col > 0),
    end_line INTEGER NOT NULL CHECK (end_line > 0),
    end_col INTEGER NOT NULL CHECK (end_col > 0),
    target_id TEXT,
    nominal_weight REAL NOT NULL CHECK (nominal_weight IN (0.10, 0.05, 0.01)),
    PRIMARY KEY (scan_id, fingerprint)
);

CREATE TABLE semgrep_target_scores (
    scan_id TEXT NOT NULL REFERENCES semgrep_enrichment_runs(id) ON DELETE CASCADE,
    target_id TEXT NOT NULL,
    base_score REAL NOT NULL CHECK (base_score >= 0.0 AND base_score <= 1.0),
    boost REAL NOT NULL CHECK (boost >= 0.0 AND boost <= 0.20),
    effective_score REAL NOT NULL CHECK (effective_score >= 0.0 AND effective_score <= 1.0),
    matched_rule_count INTEGER NOT NULL CHECK (matched_rule_count >= 0),
    PRIMARY KEY (scan_id, target_id)
);
```

- [ ] **Step 4: Implement typed reads and atomic writes**

`publish_semgrep_run` must:

1. begin one SQLx transaction;
2. verify the parent is `persisting`;
3. insert every finding;
4. insert every candidate score;
5. update the parent to `done` with every terminal field and `WHERE status = 'persisting'`;
6. require one affected parent row; and
7. commit.

`fail_semgrep_run` must reject `Done` as its requested status and delete child rows in the same transaction before setting `failed` or `cancelled`. Bound failure code to 64 bytes and message to 1,024 bytes before passing records into storage.

- [ ] **Step 5: Run storage tests**

Run:

```bash
cargo test -p hf-storage 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hf-storage/migrations/0022_semgrep_enrichment.sql \
  crates/hf-storage/src/store.rs crates/hf-storage/src/lib.rs \
  crates/hf-storage/tests/store.rs
git commit -m "feat: persist atomic Semgrep enrichment overlays"
```

---

### Task 8: Add a Durable Per-Operation Semgrep Recovery Journal

**Files:**
- Modify: `crates/hf-service/Cargo.toml`
- Modify: `crates/hf-service/src/lib.rs`
- Create: `crates/hf-service/src/semgrep_recovery.rs`

**Interfaces:**
- Consumes: service-owned operation UUID, canonical project, validated staging directory name, and ready-to-commit provenance.
- Produces:

```rust
pub struct SemgrepReadyRecord {
    pub source_sha256: String,
    pub output_sha256: String,
    pub sandbox_image_sha256: String,
    pub rules_tree_sha256: String,
    pub command_schema_version: u32,
}

pub struct InterruptedSemgrepOperation {
    pub operation_id: Uuid,
    pub project_root: PathBuf,
    pub staging_dir_name: String,
    pub ready: Option<SemgrepReadyRecord>,
}

pub struct SemgrepJournal { /* directory + shared path lock */ }

impl SemgrepJournal {
    pub fn in_memory() -> Self;
    pub fn open(directory: PathBuf) -> Self;
    pub fn durability_error(&self) -> Option<String>;
    pub fn begin(
        &self,
        operation_id: Uuid,
        project_root: &Path,
        staging_dir_name: &str,
    ) -> Result<(), ClassifiedError>;
    pub fn ready_to_commit(
        &self,
        operation_id: Uuid,
        ready: &SemgrepReadyRecord,
    ) -> Result<(), ClassifiedError>;
    pub fn close(&self, operation_id: Uuid) -> Result<(), ClassifiedError>;
    pub fn is_closed(&self, operation_id: Uuid) -> Result<bool, ClassifiedError>;
    pub fn interrupted(&self) -> Result<Vec<InterruptedSemgrepOperation>, ClassifiedError>;
}
```

- [ ] **Step 1: Establish the feature boundary and write failing journal tests**

Declare the service feature before running the Task 8 tests:

```toml
[features]
default = ["automotive-scapy", "proof-carrying", "semgrep-enrichment"]
semgrep-enrichment = ["hf-discovery/semgrep-enrichment"]
```

Gate `pub mod semgrep_recovery;` with
`#[cfg(feature = "semgrep-enrichment")]`. This moves the service feature wiring
forward from Task 9 so the Task 8 test command is valid and the new recovery
subsystem is feature-gated from its first commit.

Test:

- `begin -> ready_to_commit -> close` survives reopen and reports closed;
- begin-only and ready-without-close are interrupted;
- close without begin, duplicate begin, duplicate ready, and ready after close fail;
- malformed, oversized, unknown-version, and truncated records set a sticky durability error;
- `staging_dir_name` must equal the operation UUID string;
- each operation file is `<journal-dir>/<uuid>.jsonl`, opened without following symlinks;
- every append flushes and `sync_all`s before returning success; and
- one operation's corrupt journal does not cause another operation to be reported as safely closed.

- [ ] **Step 2: Run the journal tests and verify red**

Run:

```bash
cargo test -p hf-service --features semgrep-enrichment semgrep_recovery::tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because `semgrep_recovery` does not exist.

- [ ] **Step 3: Implement versioned bounded JSONL records**

Use:

```rust
#[derive(Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum SemgrepJournalEvent {
    Open {
        version: u32,
        operation_id: Uuid,
        project_root: PathBuf,
        staging_dir_name: String,
        timestamp: DateTime<Utc>,
    },
    ReadyToCommit {
        version: u32,
        operation_id: Uuid,
        ready: SemgrepReadyRecord,
        timestamp: DateTime<Utc>,
    },
    Close {
        version: u32,
        operation_id: Uuid,
        timestamp: DateTime<Utc>,
    },
}
```

Set version `1`, maximum file size 64 KiB, maximum line size 16 KiB, and exactly three lifecycle records. Keep closed files as durable terminal evidence so historical result readers can prove both DB and journal completion. Serialize access with a shared per-directory lock modeled on `RunJournal`.

- [ ] **Step 4: Run the journal tests**

Run:

```bash
cargo test -p hf-service --features semgrep-enrichment semgrep_recovery::tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-service/Cargo.toml crates/hf-service/src/lib.rs \
  crates/hf-service/src/semgrep_recovery.rs
git commit -m "feat: journal Semgrep enrichment publication"
```

---

### Task 9: Build a Bounded, Stable C/C++ Source Snapshot

**Files:**
- Modify: `crates/hf-discovery/src/scanner.rs`
- Modify: `crates/hf-discovery/src/lib.rs`
- Modify: `crates/hf-service/Cargo.toml`
- Modify: `crates/hf-service/src/lib.rs`
- Create: `crates/hf-service/src/semgrep.rs`

**Interfaces:**
- Consumes:

```rust
pub fn discoverable_source_files(
    canonical_root: &Path,
    lang: TargetLanguage,
) -> Result<Vec<PathBuf>, ClassifiedError>;
```

- Produces:

```rust
pub const SEMGREP_VERSION: &str = "1.169.0";
pub const RULES_COMMIT: &str = "4d66ecf30bfb1809a984085f2c86a8c3915bfc71";
pub const COMMAND_SCHEMA_VERSION: u32 = 1;

struct SourceSnapshot {
    operation_root: PathBuf,
    source_dir: PathBuf,
    output_dir: PathBuf,
    relative_paths: BTreeSet<PathBuf>,
    source_sha256: String,
    file_count: usize,
    total_bytes: u64,
}

#[derive(Clone, Copy)]
struct SnapshotLimits {
    max_files: usize,
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_relative_path_bytes: usize,
}

const SNAPSHOT_LIMITS: SnapshotLimits = SnapshotLimits {
    max_files: 25_000,
    max_file_bytes: 2 * 1024 * 1024,
    max_total_bytes: 512 * 1024 * 1024,
    max_relative_path_bytes: 4_096,
};

fn stage_source_snapshot(
    canonical_project: &Path,
    language: TargetLanguage,
    operation_id: Uuid,
) -> Result<SourceSnapshot, ClassifiedError>;

fn digest_live_sources(
    canonical_project: &Path,
    language: TargetLanguage,
) -> Result<String, ClassifiedError>;
```

Production calls `stage_source_snapshot_with_limits(..., SNAPSHOT_LIMITS)`. Unit tests inject single-digit limits, so limit-boundary coverage does not create 25,001 files or allocate 512 MiB.

- [ ] **Step 1: Write failing source-set and snapshot tests**

Test:

- C includes `.c` and `.h`; C++ includes `.cc`, `.cpp`, `.cxx`, `.hpp`, `.hh`;
- discovery and snapshot selection return the same sorted paths;
- `.git`, ignored files, build artifacts, managed runtime workspace paths, and ignored vendor files are absent;
- symlinks, non-regular files, absolute/traversing relative paths, unstable before/after metadata, and files outside the canonical root fail;
- file count 25,001, file size 2 MiB + 1, aggregate 512 MiB + 1, and path 4,097 bytes fail;
- the staged tree preserves normalized relative paths;
- identical bytes produce the same ordered length-prefixed digest regardless of directory iteration order;
- changing path or bytes changes the digest; and
- cleanup removes only `<workspace-root>/semgrep/<operation-uuid>`.

- [ ] **Step 2: Run focused snapshot tests and verify red**

Run:

```bash
cargo test -p hf-service --features semgrep-enrichment semgrep::snapshot_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because snapshot interfaces do not exist.

- [ ] **Step 3: Centralize the discovery file walk**

Centralize the C/C++ walk configuration, extension filtering, and safe-file
selection in shared helpers used by both `scan_c` and
`discoverable_source_files`. The public snapshot selector returns sorted
relative paths, while `scan_c` preserves the legacy `ignore::Walk` iteration
order so ordinary discovery output remains byte-for-byte/order compatible.
Both paths use:

```rust
let walker = WalkBuilder::new(canonical_root)
    .hidden(true)
    .git_ignore(true)
    .build();
```

Preserve the existing discovery walker behavior exactly, including its ignore
semantics and legacy iteration order. Build outputs, runtime workspaces, and
vendor trees are excluded when hidden or ignored by that walker; add fixtures
with `.gitignore` entries to prove it. Filter by
`TargetLanguage::extensions()`, regular file type, and canonical-root
containment. Sort only the public snapshot manifest lexicographically. The
function supports only C/C++ and returns validation error for other languages.
Add a true pre-refactor-oracle regression covering every candidate field, ID,
and order returned by normal discovery without Semgrep.

- [ ] **Step 4: Implement stable snapshotting**

Read each selected file from a non-symlink handle, check metadata before and after the read, enforce limits before allocating/copying, write into a newly created operation directory, and hash:

```rust
fn hash_path_and_bytes(hasher: &mut Sha256, path: &[u8], bytes: &[u8]) {
    hasher.update(u64::try_from(path.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(path);
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_be_bytes());
    hasher.update(bytes);
}
```

Create `source` and `output` with restrictive permissions. If any step fails, remove the validated operation directory and return the original error plus cleanup failure context when cleanup also fails.

- [ ] **Step 5: Verify and extend the service feature boundary**

Task 8 already declares:

```toml
[features]
default = ["automotive-scapy", "proof-carrying", "semgrep-enrichment"]
semgrep-enrichment = ["hf-discovery/semgrep-enrichment"]
```

Keep that mapping unchanged. Gate `pub mod semgrep;` and all new Semgrep
snapshot re-exports with `#[cfg(feature = "semgrep-enrichment")]`.

- [ ] **Step 6: Run tests and feature-off check**

Run:

```bash
cargo test -p hf-service --features semgrep-enrichment semgrep::snapshot_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo check -p hf-service --no-default-features
```

Expected: tests PASS and feature-off service compiles.

- [ ] **Step 7: Commit**

```bash
git add crates/hf-discovery/src/scanner.rs crates/hf-discovery/src/lib.rs \
  crates/hf-service/Cargo.toml crates/hf-service/src/lib.rs \
  crates/hf-service/src/semgrep.rs
git commit -m "feat: stage bounded Semgrep source snapshots"
```

---

### Task 10: Implement Asynchronous Sandboxed Scan Lifecycle and Cancellation

**Files:**
- Modify: `crates/hf-service/src/semgrep.rs`
- Modify: `crates/hf-service/src/container.rs`
- Modify: `crates/hf-service/src/lib.rs`
- Modify: `crates/hf-guardrails/src/action.rs`
- Modify: `crates/hf-guardrails/tests/policy.rs`

**Interfaces:**
- Consumes: `RuntimeAdapter::resolve_image_reference`, `run_command_streaming_opts`, snapshot interfaces, store reservation, and journal begin.
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepOperationState {
    Staging, Scanning, Validating, Persisting, Done, Failed, Cancelled,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemgrepOperationView {
    pub operation_id: Uuid,
    pub project_root: String,
    pub language: String,
    pub state: SemgrepOperationState,
    pub active: bool,
    pub started_at: String,
    pub ended_at: Option<String>,
    pub failure_code: Option<String>,
    pub failure_message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepCancelOutcome { Accepted, Inactive, NotFound }

impl ServiceContainer {
    pub async fn start_semgrep_enrichment(
        &self,
        project: PathBuf,
        language: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError>;
    pub async fn semgrep_operation(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<SemgrepOperationView>, ClassifiedError>;
    pub async fn request_semgrep_cancel(
        &self,
        operation_id: Uuid,
    ) -> Result<SemgrepCancelOutcome, ClassifiedError>;
}
```

- [ ] **Step 1: Write failing guardrail and recording-runtime tests**

Add `Action::AnalyzeSource { analyzer: String }` with:

```rust
Action::AnalyzeSource { .. } => "analyze_source",
Action::AnalyzeSource { analyzer } => format!("analyze source with {analyzer}"),
Action::AnalyzeSource { .. } => RiskTier::Medium,
```

Service tests must assert:

- non-C/C++, no store, missing persisted inventory, incomplete spans, absent image, and a busy project fail before spawn;
- canonical project identity is used for the unique reservation;
- start persists `staging`, journals `open`, registers cancellation, and returns without waiting for runtime completion;
- the runtime receives exactly `["/usr/local/bin/oxfuzz-semgrep-scan"]`;
- limits are 4,096 MiB, 2 CPUs, 600 seconds, no environment, no ptrace;
- options use the exact resolved `sha256:<digest>` image reference, `network_mode: None`, `relax_hardening: false`, no capabilities/devices/stdin, `workspace_read_only: true`, `max_file_size_bytes: Some(67_108_864)`, `max_pids: Some(128)`;
- the source is read-only at `/work/source` and output writable at `/work/output`;
- timeout/non-zero/missing output/oversized output/truncated runtime output are `failed`;
- cooperative cancellation is `cancelled`, kills through the recording adapter contract, and does not become failed;
- a second operation for the same project is busy, while another project can start;
- the workspace read lease is held through terminal cleanup; and
- status/cancel resolve only service-owned UUIDs.

- [ ] **Step 2: Run focused lifecycle tests and verify red**

Run:

```bash
cargo test -p hf-guardrails analyze_source 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment semgrep::lifecycle_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because the action and service lifecycle do not exist.

- [ ] **Step 3: Add a focused coordinator to `ServiceContainer`**

Under the feature, add:

```rust
semgrep: Arc<crate::semgrep::SemgrepCoordinator>,
```

`SemgrepCoordinator` owns:

```rust
active: Mutex<HashMap<PathBuf, (Uuid, CancellationToken)>>,
journal: Arc<SemgrepJournal>,
```

Initialize an in-memory journal in `ServiceContainer::new`, a persistent
`user_app_dir()/semgrep-journal` in `bootstrap`, and keep `with_store` unchanged
because service methods read the container's current store.

- [ ] **Step 4: Implement admission and background execution**

Admission order:

1. reject unsupported language;
2. canonicalize the project;
3. require a store and persisted same-language candidates with complete spans;
4. authorize and record `AnalyzeSource { analyzer: "semgrep" }`;
5. resolve `SANDBOX_IMAGE` to an immutable SHA-256 image ID;
6. reserve the project in the in-memory map;
7. insert the staging row; if the partial unique index reports busy, release the reservation;
8. sync journal `begin`; if it fails, mark the row failed and release;
9. register the cancellation token; and
10. spawn a task that owns the workspace lease and always removes the active entry.

Use compiled provenance without retaining the newline in the digest file:

```rust
fn rules_tree_sha256() -> &'static str {
    include_str!("../../../third_party/semgrep-rules/RULES_SHA256").trim()
}
```

The task stages, moves DB phase to scanning, invokes the fixed wrapper using the immutable image reference returned by `resolve_image_reference`, classifies `CommandTermination`, verifies exit code zero, rejects captured-output truncation markers, loads a regular non-symlink output file through a 64 MiB bounded reader, and moves to validating. No presentation callback may supply command flags or environment.

Create one tracing span containing only operation UUID, project-identity digest, language, source digest, immutable image digest, rules digest, and command schema. Emit structured stage-duration/count events for staging, execution, validation, mapping, persistence, findings by severity, matched/unmatched findings, boosted candidates, cancellation, timeout, stale overlay, and rollback. Tests must capture tracing output and prove it contains no source text, finding message, raw JSON, or absolute project path.

- [ ] **Step 5: Bound and redact failures**

Map failures to stable codes such as `unsupported_language`, `inventory_missing`, `inventory_span_incomplete`, `busy`, `snapshot_invalid`, `sandbox_unavailable`, `timeout`, `cancelled`, `tool_exit`, `output_missing`, `output_too_large`, `output_invalid`, `source_changed`, `persistence_failed`, `journal_failed`, and `cleanup_failed`. Store at most 64 code bytes and 1,024 message bytes; messages contain no source, finding text, raw output, or absolute host path.

- [ ] **Step 6: Run lifecycle and guardrail tests**

Run:

```bash
cargo test -p hf-guardrails 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment semgrep::lifecycle_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add crates/hf-service/src/semgrep.rs crates/hf-service/src/container.rs \
  crates/hf-service/src/lib.rs crates/hf-guardrails/src/action.rs \
  crates/hf-guardrails/tests/policy.rs
git commit -m "feat: run cancellable Semgrep enrichment in sandbox"
```

---

### Task 11: Publish Atomically, Recover Fail-Closed, and Serve Effective Ranking

**Files:**
- Modify: `crates/hf-service/src/semgrep.rs`
- Modify: `crates/hf-service/src/semgrep_recovery.rs`
- Modify: `crates/hf-service/src/container.rs`
- Modify: `crates/hf-service/src/lib.rs`
- Modify: `crates/hf-service/src/agent.rs`
- Modify: `crates/hf-service/src/scheduler.rs`
- Modify: `crates/hf-service/src/workbench.rs`

**Interfaces:**
- Consumes: normalized findings, `map_and_score`, storage publication, journal readiness/close, live-source digest.
- Produces:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SemgrepOverlayState {
    None, Current, StaleSource, StaleBase, IncompleteJournal,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemgrepTargetView {
    #[serde(flatten)]
    pub candidate: TargetCandidate,
    pub base_score: f64,
    pub semgrep_boost: f64,
    pub effective_score: f64,
    pub semgrep_matched_rule_count: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemgrepFindingView {
    pub fingerprint: String,
    pub rule_id: String,
    pub severity: String,
    pub message: String,
    pub relative_file: PathBuf,
    pub start_line: u32,
    pub start_col: u32,
    pub end_line: u32,
    pub end_col: u32,
    pub matched_target_id: Option<Uuid>,
    pub nominal_weight: f64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SemgrepInventoryView {
    pub project_root: PathBuf,
    pub language: TargetLanguage,
    pub scan_id: Option<Uuid>,
    pub source_sha256: Option<String>,
    pub overlay_state: SemgrepOverlayState,
    pub candidates: Vec<SemgrepTargetView>,
    pub findings: Vec<SemgrepFindingView>,
    pub call_graph: HashMap<String, Vec<String>>,
}

impl ServiceContainer {
    pub async fn effective_inventory(
        &self,
        inventory: TargetInventory,
        language: TargetLanguage,
    ) -> Result<SemgrepInventoryView, ClassifiedError>;
    pub async fn semgrep_result(
        &self,
        operation_id: Uuid,
    ) -> Result<Option<SemgrepInventoryView>, ClassifiedError>;
}
```

When Task 11 is complete, extend `SemgrepOperationView` from Task 10 with:

```rust
pub result: Option<SemgrepInventoryView>,
```

`semgrep_operation` fills `result` only for `done`; it calls `semgrep_result` for that exact operation UUID, never the latest scan. `effective_inventory` uses the latest completed scan only for general ranking consumers. Both paths share a private `inventory_with_publication(inventory, publication)` validator so their staleness behavior cannot drift.

`semgrep_result` reconstructs the inventory from persisted target records, because those records may contain LLM-ranked base scores that differ from a fresh heuristic discovery. To retain the call graph, `load_persisted_inventory_with_call_graph(project, language)` runs the read-only scanner, requires its target-ID set to equal the persisted same-language set, then uses the persisted candidates plus the scanner's call graph. A test with an LLM-like persisted base score proves a just-completed scan is current rather than immediately `stale_base`.

- [ ] **Step 1: Write failing atomic completion, recovery, and staleness tests**

Cover:

- valid output -> parse -> map -> re-digest live source -> `persisting`;
- source mutation before `ready_to_commit` fails with no children;
- `ready_to_commit` is synced before `publish_semgrep_run`;
- publication failure rolls back and a separate failure transaction leaves no children;
- a close append error after DB publication is treated as indeterminate:
  current reads are `IncompleteJournal`, new starts fail closed, replayed
  `close` preserves success, and replayed `ready_to_commit` is compensated;
- injected pre-write and post-file-sync close errors prove both replay branches:
  no same-process overlay is visible; restart compensates a replayed ready
  journal and preserves a replayed successful close;
- cleanup compensation failure leaves the journal unclosed and the result reader rejects it;
- startup repairs every interrupted staging/scanning/validating/persisting/done-but-unclosed row and every failed/cancelled-but-unaborted row; active/done repairs delete children through the existing failure/compensation transactions, already-terminal rows must verify child-free, and every successful repair terminalizes the journal with `recovered` after idempotent exact-UUID cleanup;
- ordinary failed/cancelled operations and repaired interrupted operations append
  a synced terminal abort only after their database terminal state and cleanup
  are durable; abort never fabricates ready provenance or satisfies
  `is_closed`;
- `open -> abort` and `open -> ready_to_commit -> abort` survive reopen as
  terminal non-publications, disappear from `interrupted()`, remain
  `is_closed() == false`, and reject every later transition;
- success durably removes raw source/output before the successful journal close;
- cleanup failure compensates the publication;
- a current source digest + exact candidate-ID set + exact base scores applies the overlay;
- source mismatch, candidate-set mismatch, any base-score mismatch, or unclosed journal returns base-only scores with the matching stale state;
- normalized matched and unmatched findings remain queryable for the exact historical scan even when its overlay is stale;
- `semgrep_result(operation_a)` never returns a newer operation B's findings or scores;
- an LLM-ranked persisted base inventory remains current in its exact operation result;
- a failed new scan does not replace the last successful historical row;
- rescanning does not compound boosts;
- order is effective descending, base descending, relative file ascending, symbol ascending, UUID ascending; and
- all score consumers use the service effective score without gaining permission to start Semgrep.

- [ ] **Step 2: Run focused completion tests and verify red**

Run:

```bash
cargo test -p hf-service --features semgrep-enrichment semgrep::publication_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment semgrep::effective_inventory_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because publication/effective inventory is incomplete.

- [ ] **Step 3: Complete the success sequence**

The exact success order is:

```rust
let output_sha256 = sha256_hex(&output_bytes);
let findings = hf_discovery::semgrep::parse_findings(&output_bytes, &snapshot.relative_paths)?;
let analysis = hf_discovery::semgrep::map_and_score(&inventory, findings)?;
if digest_live_sources(project, language)? != snapshot.source_sha256 {
    return fail_atomic("source_changed", "eligible source changed before publication").await;
}
store.set_semgrep_phase(id, Validating, Persisting, None).await?;
journal.ready_to_commit(id, &ready_record)?;
store.publish_semgrep_run(&publication).await?;
if let Err(error) = cleanup_operation_root(&snapshot.operation_root) {
    semgrep.mark_recovery_degraded(&error);
    if let Err(compensation) = store.compensate_semgrep_publication(
        id, "cleanup_failed", &redact(&error), Utc::now()
    ).await {
        semgrep.mark_recovery_degraded(&compensation);
        return Err(compensation);
    }
    return Err(error);
}
if let Err(error) = journal.close(id) {
    semgrep.mark_recovery_degraded(&error);
    return Err(error);
}
```

Keep the journal in `ready_to_commit` until cleanup succeeds. If cleanup fails,
run `compensate_semgrep_publication`, return `cleanup_failed`, and leave the
journal interrupted for recovery. If compensation itself fails, the still-open
ready journal prevents result readers from exposing the `done` row. A close
append error after cleanup is indeterminate because its record may already be
synced: mark recovery degraded and defer to restart replay. A valid replayed
close preserves success; a replayed ready state is compensated and treats
descriptor-proven absence of the exact UUID staging child as idempotent cleanup
success. An absent `semgrep` parent beneath the validated managed workspace is
also idempotent absence for pre-staging failures. Cleanup must sync the modified
Semgrep parent before close or abort.

Extend the Task 8 journal in this task with a versioned `Abort` record and
`abort(operation_id, terminal_kind)` API. `Abort` is valid from `open` or
`ready_to_commit`, records only `failed`, `cancelled`, or `recovered`, and is a
terminal non-publication outcome. `interrupted()` excludes aborted operations,
while `is_closed()` remains true only for the successful
`open -> ready_to_commit -> close` sequence. Append abort only after the
failed/cancelled database transaction and exact operation-directory cleanup
succeed. If database compensation, cleanup, or abort fails, leave the journal
interrupted and mark recovery degraded so new starts fail closed.
An abort append error is likewise indeterminate: the already-terminal database
row remains non-publishing, current starts stay blocked, and restart replay
either observes the abort or retries the interrupted cleanup/abort.

- [ ] **Step 4: Implement effective overlay validation and ordering**

Always create a base-only view first. Preserve the selected publication's bounded normalized findings in `SemgrepFindingView` whether the overlay is current or stale. A `done` publication applies scores only when:

```rust
journal.is_closed(scan_id).unwrap_or(false) &&
publication.run.source_sha256.as_deref() == Some(current_source_sha256.as_str()) &&
publication.scores.len() == inventory.candidates.len() &&
score_ids == candidate_ids &&
publication.scores.iter().all(|score| {
    base_by_id.get(&score.target_id).is_some_and(|base| *base == score.base_score)
})
```

Do not write effective scores into candidates. A missing, interrupted, aborted,
corrupt, or otherwise unverifiable journal maps to `IncompleteJournal` and a
base-only view rather than making parent status or historical findings
unreadable; sticky degradation still blocks starts. Sort `SemgrepTargetView`
using `f64::total_cmp` and the approved tie breakers.

- [ ] **Step 5: Route every ranking consumer through the overlay**

Make these exact changes without adding a scan-start path:

- `run_campaign`: after `self.discover`, call `effective_inventory` and choose `candidates.first()`.
- `dispatch_agent_tool("discover")`: render `base_score`, `semgrep_boost`, `effective_score`, and matched-rule count from `effective_inventory`.
- `schedulable_targets`: group persisted targets by C/C++ language, apply current overlays once per group, and place effective score in the legacy `SchedulableTarget.fit_score` field used by `priority_order`; non-C/C++ remains base.
- `workbench_dashboard`: pass an `effective_score_by_target: HashMap<Uuid, f64>` into `workbench::dashboard`; use it for top-target ordering and keep base score available in the workbench target DTO.

Do not change explicit target selection, harness qualification, or scheduler permission behavior.

- [ ] **Step 6: Wire startup recovery**

During `ServiceContainer::bootstrap`, after store and persistent Semgrep journal construction:

```rust
if let (Some(store), Some(semgrep)) = (&store, semgrep_coordinator.as_ref()) {
    if let Err(error) = semgrep.recover_interrupted(store, workspace_root()).await {
        tracing::error!(%error, "Semgrep recovery is degraded");
    }
}
```

A sticky journal/recovery error makes new starts fail closed. Status and base-only historical results remain readable. Recovery validates the staging directory as exactly `workspace_root()/semgrep/<uuid>` before deleting it. Descriptor-proven absence of that exact UUID child is idempotent success; a missing/ambiguous managed root or replaced/symlinked ancestor is still an error. Cleanup syncs the modified Semgrep parent before journal close or abort.

Recovery appends the terminal `recovered` abort only after the database repair
and exact staging cleanup succeed. It never writes `ready_to_commit` for an
operation that did not reach that state. If compensation, cleanup, or abort
cannot be made durable, the journal stays interrupted for a later retry.

- [ ] **Step 7: Run service tests**

Run:

```bash
cargo test -p hf-service --features semgrep-enrichment semgrep::publication_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment semgrep::effective_inventory_tests 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add crates/hf-service/src/semgrep.rs crates/hf-service/src/semgrep_recovery.rs \
  crates/hf-service/src/container.rs crates/hf-service/src/lib.rs \
  crates/hf-service/src/agent.rs \
  crates/hf-service/src/scheduler.rs crates/hf-service/src/workbench.rs
git commit -m "feat: publish and consume current Semgrep overlays"
```

---

### Task 11A: Make Live-Operation Ownership Cross-Process Safe

Tasks 11A-11E are the approved post-review correction to Tasks 10-11. Their
lease timing, lazy replay, finalizing registry, and close-gated status rules
supersede any earlier step that describes late workspace-lease acquisition,
eager bootstrap replay, reservation removal at completion claim, or direct
database-`done` status exposure.

**Files:**
- Modify: `crates/hf-service/src/container.rs`
- Modify: `crates/hf-service/src/semgrep.rs`
- Test: `crates/hf-service/src/semgrep.rs`

**Interfaces:**
- Consumes: `WorkspaceOperationLease`, `WorkspaceCleanupLease`, the canonical
  project path, and the existing process-local Semgrep reservation.
- Produces:

```rust
pub(crate) struct SemgrepProjectLease {
    _system_guard: std::fs::File,
}

enum StartupRecoveryOutcome {
    Recovered,
    Deferred,
}

async fn recover_semgrep_at_bootstrap(
    store: &hf_storage::Store,
    semgrep: &SemgrepCoordinator,
    workspace: &Path,
) -> Result<StartupRecoveryOutcome, ClassifiedError>;
```

- [ ] **Step 1: Write failing real-process ownership tests**

Add Unix tests named
`admitted_child_blocks_recovery_and_same_project_start_after_begin` and
`admitted_child_blocks_recovery_and_same_project_start_before_close`. Follow
the existing `current_exe() --exact <child-test>` pattern. The first child
constructs the real `ServiceContainer` with the shared test database,
persistent journal, explicit workspace, persisted C inventory, and
`RecordingRuntime`, then calls `start_semgrep_enrichment`. Add test-only pause
points after the synced journal `Begin` and immediately before `Close`. At each
pause, the admitted child signals readiness through a pipe while the real
background worker retains both lease guards.

A second child invokes the exact `recover_semgrep_at_bootstrap` helper used by
`ServiceContainer::bootstrap`; it must report `Deferred`. A third child
constructs the same real service and calls `start_semgrep_enrichment` for the
same canonical project; it must receive `busy`. At the post-`Begin` pause,
assert:

```rust
assert_eq!(outcome, StartupRecoveryOutcome::Deferred);
assert_eq!(
    store.semgrep_run(operation_id).await.unwrap().unwrap().status,
    SemgrepRunStatus::Staging
);
assert!(operation_root.exists());
assert_eq!(journal.interrupted().unwrap().len(), 1);
```

At the pre-`Close` pause, assert the database row is internally `Done`, the
journal remains unclosed, recovery still defers, and cross-process admission
still returns `busy`. Release each pause and require the admitted child to
finish successfully. These tests must use actual admission and worker guard
transfer; manually acquiring the lease primitives is insufficient.

- [ ] **Step 2: Run the process tests and verify red**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  admitted_child_blocks_recovery_and_same_project_start_after_begin \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment \
  admitted_child_blocks_recovery_and_same_project_start_before_close \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because admission does not yet own either lease before its
durable writes and bootstrap recovery does not take the exclusive lease.

- [ ] **Step 3: Implement early workspace and project ownership**

Create the project lock beside existing workspace lock files using a SHA-256 of
the canonical project path, a fixed `semgrep-project-<digest>.lock` filename,
`create(true)`, `truncate(false)`, and an exclusive nonblocking file lock. Map
lock contention to `semgrep_validation("busy")`.

In `start_semgrep_enrichment`, finish nondurable authorization and image
resolution first. Then take the shared workspace lease and project lease,
recheck `ensure_recovery_healthy`, reserve the process-local operation, and
only then insert the row and append journal `Begin`. Move both lease guards
into `run_semgrep_scan` and retain them until its active guard drops after
cleanup and close or abort. Remove the worker's late workspace-lease
acquisition.

In bootstrap, call `recover_semgrep_at_bootstrap`. It must take the matching
exclusive workspace lease before calling `recover_interrupted` and retain it
through recovery. A contended lease returns `Deferred`, marks that container's
Semgrep recovery state unavailable for new starts, and does not inspect the
journal.

- [ ] **Step 4: Run the ownership tests and service lifecycle tests**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::process_lease_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::lifecycle_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-service/src/container.rs crates/hf-service/src/semgrep.rs
git commit -m "fix: protect live Semgrep operations across processes"
```

#### Task 11A Review Correction: Pull Forward Safety Prerequisites

Independent review found that Task 11A cannot satisfy its recovery-ownership
and stable-lifecycle gate while filesystem-lazy journal construction remains in
Task 11B and close-gated resilient status remains in Tasks 11C/11E. These
prerequisites move into the Task 11A fix loop. Task 11B still owns the advisory
journal lock and process serialization; Task 11C still owns empty-inventory
historical reconstruction; Task 11E still owns the finalizing registry.

- [ ] **Review-fix Step 1: Add failing lazy-construction and cancellation tests**

Add
`persistent_coordinator_construction_does_not_touch_the_journal_filesystem`:
construct a persistent coordinator for a missing journal path and assert the
path remains absent. Create a corrupt existing operation journal, construct the
coordinator, and assert construction itself records no replay error; the first
recovery replay under the exclusive workspace lease must report the corruption.

Add
`cancelled_start_caller_does_not_orphan_durable_admission`. Install a test-only
pause after the staging insert and before journal `Begin`, spawn
`start_semgrep_enrichment`, wait for the pause, abort the caller task, release
the owned admission task, and assert it either completes a closed successful
operation or a fully terminalized failure. It must not leave a process-local
reservation, an active staging row, or an unjournaled operation.

- [ ] **Review-fix Step 2: Add mutation-sensitive lease-lifetime tests**

Extend the real child-process harness with
`AfterOwnershipBeforeDurableWrite` and `AfterCloseBeforeLeaseRelease` pauses.
At the first pause, the shared database has no Semgrep run, yet a separate
process's real same-project start must return `busy`; this fails if the project
lease is acquired after the first durable write. At the second pause, the row
is `Done` and `journal.is_closed(operation_id) == true`, yet a separate
process's real same-project start must still return `busy`; this fails if the
project lease drops before or during `Close`. Release the child and prove a new
same-project start can then acquire ownership.

- [ ] **Review-fix Step 3: Add a failing deterministic compensation-read test**

Add `operation_status_survives_concurrent_compensation`. Pause
`semgrep_operation` after it loads the `Done` parent but before exact-result
reconstruction. Compensate the unclosed publication, release the read, and
assert that the first status call returns a readable nonterminal view with
`result: None`; the next call returns `Failed`. No inconsistent terminal-count
error may escape.

- [ ] **Review-fix Step 4: Verify RED**

Run each new test with the repository-filtered form and `set -o pipefail`.
Expected failures:

- persistent construction creates/validates the journal path;
- aborting the caller cancels admission after a durable staging write;
- early/after-close contenders are admitted when the project lease lifetime is
  moved late or shortened;
- concurrent compensation escapes as inconsistent stored publication data.

- [ ] **Review-fix Step 5: Make journal construction filesystem-lazy**

`SemgrepJournal::open` normalizes and stores its path but performs no filesystem
create/open/validation/replay. Write/recovery methods lazily open or create the
directory only after their service caller owns the required workspace lease.
Result-only `is_closed` may open an existing directory but treats a missing
directory as not closed and never creates it. Preserve sticky durability errors
after the first actual filesystem/replay failure. Task 11B will add the fixed
descriptor-opened advisory lock around these lazy transactions.

- [ ] **Review-fix Step 6: Make durable admission caller-cancellation safe**

After authorization and immutable image resolution, spawn an owned service task
that acquires workspace then project ownership and performs reservation,
staging insert, synced journal `Begin`, and scan-worker handoff. Return the
admission result through a one-shot channel. Dropping
`start_semgrep_enrichment` detaches only the receiver; the owned task continues
to a fully handed-off operation or a cleaned admission error. Move the active
RAII guard into this owned path before the first await after reservation and
transfer it to `run_semgrep_scan`.

- [ ] **Review-fix Step 7: Pull forward close-gated resilient status**

For a database `Done` row, `semgrep_operation` reports external `Done` only when
`journal.is_closed(operation_id) == Ok(true)`; otherwise it reports
`Persisting`. Exact-result reconstruction failure is logged with bounded
structured metadata and yields `result: None` without hiding the parent
lifecycle. This pulls forward only the parent-read resilience from Task 11C and
the external close gate from Task 11E.

- [ ] **Review-fix Step 8: Verify and commit the fix round**

Run the new focused tests, `semgrep::process_lease_tests`,
`semgrep::lifecycle_tests`, and the mandated Rust gates in repository order.
Append RED/GREEN and gate evidence to the Task 11A report. Commit:

```bash
git add crates/hf-service/src/container.rs crates/hf-service/src/semgrep.rs \
  crates/hf-service/src/semgrep_recovery.rs
git commit -m "fix: complete Semgrep admission ownership"
```

---

### Task 11B: Serialize Persistent Journal Transactions Across Processes

**Files:**
- Modify: `crates/hf-service/src/semgrep_recovery.rs`
- Test: `crates/hf-service/src/semgrep_recovery.rs`

**Interfaces:**
- Consumes: the securely opened persistent journal-directory descriptor and
  the existing process-local `SharedJournalState::operation_lock`.
- Produces: a fixed `.semgrep-journal.lock` file, opened relative to the
  journal-directory descriptor with no symlink following, whose exclusive
  advisory lock covers one complete replay/validate/read/append transaction.

- [ ] **Step 1: Write failing multi-process journal tests**

Add Unix tests
`process_close_and_abort_serialize_to_one_terminal_outcome` and
`process_replay_waits_for_a_complete_append_transaction`. Use child tests
started through `current_exe() --exact`. Pause a child close after lifecycle
validation but before append while it owns the journal transaction lock. Start
the competing abort in another process, release the child, and assert:

```rust
assert!(reopened.is_closed(operation_id).unwrap());
assert!(reopened.interrupted().unwrap().is_empty());
assert!(abort_status.success()); // child proves the transition was rejected, not appended
```

The replay test pauses one operation append at the same point and proves a
second process cannot report directory corruption or observe the half-finished
transaction.

- [ ] **Step 2: Run the journal process tests and verify red**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep_recovery::tests::process_ \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because `SharedJournalState::operation_lock` is process-local.

- [ ] **Step 3: Add the descriptor-opened advisory lock**

Open or create `.semgrep-journal.lock` with `openat` against the already
validated journal directory, `NOFOLLOW`, owner read/write permissions, and no
truncate. Verify that the opened entry is a regular file and that its pathname
still names the opened inode. Exclude exactly this filename from
`read_all_journals` and `validate_all_journals`; continue rejecting every other
unexpected directory entry.

After taking `SharedJournalState::operation_lock`, take the advisory lock before
initial replay and before each call path that performs
replay/validate/read/append. Retain it until the complete transaction and
directory sync finish. Release it before the process mutex. No journal method
may acquire a workspace or project lease. Preserve Task 11A's filesystem-lazy
construction: constructor calls must not touch the journal path. Bootstrap's
first lifecycle replay therefore occurs only inside the workspace recovery
lease added by Task 11A.

- [ ] **Step 4: Run journal tests**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep_recovery::tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS, including the existing thread races and new process races.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-service/src/semgrep_recovery.rs
git commit -m "fix: lock Semgrep journal transactions across processes"
```

---

### Task 11C: Preserve Historical Results When the Live Inventory Is Empty

**Files:**
- Modify: `crates/hf-service/src/semgrep.rs`
- Test: `crates/hf-service/src/semgrep.rs`

**Interfaces:**
- Consumes: persisted target rows and an exact completed Semgrep publication.
- Produces:

```rust
async fn load_current_inventory(
    store: &hf_storage::Store,
    canonical_project: &Path,
    language: TargetLanguage,
    require_nonempty: bool,
) -> Result<TargetInventory, ClassifiedError>;
```

- [ ] **Step 1: Write failing empty-inventory and readable-status tests**

Add tests
`exact_result_with_deleted_inventory_is_findings_preserving_stale_base`,
`exact_result_with_reclassified_inventory_is_findings_preserving_stale_base`,
and `operation_status_survives_result_reconstruction_failure`. Complete and
close a publication with at least one matched and one unmatched finding, then
delete or reclassify every same-language target. Assert:

```rust
let exact = service.semgrep_result(operation_id).await.unwrap().unwrap();
assert_eq!(exact.overlay_state, SemgrepOverlayState::StaleBase);
assert!(exact.candidates.is_empty());
assert_eq!(exact.findings.len(), 2);

let parent = service.semgrep_operation(operation_id).await.unwrap().unwrap();
assert_eq!(parent.state, SemgrepOperationState::Done);
```

For the third test, rename the test database's `targets` table after publishing
and closing the operation:

```rust
sqlx::query("ALTER TABLE targets RENAME TO targets_unavailable")
    .execute(store.pool())
    .await
    .unwrap();
```

The parent `semgrep_enrichment_runs` row remains readable while
`list_all_targets` fails. Assert the parent operation is returned with
`result == None`.

- [ ] **Step 2: Run the focused tests and verify red**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  findings_preserving_stale_base \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment \
  operation_status_survives_result_reconstruction_failure \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because the shared inventory loader rejects an empty set and
status propagates exact-result reconstruction errors.

- [ ] **Step 3: Split scan-time and result-time inventory requirements**

Use `require_nonempty: true` for admission and scan execution. Use
`require_nonempty: false` for exact result reconstruction, then pass the empty
inventory through the existing overlay validator so its candidate-ID/count
mismatch produces `StaleBase` while retaining findings. In
`semgrep_operation`, preserve Task 11A's bounded reconstruction-error handling
and parent `result: None`.

- [ ] **Step 4: Run effective-result tests**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::effective_inventory_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-service/src/semgrep.rs
git commit -m "fix: retain Semgrep history for empty inventories"
```

---

### Task 11D: Prove Cleanup Absence from the Workspace Descriptor

**Files:**
- Modify: `crates/hf-service/src/semgrep.rs`
- Test: `crates/hf-service/src/semgrep.rs`

**Interfaces:**
- Consumes: the canonical managed workspace and exact
  `workspace/semgrep/<operation-uuid>` path.
- Produces: cleanup that opens the managed workspace with `O_NOFOLLOW`,
  verifies pathname/descriptor identity, and uses `openat` for both the
  `semgrep` parent and operation child.

- [ ] **Step 1: Write failing replacement and recreation race tests**

Add Unix tests
`cleanup_rejects_workspace_replacement_while_proving_semgrep_absent`,
`cleanup_rejects_semgrep_parent_recreation_while_proving_absence`, and
`cleanup_accepts_descriptor_proven_missing_semgrep_parent`. Add test-only hooks
immediately before the `semgrep`-parent open and before the final workspace
identity check. Assert that both races return a sandbox-validation error and
that the newly created operation directory remains untouched. The stable
absence case returns `Ok(())`.

- [ ] **Step 2: Run cleanup race tests and verify red**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  cleanup_rejects_ \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because the missing-parent branch currently returns from
path-based `symlink_metadata(...)=NotFound`.

- [ ] **Step 3: Replace the path-based early return**

Open the workspace descriptor first with
`RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC`, verify it matches the canonical
workspace pathname, and call
`openat(workspace_fd, "semgrep", RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC)`.
Treat `ENOENT` as success only after a second workspace pathname/descriptor
identity check and a second
`openat(workspace_fd, "semgrep", RDONLY | DIRECTORY | NOFOLLOW | CLOEXEC)`.
The second lookup must also return `ENOENT`; reject if the parent or exact UUID
child appeared after the first lookup. If the first parent lookup opens, retain
its descriptor and identity through the existing exact-child absence proof or
removal and parent sync. Reject symlinks, non-directories, replaced ancestors,
and a child that appears during the proof. Recovery's exclusive workspace
lease excludes compliant creators. Live-operation cleanup retains only its
shared lease, so the second lookup must also detect another project's
concurrent parent creation and fail safely.

- [ ] **Step 4: Run all snapshot and cleanup tests**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::snapshot_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/hf-service/src/semgrep.rs
git commit -m "fix: prove Semgrep cleanup paths by descriptor"
```

---

### Task 11E: Linearize Terminal Visibility and Finalizing Admission

**Files:**
- Modify: `crates/hf-service/src/semgrep.rs`
- Test: `crates/hf-service/src/semgrep.rs`

**Interfaces:**
- Consumes: database run state, `SemgrepJournal::is_closed`, the process-local
  reservation, and the cross-process project lease from Task 11A.
- Produces:

```rust
enum ActiveSemgrepOperation {
    Cancellable {
        operation_id: Uuid,
        cancellation: CancellationToken,
    },
    Finalizing {
        operation_id: Uuid,
    },
}
```

- [ ] **Step 1: Write failing finalization-window tests**

Add tests
`done_database_row_is_reported_persisting_until_close`,
`same_project_start_is_busy_until_close`,
`finalizing_operation_is_inactive_for_cancel_but_active_for_status`, and
`externally_observed_done_never_regresses_to_failed`. Pause the worker at
`CompletionPausePoint::BeforeClose`, then assert:

```rust
let view = service.semgrep_operation(operation_id).await.unwrap().unwrap();
assert_eq!(view.state, SemgrepOperationState::Persisting);
assert!(view.active);
assert_eq!(
    service.cancel_semgrep_enrichment(operation_id).await.unwrap(),
    SemgrepCancelOutcome::Inactive
);
assert!(service
    .start_semgrep_enrichment(project.clone(), TargetLanguage::C)
    .await
    .unwrap_err()
    .to_string()
    .contains("busy"));
```

Release close and assert the next visible terminal state is `Done`. In the
cleanup-failure case, assert polling sees `Persisting` followed by `Failed` and
never `Done`.

- [ ] **Step 2: Run finalization tests and verify red**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::terminal_visibility_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because completion currently removes the reservation and status
maps the database `done` state directly to external `Done`.

- [ ] **Step 3: Preserve and expose finalization correctly**

Change `claim_completion` to atomically read cancellation and replace the
matching `Cancellable` entry with `Finalizing`. `cancel` returns inactive for
`Finalizing`, `reserve` treats both variants as busy, `is_active` returns true
for both, and `ActiveSemgrepGuard::drop` remains the only successful-removal
path.

In `semgrep_operation`, preserve Task 11A's database-`Done` close gate and
reconstruction-error handling. Add the finalizing-registry behavior required
by this task and keep failed/cancelled mapping unchanged.

- [ ] **Step 4: Run cancellation, publication, and terminal tests**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::lifecycle_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-service --features semgrep-enrichment \
  semgrep::publication_tests \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 5: Run the complete Task 11 regression suite**

Run:

```bash
set -o pipefail
cargo test -p hf-service --features semgrep-enrichment \
  2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add crates/hf-service/src/semgrep.rs
git commit -m "fix: linearize Semgrep terminal visibility"
```

---

### Task 12: Add the Explicit CLI and REST Contracts

**Files:**
- Modify: `crates/hf-cli/Cargo.toml`
- Modify: `crates/hf-cli/src/main.rs`
- Modify: `crates/hf-web/Cargo.toml`
- Modify: `crates/hf-web/src/router.rs`
- Modify: `crates/hf-web/tests/api.rs`

**Interfaces:**
- Consumes: service start/status/cancel/result DTOs only.
- Produces:
  - `oxfuzz discover <project> --lang c --semgrep`;
  - `POST /semgrep/enrich`;
  - `GET /semgrep/enrich/{operation_id}`;
  - `POST /semgrep/enrich/{operation_id}/cancel`.

- [ ] **Step 1: Write failing CLI parsing and REST transport tests**

CLI tests:

```rust
#[test]
fn cli_parses_semgrep_opt_in() {
let cli = Cli::try_parse_from([
    "oxfuzz", "discover", "/tmp/project", "--lang", "c", "--semgrep"
]).unwrap();
assert!(matches!(cli.command, Commands::Discover { semgrep: true, .. }));
}
```

REST tests must use a persistent service container with a recording runtime and assert:

- start returns `202 Accepted` with operation UUID and `staging`;
- status returns the service DTO unchanged, with `result: null` before done and the exact operation result after done;
- unknown operation UUID returns `404`;
- cancel returns `202` for accepted, `409` for inactive, and `404` for unknown;
- project paths pass through `approved_project`;
- invalid language/UUID is `400`;
- no handler constructs a command, score, or path match; and
- feature-off `semgrep_routes()` is empty.

- [ ] **Step 2: Run focused presentation tests and verify red**

Run:

```bash
cargo test -p hf-cli cli_parses_semgrep_opt_in 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-web --features semgrep-enrichment semgrep_ 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
```

Expected: FAIL because the flag/routes do not exist.

- [ ] **Step 3: Wire product features**

Use in both product crates:

```toml
default = ["automotive-scapy", "proof-carrying", "semgrep-enrichment"]
semgrep-enrichment = ["hf-service/semgrep-enrichment"]
```

For CLI, use the exact mapping:

```toml
semgrep-enrichment = [
    "hf-service/semgrep-enrichment",
    "hf-web/semgrep-enrichment",
]
```

- [ ] **Step 4: Implement the CLI opt-in**

Keep omitted behavior byte-for-byte on the existing path. Under the feature:

```rust
#[arg(long)]
semgrep: bool,
```

In `cmd_discover`, perform normal discovery and optional LLM rank first. If `semgrep` is false, serialize the existing `TargetInventory`. If true, validate C/C++, call `start_semgrep_enrichment`, poll `semgrep_operation` at 250 ms while printing state changes to stderr, cancel the exact operation on Ctrl-C, and serialize the done view's exact `result`. Failed/cancelled states return an error containing the bounded service failure. Print the label `Semgrep static-analysis signals` to stderr before the enriched JSON.

- [ ] **Step 5: Implement feature-gated Axum routes**

Merge:

```rust
#[cfg(feature = "semgrep-enrichment")]
fn semgrep_routes() -> Router<AppState> {
    Router::new()
        .route("/semgrep/enrich", post(semgrep_start))
        .route("/semgrep/enrich/{id}", get(semgrep_status))
        .route("/semgrep/enrich/{id}/cancel", post(semgrep_cancel))
}

#[cfg(not(feature = "semgrep-enrichment"))]
fn semgrep_routes() -> Router<AppState> { Router::new() }
```

Handlers parse/marshal only and use `classified_api_error`; they do not poll or recompute.

- [ ] **Step 6: Run CLI/web tests and no-default checks**

Run:

```bash
cargo test -p hf-cli 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo test -p hf-web --features semgrep-enrichment 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo check -p hf-cli --no-default-features
cargo check -p hf-web --no-default-features
```

Expected: tests PASS and feature-off builds contain no Semgrep CLI flag/routes.

- [ ] **Step 7: Commit**

```bash
git add crates/hf-cli/Cargo.toml crates/hf-cli/src/main.rs \
  crates/hf-web/Cargo.toml crates/hf-web/src/router.rs crates/hf-web/tests/api.rs
git commit -m "feat: expose explicit Semgrep CLI and REST operations"
```

---

### Task 13: Add Typed Tauri Transport and Advisory GUI Rendering

**Files:**
- Modify: `crates/hf-gui/src-tauri/Cargo.toml`
- Modify: `crates/hf-gui/src-tauri/src/commands.rs`
- Modify: `crates/hf-gui/src-tauri/src/lib.rs`
- Modify: `crates/hf-gui/src/lib/httpTransport.ts`
- Modify: `crates/hf-gui/src/lib/transport.ts`
- Modify: `crates/hf-gui/src/types/index.ts`
- Modify: `crates/hf-gui/src/views/DiscoverView.tsx`
- Create: `crates/hf-gui/src/lib/semgrep.ts`
- Create: `crates/hf-gui/src/__tests__/semgrepTransport.test.ts`
- Create: `crates/hf-gui/src/__tests__/semgrepSurface.test.ts`
- Modify: `crates/hf-gui/src/i18n.tsx`
- Modify: `crates/hf-gui/src/i18n.extra.ts`

**Interfaces:**
- Consumes: exact service DTOs and REST routes from Task 12.
- Produces Tauri commands:

```rust
semgrep_enrich(project: PathBuf, lang: String) -> Result<Uuid, String>
semgrep_status(operation_id: Uuid) -> Result<SemgrepOperationView, String>
semgrep_cancel(operation_id: Uuid) -> Result<SemgrepCancelOutcome, String>
```

The Tauri status command converts a service `None` into a bounded “operation not found” error; this keeps the TypeScript contract non-null and matches REST's `404`.

TypeScript contracts:

```ts
export type SemgrepOperationState =
  | "staging" | "scanning" | "validating" | "persisting"
  | "done" | "failed" | "cancelled";

export type SemgrepOverlayState =
  | "none" | "current" | "stale_source" | "stale_base" | "incomplete_journal";

export interface SemgrepOperationView {
  operation_id: string;
  project_root: string;
  language: "c" | "cpp";
  state: SemgrepOperationState;
  active: boolean;
  started_at: string;
  ended_at: string | null;
  failure_code: string | null;
  failure_message: string | null;
  result: SemgrepInventory | null;
}

export interface SemgrepTargetCandidate extends TargetCandidate {
  base_score: number;
  semgrep_boost: number;
  effective_score: number;
  semgrep_matched_rule_count: number;
}

export interface SemgrepFinding {
  fingerprint: string;
  rule_id: string;
  severity: "error" | "warning" | "info";
  message: string;
  relative_file: string;
  start_line: number;
  start_col: number;
  end_line: number;
  end_col: number;
  matched_target_id: string | null;
  nominal_weight: number;
}

export interface SemgrepInventory {
  project_root: string;
  language: "c" | "cpp";
  scan_id: string | null;
  source_sha256: string | null;
  overlay_state: SemgrepOverlayState;
  candidates: SemgrepTargetCandidate[];
  findings: SemgrepFinding[];
  call_graph: Record<string, string[]>;
}
```

- [ ] **Step 1: Write failing transport and surface tests**

Transport tests must assert exact mappings:

```ts
semgrep_enrich  -> POST /semgrep/enrich
semgrep_status  -> GET  /semgrep/enrich/{operation_id}
semgrep_cancel  -> POST /semgrep/enrich/{operation_id}/cancel
```

Surface tests must assert:

- **Enrich with Semgrep** appears only after C/C++ discovery;
- the action is explicit and never fires from normal Discover;
- state text covers staging/scanning/validating/persisting/done/failed/cancelled;
- a stop action cancels the exact UUID;
- candidates are rendered in service order with base, `+boost`, effective, and matched-rule count;
- stale source/base/journal state removes boosts from display and says rerun discovery/enrichment;
- failure/cancellation does not replace the prior base inventory; and
- the exact label **Semgrep static-analysis signals** is present, with no “confirmed vulnerability” or “crash” claim.

- [ ] **Step 2: Run frontend tests and verify red**

Run:

```bash
npm --prefix crates/hf-gui test -- --run \
  src/__tests__/semgrepTransport.test.ts \
  src/__tests__/semgrepSurface.test.ts
```

Expected: FAIL because contracts and UI do not exist.

- [ ] **Step 3: Wire the Tauri feature and thin commands**

Use:

```toml
default = ["automotive-scapy", "proof-carrying", "semgrep-enrichment"]
semgrep-enrichment = ["hf-service/semgrep-enrichment"]
```

Gate imports, command functions, and `generate_handler!` entries with the feature. Each command performs only language/UUID argument conversion and one service call.

- [ ] **Step 4: Add HTTP transport and polling helper**

Add the three command-map entries. `semgrep.ts` owns UI polling only:

```ts
export async function waitForSemgrep(
  operationId: string,
  onState: (state: SemgrepOperationState) => void,
  signal: AbortSignal,
): Promise<SemgrepInventory> {
  while (!signal.aborted) {
    const view = await getTransport().invoke<SemgrepOperationView>("semgrep_status", {
      operationId,
    });
    onState(view.state);
    if (view.state === "done") {
      if (!view.result) throw new Error("completed Semgrep operation has no result");
      return view.result;
    }
    if (view.state === "failed" || view.state === "cancelled") {
      throw new Error(view.failure_message ?? `Semgrep enrichment ${view.state}`);
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await getTransport().invoke("semgrep_cancel", { operationId });
  throw new DOMException("Semgrep enrichment cancelled", "AbortError");
}
```

The helper never joins findings, calculates a boost, checks staleness, or sorts candidates.

- [ ] **Step 5: Render the service-owned effective inventory**

Keep normal `TargetInventory` rendering unchanged. After enrichment, replace the rendered view with `SemgrepInventory`, render `candidates` in returned order, and show:

```text
Base 0.740
Semgrep +0.150
Effective 0.890
3 matched rules
Semgrep static-analysis signals
```

Use service `overlay_state` for stale messaging. Do not show raw messages/snippets or call findings vulnerabilities.

- [ ] **Step 6: Run frontend, Tauri, and feature-off checks**

Run:

```bash
npm --prefix crates/hf-gui test
npm --prefix crates/hf-gui run build
npm --prefix crates/hf-gui run lint
cargo test -p hf-gui --features semgrep-enrichment 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo check -p hf-gui --no-default-features
```

Expected: all PASS; no-default Tauri compiles without Semgrep commands.

- [ ] **Step 7: Commit**

```bash
git add crates/hf-gui/src-tauri/Cargo.toml \
  crates/hf-gui/src-tauri/src/commands.rs crates/hf-gui/src-tauri/src/lib.rs \
  crates/hf-gui/src/lib/httpTransport.ts crates/hf-gui/src/lib/transport.ts \
  crates/hf-gui/src/lib/semgrep.ts crates/hf-gui/src/types/index.ts \
  crates/hf-gui/src/views/DiscoverView.tsx crates/hf-gui/src/i18n.tsx \
  crates/hf-gui/src/i18n.extra.ts crates/hf-gui/src/__tests__/semgrepTransport.test.ts \
  crates/hf-gui/src/__tests__/semgrepSurface.test.ts
git commit -m "feat: render advisory Semgrep target enrichment"
```

---

### Task 14: Add Release Documentation, Smoke Gate, and Run All Quality Gates

**Files:**
- Create: `scripts/test-semgrep-sandbox.sh`
- Modify: `scripts/build-release.sh`
- Modify: `docs/guides/GETTING_STARTED.md`
- Modify: `docs/guides/RELEASE_CHECKLIST.md`
- Modify: `README.md`

**Interfaces:**
- Consumes: completed feature and pinned sandbox image.
- Produces: operator documentation, LGPL-2.1/MIT notices and source references, a repeatable container-only release gate, and a fully verified workspace.

- [ ] **Step 1: Write the failing release-contract script**

`scripts/test-semgrep-sandbox.sh` must:

1. resolve the versioned `OXFUZZ_SANDBOX_IMAGE` default;
2. reject `latest`;
3. create a temporary source/output tree;
4. copy the committed vulnerable and clean C fixtures;
5. run the image with `--network none`, `--read-only`, `--cap-drop ALL`, `no-new-privileges`, `--pids-limit 128`, `--memory 4096m`, `--cpus 2`, source read-only, output writable, and 64 MiB `fsize`;
6. invoke `/usr/local/bin/oxfuzz-semgrep-scan`;
7. use a bounded host-side JSON reader to assert empty `errors`/`paths.skipped`, exactly one `raptor-insecure-api-gets` finding in `vulnerable.c`, and no findings in `clean.c`;
8. assert Semgrep `1.169.0`, exact rules commit, and exact tree digest inside the same network-disabled image; and
9. assert both `third_party/semgrep/LICENSE` and `third_party/semgrep-rules/LICENSE` are shipped in the release source; and
10. remove only the temporary directory via its validated `mktemp -d` path.

Run:

```bash
./scripts/test-semgrep-sandbox.sh
```

Expected: FAIL until the script and release integration exist.

- [ ] **Step 2: Document opt-in use, interpretation, and licensing**

Add:

```markdown
oxfuzz discover /path/to/c-project --lang c --semgrep
```

Document:

- normal discovery is unchanged without `--semgrep`;
- results are “Semgrep static-analysis signals,” not confirmed vulnerabilities or crashes;
- base/boost/effective score meaning and the `0.20` cap;
- C/C++ only, one active operation per project, cancellation, stale overlays, and atomic failure;
- offline bundled rules and no registry/user-rule support;
- Semgrep CE `1.169.0` as a separate LGPL-2.1 process with upstream source URL;
- `0xdea/semgrep-rules` MIT snapshot with exact commit/source URL;
- rebuild/update commands and review expectations; and
- CVE Binary Tool is out of scope.

- [ ] **Step 3: Integrate the release gate**

Make `scripts/build-release.sh` verify the default product includes `semgrep-enrichment`, while `OXFUZZ_RELEASE_FEATURES` can still select a feature set. Add an explicit opt-in:

```bash
if [[ "${OXFUZZ_VERIFY_SEMGREP_SANDBOX:-0}" == "1" ]]; then
  ./scripts/test-semgrep-sandbox.sh
fi
```

The normal source-only release build does not download or run Semgrep; release candidates set the variable after building the sandbox.

- [ ] **Step 4: Run the post-development Rust gates in repository order**

Run:

```bash
cargo fmt --all
cargo clippy --fix --allow-dirty --workspace -- -D warnings
cargo clippy --workspace -- -D warnings
cargo check --workspace
cargo test --workspace 2>&1 | { grep -v '^\s*Compiling\|^\s*Running\|^\s*Downloading\|^\s*Downloaded\|^\s*Blocking\|^\s*Finished\|^\s*Doc-tests\|^running\|^test \|^$' || true; } | head -200
cargo doc --workspace --no-deps
```

Expected: every command exits zero and the filtered test output contains no failure.

- [ ] **Step 5: Run dependency, frontend, feature-boundary, and release gates**

Run:

```bash
cargo deny check
npm --prefix crates/hf-gui test
npm --prefix crates/hf-gui run build
npm --prefix crates/hf-gui run lint
cargo check -p hf-discovery --no-default-features
cargo check -p hf-service --no-default-features
cargo check -p hf-web --no-default-features
cargo check -p hf-cli --no-default-features
cargo check -p hf-gui --no-default-features
OXFUZZ_VERIFY_SEMGREP_SANDBOX=1 ./scripts/build-release.sh
```

Expected: all commands PASS. The last command is container-only and requires the already-built pinned sandbox image.

- [ ] **Step 6: Inspect the final diff for safety and scope**

Run:

```bash
git diff --check
if rg -n -i \
  --glob '!docs/superpowers/**' \
  'semgrep.*(confirmed vulnerability|confirmed crash)|--env=.*SEMGREP_APP_TOKEN|--autofix|--config[ =]+(auto|p/|r/)' \
  crates scripts docker README.md docs
then
  exit 1
fi
git status --short
```

Expected: no whitespace errors; no production path claims confirmation, passes a token, enables autofix, or uses a registry rules path; status contains only the intended release/docs task files.

- [ ] **Step 7: Commit**

```bash
git add scripts/test-semgrep-sandbox.sh scripts/build-release.sh \
  docs/guides/GETTING_STARTED.md docs/guides/RELEASE_CHECKLIST.md README.md
git commit -m "docs: add Semgrep enrichment release contract"
```
