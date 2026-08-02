# Report Integrity and Semgrep Portability Design

Status: approved for implementation. Owner: oxfuzz core team.

## 1. Goal

Restore a clean workspace test baseline on macOS and restricted CI runners,
and make deterministic campaign reports structurally safe when retained paths,
target metadata, CASR evidence, or provider-authored bug-report fields contain
Markdown delimiters.

This change does not alter the Semgrep sandbox, recovery, cleanup, or canonical
path policy. It does not change report schemas, persisted data, public service
method signatures, or localization vocabulary.

## 2. Evidence and Root Causes

### 2.1 Semgrep test portability

The workspace test suite currently has five reproducible failures in
`hf-service`:

- three lifecycle recovery tests pass `workspace_root()` directly to a helper
  that requires the canonical managed workspace;
- the runtime-contract test compares a canonical operation path with the raw
  configured workspace path; and
- the source-snapshot test requires creation of a Unix-domain socket, which is
  rejected with `EPERM` by restricted runners.

On macOS, `$TMPDIR` is commonly spelled through `/var`, while
`canonicalize()` resolves the same directory through `/private/var`. Production
Semgrep staging and recovery already use `initialize_workspace_root()`, which
returns the validated canonical root. The failing tests bypass that production
boundary and therefore compare or pass inconsistent path representations.

The socket fixture is not necessary to exercise the source-snapshot branch.
The production predicate rejects every non-regular entry. A directory exercises
the same predicate without requiring permission to create an IPC endpoint.

### 2.2 Campaign report structure

`hf-service::report` already has an `escape_inline` helper, but it is used only
in the findings summary and replaces only a subset of Markdown delimiters.
Other retained or provider-derived values are written directly into headings,
tables, blockquotes, bullets, and fenced blocks. Pipes can split table cells,
backticks can close code spans, newlines can create headings, and a line of
three backticks in stack or suggested-fix evidence can close a fenced block.

The automotive renderer demonstrates the local expectation that values are
escaped before insertion. The general renderer needs the same property while
preserving technical evidence rather than deleting it.

## 3. Design

### 3.1 Context-specific Markdown rendering

Keep all report assembly in `hf-service`. Add three private renderer helpers:

1. `escape_markdown_text(&str) -> String` normalizes CR/LF to spaces and
   backslash-escapes Markdown punctuation. It is used for provider-authored or
   retained prose placed in headings, blockquotes, and ordinary paragraphs.
2. `inline_code(&str) -> String` normalizes CR/LF, escapes table pipes, finds
   the longest run of backticks in the value, and wraps the value in a longer
   CommonMark code-span delimiter. Technical tokens remain readable and exact.
3. `fenced_code_block(info: &str, value: &str) -> String` chooses a backtick
   fence longer than any backtick run in the block and emits a complete block
   with the requested information string. Stack evidence and suggested diffs
   cannot terminate their own container.

Apply the helpers to every data-bearing report site:

- report title, project and target summary;
- candidate symbol, location, signature, and rationale;
- finding title, signature, input path, CASR detail, and stack;
- bug-report severity, summary, reproduction steps, root cause, and suggested
  fix.

Static labels, numeric values, timestamps, and closed Rust enums remain direct
output because they do not cross an untrusted string boundary.

### 3.2 Fence-aware export transforms

`report_export` currently toggles fenced state on any line starting with three
backticks. Replace that boolean heuristic with a small private fence parser
that records marker type and opening length. A closing fence must use the same
marker and at least the opening length, with no non-whitespace suffix.

Use the parser in both transforms:

- `strip_mermaid_blocks` removes only a complete fence whose information
  string identifies Mermaid and does not stop on shorter backtick runs inside
  that block;
- `insert_break_hints` leaves slash characters unchanged inside both backtick
  and tilde fenced blocks, including dynamically sized fences.

The Markdown, HTML, DOCX, and PDF entrypoints remain unchanged.

### 3.3 Semgrep test corrections

In lifecycle tests, obtain the workspace through
`initialize_workspace_root()` before passing it to recovery or comparing it
with runtime calls. This matches the production boundary and retains the
fail-closed canonical-directory validation.

Replace the Unix socket fixture with a directory named like a source file and
rename the test to describe rejection of non-regular entries. Keep the symlink
and identity-replacement cases in the same test, so the original security
coverage remains present.

## 4. Data Flow

For report generation, `ServiceContainer` continues to gather `ReportData`.
`render_markdown` selects a context-specific helper at the final interpolation
boundary. Export receives valid Markdown and either writes it unchanged or
applies a fence-aware transform before invoking the existing renderer.

For Semgrep, service behavior is unchanged:

```text
configured path -> initialize/validate -> canonical managed workspace
                -> stage/recover/cleanup with descriptor-safe validation
```

Tests will now enter through the same initialize/validate boundary.

## 5. Error and Safety Semantics

Rendering helpers are total and allocation-only; they introduce no new error
surface. They preserve the original text content while preventing it from
changing document structure.

No Semgrep validation is relaxed. Tests will not treat non-canonical paths as
valid and will not skip non-regular-file coverage. No generated harness,
Semgrep engine, or fuzzing engine is executed on the host.

## 6. Verification

TDD order:

1. Add a report regression test containing pipes, backticks, newlines,
   heading syntax, and embedded fence delimiters; verify that it fails because
   the current renderer leaks structure.
2. Add export-transform tests for long backtick fences and tilde fences; verify
   that the current three-backtick toggle fails.
3. Implement only the private rendering and fence-parsing helpers needed to
   make those tests pass.
4. Re-run the five currently failing Semgrep tests after their test-fixture
   corrections.
5. Run the affected `hf-service` report and library tests.
6. Run all repository-mandated Rust quality gates in order, including the
   filtered workspace test suite, followed by the documented dependency and
   GUI gates.

Success means the hostile values remain visible as data, produce no injected
heading or broken table/fence, all five Semgrep failures are gone, and no
existing localized report output changes for ordinary values.

## 7. Alternatives

### Test-only stabilization

Correct only the five Semgrep tests. This is lower risk but leaves a confirmed
production report-integrity defect, so it is rejected.

### Global Markdown abstraction

Introduce a shared Markdown AST or renderer across campaign and automotive
reports. This could reduce duplication but is a broader architectural change
than the defects require and risks altering localized output. It is deferred.

### Sanitize data at ingestion

Mutate paths, findings, or provider-authored fields before persistence. This
would destroy retained evidence and mix presentation concerns into domain and
storage layers, so it is rejected. Escaping belongs at the rendering boundary.
