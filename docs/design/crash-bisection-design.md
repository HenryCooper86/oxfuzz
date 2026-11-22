# Crash Bisection

Status: **active implementation**. Owner: `hf-service` (feature
`crash-bisection`), reusing `hf-harness` compilation and the `hf-runtime`
sandbox. Presentation: `oxfuzz bisect`.

## 1. Goal

Answer "which commit introduced this crash" for a triaged crash: given a
revision where the crash input does not crash (`good`) and one where it does
(`bad`, default `HEAD`), find the first commit on the first-parent path between
them at which replaying the crash input under the promoted harness crashes.

The result states what was observed. It does not claim the commit is the root
cause: a commit that only makes an older defect reachable is reported the same
way, and the report says so.

## 2. Inputs and identity

- The crash: its retained input file and the target it belongs to.
- The harness: the active promoted harness source, language, build command and
  sanitizer for the target and engine. Bisection never drafts, repairs or
  promotes a harness, and never changes the target workspace.
- The revisions: `good` and `bad`, validated against a conservative grammar
  (hex ids, branch and tag names, `~N` and `^N` suffixes; no leading `-`, no
  `..`, no whitespace or shell metacharacters) before they reach `git`.

## 3. Reading history without changing the repository

Every `git` call uses `hf_runtime::scrubbed_tokio_command`, never a shell,
with stdin closed, a bounded stdout read and a timeout.

- `git rev-parse --verify <rev>^{commit}` resolves each end to a full id.
- `git rev-list --first-parent --reverse <good>..<bad>` lists the candidates,
  oldest first, capped at 4096 commits (a longer range is refused).
- `git ls-tree -r -z --long <commit>` lists the tree, and
  `git cat-file --batch` streams the selected blobs.

Blobs are read as stored objects. No checkout, worktree, index write, smudge
filter, hook or `export-subst` runs, so repository configuration cannot turn
bisection into host execution and the operator's checkout is untouched.

Only regular files (mode `100644`/`100755`) with a staged source or header
extension are materialized; symbolic links, submodules and every other file
are skipped. Paths must consist of normal components only. File count, single
file size and total size are capped with the staging limits already used for
live builds. Files are written under
`<workspace_root>/<project>/.bisect/<crash id>/<commit>`, which is removed when
the step finishes.

## 4. Testing one commit

1. Materialize the commit's sources (section 3) and copy the crash input in.
2. Compile the promoted harness against them with
   `hf_harness::try_compile_with_options`, in the sandbox, with the same build
   command and flags as the promoted revision.
3. Replay the crash input through the built binary in the sandbox with the
   workspace mounted read-only, the same limits as triage replay.
4. Verdict:
   - `bad`: the replay output is a crash by `hf_crash::looks_like_crash`.
   - `good`: the replay completed and is not a crash.
   - `skip`: the build failed (the harness or flags do not fit that commit) or
     the replay did not complete. A skipped commit is never counted as good or
     bad.

Both ends are tested first. If `bad` does not crash or `good` does, bisection
stops with that statement instead of producing a commit.

## 5. Search

Binary search over the candidate list with skips: when the midpoint is skipped
the nearest untested commit inside the open interval is tried instead. If every
remaining commit is skipped, the result is the range of commits that could not
be told apart, as `git bisect` reports it. At most 40 commits are built per
bisection.

## 6. Approval and safety

Each bisection asks the approval gate once for `Action::CompileHarness` and
once for `Action::RunHarness` before any sandbox work; a denial ends it. The
compile and replay run in the sandbox image pinned by configuration. Nothing
from the bisect workspace is promoted, stored as a harness revision or used by
a campaign.

## 7. Result

A `BisectOutcome`: the resolved `good` and `bad` ids, the first bad commit (id
and subject) or the undecided range, and one line per tested commit with its
verdict and, for a skip, the first line of the reason. The CLI prints it as
text or JSON.

## 8. Limits

- First-parent history only: a defect introduced on a merged side branch is
  attributed to its merge commit.
- The harness and build flags are those of the current tree. A commit whose
  layout differs enough that they do not build is skipped, not guessed.
- C and C++ harnesses on libFuzzer, AFL++ and honggfuzz. Rust (cargo-fuzz),
  Go and syzkaller targets are refused.
- Dependency-fetching builds are out of reach, as for live builds: the sandbox
  has no network.

## 9. Testing

Unit: revision grammar, `ls-tree` parsing, path and size admission, the search
with scripted verdicts (clean, skips at the midpoint, all-skipped tail,
non-reproducing ends). Integration against a temporary git repository for the
history reader. Live: a repository with a planted regression, bisected through
the CLI in the sandbox.
