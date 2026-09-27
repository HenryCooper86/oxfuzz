# Continuous Integration

oxfuzz is gated on two hosts, and both invoke the same gate definitions from
`scripts/tests/gates.sh`. The duplication is a job list, not a command list, so
the two cannot drift from the single source of truth.

| Host | File | Gates | Purpose |
| --- | --- | --- | --- |
| GitHub Actions | `.github/workflows/ci.yml` | twelve required gates; coverage is informational | public repository |
| GitLab CI | `.gitlab-ci.yml` | twelve required gates | current OrbStack origin |

`scripts/tests/gates.sh` is authoritative. Run it locally before pushing:

```bash
scripts/tests/gates.sh            # every gate, in ENGINEERING_PROTOCOL.md 4.5 order
scripts/tests/gates.sh clippy test  # only the named gates
```

The thirteen available gates: `fmt`, `clippy`, `check`,
`check-no-default-features`, `check-feature-matrix`, `test`, `doc`, `deny`,
`coverage`, `script-tests`, `translation-pairing`, `frontend-test`, and
`frontend-lint`. GitHub runs the coverage report without including it in the
required `gates-passed` job; GitLab does not run that informational gate.

`translation-pairing` needs only a Python interpreter -- not even git -- so it
runs beside `script-tests` rather than behind the Rust gates. A documentation
change should not wait on a workspace build to learn that its counterpart is
stale. On GitLab it rides in the `script-tests` job for the same reason: the
Rust image has no `python3`.

## GitHub Actions

`ci.yml` runs on every push and pull request in four parallel jobs: Rust gates
and frontend gates and dependency policy on Linux, plus a `cross-platform`
matrix that runs `check` and `test` on macOS and Windows. It needs no secrets.
Going cross-platform surfaced five real bugs on the first run of each new
platform, so compile-and-test truth is gated everywhere the desktop app ships;
style gates stay Linux-only, and `release.yml` builds the four bundles on tag.

A fifth job, `gates-passed`, aggregates the other four and is the single check
branch protection should require. Two reasons it exists rather than requiring
each job by name:

- A matrix job's check name is derived from its label, so a required check
  pinned to `macOS tests` disappears the moment the label changes.
- `gates-passed` carries `if: always()`. Without it a failed dependency would
  *skip* the aggregate, and GitHub counts a skipped required check as passing --
  the gate would report green for exactly the pipelines it exists to stop. The
  step fails on `failure`, `cancelled`, and `skipped` alike.

`release.yml` builds the Tauri desktop app for macOS (Apple silicon and Intel),
Linux, and Windows when a `v*` tag is pushed. It first checks that the tag and
three version manifests agree, then opens a single draft and has each platform
upload into it. Before publication, it waits for the latest push-triggered
`ci.yml` run on the exact tag commit and requires its `All gates passed` job to
succeed. The informational coverage job remains informational. It checks that
all seven required installers are uploaded, nonempty, and have SHA-256 digests.
It records the CI
run and asset digests in the release body. It also requires the editable draft
acceptance record to name reviewed evidence URLs and hashes for userspace
engines, sandbox isolation, and installed clients. Failed or unavailable CI, a
moved tag, missing evidence, or a missing installer leaves the release as a draft.
After adding reviewed references, rerun the failed publish job. Its first step
inspects the candidate without publication; its second step revalidates and
publishes.

The automated publication check verifies that references and digests are present;
it does not verify the live result behind a link. Review those items using
the [release checklist](RELEASE_CHECKLIST.md) and the
[acceptance record format](../acceptance/README.md).

```bash
git tag v0.1.0 && git push origin v0.1.0
```

`fuzz.yml.example` is an opt-in per-repo fuzz-on-PR gate. Copy it to
`fuzz.yml`, adjust the target/engine/duration, and set the `HF_PROVIDER_API_KEY`
repository secret. It needs Docker on the runner and fails the check on any
crash, uploading SARIF to code scanning.

Actions are pinned to a major version so Dependabot can propose upgrades. Verify
the current major before changing a pin rather than trusting the value in git.

## GitLab CI on an OrbStack runner

`.gitlab-ci.yml` can gate a private GitLab mirror such as
`git@gitlab.example.com:group/oxfuzz.git`. Its jobs use the Docker executor, so
they sit pending until a runner is registered. Register a runner once to close
that gap.

The runner is itself an OrbStack Docker container. Register it with the helper:

```bash
# 1. In the project on the OrbStack GitLab UI:
#    Settings > CI/CD > Runners > "New project runner" -> copy the glrt-... token
# 2. Register and start the runner (idempotent):
GITLAB_RUNNER_TOKEN=glrt-xxxxxxxx scripts/ci/register-gitlab-runner.sh
```

The helper writes the runner configuration into a named Docker volume and starts
a `--restart always` daemon container that spawns one throwaway container per CI
job. Override the instance URL, runner name, or default image with `--url`,
`--name`, `--image`; run with `--help` for details. Legacy registration tokens
are supported with `--registration-token`.

Notes for the OrbStack setup:

- The runner container must resolve and reach `gitlab.example.com`. If DNS
  resolution fails from inside the container, pass the instance's reachable URL
  with `--url`, or attach the runner to the same Docker network as the GitLab
  container.
- The gate jobs do not build or run the fuzzing sandbox, so the runner does not
  need privileged mode. The host Docker socket is mounted only so the Docker
  executor can create job containers.

Verify the runner is picked up:

```bash
docker logs -f oxfuzz-gitlab-runner
```

Then push a branch and confirm the pipeline leaves "pending" and runs.

### Frontend JavaScript budgets

Both desktop and HTTP production builds enforce an 800,000-byte initial
JavaScript budget, including transitive static imports, and an 800,000-byte
limit for each chunk. The total app and vendor limits remain 1,400,000 and
3,700,000 bytes. Navigation-only workflow stages and Settings load on demand;
Dashboard remains eager. These limits guard the built output rather than source
file size.
