# Continuous Integration

oxfuzz is gated on two hosts, and both invoke the same gate definitions from
`scripts/tests/gates.sh`. The duplication is a job list, not a command list, so
the two cannot drift from the single source of truth.

| Host | File | Gates | Purpose |
| --- | --- | --- | --- |
| GitHub Actions | `.github/workflows/ci.yml` | all ten | public repository |
| GitLab CI | `.gitlab-ci.yml` | all ten | current OrbStack origin |

`scripts/tests/gates.sh` is authoritative. Run it locally before pushing:

```bash
scripts/tests/gates.sh            # every gate, in AGENTS.md 4.5 order
scripts/tests/gates.sh clippy test  # only the named gates
```

The ten gates: `fmt`, `clippy`, `check`, `check-no-default-features`, `test`,
`doc`, `deny`, `script-tests`, `frontend-test`, `frontend-lint`.

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
Linux, and Windows when a `v*` tag is pushed, then publishes them as one GitHub
Release. It opens a single draft, has each platform upload into it, and makes the
release public only after every platform succeeds, so a release is never
half-populated.

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
