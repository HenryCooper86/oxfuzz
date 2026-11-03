# Continuous Integration

Pull requests to the public repository are gated by GitHub Actions. Every CI
job invokes named gates from `scripts/tests/gates.sh`, which is the single
definition of what each gate runs. Workflow files decide only which gates run
where, so they cannot drift from the commands a contributor runs locally.

## Running the gates locally

```bash
scripts/tests/gates.sh              # every gate, in ENGINEERING_PROTOCOL.md 4.5 order
scripts/tests/gates.sh clippy test  # only the named gates
```

The fifteen standard gates are `fmt`, `clippy`, `check`,
`check-no-default-features`, `check-feature-matrix`, `test`,
`feature-behavior`, `doc`, `deny`, `coverage`, `performance`, `script-tests`,
`translation-pairing`, `frontend-test`, and `frontend-lint`. A sixteenth gate,
`clang-analysis`, is run only by name because it needs a built LLVM 18
qualification image.

Some gates need tools beyond the Rust toolchain: `deny` needs `cargo-deny`;
`coverage` needs `cargo-llvm-cov`, the `llvm-tools-preview` rustup component,
and Python 3; `performance`, `script-tests`, and `translation-pairing` need
Python 3; `script-tests` and the frontend gates need Node. On Linux, any gate
that builds the whole workspace also needs the packages from
`scripts/ci/install-linux-deps.sh`, because the Tauri desktop crate is a
workspace member.

What the less obvious gates do:

- `feature-behavior` executes disabled API responses and selected
  standalone-feature service tests, which compile-only feature checks cannot
  establish.
- `coverage` produces structured per-crate coverage reports. On Linux it
  enforces the [recorded baseline](../../config/quality/coverage-baseline.json)
  and fails if a package is missing or its line coverage regresses. On other
  hosts it reports a diagnostic measurement.
- `performance` compiles the dispatch benchmark and tests the retained-report
  validators. It does not impose timing thresholds on shared CI runners.
- `translation-pairing` needs only a Python interpreter, not even git, so it
  runs before the Rust gates. A documentation change should not wait on a
  workspace build to learn that its translated counterpart is stale.

## GitHub Actions

`ci.yml` runs on every push and pull request. It needs no secrets. Its jobs
run in parallel:

| Job | Runs |
| --- | --- |
| Rust gates (Linux) | `script-tests`, `translation-pairing`, `fmt`, `clippy`, `check`, `check-no-default-features`, `check-feature-matrix`, `test`, `feature-behavior`, `doc`, `performance` |
| macOS tests, Windows tests | `check` and `test` |
| Frontend gates | `frontend-test` (install, audit, tests, production build) and `frontend-lint` |
| Dependency policy | `deny` |
| Coverage report | `coverage`, with the per-crate JSON reports uploaded as an artifact |
| Clang semantic pipeline | builds the optional `clang-analysis` CLI feature and the LLVM 18 image, then runs `clang-analysis` |

Going cross-platform surfaced real bugs on the first run of each new platform,
so compile-and-test truth is gated everywhere the desktop app ships. Style
gates stay Linux-only.

A final job, `gates-passed` (shown as **All gates passed**), aggregates the
others and is the single check branch protection should require. Two reasons
it exists rather than requiring each job by name:

- A matrix job's check name is derived from its label, so a required check
  pinned to `macOS tests` disappears the moment the label changes.
- `gates-passed` carries `if: always()`. Without it a failed dependency would
  *skip* the aggregate, and GitHub counts a skipped required check as passing,
  so the gate would report green for exactly the pipelines it exists to stop.
  The step fails on `failure`, `cancelled`, and `skipped` alike.

Actions are pinned to a major version tag. Verify the current major before
changing a pin rather than trusting the value in git.

### Release workflow

`release.yml` builds the Tauri desktop app for macOS (Apple silicon and Intel),
Linux, and Windows when a `v*` tag is pushed. It first checks that the tag and
three version manifests agree, then opens a single draft and has each platform
upload into it. Before publication, it waits for the latest push-triggered
`ci.yml` run on the exact tag commit and requires its `All gates passed` job to
succeed, including the Linux coverage baseline. It checks that all seven
required installers are uploaded, nonempty, and have SHA-256 digests. It
records the CI run and asset digests in the release body. It also requires the
editable draft acceptance record to name reviewed evidence URLs and hashes for
userspace engines, sandbox isolation, and installed clients. Failed or
unavailable CI, a moved tag, missing evidence, or a missing installer leaves
the release as a draft. After adding reviewed references, rerun the failed
publish job. Its first step inspects the candidate without publication; its
second step revalidates and publishes.

The automated publication check verifies that references and digests are
present; it does not verify the live result behind a link. Review those items
using the [release checklist](RELEASE_CHECKLIST.md) and the
[acceptance record format](../acceptance/README.md).

```bash
git tag v0.1.0 && git push origin v0.1.0
```

### Other workflows

- `performance.yml` is a manually dispatched diagnostic on `main` that records
  release-profile measurements on Linux, macOS, and Windows runners. It is not
  a merge gate.
- `fuzz.yml.example` is an opt-in per-repository fuzz-on-PR gate. Copy it to
  `fuzz.yml`, adjust the target, engine, and duration, and set the
  `HF_PROVIDER_API_KEY` repository secret. It needs Docker on the runner and
  fails the check on any crash, uploading SARIF to code scanning.
- `sandbox-image.yml` is a manually dispatched build of the fuzzing sandbox
  image on native amd64 and arm64 runners, verified with
  `scripts/build-sandbox.sh`. See below.

### Publishing the sandbox image

Every user currently builds `oxfuzz/fuzz-sandbox` locally, which is the
slowest part of a first install. `sandbox-image.yml` can publish it instead:

1. Run **Actions -> Sandbox image -> Run workflow** with `publish` unticked.
   This builds and verifies both architectures without pushing anything.
2. Before ticking `publish`, confirm the license obligations of distributing
   the image. It contains GPL-licensed binaries (SymCC and Ubuntu packages)
   and LGPL Semgrep, whose notices live under `third_party/`. The automotive
   Scapy sidecar is not part of this image.
3. With `publish` ticked, the workflow pushes
   `ghcr.io/<owner>/oxfuzz-fuzz-sandbox:<version>-<arch>` and a multi-arch
   `<version>` tag. Make the GHCR package public in its package settings.

Users then run `./scripts/pull-sandbox.sh`, which pulls that tag, retags it as
the `oxfuzz/fuzz-sandbox:<version>` name the runtime expects, and runs the same
compiler verification as a local build. The version comes from
`scripts/build-sandbox.sh`, so bump it there (and in
`crates/hf-runtime/src/config.rs`) when the Dockerfile changes.

## Frontend JavaScript budgets

Both desktop and HTTP production builds enforce an 800,000-byte initial
JavaScript budget, including transitive static imports, and an 800,000-byte
limit for each chunk. The total app and vendor limits remain 1,400,000 and
3,700,000 bytes. Navigation-only workflow stages and Settings load on demand;
Dashboard remains eager. These limits guard the built output rather than source
file size.

## Maintainer's internal GitLab mirror

This section applies only to the maintainer's private GitLab mirror.
Contributors on GitHub do not need it; open pull requests on GitHub.

`.gitlab-ci.yml` gates merges on that mirror. Like `ci.yml`, it invokes named
gates from `scripts/tests/gates.sh` rather than restating commands, so the two
hosts run the same checks. It runs the fifteen standard gates in five jobs
(`rust`, `frontend`, `script-tests`, `supply-chain`, `coverage`). On GitLab,
`translation-pairing` rides in the `script-tests` job because the Rust image
has no `python3`. Merge request descriptions on the mirror use
`.gitlab/merge_request_templates/Default.md`.

### Registering an OrbStack runner

The mirror is represented here as `git@gitlab.example.com:group/oxfuzz.git`.
Its jobs use the Docker executor, so they sit pending until a runner is
registered. The runner is itself an OrbStack Docker container. Register it once
with the helper:

```bash
# 1. In the project on the GitLab UI:
#    Settings > CI/CD > Runners > "New project runner" -> copy the glrt-... token
# 2. Register and start the runner (idempotent):
GITLAB_RUNNER_TOKEN=glrt-xxxxxxxx scripts/ci/register-gitlab-runner.sh
```

The helper writes the runner configuration into a named Docker volume and
starts a `--restart always` daemon container that spawns one throwaway
container per CI job. Override the instance URL, runner name, or default image
with `--url`, `--name`, `--image`; run with `--help` for details. Legacy
registration tokens are supported with `--registration-token`.

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
