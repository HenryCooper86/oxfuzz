# oxfuzz 0.9.5 sandbox build kit

This kit builds the local Docker image required by the desktop app. It contains
only the sandbox recipe, verification scripts, Clang helper source, bundled
Semgrep rules and license notices. Application source and credentials are not
included. The Dockerfile downloads pinned upstream toolchain releases.

Requirements: Docker with its daemon running, Bash, Python 3, internet access
for the initial build, and several GB of free disk space. On Windows use a
WSL 2 distribution integrated with Docker Desktop. The default build targets
the Docker host architecture (Apple silicon/arm64 or x86_64).

Run from this directory:

    ./scripts/build-sandbox.sh

Keep the resulting image named oxfuzz/fuzz-sandbox:0.2.2. Start oxfuzz, configure
a provider, and check sandbox readiness in Settings before opening a project.
Every generated harness still requires the application's review and human
approval flow. Do not execute generated harnesses on the host.

Kernel fuzzing additionally requires a compatible instrumented kernel, rootfs
and guest SSH key. Those files are not shipped in this kit. Physical automotive
interfaces are outside this kit's setup scope.

The build verifies compilers and an offline Semgrep scan. Third-party tools have
their own upstream licenses. See LICENSE, third_party/semgrep/LICENSE,
third_party/semgrep/UPSTREAM.md and third_party/semgrep-rules/LICENSE. The Dockerfile
identifies the source URLs and versions fetched during the build.
