# oxfuzz sandbox image
#
# Provides: clang (with libFuzzer), AFL++, honggfuzz, the syzkaller toolchain
# (Go + qemu + syz-* binaries), and common build tools. Used by hf-runtime
# DockerRuntime to build harnesses and run fuzzers in isolation.
#
# Multi-arch: built per fuzzing target via `docker build --platform=linux/amd64`
# or `linux/arm64` so the produced harness binaries match the target ABI.

ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90
FROM ${UBUNTU_IMAGE}

LABEL org.opencontainers.image.title="oxfuzz sandbox" \
      org.opencontainers.image.description="Sandbox toolchain for oxfuzz: clang and libFuzzer, AFL++, honggfuzz, syzkaller, SymCC, CASR, Semgrep CE, Jazzer, Jazzer.js, Atheris and Bazel. Third-party licences and corresponding-source locations are in /usr/share/doc/oxfuzz-sandbox/NOTICES.md." \
      org.opencontainers.image.licenses="MIT AND Apache-2.0 AND BSD-3-Clause AND GPL-2.0-or-later AND GPL-3.0-or-later AND LGPL-2.1-or-later AND LGPL-3.0-or-later AND LicenseRef-Mixed-Ubuntu-packages" \
      org.opencontainers.image.version="0.2.4" \
      org.opencontainers.image.source="https://github.com/HenryCooper86/oxfuzz"

ENV DEBIAN_FRONTEND=noninteractive

# Install clang, build tools, AFL++, libFuzzer dev, and clang runtime (asan/fuzzer).
# meson + autoconf/automake/libtool cover the Meson and Autotools build profiles
# alongside CMake and plain Make (docs/design/build-doctor-design.md).
# The first apt-get update of the build is timestamped (UTC, rounded up to the
# next whole hour) into ubuntu-snapshot.txt. Ubuntu binaries are not
# version-pinned, so that time is what locates the matching source packages on
# https://snapshot.ubuntu.com/ubuntu/<timestamp>/ (docker/sandbox/NOTICES.md).
# Later layers of a cached rebuild may install newer versions; packages.tsv
# lists what the image actually contains.
RUN mkdir -p /usr/share/doc/oxfuzz-sandbox \
    && date -u -d "@$(( ($(date +%s) + 3599) / 3600 * 3600 ))" +%Y%m%dT%H%M%SZ \
        > /usr/share/doc/oxfuzz-sandbox/ubuntu-snapshot.txt \
    && apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    lld \
    libclang-rt-18-dev \
    libclang-18-dev \
    llvm-18-dev \
    make \
    cmake \
    ninja-build \
    meson \
    autoconf \
    automake \
    libtool \
    git \
    wget \
    ca-certificates \
    python3 \
    afl++ \
    libfuzzer-18-dev \
    && rm -rf /var/lib/apt/lists/*

# markitdown: convert documents (PDF/Office/HTML/CSV) to Markdown for the
# knowledge base. Offline formats only -- runs under --network=none.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3-pip python3-venv \
    && python3 -m pip install --no-cache-dir --break-system-packages \
       'markitdown[pdf,docx,pptx,xlsx]==0.1.6' \
    && rm -rf /var/lib/apt/lists/*

# Build the pinned honggfuzz 2.6 release from source (not in Ubuntu repos).
ARG HONGGFUZZ_COMMIT=83a8415a372d84dcc69ac1e2c2f152190bcf76d1
COPY docker/sandbox/honggfuzz-profile-flush.patch /tmp/honggfuzz-profile-flush.patch
COPY docker/sandbox/honggfuzz-periodic-stats.patch /tmp/honggfuzz-periodic-stats.patch
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbfd-dev \
    libunwind-dev \
    && git init /tmp/honggfuzz \
    && git -C /tmp/honggfuzz remote add origin https://github.com/google/honggfuzz.git \
    && git -C /tmp/honggfuzz fetch --depth=1 origin "${HONGGFUZZ_COMMIT}" \
    && git -C /tmp/honggfuzz checkout --detach FETCH_HEAD \
    && git -C /tmp/honggfuzz apply --check /tmp/honggfuzz-profile-flush.patch \
    && git -C /tmp/honggfuzz apply /tmp/honggfuzz-profile-flush.patch \
    && git -C /tmp/honggfuzz apply --check /tmp/honggfuzz-periodic-stats.patch \
    && git -C /tmp/honggfuzz apply /tmp/honggfuzz-periodic-stats.patch \
    && cd /tmp/honggfuzz && make && make install \
    && rm -rf /tmp/honggfuzz /tmp/honggfuzz-profile-flush.patch /tmp/honggfuzz-periodic-stats.patch \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# syzkaller (kernel fuzzer) toolchain.
#
# syzkaller is written in Go and drives qemu VMs running a KCOV-enabled kernel.
# We install Go + qemu and build the host tools (syz-manager, syz-fuzzer, ...).
# Note: a live kernel-fuzzing campaign still needs a built kernel image + a
# manager.cfg supplied at runtime; this layer provides the toolchain only.
#
# IMPORTANT: syzkaller tracks a very recent Go toolchain (its go.mod currently
# requires Go >= 1.26), newer than the distro `golang-go` package. We install a
# checksum-verified Go toolchain and keep automatic toolchain downloads off.
# ---------------------------------------------------------------------------
ARG GO_VERSION=1.26.5
ARG GO_SHA256_AMD64=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
ARG GO_SHA256_ARM64=fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49
RUN arch="$(dpkg --print-architecture)" \
    && wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -O /tmp/go.tgz \
    && case "$arch" in \
         amd64) checksum="$GO_SHA256_AMD64" ;; \
         arm64) checksum="$GO_SHA256_ARM64" ;; \
         *) echo "unsupported Go architecture: $arch" >&2; exit 1 ;; \
       esac \
    && echo "${checksum}  /tmp/go.tgz" | sha256sum -c - \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:/root/go/bin:/opt/syzkaller/bin:${PATH}"
ENV GOTOOLCHAIN=local

ARG SYZKALLER_COMMIT=27a8bd60fa3a186e2b15eb9c4706689e3d2be6f2
RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    qemu-system-arm \
    qemu-utils \
    flex \
    bison \
    bc \
    libelf-dev \
    libssl-dev \
    && git init /opt/syzkaller \
    && git -C /opt/syzkaller remote add origin https://github.com/google/syzkaller.git \
    && git -C /opt/syzkaller fetch --depth=1 origin "${SYZKALLER_COMMIT}" \
    && git -C /opt/syzkaller checkout --detach FETCH_HEAD \
    && make -C /opt/syzkaller \
    && ln -sf /opt/syzkaller/bin/syz-manager /usr/local/bin/syz-manager \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------------------
# CASR (Crash Analysis and Severity Report) -- crash triage: exploitability
# classification (EXPLOITABLE/PROBABLY/NOT), severity, crash line, and
# stack-trace clustering/dedup. casr-* run the (sanitizer/gdb) harness under
# ptrace, so hf-runtime invokes the sandbox with SYS_PTRACE + unconfined
# seccomp for triage. gdb + lsb-release are CASR runtime deps.
#
# casr is installed from crates.io via a temporary Rust toolchain whose
# binaries land in /usr/local/bin; the toolchain + caches are then removed to
# keep the image slim. pkg-config/libssl-dev satisfy the build.
# ---------------------------------------------------------------------------
ARG CASR_VERSION=2.13.1
ARG CASR_BUILD_TOOLCHAIN=1.94.0
# gdb-command's timed execution waits before reading pipes and can deadlock
# while printing symbolized stacks/mappings. Keep timeouts and drain concurrently.
COPY docker/sandbox/gdb-command-output.patch /tmp/gdb-command-output.patch
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    lsb-release \
    curl \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${CASR_BUILD_TOOLCHAIN}" \
    && . "$HOME/.cargo/env" \
    && curl -sSfL https://static.crates.io/crates/gdb-command/gdb-command-0.7.8.crate -o /tmp/gdb-command.crate \
    && echo "73b2762e2f2c0768e1137b33e9f7cf31599994e96496f4e020cc16e0d4e66319  /tmp/gdb-command.crate" | sha256sum -c - \
    && tar -xzf /tmp/gdb-command.crate -C /tmp \
    && patch -d /tmp/gdb-command-0.7.8 -p1 < /tmp/gdb-command-output.patch \
    && cargo test --manifest-path /tmp/gdb-command-0.7.8/Cargo.toml --lib output_regressions \
    && cargo install casr --version "${CASR_VERSION}" --root /usr/local --locked \
        --config 'patch.crates-io.gdb-command.path="/tmp/gdb-command-0.7.8"' \
    && rm -rf /tmp/gdb-command* \
    && rustup self uninstall -y \
    && rm -rf "$HOME/.cargo" "$HOME/.rustup"

# ---------------------------------------------------------------------------
# Rust + cargo-fuzz (libFuzzer) toolchain for fuzzing Rust crates.
#
# cargo-fuzz drives libfuzzer-sys and requires a nightly toolchain (it passes
# -Z sanitizer flags), so we install rustup with nightly as the default
# toolchain plus cargo-fuzz, and KEEP them (unlike the casr layer above, which
# removes its temporary toolchain). Installed under /opt/rust so it is
# independent of the casr layer's $HOME/.cargo cleanup. hf-runtime builds a Rust
# harness by scaffolding a cargo-fuzz project beside the staged crate and running
# `cargo fuzz build`; the produced libFuzzer binary is then driven by the normal
# libFuzzer run path.
# ---------------------------------------------------------------------------
ENV RUSTUP_HOME=/opt/rust/rustup \
    CARGO_HOME=/opt/rust/cargo \
    PATH=/opt/rust/cargo/bin:${PATH}
ARG RUST_NIGHTLY=nightly-2026-06-10
ARG CARGO_FUZZ_VERSION=0.13.2
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "${RUST_NIGHTLY}" \
    && rustup component add --toolchain "${RUST_NIGHTLY}" llvm-tools-preview \
    && cargo install cargo-fuzz --version "${CARGO_FUZZ_VERSION}" --locked

# Vendor the fuzz-target dependency that cargo-fuzz-generated projects declare
# (libfuzzer-sys and its transitive crates), with a crates.io source
# replacement in the global cargo config: harness builds run with networking
# disabled, so dependency resolution must be fully local. Exact versions are
# pinned by this image build; the probe project exists only to compute the
# vendor set and is removed afterwards.
RUN mkdir -p /opt/vendor-probe/src \
    && printf '[package]\nname = "vendor-probe"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\nlibfuzzer-sys = "0.4"\n' \
        > /opt/vendor-probe/Cargo.toml \
    && printf 'pub fn probe() {}\n' > /opt/vendor-probe/src/lib.rs \
    && cd /opt/vendor-probe \
    && cargo vendor /opt/rust/vendor > /tmp/vendor-config.toml \
    && { cat /tmp/vendor-config.toml; printf '[net]\noffline = true\n'; } \
        >> "${CARGO_HOME}/config.toml" \
    && rm -rf /opt/vendor-probe /tmp/vendor-config.toml

# Fail the image build when any advertised toolchain is absent.
# honggfuzz 2.6 exposes help, but intentionally has no version flag.
RUN clang --version \
    && afl-fuzz --version \
    && honggfuzz --help >/dev/null \
    && command -v syz-manager \
    && command -v casr-san \
    && command -v casr-cluster \
    && cargo fuzz --version \
    && cargo +"${RUST_NIGHTLY}" --version

# ---------------------------------------------------------------------------
# SymCC -- concolic execution for corpus enrichment.
#
# Built against LLVM 17, not the image default: SymCC's own CMakeLists warns it
# targets LLVM 8 through 17 and is "unlikely to work" outside that range, and
# Ubuntu 24.04 defaults to 18. LLVM 17 is packaged, so no external apt source.
#
# SYMCC_RT_BACKEND=qsym is required, not preferred: only the qsym backend writes
# solved inputs to SYMCC_OUTPUT_DIR. The "simple" backend solves the constraint
# and prints it to stdout without writing a file, and announces at startup that
# it exists for debugging SymCC itself. Note QSYM_BACKEND is not an option in
# current SymCC and does nothing if passed.
#
# The runtime is a git submodule, so a plain clone leaves it empty and cmake
# fails naming the directory rather than the cause. zlib/zstd dev packages are
# needed because LLVM's cmake exports reference ZLIB::ZLIB.
# ---------------------------------------------------------------------------
ARG SYMCC_COMMIT=3b8acabf06c83b92facccde7f6dfb191b1a163b3
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang-17 llvm-17 llvm-17-dev llvm-17-tools lld-17 libclang-rt-17-dev \
    libz3-dev z3 zlib1g-dev libzstd-dev \
    && git init /opt/symcc \
    && git -C /opt/symcc remote add origin https://github.com/eurecom-s3/symcc.git \
    && git -C /opt/symcc fetch --depth=1 origin "${SYMCC_COMMIT}" \
    && git -C /opt/symcc checkout --detach FETCH_HEAD \
    && git -C /opt/symcc submodule update --init --recursive --depth=1 \
    && cmake -S /opt/symcc -B /opt/symcc/build -G Ninja \
       -DCMAKE_BUILD_TYPE=Release \
       -DCMAKE_C_COMPILER=/usr/lib/llvm-17/bin/clang \
       -DCMAKE_CXX_COMPILER=/usr/lib/llvm-17/bin/clang++ \
       -DLLVM_DIR=/usr/lib/llvm-17/lib/cmake/llvm \
       -DSYMCC_RT_BACKEND=qsym \
       -DZ3_TRUST_SYSTEM_VERSION=ON \
    && cmake --build /opt/symcc/build \
    && ln -sf /opt/symcc/build/symcc /usr/local/bin/symcc \
    && rm -rf /var/lib/apt/lists/*

# Prove the wrapper instruments AND writes a solved input. Checking that it
# compiles is not sufficient: both backends compile, only qsym writes a file,
# and a layer that builds but never solves would report empty passes forever.
RUN printf '%s\n' \
      '#include <stdio.h>' \
      '#include <stdlib.h>' \
      'int main(int argc, char **argv) {' \
      '    FILE *f = fopen(argv[1], "rb");' \
      '    unsigned char b[8] = {0};' \
      '    fread(b, 1, 4, f);' \
      '    if (b[0] == 0xDE && b[1] == 0xAD) { abort(); }' \
      '    return 0;' \
      '}' > /tmp/symcc-selftest.c \
    && symcc /tmp/symcc-selftest.c -o /tmp/symcc-selftest \
    && printf 'AAAA' > /tmp/symcc-selftest.bin \
    && mkdir -p /tmp/symcc-selftest-out \
    && SYMCC_OUTPUT_DIR=/tmp/symcc-selftest-out \
       SYMCC_INPUT_FILE=/tmp/symcc-selftest.bin \
       /tmp/symcc-selftest /tmp/symcc-selftest.bin \
    && test "$(ls -1 /tmp/symcc-selftest-out | wc -l)" -gt 0 \
    && rm -rf /tmp/symcc-selftest*

# Semgrep CE and its reviewed C rules are pinned and verified at image build
# time. Runtime scanning uses only the fixed wrapper and bundled rules below.
ARG SEMGREP_VERSION=1.169.0
RUN python3 -m pip install --no-cache-dir --break-system-packages \
    "semgrep==${SEMGREP_VERSION}"
ENV SEMGREP_SETTINGS_FILE=/tmp/oxfuzz-semgrep-settings.yml \
    SEMGREP_LOG_FILE=/tmp/oxfuzz-semgrep.log \
    SEMGREP_SEND_METRICS=off

COPY third_party/semgrep-rules /opt/oxfuzz/semgrep-rules
COPY scripts/semgrep-tree-digest.py /opt/oxfuzz/semgrep-tree-digest.py
COPY docker/sandbox/semgrep/scan.sh /usr/local/bin/oxfuzz-semgrep-scan
# Do not add `semgrep scan --validate` here: Semgrep CE 1.169.0 fetches the
# registry-hosted p/semgrep-rule-lints pack even for an entirely local config.
# The network-disabled fixed-wrapper fixture scan is the authoritative gate.
RUN chmod 0755 /usr/local/bin/oxfuzz-semgrep-scan /opt/oxfuzz/semgrep-tree-digest.py \
    && test "$(semgrep --version --disable-version-check)" = "${SEMGREP_VERSION}" \
    && test -z "$(find /opt/oxfuzz/semgrep-rules/rules/c -type l -print -quit)" \
    && test "$(python3 /opt/oxfuzz/semgrep-tree-digest.py /opt/oxfuzz/semgrep-rules/rules/c)" = \
       "$(cat /opt/oxfuzz/semgrep-rules/RULES_SHA256)"

# Build Doctor observes plain Make through Bear. Install this late so adding
# the observer does not rebuild the pinned compiler and engine toolchains.
RUN apt-get update && apt-get install -y --no-install-recommends bear \
    && rm -rf /var/lib/apt/lists/* \
    && bear --version \
    && cmake --version \
    && make --version \
    && pkg-config --version

# `autoreconf -i` runs autopoint for every project whose configure.ac uses
# AM_GNU_GETTEXT (libexif and most GNU-style libraries); without it the
# Autotools profile fails at its first step. Installed late for the same
# reason as Bear.
RUN apt-get update && apt-get install -y --no-install-recommends autopoint gettext \
    && rm -rf /var/lib/apt/lists/* \
    && autopoint --version \
    && msgfmt --version

WORKDIR /work

CMD ["true"]

# Compiler-resolved C/C++ declarations and call graph metadata. LLVM C++ APIs
# remain inside this immutable image; the Rust service consumes versioned JSON.
COPY tools/clang-analysis /tmp/oxfuzz-clang-analysis
RUN cmake -S /tmp/oxfuzz-clang-analysis -B /tmp/oxfuzz-clang-build \
      -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm \
      -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang \
    && cmake --build /tmp/oxfuzz-clang-build -j2 \
    && cmake --install /tmp/oxfuzz-clang-build \
    && rm -rf /tmp/oxfuzz-clang-analysis /tmp/oxfuzz-clang-build

# syz-manager uses ssh to check guest readiness and scp to install its executor.
RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/* \
    && command -v ssh && command -v scp

# --- Image 0.2.3 additions (managed-language engines, binary-only targets,
# C++ MemorySanitizer). Appended so the pinned toolchains above keep their
# build cache.

# Python targets: Atheris (coverage-guided, libFuzzer-based). PyPI ships no wheel for
# CPython 3.12 on linux/arm64, so the pinned sdist is built here.
ARG ATHERIS_VERSION=3.0.0
ARG ATHERIS_SHA256=1f0929c7bc3040f3fe4102e557718734190cf2d7718bbb8e3ce6d3eb56ef5bb3
RUN apt-get update && apt-get install -y --no-install-recommends python3-dev \
    && rm -rf /var/lib/apt/lists/* \
    && printf 'atheris==%s --hash=sha256:%s\n' "$ATHERIS_VERSION" "$ATHERIS_SHA256" > /tmp/atheris.txt \
    && python3 -m pip install --no-cache-dir --break-system-packages --no-binary atheris \
       --require-hashes -r /tmp/atheris.txt \
    && rm /tmp/atheris.txt \
    && python3 -I -c 'import atheris'

# JVM targets: the Jazzer standalone launcher and a headless JDK. The release
# archive is verified against the digest of its architecture.
ARG JAZZER_VERSION=0.30.0
ARG JAZZER_SHA256_ARM64=16636a4d3e98f1d3a7fcf59d4ab37f5be1d1ad6df9d94d5c3ca8de644838e369
ARG JAZZER_SHA256_AMD64=6eeaf0026d75599b07527d93b576593ce847cfca8b337a579971a5a9cdf792d0
RUN apt-get update && apt-get install -y --no-install-recommends openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/* \
    && arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         arm64) asset=jazzer-linux-arm64.tar.gz; sum="$JAZZER_SHA256_ARM64" ;; \
         amd64) asset=jazzer-linux-x86-64.tar.gz; sum="$JAZZER_SHA256_AMD64" ;; \
         *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
       esac \
    && wget -q -O /tmp/jazzer.tar.gz "https://github.com/CodeIntelligenceTesting/jazzer/releases/download/v${JAZZER_VERSION}/${asset}" \
    && echo "${sum}  /tmp/jazzer.tar.gz" | sha256sum -c - \
    && mkdir -p /opt/jazzer && tar -xzf /tmp/jazzer.tar.gz -C /opt/jazzer \
    && rm /tmp/jazzer.tar.gz && test -x /opt/jazzer/jazzer && java -version && javac -version
ENV PATH="/opt/jazzer:${PATH}"

# Binary-only targets: AFL++ QEMU mode (afl-qemu-trace) for the image's own
# AFL++ release, built for the image architecture.
ARG AFLPP_COMMIT=108fb0b29ad1586e668ba23e23a0eb1a13c45c49
RUN apt-get update && apt-get install -y --no-install-recommends \
       libtool-bin bison flex libglib2.0-dev libpixman-1-dev python3-setuptools pkg-config \
    && rm -rf /var/lib/apt/lists/* \
    && git init -q /tmp/aflpp && cd /tmp/aflpp \
    && git remote add origin https://github.com/AFLplusplus/AFLplusplus \
    && git fetch -q --depth 1 origin "$AFLPP_COMMIT" && git checkout -q FETCH_HEAD \
    && ln -s "$(command -v afl-showmap)" afl-showmap \
    && cd qemu_mode \
    && case "$(dpkg --print-architecture)" in arm64) cpu=aarch64 ;; amd64) cpu=x86_64 ;; esac \
    && CPU_TARGET="$cpu" ./build_qemu_support.sh \
    && install -m 0755 ../afl-qemu-trace /usr/bin/afl-qemu-trace \
    && cd / && rm -rf /tmp/aflpp \
    && afl-qemu-trace -version | head -1

# MemorySanitizer for C++: an MSan-instrumented libc++ and a libFuzzer
# runtime built against it, from the LLVM release the image's clang is.
ARG LLVM_TAG=llvmorg-18.1.3
ARG LLVM_COMMIT=c13b7485b87909fcf739f62cfa382b55407433c0
RUN git init -q /tmp/llvm && cd /tmp/llvm \
    && git remote add origin https://github.com/llvm/llvm-project \
    && git config core.sparseCheckout true \
    && printf '%s\n' /runtimes/ /libcxx/ /libcxxabi/ /libc/ /cmake/ /llvm/cmake/ /llvm/utils/llvm-lit/ /compiler-rt/lib/fuzzer/ /third-party/ > .git/info/sparse-checkout \
    && git fetch -q --depth 1 --filter=blob:none origin "$LLVM_COMMIT" && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "$LLVM_COMMIT" \
    && cmake -G Ninja -S runtimes -B /tmp/llvm-build \
         -DCMAKE_BUILD_TYPE=Release \
         -DLLVM_ENABLE_RUNTIMES="libcxx;libcxxabi" \
         -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ \
         -DLLVM_USE_SANITIZER=MemoryWithOrigins \
         -DLIBCXXABI_USE_LLVM_UNWINDER=OFF \
         -DLIBCXX_INCLUDE_BENCHMARKS=OFF -DLIBCXX_INCLUDE_TESTS=OFF -DLIBCXXABI_INCLUDE_TESTS=OFF \
         -DCMAKE_INSTALL_PREFIX=/opt/oxfuzz/msan-libcxx \
    && ninja -C /tmp/llvm-build cxx cxxabi \
    && ninja -C /tmp/llvm-build install-cxx install-cxxabi \
    && mkdir /tmp/fuzzer-msan && cd /tmp/fuzzer-msan \
    && clang++ -c -O2 -g -std=c++17 -fPIC -fsanitize=memory -fsanitize-memory-track-origins \
         -fno-omit-frame-pointer -stdlib=libc++ -nostdinc++ \
         -isystem /opt/oxfuzz/msan-libcxx/include/c++/v1 \
         /tmp/llvm/compiler-rt/lib/fuzzer/*.cpp \
    && ar rcs /opt/oxfuzz/msan-libcxx/lib/libFuzzer-msan.a *.o \
    && cd / && rm -rf /tmp/llvm /tmp/llvm-build /tmp/fuzzer-msan \
    && test -f /opt/oxfuzz/msan-libcxx/lib/libc++.so.1 \
    && test -f /opt/oxfuzz/msan-libcxx/lib/libFuzzer-msan.a

# JavaScript targets: Node.js and Jazzer.js. The Node.js release archive is
# verified against the digest of its architecture. The Jazzer.js tree is
# installed from the committed lockfile, which pins every package by its
# integrity hash, and no package's install script is run (none declares
# one; the fuzzer's native module ships prebuilt for both architectures).
# `jazzer-js` is the launcher a JavaScript harness artifact starts.
ARG NODE_VERSION=24.22.3
ARG NODE_SHA256_ARM64=6e51a2ada00f0011cc266f65d98922b403d7ad88f809ca2aa615a5fe1ce6e86c
ARG NODE_SHA256_AMD64=4f2b175a6d53a5c617a80dba2676238a0688cef28c6da4eba35c7d844e66fcfb
COPY docker/sandbox/jazzerjs/package.json docker/sandbox/jazzerjs/package-lock.json /opt/jazzerjs/
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         arm64) node_arch=arm64; sum="$NODE_SHA256_ARM64" ;; \
         amd64) node_arch=x64; sum="$NODE_SHA256_AMD64" ;; \
         *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
       esac \
    && wget -q -O /tmp/node.tar.xz "https://nodejs.org/dist/v${NODE_VERSION}/node-v${NODE_VERSION}-linux-${node_arch}.tar.xz" \
    && echo "${sum}  /tmp/node.tar.xz" | sha256sum -c - \
    && mkdir -p /opt/node && tar -xJf /tmp/node.tar.xz -C /opt/node --strip-components=1 \
    && rm /tmp/node.tar.xz \
    && cd /opt/jazzerjs \
    && PATH="/opt/node/bin:$PATH" npm ci --ignore-scripts --no-audit --no-fund \
    && rm -rf /root/.npm \
    && test -f "/opt/jazzerjs/node_modules/@jazzer.js/fuzzer/prebuilds/fuzzer-linux-${node_arch}.node" \
    && printf '#!/bin/sh\nexec /opt/node/bin/node /opt/jazzerjs/node_modules/@jazzer.js/core/dist/cli.js "$@"\n' > /usr/local/bin/jazzer-js \
    && chmod 0755 /usr/local/bin/jazzer-js \
    && /opt/node/bin/node --version \
    && jazzer-js --version

# Bazel projects: two pinned Bazel releases, each verified against the
# digest of its architecture, the launcher that picks one from a workspace's
# .bazelversion, and the tool a Bazel build profile runs. That tool queries
# compile commands offline from the vendor directory a project carries; the
# image never fetches a Bazel dependency.
ARG BAZEL8_VERSION=8.9.0
ARG BAZEL8_SHA256_ARM64=db09df9fffd29e739ec45f2ce1b6e9db8c763e86e0ca95f625863c5c1846194f
ARG BAZEL8_SHA256_AMD64=bc4b5efbaf8b1d85913fb0e6873e40e4d9b33244d30cbbbbcd1b7835d940f8fa
ARG BAZEL9_VERSION=9.3.3
ARG BAZEL9_SHA256_ARM64=41349440c343005f0531ad128df3d3da58e39d5b50bda3eb495e186c2e0bd23b
ARG BAZEL9_SHA256_AMD64=24f30faa845410547a4fdeaa8d083e2eb9e95438b996ca76a0102ff8ef171334
COPY docker/sandbox/bazel/bazel docker/sandbox/bazel/oxfuzz-bazel-compdb /usr/local/bin/
RUN arch="$(dpkg --print-architecture)" \
    && case "$arch" in \
         arm64) bazel_arch=arm64; sum8="$BAZEL8_SHA256_ARM64"; sum9="$BAZEL9_SHA256_ARM64" ;; \
         amd64) bazel_arch=x86_64; sum8="$BAZEL8_SHA256_AMD64"; sum9="$BAZEL9_SHA256_AMD64" ;; \
         *) echo "unsupported architecture $arch" >&2; exit 1 ;; \
       esac \
    && mkdir -p /opt/bazel \
    && wget -q -O /opt/bazel/bazel-8 "https://github.com/bazelbuild/bazel/releases/download/${BAZEL8_VERSION}/bazel-${BAZEL8_VERSION}-linux-${bazel_arch}" \
    && echo "${sum8}  /opt/bazel/bazel-8" | sha256sum -c - \
    && wget -q -O /opt/bazel/bazel-9 "https://github.com/bazelbuild/bazel/releases/download/${BAZEL9_VERSION}/bazel-${BAZEL9_VERSION}-linux-${bazel_arch}" \
    && echo "${sum9}  /opt/bazel/bazel-9" | sha256sum -c - \
    && chmod 0755 /opt/bazel/bazel-8 /opt/bazel/bazel-9 /usr/local/bin/bazel /usr/local/bin/oxfuzz-bazel-compdb \
    && python3 -m py_compile /usr/local/bin/oxfuzz-bazel-compdb \
    && rm -rf /usr/local/bin/__pycache__

# --- Image 0.2.4 additions: licence notices. Appended last so the pinned
# toolchains above keep their build cache. The notices file names every
# component built from source or downloaded, its licence, and where its
# corresponding source is. The package manifest lists the exact Ubuntu package
# versions this build installed; their source packages are on the Ubuntu
# archive under those versions, and ubuntu-snapshot.txt names the snapshot.ubuntu.com
# timestamp to look them up at. The licence texts come from base-files.
COPY docker/sandbox/NOTICES.md /usr/share/doc/oxfuzz-sandbox/NOTICES.md
RUN mkdir -p /usr/share/doc/oxfuzz-sandbox/licenses \
    && for text in GPL-2 GPL-3 LGPL-2.1 LGPL-3; do \
         cp "/usr/share/common-licenses/${text}" "/usr/share/doc/oxfuzz-sandbox/licenses/${text}"; \
       done \
    && dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n' \
         > /usr/share/doc/oxfuzz-sandbox/packages.tsv \
    && chmod 0644 /usr/share/doc/oxfuzz-sandbox/NOTICES.md /usr/share/doc/oxfuzz-sandbox/packages.tsv \
    && test -s /usr/share/doc/oxfuzz-sandbox/NOTICES.md \
    && test -s /usr/share/doc/oxfuzz-sandbox/packages.tsv \
    && grep -Eqx '[0-9]{8}T[0-9]{6}Z' /usr/share/doc/oxfuzz-sandbox/ubuntu-snapshot.txt \
    && test -s /usr/share/doc/oxfuzz-sandbox/licenses/LGPL-3
