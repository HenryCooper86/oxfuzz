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
      org.opencontainers.image.version="0.1.0" \
      org.opencontainers.image.source="https://github.com/HenryCooper86/oxfuzz"

ENV DEBIAN_FRONTEND=noninteractive

# Install clang, build tools, AFL++, libFuzzer dev, and clang runtime (asan/fuzzer).
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    lld \
    libclang-rt-18-dev \
    make \
    cmake \
    ninja-build \
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
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbfd-dev \
    libunwind-dev \
    && git init /tmp/honggfuzz \
    && git -C /tmp/honggfuzz remote add origin https://github.com/google/honggfuzz.git \
    && git -C /tmp/honggfuzz fetch --depth=1 origin "${HONGGFUZZ_COMMIT}" \
    && git -C /tmp/honggfuzz checkout --detach FETCH_HEAD \
    && cd /tmp/honggfuzz && make && make install \
    && rm -rf /tmp/honggfuzz \
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
    && cargo install casr --version "${CASR_VERSION}" --root /usr/local --locked \
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

WORKDIR /work

CMD ["true"]
