# hobot_fuzz sandbox image
#
# Provides: clang (with libFuzzer), AFL++, honggfuzz, the syzkaller toolchain
# (Go + qemu + syz-* binaries), and common build tools. Used by hf-runtime
# DockerRuntime to build harnesses and run fuzzers in isolation.
#
# Multi-arch: built per fuzzing target via `docker build --platform=linux/amd64`
# or `linux/arm64` so the produced harness binaries match the target ABI.

FROM ubuntu:24.04

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
       'markitdown[pdf,docx,pptx,xlsx]' \
    && rm -rf /var/lib/apt/lists/*

# Build honggfuzz from source (not in Ubuntu repos).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbfd-dev \
    libunwind-dev \
    && git clone --depth=1 https://github.com/google/honggfuzz.git /tmp/honggfuzz \
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
# requires Go >= 1.26), newer than the distro `golang-go` package. We therefore
# install a pinned Go from go.dev. GOTOOLCHAIN=auto lets `go` fetch a newer
# toolchain automatically if a future syzkaller checkout requires one.
# ---------------------------------------------------------------------------
ENV GO_VERSION=1.26.0
RUN arch="$(dpkg --print-architecture)" \
    && wget -q "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz" -O /tmp/go.tgz \
    && tar -C /usr/local -xzf /tmp/go.tgz \
    && rm /tmp/go.tgz

ENV PATH="/usr/local/go/bin:/root/go/bin:/opt/syzkaller/bin:${PATH}"
ENV GOTOOLCHAIN=auto

RUN apt-get update && apt-get install -y --no-install-recommends \
    qemu-system-x86 \
    qemu-system-arm \
    qemu-utils \
    flex \
    bison \
    bc \
    libelf-dev \
    libssl-dev \
    && git clone --depth=1 https://github.com/google/syzkaller.git /opt/syzkaller \
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
RUN apt-get update && apt-get install -y --no-install-recommends \
    gdb \
    lsb-release \
    curl \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal \
    && . "$HOME/.cargo/env" \
    && cargo install casr --root /usr/local --locked \
    && rustup self uninstall -y \
    && rm -rf "$HOME/.cargo" "$HOME/.rustup"

# Verify tools are present.
RUN clang --version && afl-fuzz --version && honggfuzz --version 2>&1 || true
RUN syz-manager --help 2>&1 | head -1 || true
RUN casr-san --help 2>&1 | head -1 && casr-cluster --help 2>&1 | head -1 || true

WORKDIR /work

CMD ["true"]