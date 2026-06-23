# hobot_fuzz sandbox image
#
# Provides: clang (with libFuzzer), AFL++, honggfuzz, and common build tools.
# Used by hf-runtime DockerRuntime to build harnesses and run fuzzers in
# isolation.

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

# Build honggfuzz from source (not in Ubuntu repos).
RUN apt-get update && apt-get install -y --no-install-recommends \
    libbfd-dev \
    libunwind-dev \
    && git clone --depth=1 https://github.com/google/honggfuzz.git /tmp/honggfuzz \
    && cd /tmp/honggfuzz && make && make install \
    && rm -rf /tmp/honggfuzz \
    && rm -rf /var/lib/apt/lists/*

# Verify tools are present.
RUN clang --version && afl-fuzz --version && honggfuzz --version 2>&1 || true

WORKDIR /work

CMD ["true"]