# hobot_fuzz sandbox image
#
# Provides: clang (with libFuzzer), AFL++, honggfuzz, and common build tools.
# Used by hf-runtime DockerRuntime to build harnesses and run fuzzers in
# isolation.

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    lld \
    make \
    cmake \
    ninja-build \
    git \
    wget \
    ca-certificates \
    python3 \
    AFL++ \
    honggfuzz \
    && rm -rf /var/lib/apt/lists/*

# Verify tools are present.
RUN clang --version && afl-fuzz --version || true && honggfuzz --version || true

WORKDIR /work

# Default entrypoint: do nothing, the runtime execs commands directly.
CMD ["true"]