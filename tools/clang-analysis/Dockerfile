# Lightweight qualification build using the existing sandbox as its toolchain base.
ARG BASE_IMAGE=oxfuzz/fuzz-sandbox:0.2.1
FROM ${BASE_IMAGE}
RUN apt-get update && apt-get install -y --no-install-recommends libclang-18-dev llvm-18-dev && rm -rf /var/lib/apt/lists/*
COPY . /tmp/clang-analysis
RUN cmake -S /tmp/clang-analysis -B /tmp/clang-build -DCMAKE_BUILD_TYPE=Release -DLLVM_DIR=/usr/lib/llvm-18/lib/cmake/llvm -DClang_DIR=/usr/lib/llvm-18/lib/cmake/clang && cmake --build /tmp/clang-build -j2 && cmake --install /tmp/clang-build && rm -rf /tmp/clang-build /tmp/clang-analysis
