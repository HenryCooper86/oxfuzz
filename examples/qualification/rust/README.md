# Rust userspace qualification fixture

This benign two-package Cargo workspace parses a short `OX`-prefixed record
and computes a wrapping checksum over at most 255 payload bytes. The harness
calls `parse_record` once per input. The source allocates no memory, opens no
files or sockets, starts no processes, and contains no deliberate crash.
The nested local package exercises workspace path-dependency staging. The
fuzzing dependency `libfuzzer-sys` must resolve in the network-disabled pinned
sandbox image.

## Exact source review

Review `Cargo.toml`, `src/lib.rs`, `crates/codec/Cargo.toml`,
`crates/codec/src/lib.rs`, and `harness.rs` before approval. Their combined
identity is SHA-256 over that ordered list, appending each relative path,
a zero byte, the file bytes, and a zero byte:

```text
d3bdffb5321b4012f42e7827b996fdee7e0ea8583917cf2d1f55f726d7cd2380
```

The ignored live qualification test will require this exact digest in its
approval environment variable. It must run every build, smoke, campaign, and
replay through `hf-runtime` in a disposable workspace, with a real provider
review before promotion. This fixture establishes engine and workspace
operation, not vulnerability discovery or Rust function-counter coverage.
