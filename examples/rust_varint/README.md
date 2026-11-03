# rust_varint

A standalone Rust library crate that decodes unsigned LEB128 varints, the
integer encoding used by protobuf, WebAssembly and DWARF. Its `Cargo.toml`
has an empty `[workspace]` table, so it is not a member of the oxfuzz
workspace and builds on its own.

| | |
| --- | --- |
| Entry point | `pub fn decode(data: &[u8]) -> Result<(u64, usize), DecodeError>` in `src/lib.rs` |
| Bug class | arithmetic overflow: unchecked shift amount (panic) |
| Finds it | cargo-fuzz / libFuzzer (the panic aborts the target) |

## The bug

A `u64` holds ten 7-bit groups, at shifts 0 through 63. `decode` keeps
adding 7 to `shift` for as long as the continuation bit is set and never
checks it against 64. The `// BUG:` comment marks the line.

Trigger input class: ten or more bytes with the continuation bit (0x80) set,
followed by any byte. For example the 11 bytes

```text
80 80 80 80 80 80 80 80 80 80 00
```

On the 11th byte `shift` is 70:

- With overflow checks enabled, `u64 << 70` panics with
  `attempt to shift left with overflow`. Overflow checks are on in debug
  builds and in the debug-assertion builds that `cargo fuzz` makes by
  default. libFuzzer reports the panic as a crash ("deadly signal").
- With overflow checks disabled (a plain `--release` build), the shift amount
  silently wraps modulo 64. The decoder then returns a wrong value instead of
  rejecting an over-long varint, which is a logic bug that a differential
  harness or a round-trip property can catch.

The unit tests in `src/lib.rs` cover well-formed and truncated inputs only.
They pass, as tests of this kind often do in real code.

## What the harness looks like

oxfuzz generates the harness, so this crate has no `fuzz/` directory. The
generated cargo-fuzz target is roughly:

```rust
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = oxfuzz_example_varint::decode(data);
});
```

## Running oxfuzz

```bash
cargo test --manifest-path examples/rust_varint/Cargo.toml
oxfuzz discover examples/rust_varint --lang rust
oxfuzz fuzz examples/rust_varint --lang rust --target decode
```

The expected finding is a panic, `attempt to shift left with overflow`, in
`decode` on an input of eleven or more bytes whose first ten all have the
continuation bit set.
