# Local compression dependency repair

This is `include-flate-compress` 0.3.4 from crates.io, corresponding to
[`SOF3/include-flate` commit 4118d8e](https://github.com/SOF3/include-flate/tree/4118d8e5d30b81c678f889b492945c39c019f846/compress).
The Rust source is unchanged. The only functional change is the manifest's
Zstd requirement, from `0.13.3` to `0.14.3`.

The latest published adapter still selects versions affected by
RUSTSEC-2026-0391, RUSTSEC-2026-0398, RUSTSEC-2026-0403, and
RUSTSEC-2026-0410. Updating the adapter's requirement preserves Jieba's bundled
dictionary and tokenization behavior without retaining those dependencies or
suppressing advisory checks. The original Apache-2.0 license is included.

Remove this patch when an upstream adapter release selects repaired versions.
Verify changes with `cargo deny check -D warnings` and `cargo test -p hf-knowledge`.
