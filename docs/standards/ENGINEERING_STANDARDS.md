# Engineering Standards

Status: **active**. Scope: Rust code across the workspace.

## 1. Style

- `snake_case` files and functions.
- `PascalCase` types.
- `SCREAMING_SNAKE_CASE` constants.
- `max_width = 100`, 4-space indent (see `rustfmt.toml`).
- No inline lint suppression (see AGENTS.md 2.10).

## 2. Dependencies

- Dependencies point inward to `hf-core`.
- Every new subsystem behind a feature flag.
- Workspace deps declared in root `Cargo.toml`; crates reference with
  `{ workspace = true }`.
- `cargo-deny` must pass (`cargo deny check`).

## 3. Error Handling

- Library crates return `Result<T, thiserror::Error>`.
- Application crates (`hf-cli`, `hf-web`) may use `anyhow` at the boundary.
- Never `unwrap()` in production code; tests may.

## 4. Async

- `tokio` runtime; all I/O traits are `async_trait`.
- P95 tool dispatch < 100ms (exclude LLM calls).

## 5. Logging

- `tracing` spans for every service method and engine run.
- Structured JSON logs in production; pretty logs in dev.

## 6. Documentation

- Every public item has a doc comment.
- `cargo doc --workspace --no-deps` must pass.
- Crate-level `lib.rs` starts with a module overview table.