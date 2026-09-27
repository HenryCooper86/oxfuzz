# Held-out C parser cohort candidates, 2026-09-27

Status: **candidate selection, not a frozen or approved trial matrix**. These
public sources were read and hashed, but no target or generated harness was
built or executed.

| Project and pinned revision | License and candidate function | `git archive HEAD` SHA-256 | Tentative sandbox build input |
| --- | --- | --- | --- |
| [cJSON](https://github.com/DaveGamble/cJSON) `6d9f2443ab071f86e5d9b43025a40929ec41c46c` | MIT; `cJSON_ParseWithLengthOpts` | `ec38c5916785f16394225fb3f6246e2a15a235a856ecf03800828e1baf0c8031` | `cJSON.c`, `cJSON.h` |
| [yyjson](https://github.com/ibireme/yyjson) `6447536015f3d600f3d65323b10976103b337ca7` | MIT; `yyjson_read_opts` | `f135a140e1a870b2b14e95f1d6e021e800226661f5c4cfe29e6b8b98ea7d330e` | `src/yyjson.c`, `src/yyjson.h` |
| [mjson](https://github.com/cesanta/mjson) `696969cd0d35399cc66075f5ec7a96e23ba4a89b` | MIT; `mjson` | `ca738a6604fe6abc7c9c68cf7e60109a367c7b2d287ee4f08146921cf6106b72` | `src/mjson.c`, `src/mjson.h` |

Each repository contains its license file at the pinned revision. The selected
functions accept a byte buffer and length, making them plausible bounded
fuzzing targets. Three implementations of one input format support an initial
C-parser comparison, but cannot establish language or target-class parity.

The archive digests identify these review snapshots. They are **not** the
service's `oxfuzz-run-source-v1` digest of the staged build inputs, which must
be computed and frozen in the cohort before execution. Also fix the sandbox
image ID, provider/model, corpus, campaign and model budgets, and trial seeds.
Review the exact source and generated harness independently, obtain human
approval for execution, then build and run only through `hf-runtime`.
