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
service's `oxfuzz-run-source-v1` digest of the staged build inputs, calculated
for a curated subset below and still to be frozen in the cohort. Also fix the
sandbox image ID, provider/model, corpus, campaign and model budgets, and trial
seeds.
Review the exact source and generated harness independently, obtain human
approval for execution, then build and run only through `hf-runtime`.

A private curated snapshot now contains exactly the two listed C/header files
for each project at
`/Users/admin/.codex/qualification-evidence/b1-curated-c-sources-2026-09-27/`.
Its `manifest.json` SHA-256 is
`1e8c8820f5abcd4276e90c80c46361dcb216a4d2a37eeabb29ad727210a9d782`.
Each copied file was byte-compared with `git show HEAD:<path>` at its pinned
revision. With no other staged source files, the service's source-digest
algorithm (`oxfuzz-run-source-v1`, sorted relative paths, NUL separators)
produces these candidate values:

| Curated project | Candidate staged-source SHA-256 |
| --- | --- |
| cJSON | `40bf8aa4f015a902780e8c3434b73b1707a6092de135df4251717e65e6674322` |
| yyjson | `834f84f2a9b46367e671826064ae5653fc3af7f5f272e55c3412bbabe8cd5947` |
| mjson | `d08d2ca4435421c9827619ce846d3d56be39fe5783286a18aabbf2de04e38f11` |

These are preparation values, not retained campaign evidence. The actual
service-staged source digest must match before a trial is accepted. The curated
files have not been compiled, imported into an approved workspace, or run.
