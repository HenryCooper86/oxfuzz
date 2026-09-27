# Userspace qualification attempts, 2026-09-27

Outcome: **incomplete**. No libFuzzer, AFL++, or honggfuzz lifecycle is
qualified by these attempts. The ten successful cycles per engine, Stop
samples, historical replay, and positive selected-function counters remain
unmeasured.

The operator approved only the benign `examples/qualification/parser.c` and
`harness.c` pair with combined SHA-256
`a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591`.
The sandbox image was
`sha256:1a416dae015da4da47f2e6ddf6d1a3a97185a36d30b33aa569e2375f6b62d916`.
The local runner was macOS on arm64. The key belongs to BigModel's standard
API account, with model `glm-5.2`. The first three attempts mistakenly used
the Z.AI endpoint; the fourth used BigModel's
`https://open.bigmodel.cn/api/paas/v4` endpoint. No credential is included in
this record.

| Attempt | Source commit | Dirty patch SHA-256 | Outcome | Manifest SHA-256 |
| --- | --- | --- | --- | --- |
| First cycle | `9dd9846da166f259c954f6869a7e29d21aeffd23` | `e51b99cd5f7c35c01436655bda83ef4a7f92823036cb9e398ff55caa178abe10` | Review, sandbox build, smoke, and promotion passed; campaign ended before measured progress | `19bbdefb37d4868fadd4d0b63795436d68d0ef3e8f6c3936ae5c9f7a72b4f4fb` |
| Diagnostic retry 1 | `9dd9846da166f259c954f6869a7e29d21aeffd23` | `294a8d764aa536b39b4565c341bd8897cb5f20b274104034f00b37f7b7f8b098` | Provider returned HTTP 429 before smoke | `c330849f3c5c698f9453b45c64d1f8886c1f21e6cb2c0ab4dad5fc04b701d1a4` |
| Diagnostic retry 2 | `3d4a221b3ceac65a3a3c2dec11a5ecb96044c54b` | `294a8d764aa536b39b4565c341bd8897cb5f20b274104034f00b37f7b7f8b098` | Provider returned HTTP 429 before smoke | `b50b26d1b29412508b66668c3892ec651173fe8ea30cf511612d2ced25615a3e` |
| BigModel endpoint retry | `dd52bacb31e3f7ab7f5b88bc23aa43d0137603b8` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Provider returned HTTP 429 before smoke; a bounded diagnostic request returned code `1113`, insufficient balance or no usable resource package | `ab8547b415091278baed4f2cea06dfa1b4e269ac784dd8a8073b5cffc3032c35` |

The first failure was reproduced with a benign Docker command: a writable
`/work/function-coverage` bind mount could not be created beneath the
read-only `/work` workspace mount when that target directory was absent.
Commit `ad909e6e` stages an empty target before sealing execution inputs. A
second benign Docker probe with the staged directory exited successfully.
The service repair passed the Rust workspace tests and required quality gates,
but it has not yet passed a live fuzzer campaign.

Each attempt's full manifest and logs remain under the private local
`/Users/admin/.codex/qualification-evidence/` directory with the attempt
names `a2-cycle-1-zai-9dd9846d`, `a2-diagnose-progress-zai`,
`a2-diagnose-progress-zai-2`, and `a2-cycle-1-bigmodel-dd52bacb`, respectively.
The runner marked cleanup as unverified; a separate `docker ps -a` check after
these attempts found no `hf-run-` containers. The BigModel standard API
account needs usable balance or a resource package before another live cycle
can test the repair. Keep all four attempts classified as failures when
calculating qualification statistics.
