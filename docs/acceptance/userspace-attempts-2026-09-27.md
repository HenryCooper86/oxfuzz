# Userspace qualification attempts, 2026-09-27

Outcome: **the first eight trials failed and the ninth preliminary cycle
passed**. The ninth ran on an uncommitted candidate and image. The later
[clean-revision qualification](userspace-2026-09-27.md) passed ten independent
cycles and supplies the accepted Stop distributions.

The operator approved only the benign `examples/qualification/parser.c` and
`harness.c` pair with combined SHA-256
`a21529ba223ec0a03b349e9f78b879eed69dc60d8d130dbac1b97fb7bf05a591`.
The initial sandbox image was
`sha256:1a416dae015da4da47f2e6ddf6d1a3a97185a36d30b33aa569e2375f6b62d916`;
the later arm64 rebuild was
`sha256:df678050adfb1803cfac879e5dc059c90379f35ad2a5c25cb072c055df5dd74c`.
The patched honggfuzz trial used
`sha256:cfaf446158c91acb4d1698c3747756efc98cd8aaa6186bdaab2c649fe6ea0fe7`.
The local runner was macOS on arm64. The user clarified that the `glm-5.2`
key is for BigModel's Coding Plan. The first three attempts used the Z.AI
endpoint; the fourth used BigModel's standard balance endpoint
`https://open.bigmodel.cn/api/paas/v4` and returned code `1113`. Subsequent
attempts used BigModel's Coding Plan endpoint
`https://open.bigmodel.cn/api/coding/paas/v4`, which accepted review requests.
The standard-endpoint balance error does not establish Coding Plan exhaustion.
No credential is included in this record.

| Attempt | Source commit | Dirty patch SHA-256 | Outcome | Manifest SHA-256 |
| --- | --- | --- | --- | --- |
| First cycle | `9dd9846da166f259c954f6869a7e29d21aeffd23` | `e51b99cd5f7c35c01436655bda83ef4a7f92823036cb9e398ff55caa178abe10` | Review, sandbox build, smoke, and promotion passed; campaign ended before measured progress | `19bbdefb37d4868fadd4d0b63795436d68d0ef3e8f6c3936ae5c9f7a72b4f4fb` |
| Diagnostic retry 1 | `9dd9846da166f259c954f6869a7e29d21aeffd23` | `294a8d764aa536b39b4565c341bd8897cb5f20b274104034f00b37f7b7f8b098` | Provider returned HTTP 429 before smoke | `c330849f3c5c698f9453b45c64d1f8886c1f21e6cb2c0ab4dad5fc04b701d1a4` |
| Diagnostic retry 2 | `3d4a221b3ceac65a3a3c2dec11a5ecb96044c54b` | `294a8d764aa536b39b4565c341bd8897cb5f20b274104034f00b37f7b7f8b098` | Provider returned HTTP 429 before smoke | `b50b26d1b29412508b66668c3892ec651173fe8ea30cf511612d2ced25615a3e` |
| BigModel endpoint retry | `dd52bacb31e3f7ab7f5b88bc23aa43d0137603b8` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Provider returned HTTP 429 before smoke; a bounded diagnostic request returned code `1113`, insufficient balance or no usable resource package | `ab8547b415091278baed4f2cea06dfa1b4e269ac784dd8a8073b5cffc3032c35` |
| Coding Plan retry | `76dcdf27f559c3c535b368588c65c58d84272a6f` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` | Review, smoke and promotion passed; the campaign failed because the run-specific writable mount targets were absent beneath read-only `/work` | `681ae2233ab31fdbf268daec5d573e578ed58f6e18ad2d8dae3a9e32c6bcafdf` |
| Run mountpoint repair trial | `76dcdf27f559c3c535b368588c65c58d84272a6f` | `0dd2221b81f4c3357aa5a30875fd0be79a4171ec3640352a818c30d9cf2512ca` | libFuzzer passed; AFL++ compile failed because Clang 17 sanitizer/profile runtime archives were missing from the arm64 image | `1d92df1bd5f99450619b1b0da894733e5ec4f534e25252e14459649de9c1c4e7` |
| Arm64 image repair trial | `76dcdf27f559c3c535b368588c65c58d84272a6f` | `b692b5329cf9c78d67b52717590a8b7ffc8698c90d8df31ffaf18143f2d92e74` | libFuzzer passed; AFL++ smoke, campaign and replay ran, but its replay produced no raw LLVM profile; honggfuzz was not reached | `e7fe89b677f491141de2b8e9e79e6523b89322660b66a09ce90b1dc078dbfa76` |
| AFL++ profile trial | `76dcdf27f559c3c535b368588c65c58d84272a6f` | `f2f3e8396ece49ad997e04e1b7433ef023f2e9026c335d70f13c98906f2342b2` | A temporary `AFL_NO_FORKSRV=1` experiment emitted raw profiles, but replay exceeded its sandbox wall-clock limit and failed; the experiment was reverted | `ad7a9853ba0939cbbd21967ae8bc9894b590acef44a26524947967c61732f438` |
| AFL++ bounded-loop trial | `68d6609e8ad02cfccd183849c03cf3c3287983f4` | `2d43f7849d1e21fbf390895131ff184562ec0123e950b4112ffcacb781a03614` | AFL++ emitted profiles and completed replay, but LLVM 18 could not merge its LLVM 17 raw profile | `737f73aafaab1897e740e8c7303b35640ff78971c70954166d017b9b6001ff6e` |
| Versioned LLVM trial | `68d6609e8ad02cfccd183849c03cf3c3287983f4` | `8c177731d0ac27a92449be2d67e370268ee48511c9eda044c6937df681f24af1` | libFuzzer and AFL++ passed; honggfuzz smoke failed creating a 151 MiB feedback file under the 64 MiB per-file limit | `5ba1a4b811ec0485c2a907d814ded03f913671e8236fcd473ef99d37cb85e61e` |
| honggfuzz worker trial | `68d6609e8ad02cfccd183849c03cf3c3287983f4` | `6e59bde82d75e434d8f1c7a3a2d6fc697e06ac23331e78702d27d2b2bdf62fdf` | Explicitly selecting one worker did not reduce the fixed-size feedback file; smoke failed at the same limit | `9fe403fa156c1d7927691c6f28aacb2469a24830fa7e8265dd74f18c7ed022b1` |
| Bounded shared-memory trial | `68d6609e8ad02cfccd183849c03cf3c3287983f4` | `4e507f24ea51145cba7d14673d532cb0910603701b83b4e78e905a862e99df67` | All three engines ran; honggfuzz replay completed but its persistent target did not flush a function profile | `c57bb6c2d05bdf698eb8a869cff35af98f47e8f8f040153c59d87af040712c95` |
| Patched honggfuzz trial | `68d6609e8ad02cfccd183849c03cf3c3287983f4` | `8c8de5218f4e0a8b67eec9c09f630a1db263c1e57051bc87303b3cf8e69d6d9c` | Complete three-engine lifecycle passed, including positive selected-function counters and no remaining run containers; one cycle is preliminary evidence | `10f393a307f1b1568827f8e995f255e7d0748bfec0801819ff3a14ef7f1d6a` |

The first mount failure was reproduced with a benign Docker command: a writable
`/work/function-coverage` bind mount could not be created beneath the
read-only `/work` workspace mount when that target directory was absent.
Commit `ad909e6e` stages an empty target before sealing execution inputs. A
second benign Docker probe with the staged directory exited successfully.
That repair alone did not stage the run-specific corpus and output targets.
The later run mountpoint repair passed focused tests and let libFuzzer complete
live qualification. The arm64 image also needed `libclang-rt-17-dev`; the new
toolchain smoke check compiles, executes, merges, and exports a harmless C
probe with each userspace compiler and the live sanitizer/profile flags. The
first complete trial followed further repairs to persistent profile flushing,
versioned LLVM collection, and bounded honggfuzz scratch space. It is not the
ten-cycle candidate run.

Each attempt's full manifest and logs remain under the private local
`/Users/admin/.codex/qualification-evidence/` directory, in the correspondingly
named `a2-*` directories. The runner's cleanup flag is conservative; separate
`docker ps -a` checks found no `hf-run-` containers after the attempts. Exclude
the eight failed trials from the success sample. The subsequent clean candidate
and final image are recorded in the accepted qualification; these attempts
remain excluded from its ten-sample statistics.
