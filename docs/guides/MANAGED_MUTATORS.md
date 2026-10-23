# Managed native custom mutators

The Harness view supports importing C/C++ mutators for the existing AFL++ and
libFuzzer engines. This uses their upstream native APIs; honggfuzz, Rust, Go,
syzkaller, Python plugins, and chains of multiple AFL++ libraries are not
supported by this workflow. Those requests fail explicitly. Build the product
with its default `managed-mutators` feature, or select that feature explicitly.

## Engineer workflow in the GUI

1. Select the project, target and engine in Harness. Compile the base harness
   through the normal workflow. Open its existing harness card.
2. In **Native custom mutator**, paste source or import a C/C++ file. AFL++ source
   supplies `afl_custom_init`, `afl_custom_fuzz` and `afl_custom_deinit`. Optional
   custom trimming supplies all three upstream trim callbacks. C++ callbacks
   that AFL++ loads by name must use `extern "C"`.
3. Choose **Compile with mutator**. Compilation occurs in the captured sandbox
   image and creates a new unpromoted revision. Review the combined harness,
   imported source and observation wrappers, plus the displayed source, artifact
   and image identities. Inputs must fit the 64 KiB combined review allowance.
4. Use **Smoke Test**. The normal independent model review and human execution
   approval apply. A callback must return successfully within its native buffer
   allowance, and the bounded engine must exit successfully. Retained status
   shows mutation observations, trim observations and capped logs. Unobserved
   custom trimming is not presented as verified.
5. Approve the qualified revision using the existing approval controls, then
   start a bounded campaign. History/replay retains the reviewed source, native
   executable/library, starting corpus, config, exact image and input manifest.
   Changed retained bytes prevent replay. Source changes create another revision
   and require the same review, smoke and approval steps again.

The model review has only the repository's explicit audited bypass mechanisms;
there is no mutator-specific bypass. Promotion remains a human decision.
AFL++ coverage/corpus pruning executes the target and does not load a mutation
plugin. LibFuzzer corpus operations retain the reviewed linked target.

## Manual qualification commands

These commands execute native code in hf-runtime sandboxes. They were **not run**
as part of the mocked implementation verification. Review the target, harness,
example mutator, generated combined revision and captured image before granting
the normal CLI prompts. A working configured review provider and sandbox image
are required. No host dynamic-library loading command is needed or supported.

From the repository root, use the benign qualification target:

```sh
oxfuzz harness examples/qualification --target qualification_parse --engine afl++ --lang c --ai off
oxfuzz mutator examples/qualification --target qualification_parse --engine afl++ attach --source docs/examples/mutators/afl_in_place.c
oxfuzz mutator examples/qualification --target qualification_parse --engine afl++ status
oxfuzz mutator examples/qualification --target qualification_parse --engine afl++ qualify
oxfuzz mutator examples/qualification --target qualification_parse --engine afl++ promote
oxfuzz run examples/qualification --target qualification_parse --engine afl++ --duration 10s --seed 42
```

For libFuzzer, substitute `libfuzzer` for the engine and use
`docs/examples/mutators/libfuzzer_in_place.c`. `qualify` and `promote` operate on
the retained revision; invoking `harness` again drafts a different revision.
Save the returned run UUID, then replay its retained inputs with:

```sh
oxfuzz run examples/qualification --replay <run-uuid>
```

Inspect Harness status and History after each step. A passing smoke proves only
observed native callback execution in that bounded run. The examples perform
simple bit mutations; they do not establish structure-aware effectiveness.
Compare coverage using the repository's matched-budget benchmark procedure
before claiming an improvement. Record source/artifact/image hashes, engine
version, seed, duration, corpus identity, results and failures together.

## APIs and retained identity

Tauri commands `managed_mutator_status` and `attach_managed_mutator` map to
`POST /harness/mutator/status` and `POST /harness/mutator/attach`. Both take
`project`, `target`, `engine`; attach additionally takes `source` and
`expected_harness_id` (camelCase `expectedHarnessId` through the GUI transport).
The service rejects a stale active revision before compilation. REST applies
its existing approved-project policy. Smoke and promotion reuse existing APIs.

`Harness.custom_mutator` version 1 stores `api`, `source_sha256`, `artifact_name`,
`artifact_sha256`, `sandbox_image_id`, `custom_trim`, and optional `self_test`
with `exit_code`, `mutation_observed`, `trim_observed`, `log`, `log_truncated`.
AFL++ runs retain `AFL_CUSTOM_MUTATOR_LIBRARY`, `OXFUZZ_MUTATOR_SHA256` and
`OXFUZZ_MUTATOR_IMAGE_ID`; users do not configure those environment values.
Experiment comparisons normalize only the verified retained run path. Artifact
or image differences remain visible and can make an experiment incomparable.

Upstream documentation: [AFL++ native custom mutators](https://aflplus.plus/docs/custom_mutators/)
and [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html).
