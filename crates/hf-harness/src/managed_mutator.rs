//! Native AFL++ and libFuzzer source integration. No host plugin loading.

use hf_core::{engine::EngineKind, error::ClassifiedError, target::TargetLanguage};
use sha2::{Digest, Sha256};

const PREFIX: &str = "/* OXFUZZ_NATIVE_MUTATOR_V1 ";
const BASE_START: &str = "/* OXFUZZ_BASE_BEGIN */\n";
const BASE_END: &str = "\n/* OXFUZZ_BASE_END */";
const MUTATOR_START: &str = "/* OXFUZZ_MUTATOR_BEGIN */\n";
const MUTATOR_END: &str = "\n/* OXFUZZ_MUTATOR_END */";
const MAX_SOURCE_BYTES: usize = 64 * 1024;
/// Shared-library suffix, staged alongside the target executable.
pub const LIBRARY_SUFFIX: &str = ".mutator.so";
/// Observed only after an upstream mutation callback returns within its allowance.
pub const MUTATION_WITNESS: &str = "OXFUZZ_NATIVE_MUTATION_OK_V1";
/// Observed when a custom AFL++ trim callback returns within its input allowance.
pub const TRIM_WITNESS: &str = "OXFUZZ_NATIVE_TRIM_OK_V1";

/// Validated source pieces bound by a canonical envelope.
pub struct MutatorSource<'a> {
    pub base: &'a str,
    pub mutator: &'a str,
    pub source_sha256: String,
    pub custom_trim: bool,
}

fn invalid(message: &str) -> ClassifiedError {
    ClassifiedError::Validation(format!("managed mutator: {message}"))
}

fn require_support(engine: EngineKind, lang: TargetLanguage) -> Result<(), ClassifiedError> {
    if !cfg!(feature = "managed-mutators") {
        return Err(invalid("managed-mutators feature is disabled"));
    }
    if !matches!(engine, EngineKind::AflPlusPlus | EngineKind::LibFuzzer)
        || !matches!(lang, TargetLanguage::C | TargetLanguage::Cpp)
    {
        return Err(invalid(
            "only AFL++ and libFuzzer C/C++ native mutators are supported",
        ));
    }
    Ok(())
}

/// Compose a new reviewable translation unit; no file or process side effects.
pub fn compose(
    base: &str,
    mutator: &str,
    engine: EngineKind,
    lang: TargetLanguage,
) -> Result<String, ClassifiedError> {
    require_support(engine, lang)?;
    if base.len().saturating_add(mutator.len()) > MAX_SOURCE_BYTES || mutator.trim().is_empty() {
        return Err(invalid(
            "source must be nonempty and combined inputs at most 64 KiB",
        ));
    }
    let reserved_base = [
        "OXFUZZ_NATIVE_",
        "OXFUZZ_BASE_",
        "OXFUZZ_MUTATOR_",
        "oxfuzz_user_",
    ]
    .iter()
    .any(|prefix| base.contains(prefix));
    if reserved_base || mutator.contains("OXFUZZ_") || mutator.contains("oxfuzz_user_") {
        return Err(invalid(
            "reserved observation names appear in imported source",
        ));
    }
    let symbol = if engine == EngineKind::AflPlusPlus {
        "afl_custom_fuzz"
    } else {
        "LLVMFuzzerCustomMutator"
    };
    if !mutator.contains(symbol) {
        return Err(invalid(
            "source lacks the selected upstream mutation callback",
        ));
    }
    let has_identifier = |name: &str| {
        mutator
            .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .any(|word| word == name)
    };
    if engine == EngineKind::AflPlusPlus
        && (!has_identifier("afl_custom_init") || !has_identifier("afl_custom_deinit"))
    {
        return Err(invalid(
            "AFL++ requires native afl_custom_init and afl_custom_deinit callbacks",
        ));
    }
    let trim = [
        "afl_custom_init_trim",
        "afl_custom_trim",
        "afl_custom_post_trim",
    ]
    .map(|name| mutator.contains(name));
    if trim.iter().any(|value| *value)
        && (engine != EngineKind::AflPlusPlus || !trim.iter().all(|value| *value))
    {
        return Err(invalid(
            "custom trimming requires all three AFL++ trim callbacks",
        ));
    }
    let digest = format!("{:x}", Sha256::digest(mutator.as_bytes()));
    let header = format!("{PREFIX}{} {digest} */\n", engine.as_str());
    let base_guard = if engine == EngineKind::AflPlusPlus {
        "#ifndef OXFUZZ_MUTATOR_BUILD\n"
    } else {
        ""
    };
    let between = if engine == EngineKind::AflPlusPlus {
        "\n#endif\n#ifdef OXFUZZ_MUTATOR_BUILD\n"
    } else {
        "\n"
    };
    let end = if engine == EngineKind::AflPlusPlus {
        "\n#endif\n"
    } else {
        "\n"
    };
    let mut prelude = format!("#include <stdint.h>\n#include <stddef.h>\n#include <stdio.h>\n#define {symbol} oxfuzz_user_mutate\n");
    if trim[0] {
        prelude.push_str("#define afl_custom_init_trim oxfuzz_user_init_trim\n#define afl_custom_trim oxfuzz_user_trim\n#define afl_custom_post_trim oxfuzz_user_post_trim\n");
    }
    let wrapper = wrapper(engine, trim[0]);
    Ok(format!("{header}{base_guard}{BASE_START}{base}{BASE_END}{between}{prelude}{MUTATOR_START}{mutator}{MUTATOR_END}\n#undef {symbol}\n{wrapper}{end}"))
}

/// Reject edited or mismatched envelopes before any sandbox dispatch.
pub fn inspect(
    source: &str,
    engine: EngineKind,
    lang: TargetLanguage,
) -> Result<Option<MutatorSource<'_>>, ClassifiedError> {
    if !source.starts_with(PREFIX) {
        if source.contains("OXFUZZ_NATIVE_MUTATOR_V1") {
            return Err(invalid("managed source header was moved or changed"));
        }
        return Ok(None);
    }
    require_support(engine, lang)?;
    let piece = |start: &str, end: &str| -> Result<&str, ClassifiedError> {
        source
            .split_once(start)
            .and_then(|(_, value)| value.split_once(end))
            .map(|(value, _)| value)
            .ok_or_else(|| invalid("source envelope is incomplete"))
    };
    let base = piece(BASE_START, BASE_END)?;
    let mutator = piece(MUTATOR_START, MUTATOR_END)?;
    if compose(base, mutator, engine, lang)? != source {
        return Err(invalid(
            "source envelope digest or observation wrapper changed; reimport source",
        ));
    }
    Ok(Some(MutatorSource {
        base,
        mutator,
        source_sha256: format!("{:x}", Sha256::digest(mutator.as_bytes())),
        custom_trim: mutator.contains("afl_custom_init_trim"),
    }))
}

fn wrapper(engine: EngineKind, trim: bool) -> String {
    let mut source = String::from("#ifdef __cplusplus\nextern \"C\" {\n#endif\n");
    if engine == EngineKind::AflPlusPlus {
        source.push_str(r#"size_t afl_custom_fuzz(void *state, unsigned char *data, size_t size, unsigned char **out, unsigned char *add, size_t add_size, size_t max_size) {
  size_t n = oxfuzz_user_mutate(state, data, size, out, add, add_size, max_size);
  if (n > max_size || (n && !*out)) __builtin_trap();
  static int seen = 0;
  if (n && !seen) { seen = 1; fputs("OXFUZZ_NATIVE_MUTATION_OK_V1\n", stderr); }
  return n;
}
"#);
    } else {
        source.push_str(r#"size_t LLVMFuzzerCustomMutator(uint8_t *data, size_t size, size_t max_size, unsigned int seed) {
  size_t n = oxfuzz_user_mutate(data, size, max_size, seed);
  if (n > max_size) __builtin_trap();
  static int seen = 0;
  if (n && !seen) { seen = 1; fputs("OXFUZZ_NATIVE_MUTATION_OK_V1\n", stderr); }
  return n;
}
"#);
    }
    if trim {
        source.push_str(
            r#"#undef afl_custom_init_trim
#undef afl_custom_trim
#undef afl_custom_post_trim
static size_t oxfuzz_trim_limit;
int afl_custom_init_trim(void *state, unsigned char *data, size_t size) {
  oxfuzz_trim_limit = size;
  int n = oxfuzz_user_init_trim(state, data, size);
  if (n < 0) __builtin_trap();
  return n;
}
size_t afl_custom_trim(void *state, unsigned char **out) {
  size_t n = oxfuzz_user_trim(state, out);
  if (n > oxfuzz_trim_limit || (n && !*out)) __builtin_trap();
  static int seen = 0;
  if (!seen) { seen = 1; fputs("OXFUZZ_NATIVE_TRIM_OK_V1\n", stderr); }
  return n;
}
int afl_custom_post_trim(void *state, unsigned char success) {
  int n = oxfuzz_user_post_trim(state, success);
  if (n < 0) __builtin_trap();
  return n;
}
"#,
        );
    }
    source.push_str("#ifdef __cplusplus\n}\n#endif\n");
    source
}

/// Validate managed-source support and require an immutable compilation image.
pub(crate) fn validate_build(
    harness: &hf_core::harness::Harness,
    options: &hf_core::runtime::SandboxOptions,
) -> Result<(), ClassifiedError> {
    let parsed = inspect(&harness.source, harness.engine, harness.language)?;
    if parsed.is_none() && harness.custom_mutator.is_some() {
        return Err(invalid(
            "artifact record lacks its reviewed source envelope",
        ));
    }
    if parsed.is_some() {
        let image = options
            .image
            .as_deref()
            .ok_or_else(|| invalid("build requires a captured immutable sandbox image"))?;
        hf_core::runtime::ImmutableImageReference::from_sha256_id(image.to_owned())?;
    }
    Ok(())
}

pub(crate) async fn compile_artifact(
    harness: &mut hf_core::harness::Harness,
    rt: &dyn hf_core::runtime::RuntimeAdapter,
    workspace: &std::path::Path,
    options: &hf_core::runtime::SandboxOptions,
) -> Result<Option<crate::CompileFailure>, ClassifiedError> {
    let Some(parsed) = inspect(&harness.source, harness.engine, harness.language)? else {
        return Ok(None);
    };
    let source_sha256 = parsed.source_sha256;
    let custom_trim = parsed.custom_trim;
    let binary_name = harness
        .build_cmd
        .output
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| invalid("target output must have a UTF-8 filename"))?;
    let artifact_name = if harness.engine == EngineKind::AflPlusPlus {
        format!("{binary_name}{LIBRARY_SUFFIX}")
    } else {
        binary_name.to_owned()
    };
    if harness.engine == EngineKind::AflPlusPlus {
        let compiler = if harness.language == TargetLanguage::Cpp {
            "clang++"
        } else {
            "clang"
        };
        let source = harness.language.harness_filename();
        let quote = |value: &str| format!("'{}'", value.replace('\'', "'\\''"));
        let flags = harness
            .build_cmd
            .extra_flags
            .iter()
            .map(|flag| quote(flag))
            .collect::<Vec<_>>()
            .join(" ");
        let script = format!("{compiler} -shared -fPIC -O1 -g -DOXFUZZ_MUTATOR_BUILD {flags} {} -o /tmp/oxfuzz-mutator.so && cp /tmp/oxfuzz-mutator.so {}",quote(&format!("/work/{source}")),quote(&format!("/work/{artifact_name}")));
        let limits = hf_core::runtime::ResourceLimits {
            max_mem_mb: 4096,
            max_cpus: 2,
            max_duration_secs: 120,
            ..Default::default()
        };
        let result = rt
            .run_command_opts(
                &["bash".into(), "-c".into(), script],
                workspace,
                &limits,
                options,
            )
            .await?
            .require_completed("native mutator compile")?;
        if result.exit_code != 0 {
            return Ok(Some(crate::CompileFailure {
                exit_code: result.exit_code,
                stdout: result.stdout,
                stderr: result.stderr,
            }));
        }
    }
    let path = workspace.join(&artifact_name);
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| invalid(&format!("inspect artifact: {error}")))?;
    if !metadata.file_type().is_file() || metadata.len() == 0 || metadata.len() > 64 * 1024 * 1024 {
        return Err(invalid(
            "compiled artifact must be a nonempty regular file at most 64 MiB",
        ));
    }
    let image = options
        .image
        .clone()
        .ok_or_else(|| invalid("missing immutable build image"))?;
    harness.custom_mutator = Some(hf_core::mutator::ManagedMutatorArtifact {
        version: 1,
        api: if harness.engine == EngineKind::AflPlusPlus {
            hf_core::mutator::MutatorApi::AflPlusPlus
        } else {
            hf_core::mutator::MutatorApi::LibFuzzer
        },
        source_sha256,
        artifact_name,
        artifact_sha256: digest_file(&path)?,
        sandbox_image_id: image,
        custom_trim,
        self_test: None,
    });
    Ok(None)
}

/// Verify the retained artifact and its association with the complete reviewed source.
pub fn verify_artifact(
    harness: &hf_core::harness::Harness,
    artifact: &std::path::Path,
    image: Option<&str>,
) -> Result<(), ClassifiedError> {
    let parsed = inspect(&harness.source, harness.engine, harness.language)?;
    match (&harness.custom_mutator, parsed) {
        (None, None) => Ok(()),
        (Some(record), Some(parsed)) => {
            let expected_api = if harness.engine == EngineKind::AflPlusPlus {
                hf_core::mutator::MutatorApi::AflPlusPlus
            } else {
                hf_core::mutator::MutatorApi::LibFuzzer
            };
            if record.version != 1
                || record.api != expected_api
                || record.source_sha256 != parsed.source_sha256
                || record.custom_trim != parsed.custom_trim
                || image.is_some_and(|image| image != record.sandbox_image_id)
            {
                return Err(invalid(
                    "source, engine, or sandbox image differs from the compiled artifact",
                ));
            }
            let metadata = std::fs::symlink_metadata(artifact)
                .map_err(|error| invalid(&format!("inspect artifact: {error}")))?;
            if !metadata.file_type().is_file()
                || metadata.len() > 64 * 1024 * 1024
                || digest_file(artifact)? != record.artifact_sha256
            {
                return Err(invalid("artifact digest changed; rebuild and requalify"));
            }
            Ok(())
        }
        _ => Err(invalid(
            "reviewed source and artifact record disagree; rebuild and requalify",
        )),
    }
}

fn digest_file(path: &std::path::Path) -> Result<String, ClassifiedError> {
    use std::io::Read;
    let file =
        std::fs::File::open(path).map_err(|error| invalid(&format!("read artifact: {error}")))?;
    let mut bytes = Vec::new();
    file.take(64 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| invalid(&format!("read artifact: {error}")))?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err(invalid("artifact exceeds 64 MiB"));
    }
    Ok(format!("{:x}", Sha256::digest(bytes)))
}

/// Record native callbacks actually observed by the bounded upstream smoke run.
pub(crate) fn observe_smoke(
    harness: &mut hf_core::harness::Harness,
    log: &str,
    exit_code: i32,
) -> bool {
    if let Some(record) = &mut harness.custom_mutator {
        let observed = log.contains(MUTATION_WITNESS);
        record.self_test = Some(hf_core::mutator::MutatorSelfTest {
            exit_code,
            mutation_observed: observed,
            trim_observed: log.contains(TRIM_WITNESS),
            log: log.chars().take(16384).collect(),
            log_truncated: log.chars().count() > 16384,
        });
        return observed && exit_code == 0;
    }
    true
}

/// Verify the staged artifact and reviewed source in the smoke executor itself.
pub(crate) fn validate_smoke(
    harness: &hf_core::harness::Harness,
    workspace: &std::path::Path,
    binary_relative: &std::path::Path,
    image: Option<&str>,
) -> Result<(), ClassifiedError> {
    let parsed = inspect(&harness.source, harness.engine, harness.language)?;
    match (&harness.custom_mutator, parsed) {
        (None, None) => Ok(()),
        (Some(record), Some(_)) => {
            if image != Some(record.sandbox_image_id.as_str()) {
                return Err(invalid("smoke image differs from compiled image"));
            }
            let binary = workspace.join(binary_relative);
            let artifact = if record.api == hf_core::mutator::MutatorApi::AflPlusPlus {
                let filename = binary
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or_else(|| invalid("staged target filename is not UTF-8"))?;
                binary.with_file_name(format!("{filename}{LIBRARY_SUFFIX}"))
            } else {
                binary
            };
            verify_artifact(harness, &artifact, image)
        }
        _ => Err(invalid(
            "smoke source and compiled artifact record disagree",
        )),
    }
}
