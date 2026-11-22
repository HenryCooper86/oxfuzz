//! The bridge between the flat run corpus and Go's own fuzz cache.
//!
//! Go's native fuzzer reads and keeps its corpus as text files in its own
//! encoding under `<cache>/<FuzzXxx>/` and ignores raw input files, while
//! every other part of the service (seeding, snapshots, merge-back,
//! minimization) works on a flat directory of raw inputs. The run's fuzz
//! cache lives under its output directory; seeds are encoded into it before
//! the run and Go's discoveries are decoded back into the run corpus
//! afterwards. See `docs/design/go-native-fuzzing-design.md`.

use std::path::Path;

use hf_core::error::ClassifiedError;
use hf_crash::go_corpus;
use hf_engine::go_native::FUZZ_CACHE_DIR;

/// Most fuzz-test directories read back from one cache. A harness binary
/// holds one fuzz test; the bound keeps a hostile output tree cheap.
const MAX_CACHE_DIRECTORIES: usize = 8;

/// Encode the run corpus into the fuzz cache of the harness's fuzz test.
/// Returns the number of seeds staged.
///
/// # Errors
/// Returns [`ClassifiedError::Harness`] when the harness source does not
/// define one fuzz test with a `[]byte` or `string` input, and the corpus
/// errors of [`hf_corpus::export_encoded`].
pub(super) fn stage_seeds(
    run_corpus: &Path,
    run_output: &Path,
    harness_source: &str,
) -> Result<usize, ClassifiedError> {
    let symbol = hf_harness::go_native::fuzzed_symbol(harness_source)?;
    let kind = hf_harness::go_native::harness_input_kind(harness_source).ok_or_else(|| {
        ClassifiedError::Harness(
            "the Go harness callback does not take one []byte or string input, so the corpus \
             cannot be encoded for it"
                .to_owned(),
        )
    })?;
    let cache = run_output
        .join(FUZZ_CACHE_DIR)
        .join(hf_harness::go_native::fuzz_test_name(&symbol));
    hf_corpus::export_encoded(run_corpus, &cache, &|data| {
        go_corpus::encode(kind, data).into_bytes()
    })
}

/// Decode the inputs Go kept in the run's fuzz cache into the run corpus.
///
/// # Errors
/// Returns the corpus errors of [`hf_corpus::grow_decoded`].
pub(super) fn collect_discoveries(
    run_corpus: &Path,
    run_output: &Path,
) -> Result<(), ClassifiedError> {
    let cache = run_output.join(FUZZ_CACHE_DIR);
    let Ok(entries) = std::fs::read_dir(&cache) else {
        return Ok(());
    };
    let mut directories: Vec<_> = entries
        .filter_map(Result::ok)
        .filter(|entry| {
            entry.file_type().is_ok_and(|kind| kind.is_dir())
                && is_fuzz_test_name(&entry.file_name().to_string_lossy())
        })
        .map(|entry| entry.path())
        .take(MAX_CACHE_DIRECTORIES)
        .collect();
    directories.sort();
    for directory in directories {
        hf_corpus::grow_decoded(run_corpus, &directory, &|file| {
            go_corpus::decode(file).ok().map(|(_, data)| data)
        })?;
    }
    Ok(())
}

fn is_fuzz_test_name(name: &str) -> bool {
    name.strip_prefix("Fuzz").is_some_and(|rest| {
        !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
    })
}
