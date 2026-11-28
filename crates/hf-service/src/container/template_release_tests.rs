//! The model-free C template releases what a constructor-style target returns.

use std::path::Path;

use hf_core::engine::EngineKind;
use hf_core::target::{
    InputSurface, Sanitizer, SourceLocation, TargetCandidate, TargetKind, TargetLanguage,
};
use uuid::Uuid;

fn c_target(root: &Path, symbol: &str, signature: &str) -> TargetCandidate {
    TargetCandidate {
        id: Uuid::new_v4(),
        project_root: root.to_path_buf(),
        language: TargetLanguage::C,
        symbol: symbol.to_owned(),
        kind: TargetKind::Parser,
        location: SourceLocation {
            file: root.join("libexif/exif-data.c"),
            line: 145,
            col: 1,
            end_line: None,
            end_col: None,
        },
        signature: Some(signature.to_owned()),
        input_surface: InputSurface::Bytes,
        complexity: 3,
        fit_score: 1.0,
        sanitizers: Vec::new(),
        rationale: String::new(),
        reachable_functions: Vec::new(),
        accumulated_complexity: 3,
    }
}

fn draft(target: &TargetCandidate) -> String {
    super::heuristic_draft(target, EngineKind::LibFuzzer, Sanitizer::Address, false)
        .unwrap()
        .source
}

#[test]
fn a_returned_object_is_released_with_the_projects_own_release_function() {
    // libexif: the template dropped the ExifData this returns, and every smoke
    // run stopped at once on a LeakSanitizer report that was not a bug.
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("libexif")).unwrap();
    std::fs::write(
        project.path().join("libexif/exif-data.h"),
        "ExifData *exif_data_new_from_data (const unsigned char *data, unsigned int size);\n\
         void      exif_data_unref  (ExifData *data);\n",
    )
    .unwrap();
    let target = c_target(
        project.path(),
        "exif_data_new_from_data",
        "ExifData * exif_data_new_from_data (const unsigned char *data, unsigned int size)",
    );

    let source = draft(&target);

    assert!(
        source.contains("ExifData * _result = exif_data_new_from_data("),
        "{source}"
    );
    assert!(
        source.contains("if (_result) exif_data_unref(_result);"),
        "{source}"
    );
}

#[test]
fn nothing_is_released_without_a_declared_release_function_or_for_a_string() {
    let project = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(project.path().join("libexif")).unwrap();
    std::fs::write(
        project.path().join("libexif/exif-data.h"),
        "/* no destructor */\n",
    )
    .unwrap();
    let object = c_target(
        project.path(),
        "exif_data_new_from_data",
        "ExifData * exif_data_new_from_data (const unsigned char *data, unsigned int size)",
    );
    assert!(!draft(&object).contains("_result"));

    // A returned string may be static; freeing it would be the bug.
    std::fs::write(
        project.path().join("libexif/exif-data.h"),
        "void name_free (char *);\n",
    )
    .unwrap();
    let string = c_target(
        project.path(),
        "name_lookup",
        "const char * name_lookup (const unsigned char *data, unsigned int size)",
    );
    assert!(!draft(&string).contains("_result"));
}
