use hf_coverage::parse_llvm_function_coverage;

#[test]
fn retains_counts_and_source_files_from_every_export_entry() {
    let functions = parse_llvm_function_coverage(
        r#"{"data":[
      {"functions":[{"name":"parse","count":7,"filenames":["/work/a.c"]}]},
      {"functions":[{"name":"parse","count":0,"filenames":["/work/b.c"]}]}
    ]}"#,
    )
    .unwrap();
    assert_eq!(functions.len(), 2);
    assert_eq!(functions[0].count, 7);
    assert_eq!(functions[1].count, 0);
    assert_eq!(functions[1].files, ["/work/b.c"]);
}

#[test]
fn malformed_or_missing_measurements_are_not_zero_coverage() {
    for json in [
        r#"{"data":[]}"#,
        r#"{"data":[{}]}"#,
        r#"{"data":[{"functions":[{"name":"parse","filenames":["a.c"]}]}]}"#,
        r#"{"data":[{"functions":[{"name":"parse","count":-1,"filenames":["a.c"]}]}]}"#,
    ] {
        assert!(parse_llvm_function_coverage(json).is_err(), "{json}");
    }
}
