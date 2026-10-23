#![cfg(not(feature = "managed-mutators"))]

#[test]
fn disabled_import_and_retained_envelope_fail_explicitly() {
    let error = hf_harness::managed_mutator::compose(
        "base",
        "native",
        hf_core::engine::EngineKind::AflPlusPlus,
        hf_core::target::TargetLanguage::C,
    )
    .unwrap_err();
    assert!(error.to_string().contains("feature is disabled"));
    let error = hf_harness::managed_mutator::inspect(
        "/* OXFUZZ_NATIVE_MUTATOR_V1 afl++ digest */",
        hf_core::engine::EngineKind::AflPlusPlus,
        hf_core::target::TargetLanguage::C,
    )
    .err()
    .expect("disabled retained source denied");
    assert!(error.to_string().contains("feature is disabled"));
}
