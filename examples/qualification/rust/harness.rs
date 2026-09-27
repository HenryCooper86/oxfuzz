#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    let _ = qualification_rust::parse_record(data);
});
