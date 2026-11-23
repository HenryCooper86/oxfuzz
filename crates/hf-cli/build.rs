//! Give the `oxfuzz` binary the same main-thread stack on every platform.
//!
//! The CLI runs its command dispatch on the main thread, and an unoptimized
//! build reserves stack for every command's future in that one frame. Linux and
//! macOS default to an 8 MiB main-thread stack; Windows links 1 MiB, which a
//! debug build of the `fuzz` pipeline exceeds.

const MAIN_THREAD_STACK_BYTES: u32 = 8 * 1024 * 1024;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    match std::env::var("CARGO_CFG_TARGET_ENV").as_deref() {
        Ok("msvc") => {
            println!("cargo:rustc-link-arg-bin=oxfuzz=/STACK:{MAIN_THREAD_STACK_BYTES}");
        }
        Ok("gnu") => {
            println!("cargo:rustc-link-arg-bin=oxfuzz=-Wl,--stack,{MAIN_THREAD_STACK_BYTES}");
        }
        _ => {}
    }
}
