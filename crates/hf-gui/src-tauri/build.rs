fn main() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo sets the target OS");
    let target_env =
        std::env::var("CARGO_CFG_TARGET_ENV").expect("Cargo sets the target environment");
    if target_os == "windows" && target_env == "msvc" {
        // Kept identical to tauri-build 2.6.3's src/windows-app-manifest.xml.
        let manifest = std::path::PathBuf::from(
            std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets the package directory"),
        )
        .join("windows-app-manifest.xml");
        println!("cargo:rerun-if-changed={}", manifest.display());
        // Tauri's resource compiler links only binary targets. Native mock IPC
        // tests also import Common Controls v6 and need its activation manifest.
        // `rustc-link-arg-tests` excludes lib unit tests, so embed for all targets.
        println!("cargo:rustc-link-arg=/MANIFEST:EMBED");
        println!("cargo:rustc-link-arg=/MANIFESTINPUT:{}", manifest.display());
        // Keep one manifest resource while retaining Tauri's icon and version.
        let attributes = tauri_build::Attributes::new()
            .windows_attributes(tauri_build::WindowsAttributes::new_without_app_manifest());
        tauri_build::try_build(attributes).expect("failed to run Tauri build script");
    } else {
        tauri_build::build();
    }
}
