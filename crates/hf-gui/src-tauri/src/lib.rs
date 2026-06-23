//! `hobot_fuzz` GUI -- Tauri v2 desktop app.
//!
//! Thin Tauri command wrappers around hf-discovery, hf-harness, hf-engine,
//! hf-crash, hf-corpus. No domain logic here (AGENTS.md 2.9).

mod commands;

use commands::{
    corpus_grow, corpus_list, corpus_prune, corpus_seed, discover, show_window, system_status,
    triage,
};
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Run the Tauri GUI application.
///
/// # Panics
/// Panics if the Tauri runtime fails to initialize.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![
            discover,
            corpus_list,
            corpus_seed,
            corpus_grow,
            corpus_prune,
            triage,
            system_status,
            show_window,
        ])
        .setup(|app| {
            let main_window = app.get_webview_window("main").expect("no main window");
            main_window.show().expect("failed to show window");
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running hobot_fuzz GUI");
}
