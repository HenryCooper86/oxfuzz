//! `hobot_fuzz` GUI -- Tauri v2 desktop app.
//!
//! Thin Tauri command wrappers around `hf-service::ServiceContainer`. No
//! domain logic here (AGENTS.md 2.9). All builds and fuzz runs go through
//! `hf-runtime` sandboxing (AGENTS.md 2.12).

mod commands;
mod state;

use state::AppState;
use tauri::Manager;

use commands::{
    agent_info, app_paths, chat_agent, chat_answer_permission, chat_send, corpus_grow, corpus_list,
    corpus_prune, corpus_seed, create_session, delete_agent, delete_skill, discover, ensure_docker,
    generate_seeds, get_providers, harness_compile, harness_draft, host_arch, knowledge_summary,
    list_agents, list_configs, list_models, list_skills, open_file_dialog, open_folder_dialog,
    read_config, read_skill, run_fuzzer, run_syzkaller, save_agent, save_skill, set_providers,
    show_window, system_status_cmd, triage, write_config,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Run the Tauri GUI application.
///
/// # Panics
/// Panics if the Tauri runtime fails to initialize.
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(build_app_state())
        .invoke_handler(tauri::generate_handler![
            discover,
            open_folder_dialog,
            open_file_dialog,
            harness_draft,
            harness_compile,
            generate_seeds,
            corpus_list,
            corpus_seed,
            corpus_grow,
            corpus_prune,
            triage,
            system_status_cmd,
            ensure_docker,
            app_paths,
            host_arch,
            show_window,
            list_configs,
            list_models,
            get_providers,
            set_providers,
            read_config,
            write_config,
            run_fuzzer,
            run_syzkaller,
            chat_send,
            chat_agent,
            create_session,
            chat_answer_permission,
            knowledge_summary,
            agent_info,
            list_skills,
            read_skill,
            save_skill,
            delete_skill,
            list_agents,
            save_agent,
            delete_agent,
        ])
        .setup(|app| {
            let main_window = app.get_webview_window("main").expect("no main window");

            // macOS: apply native frosted-glass vibrancy (Apple-style layered
            // chrome) behind the transparent webview. Requires the
            // `macos-private-api` feature and a transparent app background in CSS.
            #[cfg(target_os = "macos")]
            {
                use tauri::utils::config::WindowEffectsConfig;
                use tauri::utils::{WindowEffect, WindowEffectState};

                let effects = WindowEffectsConfig {
                    effects: vec![WindowEffect::Sidebar],
                    state: Some(WindowEffectState::FollowsWindowActiveState),
                    radius: None,
                    color: None,
                };
                if let Err(e) = main_window.set_effects(Some(effects)) {
                    eprintln!("Failed to apply vibrancy effects: {e}");
                }
            }

            main_window.show().expect("failed to show window");

            // On launch, bring Docker up and ensure the sandbox image is loaded
            // in the background so the first compile/run "just works". Progress
            // is reported to the UI via `docker:status` events.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let _ = commands::ensure_docker_ready(&handle, None).await;
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running hobot_fuzz GUI");
}

/// Build the `AppState` from the canonical [`hf_service::ServiceContainer::bootstrap`]:
/// a Docker (or stub) runtime, an LLM provider pool from the environment, and
/// the `HF_DB_PATH` persistence store -- the same construction the CLI and web
/// API use.
fn build_app_state() -> AppState {
    let container = tauri::async_runtime::block_on(hf_service::ServiceContainer::bootstrap());
    AppState::new(container)
}
