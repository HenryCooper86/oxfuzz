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
    agent_info, agent_tools, app_paths, cancel_run, chat_agent, chat_answer_permission,
    chat_branch, chat_branches, chat_checkpoints, chat_history, chat_rollback, chat_rollback_to,
    chat_send, config_toml_to_value, config_value_to_toml, corpus_grow, corpus_list, corpus_prune,
    corpus_seed, coverage_functions, create_session, delete_agent, delete_skill,
    diagnostics_cost_summary, discover, dismiss_interrupted_run, ensure_docker, generate_report,
    generate_seeds, get_agent, get_providers, harness_compile, harness_draft, host_arch,
    interrupted_runs,
    knowledge_index, knowledge_search, knowledge_summary, list_agents, list_configs, list_models,
    list_skills, open_file_dialog, open_folder_dialog, provider_test, read_config, read_skill,
    run_fuzzer, run_syzkaller, save_agent, save_report, save_skill, schedule_create, schedule_delete,
    schedule_history, schedule_list, schedule_set_enabled, set_providers, show_window,
    system_status_cmd, triage, write_config,
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
            provider_test,
            read_config,
            write_config,
            config_toml_to_value,
            config_value_to_toml,
            run_fuzzer,
            run_syzkaller,
            cancel_run,
            generate_report,
            save_report,
            chat_send,
            chat_agent,
            create_session,
            chat_answer_permission,
            chat_rollback,
            chat_checkpoints,
            chat_rollback_to,
            chat_branch,
            chat_branches,
            coverage_functions,
            chat_history,
            knowledge_summary,
            diagnostics_cost_summary,
            interrupted_runs,
            dismiss_interrupted_run,
            schedule_list,
            schedule_history,
            schedule_create,
            schedule_delete,
            schedule_set_enabled,
            knowledge_index,
            knowledge_search,
            agent_info,
            list_skills,
            read_skill,
            save_skill,
            delete_skill,
            list_agents,
            get_agent,
            agent_tools,
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
    ensure_writable_data_paths();
    tauri::async_runtime::block_on(async {
        let container = hf_service::ServiceContainer::bootstrap().await;
        // The scheduler runs campaigns headlessly; persist schedules under the
        // user data dir so they survive restarts.
        let store_path = hf_service::init::user_app_dir().join("schedules.json");
        let scheduler = std::sync::Arc::new(
            hf_service::scheduler::CampaignScheduler::start(container.clone(), store_path).await,
        );
        AppState::new(container, scheduler)
    })
}

/// When the app runs as an installed bundle (no source checkout), a
/// Finder-launched process has cwd `/`, so the relative `data/hobot_fuzz.db`
/// default would target the read-only system volume and persistence silently
/// fails. Point `HF_DB_PATH` at the writable per-user data directory instead.
/// In a dev checkout (`repo_root()` resolves) the repo-relative paths are kept.
fn ensure_writable_data_paths() {
    if hf_service::repo_root().is_some() {
        return;
    }
    let data = hf_service::init::user_app_dir().join("data");
    let _ = std::fs::create_dir_all(&data);
    if std::env::var_os("HF_DB_PATH").is_none() {
        std::env::set_var("HF_DB_PATH", data.join("hobot_fuzz.db"));
    }
}
