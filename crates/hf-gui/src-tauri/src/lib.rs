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
    agent_info, agent_tools, all_corpus, all_crashes, app_paths, artifact_summary, cancel_run,
    chat_agent, chat_answer_permission, chat_branch, chat_branches, chat_checkpoints, chat_history,
    chat_rollback, chat_rollback_to, chat_send, clear_knowledge, clear_workspace,
    config_toml_to_value, config_value_to_toml, corpus_grow, corpus_list, corpus_prune,
    corpus_seed, coverage_functions, create_session, delete_agent, delete_project,
    delete_report_draft, delete_session, delete_skill, diagnostics_cost_summary, discover,
    dismiss_interrupted_run, ensure_docker, export_markdown, export_project_data, export_report,
    generate_report, generate_seeds, generate_seeds_llm, get_agent, get_providers,
    gitlab_issue_export, harness_compile, harness_draft, harness_review_queue, host_arch,
    interrupted_runs, knowledge_index, knowledge_ingest, knowledge_search, knowledge_summary,
    list_agents, list_configs, list_models, list_report_drafts, list_skills, open_file_dialog,
    open_folder_dialog, open_path, provider_statuses, provider_test, read_config, read_skill,
    report_formats, reveal_path, run_coverage_series, run_fuzzer, run_harness_source, run_history,
    run_syzkaller, save_agent, save_report, save_report_draft, save_skill, schedule_create,
    schedule_delete, schedule_history, schedule_list, schedule_set_enabled, set_providers,
    show_window, system_snapshot, system_status_cmd, triage, workbench_dashboard, write_config,
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
            generate_seeds_llm,
            corpus_list,
            corpus_seed,
            corpus_grow,
            corpus_prune,
            all_crashes,
            all_corpus,
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
            export_report,
            export_markdown,
            export_project_data,
            report_formats,
            reveal_path,
            open_path,
            run_history,
            run_coverage_series,
            run_harness_source,
            save_report,
            chat_send,
            chat_agent,
            create_session,
            delete_session,
            chat_answer_permission,
            chat_rollback,
            chat_checkpoints,
            chat_rollback_to,
            chat_branch,
            chat_branches,
            coverage_functions,
            chat_history,
            knowledge_summary,
            clear_knowledge,
            clear_workspace,
            delete_project,
            diagnostics_cost_summary,
            provider_statuses,
            artifact_summary,
            system_snapshot,
            workbench_dashboard,
            harness_review_queue,
            gitlab_issue_export,
            list_report_drafts,
            save_report_draft,
            delete_report_draft,
            interrupted_runs,
            dismiss_interrupted_run,
            schedule_list,
            schedule_history,
            schedule_create,
            schedule_delete,
            schedule_set_enabled,
            knowledge_index,
            knowledge_ingest,
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
    pin_user_data_dirs();
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

/// Pin the desktop app's config and data to the writable per-user directory so
/// the Settings panel is the single source of truth.
///
/// The desktop app is the user-facing surface: whatever its Settings panel saves
/// must be exactly what the app loads. Without this, `config_dir()` prefers
/// `<repo>/config` whenever the binary sits inside a source checkout (e.g. a
/// bundle built into `target/`), so Settings edits (written under Application
/// Support) would be silently ignored. Pinning `HF_CONFIG_DIR` + `HF_DB_PATH`
/// here makes reads and writes align on the per-user directory in every launch
/// mode. Explicit env overrides are respected. The CLI/web do not run this, so
/// they keep using `<repo>/config` for development.
///
/// On first run the per-user config is seeded from `<repo>/config` when present,
/// so a developer's existing providers carry over into the GUI.
fn pin_user_data_dirs() {
    let base = hf_service::init::user_app_dir();

    let cfg_dir = base.join("config");
    if std::env::var_os("HF_CONFIG_DIR").is_none() {
        let _ = std::fs::create_dir_all(&cfg_dir);
        // Seed from the source checkout's config on first run (only when the
        // per-user file does not exist yet -- never clobber the user's edits).
        let user_providers = cfg_dir.join("providers.toml");
        if !user_providers.exists() {
            if let Some(repo_providers) =
                hf_service::repo_root().map(|r| r.join("config").join("providers.toml"))
            {
                if repo_providers.exists() {
                    let _ = std::fs::copy(&repo_providers, &user_providers);
                }
            }
        }
        std::env::set_var("HF_CONFIG_DIR", &cfg_dir);
    }

    let data = base.join("data");
    let _ = std::fs::create_dir_all(&data);
    if std::env::var_os("HF_DB_PATH").is_none() {
        std::env::set_var("HF_DB_PATH", data.join("hobot_fuzz.db"));
    }
}
