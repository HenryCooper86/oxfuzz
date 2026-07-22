//! `oxfuzz` GUI -- Tauri v2 desktop app.
//!
//! Thin Tauri command wrappers around `hf-service::ServiceContainer`. No
//! domain logic here (AGENTS.md 2.9). All builds and fuzz runs go through
//! `hf-runtime` sandboxing (AGENTS.md 2.12).

mod commands;
mod state;

use state::AppState;
use tauri::Manager;

use commands::{
    agent_info, agent_tools, all_corpus, all_crashes, app_paths, artifact_summary,
    auto_revert_events, automotive_analyze_capture, automotive_build_replay_plan,
    automotive_capabilities, automotive_diff_captures, automotive_execute_replay,
    automotive_generate_mutations, automotive_import_capture, automotive_live_monitor,
    automotive_scan_uds, campaign_advice, campaign_evidence, cancel_run, chat_agent,
    chat_answer_permission, chat_branch, chat_branches, chat_checkpoints, chat_history,
    chat_rollback, chat_rollback_to, clear_all_artifacts, clear_all_runs, clear_knowledge,
    clear_project_auto_revert_override, clear_workspace, config_toml_to_value,
    config_value_to_toml, corpus_grow, corpus_list, corpus_prune, corpus_seed, coverage_functions,
    create_session, defectdojo_configured, defectdojo_embed, defectdojo_embed_close,
    defectdojo_embed_reload, defectdojo_start, defectdojo_status, defectdojo_stop,
    defectdojo_test_connection, delete_agent, delete_corpus_entry, delete_crash, delete_project,
    delete_report_draft, delete_run, delete_session, delete_skill, diagnostics_cost_summary,
    discover, dismiss_interrupted_run, effective_auto_revert_policy, ensure_docker,
    export_markdown, export_project_data, export_remediation_draft, export_report, export_repro,
    file_issue, generate_automotive_report, generate_report, generate_seeds, generate_seeds_llm,
    get_automotive_settings, get_defectdojo_config, get_fuzzing_settings, get_issue_tracker_config,
    get_providers, harness_compile, harness_draft, harness_promote, harness_promote_with_findings,
    harness_review_queue, harness_smoke, host_arch, interrupted_runs, issue_export,
    issue_tracker_test_connection, knowledge_index, knowledge_ingest, knowledge_search,
    knowledge_stats, knowledge_summary, list_agents, list_automotive_operations, list_models,
    list_report_drafts, list_skills, open_defectdojo, open_file_dialog, open_folder_dialog,
    open_path, open_url, patch_defectdojo_config, patch_issue_tracker_config,
    project_auto_revert_override, project_auto_revert_overrides, provider_test, push_to_defectdojo,
    read_config, read_skill, report_formats, reveal_path, revert_harness_from_run,
    run_coverage_series, run_fuzzer, run_harness_source, run_history, run_syzkaller, save_agent,
    save_report_draft, save_skill, schedule_concurrency_limits, schedule_concurrency_set,
    schedule_create, schedule_delete, schedule_history, schedule_history_clear, schedule_list,
    schedule_set_enabled, schedule_targets, set_automotive_settings,
    set_project_auto_revert_override, set_providers, system_snapshot, system_status_cmd, triage,
    verify_crash, workbench_dashboard, write_config,
};

#[cfg_attr(mobile, tauri::mobile_entry_point)]
/// Run the Tauri GUI application.
///
/// # Panics
/// Panics if the Tauri runtime fails to initialize.
pub fn run() {
    let app_state = match build_app_state() {
        Ok(state) => state,
        Err(error) => {
            eprintln!("failed to initialize oxfuzz application state: {error}");
            return;
        }
    };
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(app_state)
        .invoke_handler(tauri::generate_handler![
            discover,
            open_folder_dialog,
            open_file_dialog,
            harness_draft,
            harness_compile,
            harness_smoke,
            harness_promote,
            harness_promote_with_findings,
            generate_seeds,
            generate_seeds_llm,
            corpus_list,
            corpus_seed,
            corpus_grow,
            corpus_prune,
            all_crashes,
            all_corpus,
            triage,
            verify_crash,
            system_status_cmd,
            ensure_docker,
            app_paths,
            host_arch,
            list_models,
            get_fuzzing_settings,
            get_automotive_settings,
            set_automotive_settings,
            automotive_capabilities,
            automotive_analyze_capture,
            automotive_generate_mutations,
            automotive_build_replay_plan,
            automotive_execute_replay,
            list_automotive_operations,
            generate_automotive_report,
            automotive_import_capture,
            automotive_diff_captures,
            automotive_live_monitor,
            automotive_scan_uds,
            get_defectdojo_config,
            patch_defectdojo_config,
            get_issue_tracker_config,
            patch_issue_tracker_config,
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
            export_repro,
            campaign_advice,
            campaign_evidence,
            export_remediation_draft,
            export_markdown,
            export_project_data,
            report_formats,
            reveal_path,
            open_path,
            open_url,
            open_defectdojo,
            run_history,
            run_coverage_series,
            run_harness_source,
            revert_harness_from_run,
            project_auto_revert_override,
            project_auto_revert_overrides,
            effective_auto_revert_policy,
            auto_revert_events,
            set_project_auto_revert_override,
            clear_project_auto_revert_override,
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
            delete_crash,
            delete_corpus_entry,
            clear_all_artifacts,
            delete_run,
            clear_all_runs,
            diagnostics_cost_summary,
            artifact_summary,
            system_snapshot,
            workbench_dashboard,
            harness_review_queue,
            issue_export,
            file_issue,
            issue_tracker_test_connection,
            defectdojo_configured,
            defectdojo_embed,
            defectdojo_embed_close,
            defectdojo_embed_reload,
            defectdojo_status,
            defectdojo_start,
            defectdojo_stop,
            defectdojo_test_connection,
            push_to_defectdojo,
            list_report_drafts,
            save_report_draft,
            delete_report_draft,
            interrupted_runs,
            dismiss_interrupted_run,
            schedule_list,
            schedule_history,
            schedule_history_clear,
            schedule_targets,
            schedule_concurrency_limits,
            schedule_concurrency_set,
            schedule_create,
            schedule_delete,
            schedule_set_enabled,
            knowledge_index,
            knowledge_ingest,
            knowledge_search,
            knowledge_stats,
            agent_info,
            list_skills,
            read_skill,
            save_skill,
            delete_skill,
            list_agents,
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

            // Bind the scheduler's crash notifier now that we have an AppHandle:
            // a headless scheduled campaign that finds crashes emits a
            // `campaign:crash` event the frontend toasts on.
            {
                use tauri::{Emitter, Manager};
                let emitter = app.handle().clone();
                let state = app.state::<AppState>();
                state.scheduler.set_notifier(std::sync::Arc::new(
                    move |notice: hf_service::scheduler::CampaignNotice| {
                        let _ = emitter.emit("campaign:crash", notice);
                    },
                ));
            }

            // On launch, bring Docker up and ensure the sandbox image is loaded
            // in the background so the first compile/run "just works". Progress
            // is reported to the UI via `docker:status` events. DefectDojo rides
            // on the back of that: it is a Docker stack too, so it can only start
            // once the daemon is up.
            let handle = app.handle().clone();
            tauri::async_runtime::spawn(async move {
                let _ = commands::ensure_docker_ready(&handle, None).await;
                commands::autostart_defectdojo(&handle).await;
            });

            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running oxfuzz GUI");
}

/// Build the `AppState` from the canonical [`hf_service::ServiceContainer::bootstrap`]:
/// a Docker (or stub) runtime, an LLM provider pool from the environment, and
/// the `HF_DB_PATH` persistence store -- the same construction the CLI and web
/// API use.
fn build_app_state() -> Result<AppState, String> {
    pin_user_data_dirs()?;
    tauri::async_runtime::block_on(async {
        let container = hf_service::ServiceContainer::bootstrap().await;
        // The scheduler runs campaigns headlessly; persist schedules under the
        // user data dir so they survive restarts.
        let store_path = hf_service::init::user_app_dir().join("schedules.json");
        let scheduler = std::sync::Arc::new(
            hf_service::scheduler::CampaignScheduler::try_start(
                container.clone(),
                store_path,
                None,
            )
            .await
            .map_err(|error| error.to_string())?,
        );
        Ok(AppState::new(container, scheduler))
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
fn pin_user_data_dirs() -> Result<(), String> {
    let base = hf_service::init::user_app_dir();

    let cfg_dir = base.join("config");
    if std::env::var_os("HF_CONFIG_DIR").is_none() {
        std::fs::create_dir_all(&cfg_dir).map_err(|error| error.to_string())?;
        // Seed from the source checkout's config on first run (only when the
        // per-user file does not exist yet -- never clobber the user's edits).
        let user_providers = cfg_dir.join("providers.toml");
        let repo_providers =
            hf_service::repo_root().map(|root| root.join("config").join("providers.toml"));
        seed_user_provider_config(repo_providers.as_deref(), &user_providers)?;
        std::env::set_var("HF_CONFIG_DIR", &cfg_dir);
    }

    let data = base.join("data");
    std::fs::create_dir_all(&data).map_err(|error| error.to_string())?;
    if std::env::var_os("HF_DB_PATH").is_none() {
        std::env::set_var("HF_DB_PATH", data.join("oxfuzz.db"));
    }
    Ok(())
}

fn seed_user_provider_config(
    repo_providers: Option<&std::path::Path>,
    user_providers: &std::path::Path,
) -> Result<bool, String> {
    let Some(repo_providers) = repo_providers else {
        return Ok(false);
    };
    match std::fs::symlink_metadata(repo_providers) {
        Ok(metadata) if metadata.file_type().is_file() => {
            hf_service::config::copy_private_config_if_missing(repo_providers, user_providers)
        }
        Ok(_) => Err(format!(
            "provider seed is not a regular file: {}",
            repo_providers.display()
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::seed_user_provider_config;

    #[test]
    fn first_run_provider_seed_is_private_and_never_clobbers() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("repo-providers.toml");
        let destination = dir.path().join("user/config/providers.toml");
        std::fs::write(&source, "api_key = \"first\"\n").unwrap();

        assert!(seed_user_provider_config(Some(&source), &destination).unwrap());
        std::fs::write(&source, "api_key = \"replacement\"\n").unwrap();
        assert!(!seed_user_provider_config(Some(&source), &destination).unwrap());
        assert_eq!(
            std::fs::read_to_string(&destination).unwrap(),
            "api_key = \"first\"\n"
        );

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(destination).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}
