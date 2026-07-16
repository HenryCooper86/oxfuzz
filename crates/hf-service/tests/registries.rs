//! Service-boundary tests for user-authored agents and skills.

use std::sync::Arc;

use hf_service::{AgentTurnRequest, NullSink, ServiceContainer, TrustTier};

#[tokio::test]
async fn service_owns_registry_paths_crud_and_selected_agent_validation() {
    let root = tempfile::tempdir().unwrap();
    let config = root.path().join("config-root");
    std::env::set_var("HF_CONFIG_DIR", &config);
    let service = ServiceContainer::new(Arc::new(hf_runtime::StubRuntime), None);

    let mut agent = service
        .get_agent_definition("crash-triager")
        .expect("built-in agent");
    agent.id = "release-triager".to_owned();
    agent.name = "Release Triager".to_owned();
    service.save_agent_definition(agent).unwrap();
    assert!(config.join("agents/release-triager.toml").is_file());
    assert_eq!(
        service
            .get_agent_definition("release-triager")
            .unwrap()
            .trust_tier,
        hf_agent::TrustTier::UserDefined
    );

    let mut skill = service
        .get_skill_definition("crash-triage")
        .expect("built-in skill");
    skill.name = "release-evidence".to_owned();
    skill.description = "Retain release evidence".to_owned();
    skill.body = "Verify every release gate and retain its output.".to_owned();
    skill.trust_tier = TrustTier::UserDefined;
    service.save_skill_definition(skill).unwrap();
    assert!(config.join("skills/release-evidence/skill.toml").is_file());
    assert!(config.join("skills/release-evidence/root.md").is_file());

    let mut unsafe_agent = service
        .get_agent_definition("crash-triager")
        .expect("built-in agent");
    unsafe_agent.id = "unsafe-agent".to_owned();
    unsafe_agent.allowed_tools.push("host-shell".to_owned());
    let error = service
        .save_agent_definition(unsafe_agent)
        .expect_err("unknown executable capabilities must be rejected by the service");
    assert!(matches!(error, hf_service::ClassifiedError::Validation(_)));

    let mut empty_skill = service
        .get_skill_definition("crash-triage")
        .expect("built-in skill");
    empty_skill.name = "empty-skill".to_owned();
    empty_skill.body.clear();
    let error = service
        .save_skill_definition(empty_skill)
        .expect_err("empty playbooks must not enter the runtime registry");
    assert!(matches!(error, hf_service::ClassifiedError::Validation(_)));

    let error = service
        .run_chat_turn(
            AgentTurnRequest {
                project: None,
                agent_id: Some("misspelled-agent".to_owned()),
                session: None,
                history_fallback: Vec::new(),
                message: "hello".to_owned(),
                display_message: None,
            },
            &NullSink,
        )
        .await
        .expect_err("an explicit unknown agent must not silently run the default");
    assert!(matches!(error, hf_service::ClassifiedError::Validation(_)));
    assert!(error.to_string().contains("misspelled-agent"));

    service.delete_agent_definition("release-triager").unwrap();
    service.delete_skill_definition("release-evidence").unwrap();
    assert!(service.get_agent_definition("release-triager").is_none());
    assert!(service.get_skill_definition("release-evidence").is_none());
}
