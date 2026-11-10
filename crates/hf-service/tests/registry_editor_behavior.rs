//! Registry editing preserves usable definitions and reports reset semantics.
use hf_service::ServiceContainer;
static ENVIRONMENT: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
fn editors_expose_delegation_from_the_runtime_roster() {
    let service = ServiceContainer::stubbed();
    assert!(service
        .agent_tool_definitions()
        .iter()
        .any(|tool| tool.name == "delegate"));
}

#[test]
fn overrides_report_reset_availability() {
    let _environment = ENVIRONMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path());
    let service = ServiceContainer::stubbed();
    let mut agent = service.get_agent_definition("orchestrator").unwrap();
    agent.name = "Customized orchestrator".into();
    service.save_agent_definition(agent).unwrap();
    let agents = serde_json::to_value(service.list_agent_definitions()).unwrap();
    let edited = agents
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "orchestrator")
        .unwrap();
    assert_eq!(edited["trust_tier"], "user-defined");
    assert_eq!(edited["builtin_available"], true);

    let mut skill = service.get_skill_definition("target-triage").unwrap();
    skill.body = "Custom target selection instructions".into();
    service.save_skill_definition(skill.clone()).unwrap();
    let skills = serde_json::to_value(service.list_skill_definitions()).unwrap();
    let edited = skills
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["name"] == "target-triage")
        .unwrap();
    assert_eq!(edited["builtin_available"], true);
    service.delete_skill_definition("target-triage").unwrap();
    assert_eq!(
        service
            .get_skill_definition("target-triage")
            .unwrap()
            .trust_tier,
        hf_service::TrustTier::BuiltIn
    );
}

#[test]
fn referenced_custom_skills_cannot_be_deleted() {
    let _environment = ENVIRONMENT
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let root = tempfile::tempdir().unwrap();
    std::env::set_var("HF_CONFIG_DIR", root.path());
    let service = ServiceContainer::stubbed();
    let mut skill = service.get_skill_definition("target-triage").unwrap();
    skill.name = "custom-playbook".into();
    service.save_skill_definition(skill.clone()).unwrap();
    let mut agent = service.get_agent_definition("target-scout").unwrap();
    agent.id = "custom-scout".into();
    agent.skills = vec![skill.name.clone()];
    service.save_agent_definition(agent.clone()).unwrap();
    let error = service
        .delete_skill_definition(&skill.name)
        .expect_err("must preserve a referenced playbook");
    assert!(error.to_string().contains("custom-scout"));
    assert!(service.get_skill_definition(&skill.name).is_some());
    agent.skills.clear();
    service.save_agent_definition(agent).unwrap();
    service.delete_skill_definition(&skill.name).unwrap();
    assert!(service.get_skill_definition(&skill.name).is_none());
}
