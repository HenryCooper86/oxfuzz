use hf_core::types::ToolCallRequest;
use serde_json::json;

#[test]
fn tool_call_metadata_survives_serde_without_changing_legacy_calls() {
    let legacy = json!({"id":"call_a", "name":"read", "arguments":{"path":"a"}});
    let call: ToolCallRequest = serde_json::from_value(legacy.clone()).unwrap();
    assert_eq!(serde_json::to_value(call).unwrap(), legacy);

    let mut persisted = legacy;
    persisted["provider_metadata"] = json!({"gemini":{"version":1,"parts":[]}});
    let call: ToolCallRequest = serde_json::from_value(persisted.clone()).unwrap();
    assert_eq!(serde_json::to_value(call).unwrap(), persisted);
}
