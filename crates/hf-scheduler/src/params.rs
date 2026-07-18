//! Parameter resolution engine for scheduled workflows.
//!
//! Resolves parameter values through a three-step chain:
//! 1. Defaults from a parameter schema
//! 2. Static overrides from the schedule's `parameter_values`
//! 3. Dynamic expressions evaluated at trigger time (e.g. `{{ trigger.time }}`)
//!
//! An expression that cannot be resolved is a hard [`ResolveError`]: silently
//! passing a raw `{{ ... }}` template through to a workflow would run it with
//! a parameter the author never intended.

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::trigger::TriggerType;

/// Context available during parameter resolution.
#[derive(Debug, Clone)]
pub struct ResolutionContext {
    /// When the trigger fired.
    pub trigger_time: DateTime<Utc>,
    /// Type of trigger.
    pub trigger_type: TriggerType,
    /// Execution sequence number.
    pub execution_sequence: u64,
    /// Optional event payload (for event-driven triggers).
    pub event_payload: Option<Value>,
}

/// A parameter expression that could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    /// The expression inside `{{ ... }}` is not one of the supported forms.
    #[error("unknown parameter expression: {0}")]
    UnknownExpression(String),
    /// An `event.payload.*` reference has no event payload or no such field.
    #[error("event payload field not found: {0}")]
    EventFieldNotFound(String),
}

/// Resolve parameter values for a scheduled workflow execution.
///
/// Resolution chain:
/// 1. Start with `defaults`
/// 2. Override with `static_values` (schedule's `parameter_values`)
/// 3. Resolve expression strings (`{{ expr }}`) using `context`
///
/// # Errors
/// Returns [`ResolveError`] when any `{{ ... }}` expression in the merged
/// values cannot be resolved against `context`.
pub fn resolve_parameters(
    defaults: &Value,
    static_values: &Value,
    context: &ResolutionContext,
) -> Result<Value, ResolveError> {
    let mut result = merge_values(defaults, static_values);
    resolve_expressions(&mut result, context)?;
    Ok(result)
}

/// Merge two JSON objects. Values in `overlay` override those in `base`.
/// Non-object values in `overlay` replace `base` entirely.
fn merge_values(base: &Value, overlay: &Value) -> Value {
    match (base, overlay) {
        (Value::Object(base_map), Value::Object(overlay_map)) => {
            let mut merged = base_map.clone();
            for (key, value) in overlay_map {
                if let Some(existing) = merged.get(key) {
                    merged.insert(key.clone(), merge_values(existing, value));
                } else {
                    merged.insert(key.clone(), value.clone());
                }
            }
            Value::Object(merged)
        }
        (_, overlay) => overlay.clone(),
    }
}

/// Resolve `{{ expression }}` strings in a JSON value tree.
fn resolve_expressions(value: &mut Value, ctx: &ResolutionContext) -> Result<(), ResolveError> {
    match value {
        Value::String(s) => {
            if let Some(resolved) = try_resolve_expression(s, ctx)? {
                *value = resolved;
            }
        }
        Value::Object(map) => {
            for v in map.values_mut() {
                resolve_expressions(v, ctx)?;
            }
        }
        Value::Array(arr) => {
            for v in arr.iter_mut() {
                resolve_expressions(v, ctx)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Try to resolve a single `{{ expr }}` expression.
///
/// Supported expressions:
/// - `{{ trigger.time }}` → ISO 8601 timestamp
/// - `{{ trigger.type }}` → trigger type string
/// - `{{ execution.sequence }}` → sequence number
/// - `{{ event.payload.FIELD }}` → field from event payload
///
/// Returns `Ok(None)` for plain strings that are not expressions at all;
/// `Err` for strings that are expressions but cannot be resolved.
fn try_resolve_expression(s: &str, ctx: &ResolutionContext) -> Result<Option<Value>, ResolveError> {
    let trimmed = s.trim();
    if !trimmed.starts_with("{{") || !trimmed.ends_with("}}") {
        return Ok(None);
    }

    let expr = trimmed[2..trimmed.len() - 2].trim();

    match expr {
        "trigger.time" => Ok(Some(Value::String(ctx.trigger_time.to_rfc3339()))),
        "trigger.type" => Ok(Some(Value::String(ctx.trigger_type.to_string()))),
        "execution.sequence" => Ok(Some(Value::Number(ctx.execution_sequence.into()))),
        _ if expr.starts_with("event.payload.") => {
            let field = &expr["event.payload.".len()..];
            ctx.event_payload
                .as_ref()
                .and_then(|payload| resolve_json_path(payload, field))
                .map(Some)
                .ok_or_else(|| ResolveError::EventFieldNotFound(field.to_owned()))
        }
        _ => Err(ResolveError::UnknownExpression(expr.to_owned())),
    }
}

/// Resolve a dot-path (e.g. `"nested.field"`) in a JSON value.
pub(crate) fn resolve_json_path(value: &Value, path: &str) -> Option<Value> {
    let parts: Vec<&str> = path.split('.').collect();
    let mut current = value;
    for part in parts {
        match current {
            Value::Object(map) => {
                current = map.get(part)?;
            }
            _ => return None,
        }
    }
    Some(current.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn test_context() -> ResolutionContext {
        ResolutionContext {
            trigger_time: "2026-03-11T09:00:00Z".parse().unwrap(),
            trigger_type: TriggerType::Cron,
            execution_sequence: 42,
            event_payload: Some(json!({
                "path": "/workspace/test.md",
                "nested": { "value": 123 }
            })),
        }
    }

    #[test]
    fn test_param_resolution_defaults_only() {
        let defaults = json!({"key": "default_value", "count": 10});
        let static_values = json!({});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["key"], "default_value");
        assert_eq!(result["count"], 10);
    }

    #[test]
    fn test_param_resolution_static_override() {
        let defaults = json!({"key": "default", "count": 10});
        let static_values = json!({"key": "overridden"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["key"], "overridden");
        assert_eq!(result["count"], 10); // Not overridden.
    }

    #[test]
    fn test_param_resolution_trigger_time() {
        let defaults = json!({});
        let static_values = json!({"fired_at": "{{ trigger.time }}"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert!(result["fired_at"].as_str().unwrap().contains("2026-03-11"));
    }

    #[test]
    fn test_param_resolution_trigger_type() {
        let defaults = json!({});
        let static_values = json!({"type": "{{ trigger.type }}"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["type"], "cron");
    }

    #[test]
    fn test_param_resolution_execution_sequence() {
        let defaults = json!({});
        let static_values = json!({"seq": "{{ execution.sequence }}"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["seq"], 42);
    }

    #[test]
    fn test_param_resolution_event_payload() {
        let defaults = json!({});
        let static_values = json!({"file": "{{ event.payload.path }}"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["file"], "/workspace/test.md");
    }

    #[test]
    fn test_param_resolution_nested_event_payload() {
        let defaults = json!({});
        let static_values = json!({"val": "{{ event.payload.nested.value }}"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["val"], 123);
    }

    #[test]
    fn test_param_resolution_unknown_expression_fails() {
        let defaults = json!({});
        let static_values = json!({"x": "{{ unknown.expr }}"});
        let ctx = test_context();

        // An unresolvable expression must fail visibly, never pass the raw
        // template through to the workflow as if it were a literal value.
        let error = resolve_parameters(&defaults, &static_values, &ctx).unwrap_err();
        assert!(
            matches!(error, ResolveError::UnknownExpression(ref expr) if expr == "unknown.expr")
        );
    }

    #[test]
    fn test_param_resolution_event_field_without_payload_fails() {
        let defaults = json!({});
        let static_values = json!({"file": "{{ event.payload.path }}"});
        let ctx = ResolutionContext {
            event_payload: None,
            ..test_context()
        };

        let error = resolve_parameters(&defaults, &static_values, &ctx).unwrap_err();
        assert!(matches!(error, ResolveError::EventFieldNotFound(ref field) if field == "path"));
    }

    #[test]
    fn test_param_resolution_missing_event_field_fails() {
        let defaults = json!({});
        let static_values = json!({"file": "{{ event.payload.absent }}"});
        let ctx = test_context();

        let error = resolve_parameters(&defaults, &static_values, &ctx).unwrap_err();
        assert!(matches!(error, ResolveError::EventFieldNotFound(ref field) if field == "absent"));
    }

    #[test]
    fn test_param_resolution_non_expression_unchanged() {
        let defaults = json!({});
        let static_values = json!({"msg": "Hello world"});
        let ctx = test_context();

        let result = resolve_parameters(&defaults, &static_values, &ctx).unwrap();
        assert_eq!(result["msg"], "Hello world");
    }

    #[test]
    fn test_merge_nested_objects() {
        let base = json!({"a": {"x": 1, "y": 2}});
        let overlay = json!({"a": {"y": 3, "z": 4}});

        let merged = merge_values(&base, &overlay);
        assert_eq!(merged["a"]["x"], 1);
        assert_eq!(merged["a"]["y"], 3);
        assert_eq!(merged["a"]["z"], 4);
    }
}
