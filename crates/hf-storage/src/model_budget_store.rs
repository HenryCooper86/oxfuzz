//! Durable provider-attempt reservations. Policy resolution belongs to hf-service.

use serde::{Deserialize, Serialize};
use sqlx::Row;
use uuid::Uuid;

use crate::{StorageError, Store};

/// Resolved immutable policy for one workflow.
#[derive(Debug, Clone)]
pub struct ModelBudgetPolicy {
    pub scope_id: String,
    pub policy_json: String,
    pub max_calls: Option<i64>,
    pub max_tokens: Option<i64>,
    pub max_cost_microusd: Option<i64>,
}

/// Maximum charge for a single upstream attempt.
#[derive(Debug, Clone)]
pub struct ModelBudgetCharge {
    pub provider: String,
    pub model: String,
    pub input_tokens: i64,
    pub output_tokens: i64,
    pub cost_microusd: i64,
}

/// Durable accounting totals include unsettled reservations.
#[derive(Debug, Clone, Serialize, Deserialize, sqlx::FromRow)]
pub struct ModelBudgetSnapshot {
    pub scope_id: String,
    pub calls: i64,
    pub tokens: i64,
    pub cost_microusd: i64,
    pub terminal_reason: Option<String>,
    pub blocked: bool,
}

/// Admission either commits a reservation or retains a named denial.
#[derive(Debug)]
pub enum ModelBudgetAdmission {
    Reserved(Uuid),
    Denied(String),
}

impl Store {
    /// Reserve before dispatch, serialized across connections and processes.
    pub async fn reserve_model_budget(
        &self,
        policy: &ModelBudgetPolicy,
        charge: &ModelBudgetCharge,
    ) -> Result<ModelBudgetAdmission, StorageError> {
        let mut tx = self.pool().begin().await?;
        // A write precedes the read so concurrent deferred transactions cannot
        // both read an old balance and then try to upgrade their snapshot.
        sqlx::query("INSERT INTO model_budget_scopes(scope_id, policy_json) VALUES (?, ?) ON CONFLICT(scope_id) DO NOTHING")
            .bind(&policy.scope_id).bind(&policy.policy_json).execute(&mut *tx).await?;
        let row = sqlx::query("SELECT * FROM model_budget_scopes WHERE scope_id = ?")
            .bind(&policy.scope_id)
            .fetch_one(&mut *tx)
            .await?;
        let calls: i64 = row.try_get("calls")?;
        let tokens: i64 = row.try_get("tokens")?;
        let cost: i64 = row.try_get("cost_microusd")?;
        let new_calls = calls.checked_add(1);
        let new_tokens = charge
            .input_tokens
            .checked_add(charge.output_tokens)
            .and_then(|value| tokens.checked_add(value));
        let new_cost = cost.checked_add(charge.cost_microusd);
        let reason = if row.try_get::<String, _>("policy_json")? != policy.policy_json {
            Some("scope_limits_changed")
        } else if row.try_get::<bool, _>("blocked")? {
            Some("usage_exceeded_reservation")
        } else if exceeds(new_calls, policy.max_calls) {
            Some("calls_exhausted")
        } else if exceeds(new_tokens, policy.max_tokens) {
            Some("tokens_exhausted")
        } else if exceeds(new_cost, policy.max_cost_microusd) {
            Some("cost_exhausted")
        } else {
            None
        };
        if let Some(reason) = reason {
            sqlx::query("UPDATE model_budget_scopes SET terminal_reason = ? WHERE scope_id = ?")
                .bind(reason)
                .bind(&policy.scope_id)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(ModelBudgetAdmission::Denied(reason.into()));
        }
        sqlx::query("UPDATE model_budget_scopes SET calls = ?, tokens = ?, cost_microusd = ? WHERE scope_id = ?")
            .bind(new_calls).bind(new_tokens).bind(new_cost).bind(&policy.scope_id)
            .execute(&mut *tx).await?;
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO model_budget_attempts(id, scope_id, provider, model, reserved_input, reserved_output, reserved_cost_microusd, state) VALUES (?, ?, ?, ?, ?, ?, ?, 'reserved')")
            .bind(id.to_string()).bind(&policy.scope_id).bind(&charge.provider).bind(&charge.model)
            .bind(charge.input_tokens).bind(charge.output_tokens).bind(charge.cost_microusd)
            .execute(&mut *tx).await?;
        tx.commit().await?;
        Ok(ModelBudgetAdmission::Reserved(id))
    }

    /// Settle once; unknown or interrupted requests never call this operation.
    /// Returns false when observed usage exceeds its reservation and blocks the scope.
    pub async fn settle_model_budget(
        &self,
        id: Uuid,
        input: i64,
        output: i64,
        cost: i64,
    ) -> Result<bool, StorageError> {
        let mut tx = self.pool().begin().await?;
        let changed = sqlx::query("UPDATE model_budget_attempts SET state = 'settled', observed_input = ?, observed_output = ?, observed_cost_microusd = ? WHERE id = ? AND state = 'reserved'")
            .bind(input).bind(output).bind(cost).bind(id.to_string())
            .execute(&mut *tx).await?.rows_affected();
        let row = sqlx::query("SELECT * FROM model_budget_attempts WHERE id = ?")
            .bind(id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        if changed == 0 {
            let settled = row.try_get::<String, _>("state")? == "settled";
            tx.commit().await?;
            return Ok(settled);
        }
        let reserved_input: i64 = row.try_get("reserved_input")?;
        let reserved_output: i64 = row.try_get("reserved_output")?;
        let reserved_cost: i64 = row.try_get("reserved_cost_microusd")?;
        let scope: String = row.try_get("scope_id")?;
        let within = input >= 0
            && output >= 0
            && cost >= 0
            && input <= reserved_input
            && output <= reserved_output
            && cost <= reserved_cost;
        if within {
            let refunded_tokens = (reserved_input - input) + (reserved_output - output);
            sqlx::query("UPDATE model_budget_scopes SET tokens = tokens - ?, cost_microusd = cost_microusd - ? WHERE scope_id = ?")
                .bind(refunded_tokens).bind(reserved_cost - cost).bind(scope).execute(&mut *tx).await?;
        } else {
            sqlx::query("UPDATE model_budget_attempts SET state = 'overrun' WHERE id = ?")
                .bind(id.to_string())
                .execute(&mut *tx)
                .await?;
            sqlx::query("UPDATE model_budget_scopes SET blocked = 1, terminal_reason = 'usage_exceeded_reservation' WHERE scope_id = ?")
                .bind(scope).execute(&mut *tx).await?;
        }
        tx.commit().await?;
        Ok(within)
    }

    /// Inspect durable totals without invoking a provider.
    pub async fn model_budget_snapshot(
        &self,
        scope: &str,
    ) -> Result<Option<ModelBudgetSnapshot>, StorageError> {
        Ok(sqlx::query_as("SELECT scope_id, calls, tokens, cost_microusd, terminal_reason, blocked FROM model_budget_scopes WHERE scope_id = ?")
            .bind(scope).fetch_optional(self.pool()).await?)
    }
}

fn exceeds(value: Option<i64>, limit: Option<i64>) -> bool {
    match (value, limit) {
        (None, _) => true,
        (Some(value), Some(limit)) => value > limit,
        (Some(_), None) => false,
    }
}
