//! Durable, progressive target discovery with an advisory AI overlay.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;

use hf_core::error::ClassifiedError;
use hf_core::provider::{ChatRequest, LlmProvider};
use hf_core::target::{TargetInventory, TargetLanguage};
use hf_core::types::Message;
use hf_discovery::ai_ranking::{
    order_with_assessments, parse_ai_batch, select_ai_candidates, TargetAssessment,
};
use hf_guardrails::Action;
use hf_storage::{AiDiscoveryRecord, AiDiscoveryState, AiRankingSource, Store};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::{canonical_project_root, LlmProviderBridge, ServiceContainer};
use crate::AiPolicy;

/// Lightweight status for polling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedDiscoveryStatus {
    pub operation_id: Uuid,
    pub state: AiDiscoveryState,
    pub revision: u8,
    pub assessed_count: u32,
    pub total_count: u32,
    pub reason_code: Option<String>,
}

/// Immutable scan and optional final assessment overlay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedDiscoveryResult {
    pub operation_id: Uuid,
    pub revision: u8,
    pub project_root: std::path::PathBuf,
    pub language: TargetLanguage,
    pub scanned_at: chrono::DateTime<chrono::Utc>,
    pub inventory: TargetInventory,
    pub assessments: Vec<TargetAssessment>,
    pub assessed_count: u32,
    pub total_count: u32,
    pub ranking_source: AiRankingSource,
    pub reason_code: Option<String>,
}

/// Terminal recommendation for an inventory supplied by another service flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RankedInventoryAdvice {
    pub inventory: TargetInventory,
    pub assessments: Vec<TargetAssessment>,
    pub ranking_source: AiRankingSource,
    pub reason_code: Option<String>,
}

impl ServiceContainer {
    /// Apply service-owned AI policy to an existing scan.
    ///
    /// # Errors
    /// Returns an error when `Require` cannot get a complete assessment, or
    /// when authorization or required persistence fails.
    pub async fn rank_discovered_inventory(
        &self,
        inventory: TargetInventory,
        language: TargetLanguage,
        policy: AiPolicy,
    ) -> Result<RankedInventoryAdvice, ClassifiedError> {
        if policy == AiPolicy::Off {
            return Ok(heuristic_advice(inventory, "ai_off"));
        }
        if self.provider_pool().is_none() {
            if policy == AiPolicy::Require {
                return Err(ClassifiedError::Provider(
                    "AI ranking requires a configured provider".to_owned(),
                ));
            }
            return Ok(heuristic_advice(inventory, "no_provider"));
        }
        let Ok(store) = self.ai_discovery_store() else {
            if policy == AiPolicy::Require {
                return Err(ClassifiedError::Storage(
                    "AI ranking requires persistent storage".to_owned(),
                ));
            }
            return Ok(heuristic_advice(inventory, "persistence_unavailable"));
        };
        self.authorize_recorded(Action::Discover, "discover", Some(&inventory.project_root))
            .await?;
        let id = Uuid::new_v4();
        store
            .create_ai_discovery(id, &inventory.project_root, language)
            .await?;
        let scan = serde_json::to_string(&inventory)
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let total = u32::try_from(inventory.candidates.len())
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        store.publish_ai_scan(id, &scan, total).await?;
        if let Err(error) = self.run_ranked_ai(id, &scan).await {
            store.fail_ai_scan(id, "assessment_failed").await?;
            if policy == AiPolicy::Require {
                return Err(error);
            }
            return Ok(heuristic_advice(inventory, "assessment_failed"));
        }
        let result = self.ranked_discovery_result(id).await?.ok_or_else(|| {
            ClassifiedError::Storage("AI ranking did not publish a result".to_owned())
        })?;
        let admitted = select_ai_candidates(&inventory).len();
        if policy == AiPolicy::Require
            && (result.assessments.len() != admitted || result.reason_code.is_some())
        {
            return Err(ClassifiedError::Provider(
                "AI ranking did not assess every admitted target".to_owned(),
            ));
        }
        Ok(RankedInventoryAdvice {
            inventory: result.inventory,
            assessments: result.assessments,
            ranking_source: result.ranking_source,
            reason_code: result.reason_code,
        })
    }

    /// Resolve the owning project for transport authorization.
    ///
    /// # Errors
    /// Returns a classified error if the retained operation cannot be read.
    pub async fn ranked_discovery_project(
        &self,
        id: Uuid,
    ) -> Result<Option<std::path::PathBuf>, ClassifiedError> {
        Ok(self
            .ai_discovery_store()?
            .get_ai_discovery(id)
            .await?
            .map(|record| record.project_root))
    }

    /// Reserve and start a progressive discovery operation.
    ///
    /// # Errors
    /// Returns a classified error if authorization, project validation, or persistence fails.
    pub async fn start_ranked_discovery(
        &self,
        project: &Path,
        language: TargetLanguage,
    ) -> Result<Uuid, ClassifiedError> {
        self.authorize_recorded(Action::Discover, "discover", Some(project))
            .await?;
        let project = canonical_project_root(project)?;
        let store = self.ai_discovery_store()?;
        let id = Uuid::new_v4();
        store.create_ai_discovery(id, &project, language).await?;
        let worker = self.clone();
        tokio::spawn(async move {
            if let Err(error) = worker.run_ranked_scan(id, &project, language).await {
                tracing::error!(operation_id = %id, %error, "ranked discovery failed");
                if let Err(storage_error) =
                    store.fail_ai_scan(id, "scan_or_persistence_failed").await
                {
                    tracing::error!(operation_id = %id, %storage_error, "could not retain discovery failure");
                }
            }
        });
        Ok(id)
    }

    /// Read lightweight status for an operation.
    ///
    /// # Errors
    /// Returns a classified error if the retained row cannot be read.
    pub async fn ranked_discovery_status(
        &self,
        id: Uuid,
    ) -> Result<Option<RankedDiscoveryStatus>, ClassifiedError> {
        Ok(self
            .ai_discovery_store()?
            .get_ai_discovery(id)
            .await?
            .map(|record| RankedDiscoveryStatus {
                operation_id: record.id,
                state: record.state,
                revision: record.revision,
                assessed_count: record.assessed_count,
                total_count: record.total_count,
                reason_code: record.reason_code,
            }))
    }

    /// Read the latest published scan and assessment snapshot.
    ///
    /// # Errors
    /// Returns a classified error for invalid retained data or a query failure.
    pub async fn ranked_discovery_result(
        &self,
        id: Uuid,
    ) -> Result<Option<RankedDiscoveryResult>, ClassifiedError> {
        let Some(record) = self.ai_discovery_store()?.get_ai_discovery(id).await? else {
            return Ok(None);
        };
        if record.revision == 0 {
            return Ok(None);
        }
        Ok(Some(result_from_record(record)?))
    }

    /// Cancel an active operation; a late model response can no longer publish.
    ///
    /// # Errors
    /// Returns a classified error if persistence fails.
    pub async fn cancel_ranked_discovery(&self, id: Uuid) -> Result<bool, ClassifiedError> {
        Ok(self.ai_discovery_store()?.cancel_ai_discovery(id).await?)
    }

    /// Assess the retained scan again under a new operation ID.
    ///
    /// # Errors
    /// Returns a classified error if the source scan is missing or authorization fails.
    pub async fn retry_ranked_discovery(&self, id: Uuid) -> Result<Uuid, ClassifiedError> {
        let store = self.ai_discovery_store()?;
        let source = store.get_ai_discovery(id).await?.ok_or_else(|| {
            ClassifiedError::Validation(format!("discovery operation {id} not found"))
        })?;
        let scan = source.scan_json.ok_or_else(|| {
            ClassifiedError::Validation("discovery operation has no retained scan".to_owned())
        })?;
        self.authorize_recorded(Action::Discover, "discover", Some(&source.project_root))
            .await?;
        let new_id = Uuid::new_v4();
        store.copy_ai_scan(id, new_id).await?;
        let worker = self.clone();
        tokio::spawn(async move {
            if let Err(error) = worker.run_ranked_ai(new_id, &scan).await {
                tracing::error!(operation_id = %new_id, %error, "retried AI assessment failed");
                if let Err(storage_error) =
                    store.fail_ai_scan(new_id, "ai_persistence_failed").await
                {
                    tracing::error!(operation_id = %new_id, %storage_error, "could not retain ranking failure");
                }
            }
        });
        Ok(new_id)
    }

    fn ai_discovery_store(&self) -> Result<Arc<Store>, ClassifiedError> {
        self.store().cloned().ok_or_else(|| {
            ClassifiedError::Validation(
                "ranked discovery requires the persistent service store".to_owned(),
            )
        })
    }

    async fn run_ranked_scan(
        &self,
        id: Uuid,
        project: &Path,
        language: TargetLanguage,
    ) -> Result<(), ClassifiedError> {
        let inventory = hf_discovery::discover(project, language).await?;
        let store = self.ai_discovery_store()?;
        store.save_inventory(&inventory, chrono::Utc::now()).await?;
        let scan = serde_json::to_string(&inventory)
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let total = u32::try_from(inventory.candidates.len())
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        if !store.publish_ai_scan(id, &scan, total).await? {
            return Ok(());
        }
        self.run_ranked_ai(id, &scan).await
    }

    async fn run_ranked_ai(&self, id: Uuid, scan: &str) -> Result<(), ClassifiedError> {
        let store = self.ai_discovery_store()?;
        let inventory: TargetInventory = serde_json::from_str(scan)
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        let selected = select_ai_candidates(&inventory);
        if selected.is_empty() {
            store
                .finish_ai_discovery(id, "[]", AiRankingSource::Heuristic, Some("empty_scan"), 0)
                .await?;
            return Ok(());
        }
        let Some(pool) = self.provider_pool() else {
            store
                .finish_ai_discovery(id, "[]", AiRankingSource::Heuristic, Some("no_provider"), 0)
                .await?;
            return Ok(());
        };
        let provider =
            LlmProviderBridge::new(pool).with_diagnostics(Arc::clone(&self.diagnostics), "rank");
        let mut assessments = Vec::new();
        let mut had_error = false;
        for (index, batch) in selected.chunks(16).enumerate() {
            self.authorize_recorded(Action::Discover, "discover", Some(&inventory.project_root))
                .await?;
            let Ok(prompt) = hf_prompt::render_ai_ranking_prompt(batch) else {
                had_error = true;
                continue;
            };
            let batch_index = u32::try_from(index)
                .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
            if !store
                .save_ai_rank_prompt(id, batch_index, &prompt, "configured_pool")
                .await?
            {
                return Ok(());
            }
            let request = ChatRequest::from_messages(vec![Message::user(prompt)]);
            if let Ok(response) = provider.chat_completion(&request).await {
                if let Ok(rows) = parse_ai_batch(batch, response.text()) {
                    let encoded = serde_json::to_string(&rows)
                        .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
                    store
                        .finish_ai_rank_batch(
                            id,
                            batch_index,
                            "validated",
                            Some(&encoded),
                            Some(&response.model),
                        )
                        .await?;
                    assessments.extend(rows);
                } else {
                    had_error = true;
                    store
                        .finish_ai_rank_batch(
                            id,
                            batch_index,
                            "invalid_response",
                            None,
                            Some(&response.model),
                        )
                        .await?;
                }
            } else {
                had_error = true;
                store
                    .finish_ai_rank_batch(id, batch_index, "provider_error", None, None)
                    .await?;
            }
        }
        let count = u32::try_from(assessments.len())
            .map_err(|error| ClassifiedError::Validation(error.to_string()))?;
        let source = if assessments.is_empty() {
            AiRankingSource::Heuristic
        } else if assessments.len() == inventory.candidates.len() && !had_error {
            AiRankingSource::Ai
        } else {
            AiRankingSource::Mixed
        };
        let reason = if had_error {
            Some("partial_or_failed_ai")
        } else {
            None
        };
        let encoded = serde_json::to_string(&assessments)
            .map_err(|error| ClassifiedError::Storage(error.to_string()))?;
        store
            .finish_ai_discovery(id, &encoded, source, reason, count)
            .await?;
        Ok(())
    }
}

fn heuristic_advice(inventory: TargetInventory, reason: &str) -> RankedInventoryAdvice {
    RankedInventoryAdvice {
        inventory,
        assessments: Vec::new(),
        ranking_source: AiRankingSource::Heuristic,
        reason_code: Some(reason.to_owned()),
    }
}

fn result_from_record(record: AiDiscoveryRecord) -> Result<RankedDiscoveryResult, ClassifiedError> {
    let scan = record
        .scan_json
        .as_deref()
        .ok_or_else(|| ClassifiedError::Storage("published discovery has no scan".to_owned()))?;
    let mut inventory: TargetInventory =
        serde_json::from_str(scan).map_err(|error| ClassifiedError::Storage(error.to_string()))?;
    let assessments: Vec<TargetAssessment> = record
        .assessment_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|error| ClassifiedError::Storage(error.to_string()))?
        .unwrap_or_default();
    if !assessments.is_empty() {
        let order = order_with_assessments(&inventory, &assessments);
        let positions = order
            .iter()
            .enumerate()
            .map(|(index, id)| (*id, index))
            .collect::<HashMap<_, _>>();
        inventory
            .candidates
            .sort_by_key(|candidate| positions.get(&candidate.id).copied());
    }
    Ok(RankedDiscoveryResult {
        operation_id: record.id,
        revision: record.revision,
        project_root: record.project_root,
        language: record.language,
        scanned_at: record.scanned_at.ok_or_else(|| {
            ClassifiedError::Storage("published discovery has no scan time".to_owned())
        })?,
        inventory,
        assessments,
        assessed_count: record.assessed_count,
        total_count: record.total_count,
        ranking_source: record.source,
        reason_code: record.reason_code,
    })
}
