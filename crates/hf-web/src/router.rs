//! Axum router with REST endpoints.

use axum::extract::Json;
use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::Router;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Build the application router.
pub fn build() -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/discover", post(discover))
        .route("/corpus/{op}", post(corpus))
}

async fn health() -> StatusCode {
    StatusCode::OK
}

#[derive(Debug, Deserialize)]
struct DiscoverRequest {
    project: PathBuf,
    lang: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

async fn discover(
    Json(req): Json<DiscoverRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let lang = match parse_lang(&req.lang) {
        Ok(l) => l,
        Err(e) => {
            return Err((StatusCode::BAD_REQUEST, Json(ErrorResponse { error: e })));
        }
    };
    let inv = hf_discovery::discover(&req.project, lang)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: e.to_string(),
                }),
            )
        })?;
    Ok(Json(serde_json::to_value(&inv).unwrap_or_default()))
}

#[derive(Debug, Deserialize)]
struct CorpusRequest {
    #[allow(dead_code)]
    project: PathBuf,
    #[allow(dead_code)]
    target: String,
}

async fn corpus(
    axum::extract::Path(op): axum::extract::Path<String>,
    Json(_req): Json<CorpusRequest>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    let workspace = std::env::temp_dir().join("hobot_fuzz_workspace");
    let corpus_dir = workspace.join("corpus");
    match op.as_str() {
        "list" => {
            let corpus = hf_corpus::list(&corpus_dir).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            Ok(Json(
                serde_json::to_value(&corpus.entries).unwrap_or_default(),
            ))
        }
        "seed" => {
            std::fs::create_dir_all(&corpus_dir).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            let seeds = vec![
                (b"{}".to_vec(), "seed_empty".to_owned()),
                (b"[1,2,3]".to_vec(), "seed_array".to_owned()),
            ];
            let corpus = hf_corpus::seed(uuid::Uuid::new_v4(), &corpus_dir, seeds)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error: e.to_string(),
                        }),
                    )
                })?;
            Ok(Json(serde_json::json!({"seeded": corpus.entries.len()})))
        }
        "grow" => {
            let out_dir = workspace.join("out");
            let corpus = hf_corpus::grow(&corpus_dir, &out_dir).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            Ok(Json(serde_json::json!({"entries": corpus.entries.len()})))
        }
        "prune" => {
            let corpus = hf_corpus::list(&corpus_dir).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            let pruned = hf_corpus::prune(corpus).map_err(|e| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    Json(ErrorResponse {
                        error: e.to_string(),
                    }),
                )
            })?;
            Ok(Json(serde_json::json!({"entries": pruned.entries.len()})))
        }
        other => Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: format!("unknown op: {other}"),
            }),
        )),
    }
}

fn parse_lang(s: &str) -> Result<hf_core::target::TargetLanguage, String> {
    match s.to_ascii_lowercase().as_str() {
        "c" => Ok(hf_core::target::TargetLanguage::C),
        "cpp" | "c++" => Ok(hf_core::target::TargetLanguage::Cpp),
        "rust" | "rs" => Ok(hf_core::target::TargetLanguage::Rust),
        "go" => Ok(hf_core::target::TargetLanguage::Go),
        "python" | "py" => Ok(hf_core::target::TargetLanguage::Python),
        other => Err(format!("unsupported language: {other}")),
    }
}
