//! Hosts the REST API from the desktop app, as `oxfuzz serve` does.
//!
//! The server shares the app's service container and scheduler, listens on
//! loopback only, and requires a bearer token generated for each start. The
//! token is returned once, to the window that started the server.

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::Arc;

use hf_service::scheduler::CampaignScheduler;
use hf_service::ServiceContainer;

use crate::state::AppState;

/// A started server: where it listens and how to stop it.
struct Running {
    url: String,
    project_roots: Vec<String>,
    shutdown: tokio::sync::oneshot::Sender<()>,
}

/// The REST server this app hosts, if any.
#[derive(Default)]
pub struct RestServerState {
    running: tokio::sync::Mutex<Option<Running>>,
}

/// What a caller may know about a running server. Never carries the token.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct RestServerInfo {
    /// Base URL, for example `http://127.0.0.1:8081`.
    pub url: String,
    /// Project folders the server will serve.
    pub project_roots: Vec<String>,
}

/// The reply to a start: the address plus the token, shown once.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RestServerStarted {
    /// Base URL of the server.
    pub url: String,
    /// Bearer token every request must carry.
    pub token: String,
    /// Project folders the server will serve.
    pub project_roots: Vec<String>,
}

impl RestServerState {
    /// Start the server on loopback `port` (0 picks a free port) for the
    /// given project folders.
    ///
    /// # Errors
    /// Returns a message when a server is already running, a folder does not
    /// exist, or the port cannot be bound.
    pub async fn start(
        &self,
        container: ServiceContainer,
        scheduler: Arc<CampaignScheduler>,
        port: u16,
        project_roots: Vec<String>,
    ) -> Result<RestServerStarted, String> {
        let mut running = self.running.lock().await;
        if let Some(current) = running.as_ref() {
            return Err(format!(
                "the REST server is already running at {}",
                current.url
            ));
        }
        if project_roots.is_empty() {
            return Err("choose at least one project folder for the server to serve".to_owned());
        }
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let security = hf_web::WebSecurityConfig::new(
            Some(token.clone()),
            false,
            Vec::new(),
            project_roots.iter().map(PathBuf::from).collect(),
        )
        .map_err(|error| error.to_string())?;
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .await
            .map_err(|error| format!("could not listen on port {port}: {error}"))?;
        let address = listener.local_addr().map_err(|error| error.to_string())?;
        let router = hf_web::build_with_state_and_security(
            hf_web::AppState::new(container).with_scheduler(scheduler),
            security,
        );
        let (shutdown, stopped) = tokio::sync::oneshot::channel::<()>();
        tokio::spawn(async move {
            let served = axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    // A dropped sender also ends the server: both mean stop.
                    let _stop_requested_or_owner_dropped = stopped.await;
                })
                .await;
            if let Err(error) = served {
                eprintln!("desktop REST server ended with an error: {error}");
            }
        });
        let url = format!("http://{address}");
        *running = Some(Running {
            url: url.clone(),
            project_roots: project_roots.clone(),
            shutdown,
        });
        Ok(RestServerStarted {
            url,
            token,
            project_roots,
        })
    }

    /// Stop the server. Returns whether one was running.
    pub async fn stop(&self) -> bool {
        let Some(current) = self.running.lock().await.take() else {
            return false;
        };
        // The serving task may already have ended; then there is nothing to stop.
        let _server_already_gone = current.shutdown.send(());
        true
    }

    /// The running server, if any.
    pub async fn info(&self) -> Option<RestServerInfo> {
        self.running
            .lock()
            .await
            .as_ref()
            .map(|current| RestServerInfo {
                url: current.url.clone(),
                project_roots: current.project_roots.clone(),
            })
    }
}

/// Start the REST server on loopback.
#[tauri::command]
pub async fn rest_server_start(
    state: tauri::State<'_, AppState>,
    server: tauri::State<'_, RestServerState>,
    port: u16,
    project_roots: Vec<String>,
) -> Result<RestServerStarted, String> {
    server
        .start(
            state.container.clone(),
            Arc::clone(&state.scheduler),
            port,
            project_roots,
        )
        .await
}

/// Stop the REST server. Returns whether one was running.
#[tauri::command]
pub async fn rest_server_stop(server: tauri::State<'_, RestServerState>) -> Result<bool, String> {
    Ok(server.stop().await)
}

/// The running REST server, or `null`.
#[tauri::command]
pub async fn rest_server_status(
    server: tauri::State<'_, RestServerState>,
) -> Result<Option<RestServerInfo>, String> {
    Ok(server.info().await)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use hf_service::remote_arm::{remote_schedule_arm, RemoteArmAction};

    use super::RestServerState;

    async fn scheduler(
        container: &hf_service::ServiceContainer,
        directory: &std::path::Path,
    ) -> Arc<hf_service::scheduler::CampaignScheduler> {
        Arc::new(
            hf_service::scheduler::CampaignScheduler::try_start(
                container.clone(),
                directory.join("schedules.json"),
                None,
            )
            .await
            .unwrap(),
        )
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn the_server_answers_with_its_token_refuses_without_it_and_stops() {
        let directory = tempfile::tempdir().unwrap();
        let container = hf_service::ServiceContainer::stubbed();
        let scheduler = scheduler(&container, directory.path()).await;
        let server = RestServerState::default();
        let root = directory.path().to_string_lossy().into_owned();

        let started = server
            .start(
                container.clone(),
                Arc::clone(&scheduler),
                0,
                vec![root.clone()],
            )
            .await
            .unwrap();
        assert!(started.url.starts_with("http://127.0.0.1:"));
        assert_eq!(server.info().await.unwrap().url, started.url);

        let armed =
            remote_schedule_arm(&started.url, RemoteArmAction::Status, Some(&started.token))
                .await
                .unwrap();
        assert_eq!(armed, Some(false));
        let refused = remote_schedule_arm(&started.url, RemoteArmAction::Status, None)
            .await
            .unwrap_err();
        assert!(refused.to_string().contains("401"), "{refused}");

        let second = server
            .start(container, Arc::clone(&scheduler), 0, vec![root])
            .await
            .unwrap_err();
        assert!(second.contains("already running"));

        assert!(server.stop().await);
        assert!(!server.stop().await);
        assert!(server.info().await.is_none());
        scheduler.stop().await;
    }

    #[tokio::test]
    async fn a_start_without_a_project_folder_or_with_a_missing_one_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let container = hf_service::ServiceContainer::stubbed();
        let scheduler = scheduler(&container, directory.path()).await;
        let server = RestServerState::default();
        let none = server
            .start(container.clone(), Arc::clone(&scheduler), 0, vec![])
            .await
            .unwrap_err();
        assert!(none.contains("at least one project folder"));
        let missing = server
            .start(
                container,
                Arc::clone(&scheduler),
                0,
                vec!["/no/such/folder".to_owned()],
            )
            .await;
        assert!(missing.is_err());
        assert!(server.info().await.is_none());
        scheduler.stop().await;
    }
}
