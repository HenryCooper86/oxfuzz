//! Arm, disarm, or read the arming state of another running server.
//!
//! A scheduler starts disarmed on every process start; the operator releases
//! restored work explicitly. This carries that answer to a server over its
//! own HTTP API, for the command line and the desktop app alike.

use hf_core::error::ClassifiedError;

/// What to ask the remote scheduler.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteArmAction {
    /// Authorize restored work to run.
    Arm,
    /// Hold restored work again.
    Disarm,
    /// Read the current state without changing it.
    Status,
}

/// The `schedule/arm` endpoint of the server at `url`.
#[must_use]
pub fn remote_arm_endpoint(url: &str) -> String {
    format!("{}/schedule/arm", url.trim_end_matches('/'))
}

/// Send `action` to the server at `url` and return the state it reports:
/// `Some(armed)`, or `None` when the reply carries no `armed` flag.
///
/// `token` is sent as a bearer token when present and not empty; a server
/// bound to a non-loopback address requires one.
///
/// # Errors
/// Returns [`ClassifiedError::Validation`] when `url` is not an HTTP(S) URL
/// or the server refuses the token (401 or 403), and
/// [`ClassifiedError::Internal`] when the server cannot be reached,
/// answers with an error status, or its reply is not JSON.
pub async fn remote_schedule_arm(
    url: &str,
    action: RemoteArmAction,
    token: Option<&str>,
) -> Result<Option<bool>, ClassifiedError> {
    if !(url.starts_with("http://") || url.starts_with("https://")) {
        return Err(ClassifiedError::Validation(format!(
            "server URL '{url}' must start with http:// or https://"
        )));
    }
    let endpoint = remote_arm_endpoint(url);
    let client = reqwest::Client::new();
    let request = match action {
        RemoteArmAction::Status => client.get(&endpoint),
        RemoteArmAction::Disarm => client.delete(&endpoint),
        RemoteArmAction::Arm => client.post(&endpoint),
    };
    let request = match token {
        Some(token) if !token.is_empty() => request.bearer_auth(token),
        _ => request,
    };
    let response = request.send().await.map_err(|error| {
        ClassifiedError::Internal(format!("could not reach {endpoint}: {error}"))
    })?;
    if matches!(
        response.status(),
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        return Err(ClassifiedError::Validation(format!(
            "{endpoint} refused the request ({}): send the server's bearer token, the \
             HF_WEB_TOKEN it was started with (`oxfuzz arm` reads HF_WEB_TOKEN)",
            response.status()
        )));
    }
    if !response.status().is_success() {
        return Err(ClassifiedError::Internal(format!(
            "{endpoint} returned {}",
            response.status()
        )));
    }
    let body: serde_json::Value = response
        .json()
        .await
        .map_err(|error| ClassifiedError::Internal(format!("{endpoint} reply: {error}")))?;
    Ok(body.get("armed").and_then(serde_json::Value::as_bool))
}

#[cfg(test)]
mod tests {
    use super::{remote_arm_endpoint, remote_schedule_arm, RemoteArmAction};

    #[test]
    fn the_endpoint_ignores_a_trailing_slash() {
        assert_eq!(
            remote_arm_endpoint("http://127.0.0.1:8081/"),
            "http://127.0.0.1:8081/schedule/arm"
        );
    }

    #[tokio::test]
    async fn a_url_without_an_http_scheme_is_refused_before_any_request() {
        let error = remote_schedule_arm("127.0.0.1:8081", RemoteArmAction::Status, None)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("must start with http://"));
    }

    #[tokio::test]
    async fn an_unreachable_server_is_reported_with_its_endpoint() {
        // Port 9 (discard) on loopback has no listener.
        let error = remote_schedule_arm("http://127.0.0.1:9", RemoteArmAction::Arm, None)
            .await
            .unwrap_err();
        assert!(error
            .to_string()
            .contains("could not reach http://127.0.0.1:9/schedule/arm"));
    }

    /// Serve one HTTP request on loopback with `reply` as the JSON body and
    /// return the request text the client sent.
    async fn serve_once(reply: &'static str) -> (String, tokio::task::JoinHandle<String>) {
        serve_once_with("200 OK", reply).await
    }

    /// [`serve_once`] answering with `status` (e.g. `401 Unauthorized`).
    async fn serve_once_with(
        status: &'static str,
        reply: &'static str,
    ) -> (String, tokio::task::JoinHandle<String>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let served = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buffer = vec![0_u8; 4096];
            let read = stream.read(&mut buffer).await.unwrap();
            let response = format!(
                "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{reply}",
                reply.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            String::from_utf8_lossy(&buffer[..read]).into_owned()
        });
        (url, served)
    }

    #[tokio::test]
    async fn arming_posts_to_the_endpoint_with_the_bearer_token_and_returns_the_state() {
        let (url, served) = serve_once(r#"{"armed":true}"#).await;
        let armed = remote_schedule_arm(&url, RemoteArmAction::Arm, Some("a-token"))
            .await
            .unwrap();
        assert_eq!(armed, Some(true));
        let request = served.await.unwrap().to_lowercase();
        assert!(request.starts_with("post /schedule/arm "), "{request}");
        assert!(
            request.contains("authorization: bearer a-token"),
            "{request}"
        );
    }

    #[tokio::test]
    async fn a_status_query_sends_no_token_when_none_is_given() {
        let (url, served) = serve_once(r#"{"armed":false}"#).await;
        let armed = remote_schedule_arm(&url, RemoteArmAction::Status, Some(""))
            .await
            .unwrap();
        assert_eq!(armed, Some(false));
        let request = served.await.unwrap().to_lowercase();
        assert!(request.starts_with("get /schedule/arm "), "{request}");
        assert!(!request.contains("authorization:"), "{request}");
    }

    #[tokio::test]
    async fn a_refused_token_is_named_as_an_authentication_problem() {
        // `oxfuzz arm --status` without `HF_WEB_TOKEN` against a server that
        // has one printed "internal: ... returned 401 Unauthorized".
        for status in ["401 Unauthorized", "403 Forbidden"] {
            let (url, served) = serve_once_with(status, "{}").await;
            let error = remote_schedule_arm(&url, RemoteArmAction::Status, None)
                .await
                .unwrap_err();
            served.await.unwrap();
            assert!(
                matches!(error, hf_core::error::ClassifiedError::Validation(_)),
                "{error:?}"
            );
            let message = error.to_string();
            assert!(message.contains("refused the request"), "{message}");
            assert!(message.contains("HF_WEB_TOKEN"), "{message}");
        }
    }
}
