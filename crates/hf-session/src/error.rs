//! Crate-level error types for y-session.

/// Errors from session management.
#[derive(Debug, thiserror::Error)]
pub enum SessionManagerError {
    #[error("session not found: {id}")]
    NotFound { id: String },

    #[error("invalid state transition from {from:?} to {to:?}")]
    InvalidTransition { from: String, to: String },

    #[error("storage error: {message}")]
    Storage { message: String },

    #[error("transcript error: {message}")]
    Transcript { message: String },

    #[error("session configuration error: {message}")]
    Config { message: String },

    #[error("{message}")]
    Other { message: String },
}

impl From<hf_core::session::SessionError> for SessionManagerError {
    fn from(err: hf_core::session::SessionError) -> Self {
        match err {
            hf_core::session::SessionError::NotFound { id } => Self::NotFound { id },
            other => Self::Storage {
                message: other.to_string(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_not_found_maps_to_manager_not_found() {
        let err = SessionManagerError::from(hf_core::session::SessionError::NotFound {
            id: "abc".into(),
        });
        assert!(matches!(err, SessionManagerError::NotFound { id } if id == "abc"));
    }

    #[test]
    fn other_session_errors_map_to_storage() {
        let err = SessionManagerError::from(hf_core::session::SessionError::StorageError {
            message: "db locked".into(),
        });
        assert!(matches!(err, SessionManagerError::Storage { .. }));
    }
}
