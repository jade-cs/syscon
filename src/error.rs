use std::io;

/// Domain-specific error types for syscon.
#[derive(Debug, thiserror::Error)]
pub enum SysconError {
    #[error("audit subsystem error: {0}")]
    Audit(String),

    #[error("docker/container error: {0}")]
    Docker(String),

    #[error("state error: {0}")]
    State(String),

    #[error("I/O error: {context}")]
    Io {
        #[source]
        source: io::Error,
        context: String,
    },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("serialization error: {0}")]
    Serialize(String),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("rocket error: {0}")]
    Rocket(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("thread spawn error: {0}")]
    ThreadSpawn(#[from] io::Error),
}

impl SysconError {
    pub fn io(source: io::Error, context: impl Into<String>) -> Self {
        Self::Io {
            source,
            context: context.into(),
        }
    }

    pub fn audit_io(source: io::Error, context: impl Into<String>) -> Self {
        let ctx = context.into();
        Self::Audit(format!("{}: {}", ctx, source))
    }
}

/// Result type alias for syscon operations.
pub type Result<T> = std::result::Result<T, SysconError>;
