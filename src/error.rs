use std::io;

/// Domain-specific error types for syscon.
#[derive(Debug, thiserror::Error)]
pub enum SysconError {
    #[error("audit subsystem error: {0}")]
    Audit(String),

    #[error("seccomp error: {0}")]
    Seccomp(String),

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
}

impl SysconError {
    pub fn io(source: io::Error, context: impl Into<String>) -> Self {
        Self::Io {
            source,
            context: context.into(),
        }
    }
}
