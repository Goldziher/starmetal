use starmetal_core::error::StarmetalError;

/// Errors raised by the dependency-update engine and its ports.
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// A manager could not parse or patch a manifest file.
    #[error("manager error ({manager}): {message}")]
    Manager { manager: String, message: String },

    /// A versioning scheme rejected an input or could not compute a value.
    #[error("versioning error ({scheme}): {message}")]
    Versioning { scheme: String, message: String },

    /// A datasource could not return versions for a package.
    #[error("datasource error: {0}")]
    Datasource(String),

    /// A forge or git operation failed.
    #[error("forge error: {0}")]
    Forge(String),

    /// No manager, versioning scheme, or datasource was registered for a request.
    #[error("unsupported: {0}")]
    Unsupported(String),

    /// Invalid update configuration.
    #[error("config error: {0}")]
    Config(String),

    /// An error surfaced from the underlying registry/core layer.
    #[error(transparent)]
    Core(#[from] StarmetalError),

    /// A filesystem operation failed while scanning a local repository.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl UpdateError {
    /// Construct a [`UpdateError::Manager`] with owned strings.
    pub fn manager(manager: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Manager {
            manager: manager.into(),
            message: message.into(),
        }
    }

    /// Construct a [`UpdateError::Versioning`] with owned strings.
    pub fn versioning(scheme: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Versioning {
            scheme: scheme.into(),
            message: message.into(),
        }
    }
}

/// Result alias for update-engine operations.
pub type Result<T> = std::result::Result<T, UpdateError>;
