use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum StarmetalError {
    #[error("config error: {0}")]
    Config(String),

    #[error("config file not found: {0}")]
    ConfigNotFound(PathBuf),

    #[error("package not found: {ecosystem}/{name}")]
    PackageNotFound { ecosystem: String, name: String },

    #[error("version not found: {ecosystem}/{name}@{version}")]
    VersionNotFound {
        ecosystem: String,
        name: String,
        version: String,
    },

    #[error("artifact not found: {0}")]
    ArtifactNotFound(String),

    #[error("integrity check failed: expected {expected}, got {actual}")]
    IntegrityError { expected: String, actual: String },

    #[error("policy violation: {0}")]
    PolicyViolation(String),

    #[error("publish error: {0}")]
    Publish(String),

    #[error("upstream error: {0}")]
    Upstream(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("adapter error: {0}")]
    Adapter(String),

    #[error("lockfile error: {0}")]
    Lockfile(String),

    #[error("schema validation error: {0}")]
    SchemaValidation(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, StarmetalError>;
