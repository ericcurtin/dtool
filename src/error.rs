use thiserror::Error;

/// Top-level error type for dcopy.
/// Mirrors containerd's github.com/containerd/errdefs conventions.
#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid digest: {0}")]
    InvalidDigest(String),

    #[error("invalid reference: {0}")]
    InvalidReference(String),

    #[error("unsupported transport: {0}")]
    UnsupportedTransport(String),

    #[error("registry error {status}: {message}")]
    Registry { status: u16, message: String },

    #[error("manifest not found: {0}")]
    ManifestNotFound(String),

    #[error("blob not found: {0}")]
    BlobNotFound(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("platform not found: {0}")]
    PlatformNotFound(String),

    #[error("unsupported media type: {0}")]
    UnsupportedMediaType(String),

    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;
