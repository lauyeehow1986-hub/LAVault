use thiserror::Error;

#[derive(Debug, Error)]
pub enum VaultError {
    #[error("cryptographic error: {0}")]
    Crypto(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),

    #[error("authentication or integrity check failed: {0}")]
    AuthFailed(String),

    #[error("quorum error: {0}")]
    Quorum(String),

    #[error("storage error: {0}")]
    Storage(String),

    #[error("transport error: {0}")]
    Transport(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, VaultError>;
