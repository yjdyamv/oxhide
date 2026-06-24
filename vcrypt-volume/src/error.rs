//! Error types for volume operations

use thiserror::Error;

/// Volume operation result type
pub type VolResult<T> = std::result::Result<T, VolumeError>;

/// Volume operation errors
#[derive(Error, Debug)]
pub enum VolumeError {
    #[error("Cannot open volume: {0}")]
    OpenError(String),

    #[error("Invalid volume format: {0}")]
    InvalidFormat(String),

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("Read error at sector {sector}: {msg}")]
    ReadError { sector: u64, msg: String },

    #[error("Write error at sector {sector}: {msg}")]
    WriteError { sector: u64, msg: String },

    #[error("Volume is already mounted")]
    AlreadyMounted,

    #[error("Volume is not mounted")]
    NotMounted,

    #[error("Hidden volume protection triggered")]
    HiddenVolumeProtection,

    #[error("Unsupported operation: {0}")]
    Unsupported(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Format error: {0}")]
    FormatError(String),
}
