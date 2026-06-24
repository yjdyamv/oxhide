//! Error types for volume format operations

use thiserror::Error;

/// Result type for format operations
pub type FormatResult<T> = std::result::Result<T, FormatError>;

/// Errors related to volume format parsing and serialization
#[derive(Error, Debug)]
pub enum FormatError {
    /// Invalid magic number in volume header
    #[error("Invalid magic number: expected {expected:#010x}, got {actual:#010x}")]
    InvalidMagic { expected: u32, actual: u32 },

    /// Invalid header CRC32 checksum
    #[error("Invalid header CRC32: expected {expected:#010x}, got {actual:#010x}")]
    InvalidCrc { expected: u32, actual: u32 },

    /// Unsupported volume version
    #[error("Unsupported volume version: {0}")]
    UnsupportedVersion(u16),

    /// Invalid header size
    #[error("Invalid header size: expected {expected}, got {actual}")]
    InvalidHeaderSize { expected: usize, actual: usize },

    /// Header decryption failed (wrong password or corrupted)
    #[error("Header decryption failed: {0}")]
    DecryptionFailed(String),

    /// Header encryption failed
    #[error("Header encryption failed: {0}")]
    EncryptionFailed(String),

    /// I/O error during header read/write
    #[error("I/O error: {0}")]
    IoError(String),

    /// Underlying crypto error
    #[error("Crypto error: {0}")]
    CryptoError(String),
}

impl From<std::io::Error> for FormatError {
    fn from(e: std::io::Error) -> Self {
        FormatError::IoError(e.to_string())
    }
}
