//! Error types for cryptographic operations

use thiserror::Error;

/// Result type for cryptographic operations
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Cryptographic error types
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Invalid key size
    #[error("Invalid key size: expected {expected}, got {actual}")]
    InvalidKeySize {
        /// Expected key size in bytes
        expected: usize,
        /// Actual key size provided
        actual: usize,
    },

    /// Invalid block size
    #[error("Invalid block size: expected {expected}, got {actual}")]
    InvalidBlockSize {
        /// Expected block size in bytes
        expected: usize,
        /// Actual block size provided
        actual: usize,
    },

    /// Invalid data length
    #[error("Invalid data length: {0}")]
    InvalidDataLength(String),

    /// Cipher initialization failed
    #[error("Cipher initialization failed: {0}")]
    CipherInitFailed(String),

    /// Key derivation failed
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),

    /// XTS mode error
    #[error("XTS mode error: {0}")]
    XtsError(String),

    /// Unsupported cipher
    #[error("Unsupported cipher: {0}")]
    UnsupportedCipher(String),

    /// Unsupported hash function
    #[error("Unsupported hash function: {0}")]
    UnsupportedHash(String),
}
