//! Error types for cryptographic operations.
//!
//! When the `std` feature is enabled (default), the error type uses `thiserror`
//! for ergonomic `Display` and `std::error::Error` impls.
//!
//! When only the `kernel` feature is active, a manual `core::fmt::Display`
//! impl is used instead.

#[cfg(feature = "std")]
use thiserror::Error;

// String is from std or alloc depending on features
#[cfg(feature = "std")]
use std::string::String;
#[cfg(all(feature = "kernel", not(feature = "std")))]
use alloc::string::String;

/// Result type for cryptographic operations.
#[cfg(feature = "std")]
pub type Result<T> = std::result::Result<T, CryptoError>;

/// Result type for cryptographic operations (no_std / kernel).
#[cfg(not(feature = "std"))]
pub type Result<T> = core::result::Result<T, CryptoError>;

/// Cryptographic error types.
#[cfg_attr(feature = "std", derive(Error))]
#[derive(Debug)]
pub enum CryptoError {
    /// Invalid key size.
    #[cfg_attr(feature = "std", error("Invalid key size: expected {expected}, got {actual}"))]
    InvalidKeySize {
        /// Expected key size in bytes.
        expected: usize,
        /// Actual key size provided.
        actual: usize,
    },
    /// Invalid block size.
    #[cfg_attr(feature = "std", error("Invalid block size: expected {expected}, got {actual}"))]
    InvalidBlockSize {
        /// Expected block size in bytes.
        expected: usize,
        /// Actual block size provided.
        actual: usize,
    },
    /// Invalid data length.
    #[cfg_attr(feature = "std", error("Invalid data length: {0}"))]
    InvalidDataLength(String),
    /// Cipher initialisation failed.
    #[cfg_attr(feature = "std", error("Cipher initialization failed: {0}"))]
    CipherInitFailed(String),
    /// Key derivation failed.
    #[cfg_attr(feature = "std", error("Key derivation failed: {0}"))]
    KeyDerivationFailed(String),
    /// XTS mode error.
    #[cfg_attr(feature = "std", error("XTS mode error: {0}"))]
    XtsError(String),
    /// Unsupported cipher.
    #[cfg_attr(feature = "std", error("Unsupported cipher: {0}"))]
    UnsupportedCipher(String),
    /// Unsupported hash function.
    #[cfg_attr(feature = "std", error("Unsupported hash function: {0}"))]
    UnsupportedHash(String),
}

#[cfg(not(feature = "std"))]
impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeySize { expected, actual } => {
                write!(f, "Invalid key size: expected {expected}, got {actual}")
            }
            Self::InvalidBlockSize { expected, actual } => {
                write!(f, "Invalid block size: expected {expected}, got {actual}")
            }
            Self::InvalidDataLength(msg) => write!(f, "Invalid data length: {msg}"),
            Self::CipherInitFailed(msg) => write!(f, "Cipher init failed: {msg}"),
            Self::KeyDerivationFailed(msg) => write!(f, "Key derivation failed: {msg}"),
            Self::XtsError(msg) => write!(f, "XTS error: {msg}"),
            Self::UnsupportedCipher(msg) => write!(f, "Unsupported cipher: {msg}"),
            Self::UnsupportedHash(msg) => write!(f, "Unsupported hash: {msg}"),
        }
    }
}
