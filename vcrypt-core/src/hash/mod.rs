//! Hash function implementations for VeraCrypt
//!
//! This module provides all cryptographic hash functions supported by VeraCrypt:
//! - SHA-256 (via `sha2` crate)
//! - SHA-512 (via `sha2` crate)
//! - BLAKE2s-256 (via `blake2` crate)
//! - Whirlpool (via `whirlpool` crate, RustCrypto)
//! - Streebog (via `streebog` crate, RustCrypto, GOST R 34.11-2012)

/// Hash function trait
pub trait HashFunction: Send + Sync {
    /// Output size in bytes
    const OUTPUT_SIZE: usize;

    /// Get the hash function name
    fn name(&self) -> &'static str;

    /// Update the hash with input data
    fn update(&mut self, data: &[u8]);

    /// Finalize the hash and return the digest
    fn finalize(self) -> Vec<u8>;

    /// Hash data in one call
    fn hash(data: &[u8]) -> Vec<u8>
    where
        Self: Sized + Default,
    {
        let mut hasher = Self::default();
        hasher.update(data);
        hasher.finalize()
    }
}

mod sha256;
mod sha512;
mod blake2s;
mod whirlpool;
mod streebog;

pub use sha256::Sha256Hash;
pub use sha512::Sha512Hash;
pub use blake2s::Blake2sHash;
pub use whirlpool::WhirlpoolHash;
pub use streebog::{Streebog256Hash, StreebogHash};

/// Hash algorithm enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlgorithm {
    /// SHA-256
    Sha256,
    /// SHA-512
    Sha512,
    /// BLAKE2s-256
    Blake2s256,
    /// Whirlpool (512-bit)
    Whirlpool,
    /// Streebog-512 (GOST R 34.11-2012)
    Streebog,
}

impl HashAlgorithm {
    /// Get the output size in bytes
    pub fn output_size(&self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
            Self::Blake2s256 => 32,
            Self::Whirlpool => 64,
            Self::Streebog => 64,
        }
    }

    /// Get the algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha512 => "SHA-512",
            Self::Blake2s256 => "BLAKE2s-256",
            Self::Whirlpool => "Whirlpool",
            Self::Streebog => "Streebog",
        }
    }
}
