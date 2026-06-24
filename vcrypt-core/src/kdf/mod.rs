//! Key Derivation Function (KDF) implementations for VeraCrypt
//!
//! This module provides all KDF algorithms supported by VeraCrypt:
//! - PBKDF2-HMAC-SHA-256
//! - PBKDF2-HMAC-SHA-512
//! - PBKDF2-HMAC-Whirlpool
//! - PBKDF2-HMAC-Streebog
//! - PBKDF2-HMAC-BLAKE2s
//! - Argon2id

use crate::Result;

/// Key derivation function trait
pub trait KeyDerivation: Send + Sync {
    /// Derive a key from password + salt
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()>;

    /// Get the iteration count for a given PIM (Personal Iterations Multiplier)
    /// PIM=0 means use default. VeraCrypt formula: 15000 + pim * 1000
    fn get_iteration_count(&self, pim: i32) -> u32 {
        if pim > 0 { 15000 + pim as u32 * 1000 } else { 500_000 }
    }

    /// Get the human-readable KDF name
    fn name(&self) -> &'static str;
}

mod pbkdf2_sha256;
mod pbkdf2_sha512;
mod pbkdf2_blake2s;
mod pbkdf2_whirlpool;
mod pbkdf2_streebog;
mod argon2id;

pub use pbkdf2_sha256::Pbkdf2Sha256;
pub use pbkdf2_sha512::Pbkdf2Sha512;
pub use pbkdf2_blake2s::Pbkdf2Blake2s;
pub use pbkdf2_whirlpool::Pbkdf2Whirlpool;
pub use pbkdf2_streebog::Pbkdf2Streebog;
pub use argon2id::Argon2idKdf;

/// Enumeration of all supported KDF algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KdfAlgorithm {
    /// PBKDF2 with HMAC-SHA-256
    Pbkdf2Sha256,
    /// PBKDF2 with HMAC-SHA-512
    Pbkdf2Sha512,
    /// PBKDF2 with HMAC-BLAKE2s-256
    Pbkdf2Blake2s,
    /// PBKDF2 with HMAC-Whirlpool
    Pbkdf2Whirlpool,
    /// PBKDF2 with HMAC-Streebog-512
    Pbkdf2Streebog,
    /// Argon2id memory-hard KDF
    Argon2id,
}

impl KdfAlgorithm {
    /// Get the human-readable algorithm name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Pbkdf2Sha256 => "PBKDF2-HMAC-SHA-256",
            Self::Pbkdf2Sha512 => "PBKDF2-HMAC-SHA-512",
            Self::Pbkdf2Blake2s => "PBKDF2-HMAC-BLAKE2s",
            Self::Pbkdf2Whirlpool => "PBKDF2-HMAC-Whirlpool",
            Self::Pbkdf2Streebog => "PBKDF2-HMAC-Streebog",
            Self::Argon2id => "Argon2id",
        }
    }

    /// Get the default iteration count for this KDF
    pub fn default_iterations(&self) -> u32 {
        match self {
            Self::Argon2id => 10,
            _ => 500_000,
        }
    }
}
