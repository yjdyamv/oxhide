//! Block cipher implementations for VeraCrypt
//!
//! This module provides all block cipher algorithms supported by VeraCrypt:
//! - AES-256
//! - Serpent
//! - Twofish
//! - Camellia-256
//! - Kuznyechik
//! - Cascade combinations of the above

use crate::Result;

/// Block cipher trait
///
/// All block ciphers must implement this trait to be used in VeraCrypt volumes.
pub trait BlockCipher: Send + Sync {
    /// Block size in bytes (typically 16 bytes for most ciphers)
    const BLOCK_SIZE: usize;

    /// Key size in bytes (typically 32 bytes for 256-bit keys)
    const KEY_SIZE: usize;

    /// Get the cipher name
    fn name(&self) -> &'static str;

    /// Get the block size (runtime version for dyn compatibility)
    fn block_size(&self) -> usize {
        Self::BLOCK_SIZE
    }

    /// Get the key size (runtime version for dyn compatibility)
    fn key_size(&self) -> usize {
        Self::KEY_SIZE
    }

    /// Encrypt a single block in place
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()>;

    /// Decrypt a single block in place
    fn decrypt_block(&self, block: &mut [u8]) -> Result<()>;

    /// Encrypt multiple blocks in place.
    /// `data` length must be a multiple of `BLOCK_SIZE`.
    /// Default implementation calls `encrypt_block` in a loop.
    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        for chunk in data.chunks_mut(Self::BLOCK_SIZE) {
            self.encrypt_block(chunk)?;
        }
        Ok(())
    }

    /// Decrypt multiple blocks in place.
    /// Default implementation calls `decrypt_block` in a loop.
    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        for chunk in data.chunks_mut(Self::BLOCK_SIZE) {
            self.decrypt_block(chunk)?;
        }
        Ok(())
    }
}

mod aes_cipher;
mod serpent_cipher;
mod twofish_cipher;
mod camellia_cipher;
mod kuznyechik_cipher;
mod cascade;

pub use aes_cipher::AesCipher;
pub use serpent_cipher::SerpentCipher;
pub use twofish_cipher::TwofishCipher;
pub use camellia_cipher::CamelliaCipher;
pub use kuznyechik_cipher::KuznyechikCipher;
pub use cascade::{CascadeCipher, CascadeMode};

/// Cipher enumeration for easy instantiation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherType {
    /// AES-256
    Aes,
    /// Serpent
    Serpent,
    /// Twofish
    Twofish,
    /// Camellia-256
    Camellia,
    /// Kuznyechik (GOST R 34.12-2015)
    Kuznyechik,
    /// AES-Twofish cascade
    AesTwofish,
    /// AES-Twofish-Serpent cascade
    AesTwofishSerpent,
    /// Serpent-AES cascade
    SerpentAes,
    /// Serpent-Twofish-AES cascade
    SerpentTwofishAes,
    /// Twofish-Serpent cascade
    TwofishSerpent,
}

impl CipherType {
    /// All currently supported VeraCrypt-compatible volume cipher choices.
    pub const fn all_supported() -> &'static [CipherType] {
        &[
            Self::Aes,
            Self::Serpent,
            Self::Twofish,
            Self::Camellia,
            Self::Kuznyechik,
            Self::AesTwofish,
            Self::AesTwofishSerpent,
            Self::SerpentAes,
            Self::SerpentTwofishAes,
            Self::TwofishSerpent,
        ]
    }

    /// Get the total key size required for this cipher type
    pub fn key_size(&self) -> usize {
        match self {
            Self::Aes => 32,
            Self::Serpent => 32,
            Self::Twofish => 32,
            Self::Camellia => 32,
            Self::Kuznyechik => 32,
            Self::AesTwofish => 64,
            Self::AesTwofishSerpent => 96,
            Self::SerpentAes => 64,
            Self::SerpentTwofishAes => 96,
            Self::TwofishSerpent => 64,
        }
    }

    /// Get the cipher name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Aes => "AES",
            Self::Serpent => "Serpent",
            Self::Twofish => "Twofish",
            Self::Camellia => "Camellia",
            Self::Kuznyechik => "Kuznyechik",
            Self::AesTwofish => "AES-Twofish",
            Self::AesTwofishSerpent => "AES-Twofish-Serpent",
            Self::SerpentAes => "Serpent-AES",
            Self::SerpentTwofishAes => "Serpent-Twofish-AES",
            Self::TwofishSerpent => "Twofish-Serpent",
        }
    }

    /// Check if this cipher type is a cascade (multi-cipher)
    pub fn is_cascade(&self) -> bool {
        matches!(
            self,
            Self::AesTwofish
                | Self::AesTwofishSerpent
                | Self::SerpentAes
                | Self::SerpentTwofishAes
                | Self::TwofishSerpent
        )
    }

    /// Get the number of individual ciphers in this type
    pub fn cipher_count(&self) -> usize {
        match self {
            Self::Aes | Self::Serpent | Self::Twofish | Self::Camellia | Self::Kuznyechik => 1,
            Self::AesTwofish | Self::SerpentAes | Self::TwofishSerpent => 2,
            Self::AesTwofishSerpent | Self::SerpentTwofishAes => 3,
        }
    }
}
