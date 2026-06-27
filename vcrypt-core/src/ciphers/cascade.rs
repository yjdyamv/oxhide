//! Cascade cipher implementation
//!
//! This module implements cipher cascading, where data is encrypted with multiple
//! ciphers in sequence. VeraCrypt supports several cascade combinations for
//! enhanced security through defense in depth.

use super::{AesCipher, BlockCipher, CamelliaCipher, CipherType, KuznyechikCipher, SerpentCipher, TwofishCipher};
use crate::{CryptoError, Result};

#[cfg(all(feature = "kernel", not(feature = "std")))]
use alloc::vec::Vec;

/// Cascade mode defines the order of ciphers in a cascade
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CascadeMode {
    /// AES-Twofish (2 ciphers)
    AesTwofish,
    /// AES-Twofish-Serpent (3 ciphers)
    AesTwofishSerpent,
    /// Serpent-AES (2 ciphers)
    SerpentAes,
    /// Serpent-Twofish-AES (3 ciphers)
    SerpentTwofishAes,
    /// Twofish-Serpent (2 ciphers)
    TwofishSerpent,
    /// Camellia-Kuznyechik (2 ciphers)
    CamelliaKuznyechik,
    /// Camellia-Serpent (2 ciphers)
    CamelliaSerpent,
    /// Kuznyechik-AES (2 ciphers)
    KuznyechikAes,
    /// Kuznyechik-Serpent-Camellia (3 ciphers)
    KuznyechikSerpentCamellia,
    /// Kuznyechik-Twofish (2 ciphers)
    KuznyechikTwofish,
}

impl CascadeMode {
    /// Get the number of ciphers in this cascade
    pub fn cipher_count(&self) -> usize {
        match self {
            Self::AesTwofish | Self::SerpentAes | Self::TwofishSerpent
            | Self::CamelliaKuznyechik | Self::CamelliaSerpent
            | Self::KuznyechikAes | Self::KuznyechikTwofish => 2,
            Self::AesTwofishSerpent | Self::SerpentTwofishAes
            | Self::KuznyechikSerpentCamellia => 3,
        }
    }

    /// Get the total key size required (32 bytes per cipher)
    pub fn key_size(&self) -> usize {
        self.cipher_count() * 32
    }

    /// Get the cascade name
    pub fn name(&self) -> &'static str {
        match self {
            Self::AesTwofish => "AES-Twofish",
            Self::AesTwofishSerpent => "AES-Twofish-Serpent",
            Self::SerpentAes => "Serpent-AES",
            Self::SerpentTwofishAes => "Serpent-Twofish-AES",
            Self::TwofishSerpent => "Twofish-Serpent",
            Self::CamelliaKuznyechik => "Camellia-Kuznyechik",
            Self::CamelliaSerpent => "Camellia-Serpent",
            Self::KuznyechikAes => "Kuznyechik-AES",
            Self::KuznyechikSerpentCamellia => "Kuznyechik-Serpent-Camellia",
            Self::KuznyechikTwofish => "Kuznyechik-Twofish",
        }
    }

    /// VeraCrypt encryption order: the `Ciphers` list in forward (= name-reversed)
    /// order, paired with per-cipher byte offset within the data-half and tweak-half.
    ///
    /// Each half (data / tweak) is `cipher_count() * 32` bytes. Position `i` in the
    /// returned vec consumes half bytes `[offset .. offset+32]`.
    /// Encrypt: iterate forward; decrypt: iterate in reverse.
    pub fn veracrypt_order(&self) -> Vec<(CipherType, usize)> {
        match self {
            Self::AesTwofish => vec![(CipherType::Twofish, 0), (CipherType::Aes, 32)],
            Self::AesTwofishSerpent => vec![
                (CipherType::Serpent, 0),
                (CipherType::Twofish, 32),
                (CipherType::Aes, 64),
            ],
            Self::SerpentAes => vec![(CipherType::Aes, 0), (CipherType::Serpent, 32)],
            Self::SerpentTwofishAes => vec![
                (CipherType::Aes, 0),
                (CipherType::Twofish, 32),
                (CipherType::Serpent, 64),
            ],
            Self::TwofishSerpent => vec![(CipherType::Serpent, 0), (CipherType::Twofish, 32)],
            Self::CamelliaKuznyechik => vec![(CipherType::Kuznyechik, 0), (CipherType::Camellia, 32)],
            Self::CamelliaSerpent => vec![(CipherType::Serpent, 0), (CipherType::Camellia, 32)],
            Self::KuznyechikAes => vec![(CipherType::Aes, 0), (CipherType::Kuznyechik, 32)],
            Self::KuznyechikSerpentCamellia => vec![
                (CipherType::Camellia, 0),
                (CipherType::Serpent, 32),
                (CipherType::Kuznyechik, 64),
            ],
            Self::KuznyechikTwofish => vec![(CipherType::Twofish, 0), (CipherType::Kuznyechik, 32)],
        }
    }
}

/// Individual cipher in a cascade
enum CipherInstance {
    Aes(AesCipher),
    Serpent(SerpentCipher),
    Twofish(TwofishCipher),
    Camellia(CamelliaCipher),
    Kuznyechik(KuznyechikCipher),
}

impl CipherInstance {
    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match self {
            Self::Aes(c) => c.encrypt_block(block),
            Self::Serpent(c) => c.encrypt_block(block),
            Self::Twofish(c) => c.encrypt_block(block),
            Self::Camellia(c) => c.encrypt_block(block),
            Self::Kuznyechik(c) => c.encrypt_block(block),
        }
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        match self {
            Self::Aes(c) => c.decrypt_block(block),
            Self::Serpent(c) => c.decrypt_block(block),
            Self::Twofish(c) => c.decrypt_block(block),
            Self::Camellia(c) => c.decrypt_block(block),
            Self::Kuznyechik(c) => c.decrypt_block(block),
        }
    }
}

/// Cascade cipher combining multiple block ciphers
///
/// In a cascade, data is encrypted with each cipher in sequence.
/// For decryption, the order is reversed.
pub struct CascadeCipher {
    mode: CascadeMode,
    ciphers: Vec<CipherInstance>,
}

impl CascadeCipher {
    /// Create a new cascade cipher
    ///
    /// # Arguments
    /// * `mode` - The cascade mode defining cipher order
    /// * `key` - Combined key material (32 bytes per cipher)
    ///
    /// # Example
    /// ```ignore
    /// let key = [0u8; 64]; // 64 bytes for 2-cipher cascade
    /// let cascade = CascadeCipher::new(CascadeMode::AesTwofish, &key)?;
    /// ```
    pub fn new(mode: CascadeMode, key: &[u8]) -> Result<Self> {
        let required_size = mode.key_size();
        if key.len() != required_size {
            return Err(CryptoError::InvalidKeySize {
                expected: required_size,
                actual: key.len(),
            });
        }

        let ciphers = Self::create_ciphers(mode, key)?;

        Ok(Self { mode, ciphers })
    }

    /// Create the cipher chain based on the mode
    fn create_ciphers(mode: CascadeMode, key: &[u8]) -> Result<Vec<CipherInstance>> {
        let mut ciphers: Vec<CipherInstance> = Vec::new();
        let mut offset = 0;

        match mode {
            CascadeMode::AesTwofish => {
                ciphers.push(CipherInstance::Aes(AesCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Twofish(TwofishCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::AesTwofishSerpent => {
                ciphers.push(CipherInstance::Aes(AesCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Twofish(TwofishCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Serpent(SerpentCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::SerpentAes => {
                ciphers.push(CipherInstance::Serpent(SerpentCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Aes(AesCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::SerpentTwofishAes => {
                ciphers.push(CipherInstance::Serpent(SerpentCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Twofish(TwofishCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Aes(AesCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::TwofishSerpent => {
                ciphers.push(CipherInstance::Twofish(TwofishCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Serpent(SerpentCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::CamelliaKuznyechik => {
                ciphers.push(CipherInstance::Camellia(CamelliaCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Kuznyechik(KuznyechikCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::CamelliaSerpent => {
                ciphers.push(CipherInstance::Camellia(CamelliaCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Serpent(SerpentCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::KuznyechikAes => {
                ciphers.push(CipherInstance::Kuznyechik(KuznyechikCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Aes(AesCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::KuznyechikSerpentCamellia => {
                ciphers.push(CipherInstance::Kuznyechik(KuznyechikCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Serpent(SerpentCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Camellia(CamelliaCipher::new(&key[offset..offset + 32])?));
            }
            CascadeMode::KuznyechikTwofish => {
                ciphers.push(CipherInstance::Kuznyechik(KuznyechikCipher::new(&key[offset..offset + 32])?));
                offset += 32;
                ciphers.push(CipherInstance::Twofish(TwofishCipher::new(&key[offset..offset + 32])?));
            }
        }

        Ok(ciphers)
    }

    /// Get the cascade mode
    pub fn mode(&self) -> CascadeMode {
        self.mode
    }
}

impl BlockCipher for CascadeCipher {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 64; // Minimum for 2-cipher cascade

    fn name(&self) -> &'static str {
        self.mode.name()
    }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize {
                expected: Self::BLOCK_SIZE,
                actual: block.len(),
            });
        }

        // Encrypt with each cipher in forward order
        for cipher in &self.ciphers {
            cipher.encrypt_block(block)?;
        }

        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize {
                expected: Self::BLOCK_SIZE,
                actual: block.len(),
            });
        }

        // Decrypt with each cipher in reverse order
        for cipher in self.ciphers.iter().rev() {
            cipher.decrypt_block(block)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cascade_two_cipher() {
        let key = [0u8; 64];
        let cascade = CascadeCipher::new(CascadeMode::AesTwofish, &key).unwrap();

        let mut data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let original = data;

        cascade.encrypt_block(&mut data).unwrap();
        assert_ne!(data, original);

        cascade.decrypt_block(&mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_cascade_three_cipher() {
        let key = [0u8; 96];
        let cascade = CascadeCipher::new(CascadeMode::AesTwofishSerpent, &key).unwrap();

        let mut data = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
                        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0];
        let original = data;

        cascade.encrypt_block(&mut data).unwrap();
        assert_ne!(data, original);

        cascade.decrypt_block(&mut data).unwrap();
        assert_eq!(data, original);
    }

    #[test]
    fn test_cascade_key_size_validation() {
        let key = [0u8; 32]; // Too small for 2-cipher cascade
        let result = CascadeCipher::new(CascadeMode::AesTwofish, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_all_cascade_modes() {
        let modes = [
            (CascadeMode::AesTwofish, 64),
            (CascadeMode::SerpentAes, 64),
            (CascadeMode::TwofishSerpent, 64),
            (CascadeMode::CamelliaKuznyechik, 64),
            (CascadeMode::CamelliaSerpent, 64),
            (CascadeMode::KuznyechikAes, 64),
            (CascadeMode::KuznyechikTwofish, 64),
            (CascadeMode::AesTwofishSerpent, 96),
            (CascadeMode::SerpentTwofishAes, 96),
            (CascadeMode::KuznyechikSerpentCamellia, 96),
        ];

        for (mode, key_size) in modes {
            let key = vec![0u8; key_size];
            let cascade = CascadeCipher::new(mode, &key).unwrap();

            let mut data = [1u8; 16];
            let original = data;

            cascade.encrypt_block(&mut data).unwrap();
            assert_ne!(data, original, "Failed for mode {:?}", mode);

            cascade.decrypt_block(&mut data).unwrap();
            assert_eq!(data, original, "Failed for mode {:?}", mode);
        }
    }
}
