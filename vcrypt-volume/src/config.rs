//! Volume configuration

use vcrypt_core::ciphers::CipherType;
use vcrypt_core::hash::HashAlgorithm;
use vcrypt_core::kdf::KdfAlgorithm;

/// Configuration for creating or opening a VeraCrypt volume
#[derive(Debug, Clone)]
pub struct VolumeConfig {
    pub cipher: CipherType,
    pub hash: HashAlgorithm,
    pub kdf: KdfAlgorithm,
    pub iterations: u32,
    pub pim: Option<u32>,
    pub sector_size: u32,
    pub use_backup_header: bool,
}

impl Default for VolumeConfig {
    fn default() -> Self {
        VolumeConfig {
            cipher: CipherType::Aes,
            hash: HashAlgorithm::Sha512,
            kdf: KdfAlgorithm::Pbkdf2Sha512,
            iterations: 500_000,
            pim: None,
            sector_size: 512,
            use_backup_header: false,
        }
    }
}

impl VolumeConfig {
    pub fn new() -> Self { Self::default() }

    pub fn with_cipher(mut self, c: CipherType) -> Self { self.cipher = c; self }
    pub fn with_hash(mut self, h: HashAlgorithm) -> Self { self.hash = h; self }
    pub fn with_kdf(mut self, k: KdfAlgorithm) -> Self { self.kdf = k; self }
    pub fn with_iterations(mut self, n: u32) -> Self { self.iterations = n; self }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default() {
        let cfg = VolumeConfig::default();
        assert_eq!(cfg.sector_size, 512);
        assert_eq!(cfg.cipher, CipherType::Aes);
    }

    #[test]
    fn test_builder() {
        let cfg = VolumeConfig::new()
            .with_cipher(CipherType::Serpent)
            .with_hash(HashAlgorithm::Sha256)
            .with_iterations(1_000_000);
        assert_eq!(cfg.cipher, CipherType::Serpent);
        assert_eq!(cfg.hash, HashAlgorithm::Sha256);
        assert_eq!(cfg.iterations, 1_000_000);
    }
}
