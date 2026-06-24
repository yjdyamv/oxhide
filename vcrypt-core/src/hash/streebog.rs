//! Streebog hash implementation (GOST R 34.11-2012)
//!
//! Uses the `streebog` crate v0.11 from RustCrypto/Hashes.
//! Note: streebog 0.11.x outputs in little-endian word order, which differs
//! from the GOST big-endian standard. For VeraCrypt compatibility, the hash
//! values produced by this module match the crate output.

use super::HashFunction;
use streebog::{Digest, Streebog256, Streebog512};

/// Streebog-512 (64-byte output, primary GOST variant)
pub struct StreebogHash {
    hasher: Streebog512,
}

impl Default for StreebogHash {
    fn default() -> Self {
        Self { hasher: Streebog512::new() }
    }
}

impl HashFunction for StreebogHash {
    const OUTPUT_SIZE: usize = 64;

    fn name(&self) -> &'static str { "Streebog-512" }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }
}

/// Streebog-256 (32-byte output variant)
pub struct Streebog256Hash {
    hasher: Streebog256,
}

impl Default for Streebog256Hash {
    fn default() -> Self {
        Self { hasher: Streebog256::new() }
    }
}

impl HashFunction for Streebog256Hash {
    const OUTPUT_SIZE: usize = 32;

    fn name(&self) -> &'static str { "Streebog-256" }

    fn update(&mut self, data: &[u8]) {
        self.hasher.update(data);
    }

    fn finalize(self) -> Vec<u8> {
        self.hasher.finalize().to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_streebog512_empty() {
        let hash = StreebogHash::hash(b"");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_streebog512_deterministic() {
        let h1 = StreebogHash::hash(b"The quick brown fox jumps over the lazy dog");
        let h2 = StreebogHash::hash(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(h1, h2);
        // Verify non-zero
        assert!(h1.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_streebog256_empty() {
        let hash = Streebog256Hash::hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_streebog256_deterministic() {
        let h1 = Streebog256Hash::hash(b"The quick brown fox jumps over the lazy dog");
        let h2 = Streebog256Hash::hash(b"The quick brown fox jumps over the lazy dog");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_streebog_avalanche() {
        let h1 = StreebogHash::hash(b"abc");
        let h2 = StreebogHash::hash(b"abd");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_streebog_512_256_different() {
        let h512 = StreebogHash::hash(b"test");
        let h256 = Streebog256Hash::hash(b"test");
        assert_ne!(h512[..32], h256[..]);
    }
}
