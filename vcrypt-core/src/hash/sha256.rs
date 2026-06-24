//! SHA-256 hash implementation

use super::HashFunction;
use sha2::{Digest, Sha256};

/// SHA-256 hash function
pub struct Sha256Hash {
    hasher: Sha256,
}

impl Default for Sha256Hash {
    fn default() -> Self {
        Self {
            hasher: Sha256::new(),
        }
    }
}

impl HashFunction for Sha256Hash {
    const OUTPUT_SIZE: usize = 32;

    fn name(&self) -> &'static str {
        "SHA-256"
    }

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
    fn test_sha256_empty() {
        let hash = Sha256Hash::hash(b"");
        assert_eq!(hash.len(), 32);
        // SHA-256 of empty string
        assert_eq!(
            hex::encode(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn test_sha256_abc() {
        let hash = Sha256Hash::hash(b"abc");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(&hash),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
