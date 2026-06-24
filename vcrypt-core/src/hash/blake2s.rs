//! BLAKE2s-256 hash implementation

use super::HashFunction;
use blake2::{Blake2s256, Digest};

/// BLAKE2s-256 hash function
pub struct Blake2sHash {
    hasher: Blake2s256,
}

impl Default for Blake2sHash {
    fn default() -> Self {
        Self {
            hasher: Blake2s256::new(),
        }
    }
}

impl HashFunction for Blake2sHash {
    const OUTPUT_SIZE: usize = 32;

    fn name(&self) -> &'static str {
        "BLAKE2s-256"
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
    fn test_blake2s_empty() {
        let hash = Blake2sHash::hash(b"");
        assert_eq!(hash.len(), 32);
    }

    #[test]
    fn test_blake2s_abc() {
        let hash = Blake2sHash::hash(b"abc");
        assert_eq!(hash.len(), 32);
        assert_eq!(
            hex::encode(&hash),
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982"
        );
    }
}
