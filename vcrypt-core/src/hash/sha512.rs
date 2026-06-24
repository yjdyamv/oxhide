//! SHA-512 hash implementation

use super::HashFunction;
use sha2::{Digest, Sha512};

/// SHA-512 hash function
pub struct Sha512Hash {
    hasher: Sha512,
}

impl Default for Sha512Hash {
    fn default() -> Self {
        Self {
            hasher: Sha512::new(),
        }
    }
}

impl HashFunction for Sha512Hash {
    const OUTPUT_SIZE: usize = 64;

    fn name(&self) -> &'static str {
        "SHA-512"
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
    fn test_sha512_empty() {
        let hash = Sha512Hash::hash(b"");
        assert_eq!(hash.len(), 64);
    }

    #[test]
    fn test_sha512_abc() {
        let hash = Sha512Hash::hash(b"abc");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hex::encode(&hash),
            "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
             2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        );
    }
}
