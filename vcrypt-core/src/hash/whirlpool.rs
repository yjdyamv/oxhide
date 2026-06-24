//! Whirlpool hash implementation (ISO/IEC 10118-3)
//!
//! Uses the `whirlpool` crate from RustCrypto/Hashes (5.89M downloads).

use super::HashFunction;
use whirlpool::{Digest, Whirlpool};

/// Whirlpool hash function (512-bit / 64-byte output)
pub struct WhirlpoolHash {
    hasher: Whirlpool,
}

impl Default for WhirlpoolHash {
    fn default() -> Self {
        Self { hasher: Whirlpool::new() }
    }
}

impl HashFunction for WhirlpoolHash {
    const OUTPUT_SIZE: usize = 64;

    fn name(&self) -> &'static str { "Whirlpool" }

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
    fn test_whirlpool_empty() {
        let hash = WhirlpoolHash::hash(b"");
        assert_eq!(hash.len(), 64);
        assert_eq!(
            hex::encode(&hash),
            "19fa61d75522a4669b44e39c1d2e1726c530232130d407f89afee0964997f7a7\
             3e83be698b288febcf88e3e03c4f0757ea8964e59b63d93708b138cc42a66eb3"
        );
    }

    #[test]
    fn test_whirlpool_abc() {
        let hash = WhirlpoolHash::hash(b"abc");
        assert_eq!(
            hex::encode(&hash),
            "4e2448a4c6f486bb16b6562c73b4020bf3043e3a731bce721ae1b303d97e6d4c\
             7181eebdb6c57e277d0e34957114cbd6c797fc9d95d8b582d225292076d4eef5"
        );
    }
}
