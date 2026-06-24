//! PBKDF2-HMAC-BLAKE2s implementation
//!
//! Manual HMAC-BLAKE2s + PBKDF2 because blake2 0.10 (digest 0.10)
//! is incompatible with hmac 0.13 / pbkdf2 0.13 (digest 0.11).

use super::KeyDerivation;
use crate::Result;
use blake2::{Blake2s256, Digest};

const BLOCK_SIZE: usize = 64; // BLAKE2s internal block size

/// PBKDF2 with HMAC-BLAKE2s-256
pub struct Pbkdf2Blake2s;

impl KeyDerivation for Pbkdf2Blake2s {
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()> {
        pbkdf2_blake2s(password, salt, iterations, output);
        Ok(())
    }

    fn name(&self) -> &'static str { "PBKDF2-HMAC-BLAKE2s" }
}

/// HMAC-BLAKE2s (manual, avoids hmac crate digest version conflict)
fn hmac_blake2s(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = Vec::from(key);
    // If key > block size, hash it first
    if k.len() > BLOCK_SIZE {
        k = Blake2s256::digest(key).to_vec();
    }
    k.resize(BLOCK_SIZE, 0);

    let k_ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    let k_opad: Vec<u8> = k.iter().map(|b| b ^ 0x5C).collect();

    let mut inner = Blake2s256::new();
    inner.update(&k_ipad);
    inner.update(data);
    let inner_hash = inner.finalize();

    let mut outer = Blake2s256::new();
    outer.update(&k_opad);
    outer.update(&inner_hash);
    outer.finalize().to_vec()
}

/// Manual PBKDF2 (RFC 2898) using HMAC-BLAKE2s
fn pbkdf2_blake2s(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let hlen: usize = 32;
    let n_blocks = (output.len() + hlen - 1) / hlen;

    for block_num in 1..=n_blocks as u32 {
        let mut data = Vec::with_capacity(salt.len() + 4);
        data.extend_from_slice(salt);
        data.extend_from_slice(&block_num.to_be_bytes());

        let mut u = hmac_blake2s(password, &data);
        let mut t_block = u.clone();

        for _ in 1..iterations {
            u = hmac_blake2s(password, &u);
            for (t, ub) in t_block.iter_mut().zip(u.iter()) {
                *t ^= ub;
            }
        }

        let start = (block_num as usize - 1) * hlen;
        let end = (start + hlen).min(output.len());
        output[start..end].copy_from_slice(&t_block[..end - start]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_blake2s_basic() {
        let kdf = Pbkdf2Blake2s;
        let mut output = [0u8; 64];
        kdf.derive(b"password", b"salt", 1000, &mut output).unwrap();
        assert!(output.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_pbkdf2_blake2s_deterministic() {
        let kdf = Pbkdf2Blake2s;
        let mut o1 = [0u8; 32];
        let mut o2 = [0u8; 32];
        kdf.derive(b"password", b"salt", 1000, &mut o1).unwrap();
        kdf.derive(b"password", b"salt", 1000, &mut o2).unwrap();
        assert_eq!(o1, o2);
    }

    #[test]
    fn test_pbkdf2_blake2s_different_inputs() {
        let kdf = Pbkdf2Blake2s;
        let mut o1 = [0u8; 32];
        let mut o2 = [0u8; 32];
        kdf.derive(b"password1", b"salt", 100, &mut o1).unwrap();
        kdf.derive(b"password2", b"salt", 100, &mut o2).unwrap();
        assert_ne!(o1, o2);
    }

    #[test]
    fn test_pbkdf2_blake2s_long() {
        let kdf = Pbkdf2Blake2s;
        let mut output = [0u8; 128];
        kdf.derive(b"password", b"salt", 100, &mut output).unwrap();
        assert!(output.iter().any(|&b| b != 0));
    }
}
