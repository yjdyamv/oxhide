//! Kuznyechik cipher implementation (GOST R 34.12-2015)

use super::BlockCipher;
use crate::{CryptoError, Result};
use kuznyechik::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use kuznyechik::Kuznyechik;

/// Kuznyechik cipher (GOST R 34.12-2015)
pub struct KuznyechikCipher { cipher: Kuznyechik }

impl KuznyechikCipher {
    /// Create new Kuznyechik cipher with 32-byte key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize { expected: Self::KEY_SIZE, actual: key.len() });
        }
        let cipher = Kuznyechik::new_from_slice(key)
            .map_err(|e| CryptoError::CipherInitFailed(format!("Kuznyechik: {}", e)))?;
        Ok(Self { cipher })
    }
}

impl BlockCipher for KuznyechikCipher {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;

    fn name(&self) -> &'static str { "Kuznyechik" }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let mut b = kuznyechik::cipher::Block::<Kuznyechik>::default();
        b.copy_from_slice(block);
        self.cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let mut b = kuznyechik::cipher::Block::<Kuznyechik>::default();
        b.copy_from_slice(block);
        self.cipher.decrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kuznyechik_encrypt_decrypt() {
        let cipher = KuznyechikCipher::new(&[0u8; 32]).unwrap();
        let mut data = [0x12u8; 16]; let orig = data;
        cipher.encrypt_block(&mut data).unwrap();
        assert_ne!(data, orig);
        cipher.decrypt_block(&mut data).unwrap();
        assert_eq!(data, orig);
    }
}
