//! Camellia cipher implementation

use super::BlockCipher;
use crate::{CryptoError, Result};
use camellia::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use camellia::Camellia256;

/// Camellia-256 cipher
pub struct CamelliaCipher { cipher: Camellia256 }

impl CamelliaCipher {
    /// Create new Camellia cipher with 32-byte key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize { expected: Self::KEY_SIZE, actual: key.len() });
        }
        let cipher = Camellia256::new_from_slice(key)
            .map_err(|e| CryptoError::CipherInitFailed(format!("Camellia: {}", e)))?;
        Ok(Self { cipher })
    }
}

impl BlockCipher for CamelliaCipher {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;

    fn name(&self) -> &'static str { "Camellia-256" }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let b = unsafe { &mut *(block.as_mut_ptr() as *mut camellia::cipher::Block::<Camellia256>) };
        self.cipher.encrypt_block(b);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let b = unsafe { &mut *(block.as_mut_ptr() as *mut camellia::cipher::Block::<Camellia256>) };
        self.cipher.decrypt_block(b);
        Ok(())
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        let n = data.len() / Self::BLOCK_SIZE;
        let blocks = unsafe {
            std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut camellia::cipher::Block::<Camellia256>, n)
        };
        self.cipher.encrypt_blocks(blocks);
        Ok(())
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        let n = data.len() / Self::BLOCK_SIZE;
        let blocks = unsafe {
            std::slice::from_raw_parts_mut(data.as_mut_ptr() as *mut camellia::cipher::Block::<Camellia256>, n)
        };
        self.cipher.decrypt_blocks(blocks);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_camellia_encrypt_decrypt() {
        let cipher = CamelliaCipher::new(&[0u8; 32]).unwrap();
        let mut data = [0x12u8; 16]; let orig = data;
        cipher.encrypt_block(&mut data).unwrap();
        assert_ne!(data, orig);
        cipher.decrypt_block(&mut data).unwrap();
        assert_eq!(data, orig);
    }
}
