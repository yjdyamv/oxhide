//! AES cipher implementation

use super::BlockCipher;
use crate::{CryptoError, Result};
use aes::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use aes::Aes256;

/// AES-256 cipher
pub struct AesCipher {
    cipher: Aes256,
}

impl AesCipher {
    /// Create new AES cipher with 32-byte key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize {
                expected: Self::KEY_SIZE,
                actual: key.len(),
            });
        }

        let cipher = Aes256::new_from_slice(key)
            .map_err(|e| CryptoError::CipherInitFailed(format!("AES: {}", e)))?;

        Ok(Self { cipher })
    }
}

impl BlockCipher for AesCipher {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;

    fn name(&self) -> &'static str { "AES-256" }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize {
                expected: Self::BLOCK_SIZE,
                actual: block.len(),
            });
        }
        // SAFETY: length == 16 verified above; GenericArray<u8,U16> is repr(transparent) over [u8;16]
        let b = unsafe { &mut *(block.as_mut_ptr() as *mut aes::cipher::Block::<Aes256>) };
        self.cipher.encrypt_block(b);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize {
                expected: Self::BLOCK_SIZE,
                actual: block.len(),
            });
        }
        let b = unsafe { &mut *(block.as_mut_ptr() as *mut aes::cipher::Block::<Aes256>) };
        self.cipher.decrypt_block(b);
        Ok(())
    }

    fn encrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        let n = data.len() / Self::BLOCK_SIZE;
        let blocks = unsafe {
            core::slice::from_raw_parts_mut(
                data.as_mut_ptr() as *mut aes::cipher::Block::<Aes256>,
                n,
            )
        };
        self.cipher.encrypt_blocks(blocks);
        Ok(())
    }

    fn decrypt_blocks(&self, data: &mut [u8]) -> Result<()> {
        let n = data.len() / Self::BLOCK_SIZE;
        let blocks = unsafe {
            core::slice::from_raw_parts_mut(
                data.as_mut_ptr() as *mut aes::cipher::Block::<Aes256>,
                n,
            )
        };
        self.cipher.decrypt_blocks(blocks);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_encrypt_decrypt() {
        let key = [0u8; 32];
        let cipher = AesCipher::new(&key).unwrap();
        let mut data = [0x12u8; 16];
        let original = data;
        cipher.encrypt_block(&mut data).unwrap();
        assert_ne!(data, original);
        cipher.decrypt_block(&mut data).unwrap();
        assert_eq!(data, original);
    }
}
