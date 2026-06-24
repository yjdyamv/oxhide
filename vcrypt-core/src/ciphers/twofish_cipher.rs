//! Twofish cipher implementation

use super::BlockCipher;
use crate::{CryptoError, Result};
use twofish::cipher::{BlockCipherDecrypt, BlockCipherEncrypt, KeyInit};
use twofish::Twofish;

/// Twofish cipher
pub struct TwofishCipher { cipher: Twofish }

impl TwofishCipher {
    /// Create new Twofish cipher with 32-byte key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize { expected: Self::KEY_SIZE, actual: key.len() });
        }
        let cipher = Twofish::new_from_slice(key)
            .map_err(|e| CryptoError::CipherInitFailed(format!("Twofish: {}", e)))?;
        Ok(Self { cipher })
    }
}

impl BlockCipher for TwofishCipher {
    const BLOCK_SIZE: usize = 16;
    const KEY_SIZE: usize = 32;

    fn name(&self) -> &'static str { "Twofish" }

    fn encrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let mut b = twofish::cipher::Block::<Twofish>::default();
        b.copy_from_slice(block);
        self.cipher.encrypt_block(&mut b);
        block.copy_from_slice(&b);
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let mut b = twofish::cipher::Block::<Twofish>::default();
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
    fn test_twofish_encrypt_decrypt() {
        let cipher = TwofishCipher::new(&[0u8; 32]).unwrap();
        let mut data = [0x12u8; 16]; let orig = data;
        cipher.encrypt_block(&mut data).unwrap();
        assert_ne!(data, orig);
        cipher.decrypt_block(&mut data).unwrap();
        assert_eq!(data, orig);
    }

    #[test]
    fn test_key_validation() {
        assert!(TwofishCipher::new(&[0u8; 16]).is_err());
    }
}
