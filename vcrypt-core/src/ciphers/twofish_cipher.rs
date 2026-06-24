//! Twofish cipher implementation — powered by the `lsx` crate with precomputed MDS tables.

use super::BlockCipher;
use crate::{CryptoError, Result};

/// Twofish cipher
pub struct TwofishCipher { cipher: lsx::twofish::Twofish }

impl TwofishCipher {
    /// Create new Twofish cipher with 32-byte key
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != Self::KEY_SIZE {
            return Err(CryptoError::InvalidKeySize { expected: Self::KEY_SIZE, actual: key.len() });
        }
        // lsx provides key-size-specialised constructors
        let tf = lsx::twofish::Twofish::new256(
            key.try_into().map_err(|_| CryptoError::CipherInitFailed("Twofish: key length".into()))?
        );
        Ok(Self { cipher: tf })
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
        let input: [u8; 16] = block.try_into().unwrap();
        self.cipher.encrypt(&input, (&mut block[..16]).try_into().unwrap());
        Ok(())
    }

    fn decrypt_block(&self, block: &mut [u8]) -> Result<()> {
        if block.len() != Self::BLOCK_SIZE {
            return Err(CryptoError::InvalidBlockSize { expected: Self::BLOCK_SIZE, actual: block.len() });
        }
        let input: [u8; 16] = block.try_into().unwrap();
        self.cipher.decrypt(&input, (&mut block[..16]).try_into().unwrap());
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
