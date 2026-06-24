//! PBKDF2-HMAC-SHA512 implementation

use super::KeyDerivation;
use crate::Result;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha512;

/// PBKDF2 with HMAC-SHA-512
pub struct Pbkdf2Sha512;

impl KeyDerivation for Pbkdf2Sha512 {
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()> {
        pbkdf2_hmac::<Sha512>(password, salt, iterations, output);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "PBKDF2-HMAC-SHA-512"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_sha512() {
        let kdf = Pbkdf2Sha512;
        let mut output = [0u8; 64];
        kdf.derive(b"password", b"salt", 1000, &mut output).unwrap();
        assert_ne!(output, [0u8; 64]);
    }
}
