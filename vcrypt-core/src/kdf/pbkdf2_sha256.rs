//! PBKDF2-HMAC-SHA256 implementation

use super::KeyDerivation;
use crate::Result;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;

/// PBKDF2 with HMAC-SHA-256
pub struct Pbkdf2Sha256;

impl KeyDerivation for Pbkdf2Sha256 {
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()> {
        pbkdf2_hmac::<Sha256>(password, salt, iterations, output);
        Ok(())
    }

    fn name(&self) -> &'static str {
        "PBKDF2-HMAC-SHA-256"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_sha256() {
        let kdf = Pbkdf2Sha256;
        let mut output = [0u8; 32];
        kdf.derive(b"password", b"salt", 1000, &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }
}
