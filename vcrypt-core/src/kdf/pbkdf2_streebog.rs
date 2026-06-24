//! PBKDF2-HMAC-Streebog implementation

use super::KeyDerivation;
use crate::Result;
use pbkdf2::pbkdf2_hmac;
use streebog::Streebog512;

/// PBKDF2 with HMAC-Streebog-512
pub struct Pbkdf2Streebog;

impl KeyDerivation for Pbkdf2Streebog {
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()> {
        pbkdf2_hmac::<Streebog512>(password, salt, iterations, output);
        Ok(())
    }

    fn name(&self) -> &'static str { "PBKDF2-HMAC-Streebog" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_streebog() {
        let kdf = Pbkdf2Streebog;
        let mut output = [0u8; 64];
        kdf.derive(b"password", b"salt", 1000, &mut output).unwrap();
        assert_ne!(output, [0u8; 64]);
    }
}
