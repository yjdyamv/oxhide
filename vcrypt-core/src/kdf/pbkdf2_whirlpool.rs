//! PBKDF2-HMAC-Whirlpool implementation

use super::KeyDerivation;
use crate::Result;
use pbkdf2::pbkdf2_hmac;
use whirlpool::Whirlpool;

/// PBKDF2 with HMAC-Whirlpool
pub struct Pbkdf2Whirlpool;

impl KeyDerivation for Pbkdf2Whirlpool {
    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()> {
        pbkdf2_hmac::<Whirlpool>(password, salt, iterations, output);
        Ok(())
    }

    fn name(&self) -> &'static str { "PBKDF2-HMAC-Whirlpool" }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pbkdf2_whirlpool() {
        let kdf = Pbkdf2Whirlpool;
        let mut output = [0u8; 64];
        kdf.derive(b"password", b"salt", 1000, &mut output).unwrap();
        assert_ne!(output, [0u8; 64]);
    }
}
