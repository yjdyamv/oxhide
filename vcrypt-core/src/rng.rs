//! Secure random number generation
//!
//! Uses OS-provided CSPRNG via `getrandom` for key material and salt generation.

use crate::{CryptoError, Result};

/// Fill buffer with cryptographically secure random bytes
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::fill(buf).map_err(|e| CryptoError::InvalidDataLength(format!("RNG: {}", e)))
}

/// Generate 64-byte random salt
pub fn random_salt() -> Result<[u8; 64]> {
    let mut salt = [0u8; 64];
    fill_random(&mut salt)?;
    Ok(salt)
}

/// Generate random buffer of given length
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; len];
    fill_random(&mut buf)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fill_random() {
        let mut buf = [0u8; 64];
        fill_random(&mut buf).unwrap();
        assert!(buf.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_random_salt() {
        let s1 = random_salt().unwrap();
        let s2 = random_salt().unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_random_bytes() {
        let b1 = random_bytes(32).unwrap();
        let b2 = random_bytes(32).unwrap();
        assert_eq!(b1.len(), 32);
        assert_ne!(b1, b2);
    }
}
