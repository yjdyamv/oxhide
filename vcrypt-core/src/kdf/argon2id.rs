//! Argon2id implementation

use super::KeyDerivation;
use crate::{CryptoError, Result};
use argon2::{Algorithm, Argon2, ParamsBuilder, Version};

/// Argon2id key derivation function
pub struct Argon2idKdf {
    memory_cost: u32,
    time_cost: u32,
    parallelism: u32,
}

impl Default for Argon2idKdf {
    fn default() -> Self {
        Self {
            memory_cost: 65536,  // 64 MiB
            time_cost: 3,
            parallelism: 1,
        }
    }
}

impl Argon2idKdf {
    /// Create a new Argon2id KDF with custom parameters
    pub fn new(memory_cost: u32, time_cost: u32, parallelism: u32) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
        }
    }

    /// Return VeraCrypt Argon2id parameters for the provided PIM.
    pub fn params_for_pim(pim: i32) -> (u32, u32) {
        let mut effective_pim = pim.max(0);
        if effective_pim == 0 {
            effective_pim = 12;
        }

        let effective_pim = effective_pim as u32;
        let memory_cost_mib = 64u32.saturating_add((effective_pim - 1) * 32).min(1024);
        let time_cost = if effective_pim <= 31 {
            3 + ((effective_pim - 1) / 3)
        } else {
            13 + (effective_pim - 31)
        };

        (memory_cost_mib * 1024, time_cost)
    }
}

impl KeyDerivation for Argon2idKdf {
    fn get_iteration_count(&self, pim: i32) -> u32 {
        let (_, time_cost) = Self::params_for_pim(pim);
        time_cost
    }

    fn derive(&self, password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) -> Result<()> {
        let (memory_cost, time_cost) = if iterations == 0 {
            (self.memory_cost, self.time_cost)
        } else {
            (self.memory_cost, iterations)
        };

        let params = ParamsBuilder::new()
            .m_cost(memory_cost)
            .t_cost(time_cost)
            .p_cost(self.parallelism)
            .output_len(output.len())
            .build()
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("Argon2id params: {}", e)))?;

        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

        argon2
            .hash_password_into(password, salt, output)
            .map_err(|e| CryptoError::KeyDerivationFailed(format!("Argon2id: {}", e)))?;

        Ok(())
    }

    fn name(&self) -> &'static str {
        "Argon2id"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2id() {
        let kdf = Argon2idKdf::default();
        let mut output = [0u8; 32];
        kdf.derive(b"password", b"saltsaltsalt", 0, &mut output).unwrap();
        assert_ne!(output, [0u8; 32]);
    }

    #[test]
    fn test_argon2id_custom() {
        let kdf = Argon2idKdf::new(4096, 2, 1);
        let mut output = [0u8; 64];
        kdf.derive(b"password", b"saltsaltsalt", 0, &mut output).unwrap();
        assert_ne!(output, [0u8; 64]);
    }

    #[test]
    fn test_argon2id_pim_defaults() {
        assert_eq!(Argon2idKdf::params_for_pim(0), (416 * 1024, 6));
        assert_eq!(Argon2idKdf::params_for_pim(12), (416 * 1024, 6));
        assert_eq!(Argon2idKdf::params_for_pim(31), (1024 * 1024, 13));
        assert_eq!(Argon2idKdf::params_for_pim(32), (1024 * 1024, 14));
    }
}
