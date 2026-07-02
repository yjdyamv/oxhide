//! Map VeraCrypt encryption-algorithm IDs (`ea`) to `vcrypt_core::CipherType`.
//!
//! Extracted from `vcrypt-driver/src/crypto.rs` so the mapping is testable
//! without pulling in WDK dependencies.

use vcrypt_core::ciphers::CipherType;

/// Map a VeraCrypt encryption-algorithm ID (`ea`) to `CipherType`.
///
/// VeraCrypt EA values:
/// - 0x01-0x05: single ciphers (AES, Serpent, Twofish, Camellia, Kuznyechik)
/// - 0x11-0x1A: cipher cascades (various 2- and 3-cipher combinations)
///
/// Returns `None` for unknown EA values.
pub fn cipher_type_from_ea(ea: u32) -> Option<CipherType> {
    match ea {
        0x01 => Some(CipherType::Aes),
        0x02 => Some(CipherType::Serpent),
        0x03 => Some(CipherType::Twofish),
        0x04 => Some(CipherType::Camellia),
        0x05 => Some(CipherType::Kuznyechik),
        0x11 => Some(CipherType::AesTwofish),
        0x12 => Some(CipherType::AesTwofishSerpent),
        0x13 => Some(CipherType::SerpentAes),
        0x14 => Some(CipherType::SerpentTwofishAes),
        0x15 => Some(CipherType::TwofishSerpent),
        0x16 => Some(CipherType::CamelliaKuznyechik),
        0x17 => Some(CipherType::CamelliaSerpent),
        0x18 => Some(CipherType::KuznyechikAes),
        0x19 => Some(CipherType::KuznyechikSerpentCamellia),
        0x1A => Some(CipherType::KuznyechikTwofish),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_single_ciphers() {
        assert_eq!(cipher_type_from_ea(0x01), Some(CipherType::Aes));
        assert_eq!(cipher_type_from_ea(0x02), Some(CipherType::Serpent));
        assert_eq!(cipher_type_from_ea(0x03), Some(CipherType::Twofish));
        assert_eq!(cipher_type_from_ea(0x04), Some(CipherType::Camellia));
        assert_eq!(cipher_type_from_ea(0x05), Some(CipherType::Kuznyechik));
    }

    #[test]
    fn test_all_cascades() {
        assert_eq!(cipher_type_from_ea(0x11), Some(CipherType::AesTwofish));
        assert_eq!(
            cipher_type_from_ea(0x12),
            Some(CipherType::AesTwofishSerpent)
        );
        assert_eq!(cipher_type_from_ea(0x13), Some(CipherType::SerpentAes));
        assert_eq!(
            cipher_type_from_ea(0x14),
            Some(CipherType::SerpentTwofishAes)
        );
        assert_eq!(cipher_type_from_ea(0x15), Some(CipherType::TwofishSerpent));
        assert_eq!(
            cipher_type_from_ea(0x16),
            Some(CipherType::CamelliaKuznyechik)
        );
        assert_eq!(
            cipher_type_from_ea(0x17),
            Some(CipherType::CamelliaSerpent)
        );
        assert_eq!(cipher_type_from_ea(0x18), Some(CipherType::KuznyechikAes));
        assert_eq!(
            cipher_type_from_ea(0x19),
            Some(CipherType::KuznyechikSerpentCamellia)
        );
        assert_eq!(
            cipher_type_from_ea(0x1A),
            Some(CipherType::KuznyechikTwofish)
        );
    }

    #[test]
    fn test_unknown_ea_returns_none() {
        assert_eq!(cipher_type_from_ea(0x00), None);
        assert_eq!(cipher_type_from_ea(0x06), None);
        assert_eq!(cipher_type_from_ea(0x10), None);
        assert_eq!(cipher_type_from_ea(0x1B), None);
        assert_eq!(cipher_type_from_ea(0xFF), None);
        assert_eq!(cipher_type_from_ea(u32::MAX), None);
    }

    #[test]
    fn test_known_ea_count() {
        // There are exactly 15 known EA values (5 single + 10 cascades)
        let mut count = 0u32;
        for ea in 0..=0xFF {
            if cipher_type_from_ea(ea).is_some() {
                count += 1;
            }
        }
        assert_eq!(count, 15);
    }
}
