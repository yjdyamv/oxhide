//! Volume header encryption/decryption with XTS-AES

use super::header::{PKCS5_SALT_SIZE, VOLUME_HEADER_EFFECTIVE_SIZE};
use super::error::{FormatError, FormatResult};
use vcrypt_core::ciphers::{
    AesCipher, CamelliaCipher, CascadeMode, CipherType, KuznyechikCipher,
    SerpentCipher, TwofishCipher,
};
use vcrypt_core::kdf::KeyDerivation;
use vcrypt_core::xts::XtsMode;

/// Derive header key from password + salt via PBKDF2
pub fn derive_header_key(
    kdf: &dyn KeyDerivation,
    password: &[u8],
    salt: &[u8; PKCS5_SALT_SIZE],
    iterations: u32,
    cipher: CipherType,
) -> FormatResult<Vec<u8>> {
    let mut key = vec![0u8; cipher.key_size() * 2];
    kdf.derive(password, salt, iterations, &mut key)
        .map_err(|e| FormatError::CryptoError(format!("KDF: {}", e)))?;
    Ok(key)
}

/// Decrypt encrypted area (bytes 64-511) using the provided XTS cipher.
pub fn decrypt_header_area(data: &mut [u8], key: &[u8], cipher: CipherType) -> FormatResult<()> {
    if data.len() < VOLUME_HEADER_EFFECTIVE_SIZE {
        return Err(FormatError::InvalidHeaderSize { expected: VOLUME_HEADER_EFFECTIVE_SIZE, actual: data.len() });
    }
    apply_xts(cipher, key, &mut data[PKCS5_SALT_SIZE..VOLUME_HEADER_EFFECTIVE_SIZE], false)
}

/// Encrypt encrypted area (bytes 64-511) using the provided XTS cipher.
pub fn encrypt_header_area(data: &mut [u8], key: &[u8], cipher: CipherType) -> FormatResult<()> {
    if data.len() < VOLUME_HEADER_EFFECTIVE_SIZE {
        return Err(FormatError::InvalidHeaderSize { expected: VOLUME_HEADER_EFFECTIVE_SIZE, actual: data.len() });
    }
    apply_xts(cipher, key, &mut data[PKCS5_SALT_SIZE..VOLUME_HEADER_EFFECTIVE_SIZE], true)
}

fn apply_xts(cipher: CipherType, key: &[u8], encrypted_area: &mut [u8], encrypt: bool) -> FormatResult<()> {
    let expected_key_len = cipher.key_size() * 2;
    if key.len() != expected_key_len {
        return Err(FormatError::CryptoError(format!("Bad key size for {}: expected {}, got {}", cipher.name(), expected_key_len, key.len())));
    }

    match cipher {
        CipherType::Aes => apply_xts_single::<AesCipher>(key, encrypted_area, encrypt, AesCipher::new),
        CipherType::Serpent => apply_xts_single::<SerpentCipher>(key, encrypted_area, encrypt, SerpentCipher::new),
        CipherType::Twofish => apply_xts_single::<TwofishCipher>(key, encrypted_area, encrypt, TwofishCipher::new),
        CipherType::Camellia => apply_xts_single::<CamelliaCipher>(key, encrypted_area, encrypt, CamelliaCipher::new),
        CipherType::Kuznyechik => apply_xts_single::<KuznyechikCipher>(key, encrypted_area, encrypt, KuznyechikCipher::new),
        CipherType::AesTwofish => apply_xts_cascade(CascadeMode::AesTwofish, key, encrypted_area, encrypt),
        CipherType::AesTwofishSerpent => apply_xts_cascade(CascadeMode::AesTwofishSerpent, key, encrypted_area, encrypt),
        CipherType::SerpentAes => apply_xts_cascade(CascadeMode::SerpentAes, key, encrypted_area, encrypt),
        CipherType::SerpentTwofishAes => apply_xts_cascade(CascadeMode::SerpentTwofishAes, key, encrypted_area, encrypt),
        CipherType::TwofishSerpent => apply_xts_cascade(CascadeMode::TwofishSerpent, key, encrypted_area, encrypt),
    }
}

fn apply_xts_single<C>(
    key: &[u8],
    encrypted_area: &mut [u8],
    encrypt: bool,
    ctor: impl Fn(&[u8]) -> vcrypt_core::Result<C>,
) -> FormatResult<()>
where
    C: vcrypt_core::ciphers::BlockCipher,
{
    let xts = XtsMode::new(key, ctor)
        .map_err(|e| FormatError::CryptoError(format!("XTS: {}", e)))?;
    if encrypt {
        xts.encrypt(0, encrypted_area)
            .map_err(|e| FormatError::EncryptionFailed(format!("{}", e)))
    } else {
        xts.decrypt(0, encrypted_area)
            .map_err(|e| FormatError::DecryptionFailed(format!("{}", e)))
    }
}

fn apply_xts_cascade(
    mode: CascadeMode,
    key: &[u8],
    encrypted_area: &mut [u8],
    encrypt: bool,
) -> FormatResult<()> {
    let single_key_len = mode.key_size();
    if key.len() != single_key_len * 2 {
        return Err(FormatError::CryptoError(format!(
            "Bad key size for {}: expected {}, got {}",
            mode.name(),
            single_key_len * 2,
            key.len()
        )));
    }

    let data_half = &key[..single_key_len];
    let tweak_half = &key[single_key_len..];
    let order = mode.veracrypt_order();

    if encrypt {
        for (ct, offset) in &order {
            let combined: Vec<u8> = data_half[*offset..*offset + 32]
                .iter()
                .chain(&tweak_half[*offset..*offset + 32])
                .copied()
                .collect();
            apply_xts_pass(*ct, &combined, encrypted_area, true)?;
        }
    } else {
        for (ct, offset) in order.iter().rev() {
            let combined: Vec<u8> = data_half[*offset..*offset + 32]
                .iter()
                .chain(&tweak_half[*offset..*offset + 32])
                .copied()
                .collect();
            apply_xts_pass(*ct, &combined, encrypted_area, false)?;
        }
    }

    Ok(())
}

fn apply_xts_pass(
    ct: CipherType,
    key: &[u8],
    data: &mut [u8],
    encrypt: bool,
) -> FormatResult<()> {
    match ct {
        CipherType::Aes => apply_xts_single::<AesCipher>(key, data, encrypt, AesCipher::new),
        CipherType::Serpent => apply_xts_single::<SerpentCipher>(key, data, encrypt, SerpentCipher::new),
        CipherType::Twofish => apply_xts_single::<TwofishCipher>(key, data, encrypt, TwofishCipher::new),
        CipherType::Camellia => apply_xts_single::<CamelliaCipher>(key, data, encrypt, CamelliaCipher::new),
        CipherType::Kuznyechik => apply_xts_single::<KuznyechikCipher>(key, data, encrypt, KuznyechikCipher::new),
        _ => Err(FormatError::CryptoError(format!(
            "Cascade component must be a single cipher: {}",
            ct.name()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vcrypt_core::ciphers::CipherType;
    use vcrypt_core::kdf::Pbkdf2Sha256;

    #[test]
    fn test_roundtrip() {
        let salt = [0xAB; PKCS5_SALT_SIZE];
        let key = derive_header_key(&Pbkdf2Sha256, b"password", &salt, 100, CipherType::Aes).unwrap();
        let mut header = vec![0u8; VOLUME_HEADER_EFFECTIVE_SIZE];
        header[..PKCS5_SALT_SIZE].copy_from_slice(&salt);
        header[PKCS5_SALT_SIZE..PKCS5_SALT_SIZE + 4].copy_from_slice(&0x56455241u32.to_be_bytes());
        let orig = header.clone();
        encrypt_header_area(&mut header, &key, CipherType::Aes).unwrap();
        assert_ne!(&header[PKCS5_SALT_SIZE..], &orig[PKCS5_SALT_SIZE..]);
        decrypt_header_area(&mut header, &key, CipherType::Aes).unwrap();
        assert_eq!(header, orig);
    }

    #[test]
    fn test_cascade_roundtrip() {
        let salt = [0xCD; PKCS5_SALT_SIZE];
        let cipher = CipherType::AesTwofishSerpent;
        let key = derive_header_key(&Pbkdf2Sha256, b"password", &salt, 25, cipher).unwrap();
        let mut header = vec![0u8; VOLUME_HEADER_EFFECTIVE_SIZE];
        header[..PKCS5_SALT_SIZE].copy_from_slice(&salt);
        header[PKCS5_SALT_SIZE..PKCS5_SALT_SIZE + 4].copy_from_slice(&0x56455241u32.to_be_bytes());
        let orig = header.clone();
        encrypt_header_area(&mut header, &key, cipher).unwrap();
        decrypt_header_area(&mut header, &key, cipher).unwrap();
        assert_eq!(header, orig);
    }
}
