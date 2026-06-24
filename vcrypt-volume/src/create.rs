//! Volume creation — generate keys, header, write encrypted volume

use super::error::{VolResult, VolumeError};
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::{KdfAlgorithm, KeyDerivation};
use vcrypt_core::rng;
use vcrypt_format::header::{MASTER_KEYDATA_SIZE, VolumeHeader, VOLUME_HEADER_SIZE};
use std::io::{Seek, SeekFrom, Write};

const MAX_HEADER_KEY_SIZE: usize = 192;

/// Create a new encrypted volume file with explicit cipher and KDF.
pub fn create_volume_full(
    file: &mut (impl Write + Seek),
    volume_size: u64,
    password: &[u8],
    cipher: CipherType,
    kdf: &dyn KeyDerivation,
    _kdf_type: KdfAlgorithm,
    iterations: u32,
    _memory_cost_kib: Option<u32>,
) -> VolResult<()> {
    let salt = rng::random_salt()
        .map_err(|e| VolumeError::CryptoError(format!("salt: {}", e)))?;

    let key_bytes = cipher.key_size() * 2;
    let master_key = rng::random_bytes(key_bytes)
        .map_err(|e| VolumeError::CryptoError(format!("key: {}", e)))?;

    let mut header = VolumeHeader::new();
    header.salt = salt;
    header.volume_size = volume_size;
    header.encrypted_area_start = (VOLUME_HEADER_SIZE * 4) as u64;
    header.encrypted_area_length = volume_size;
    // Clear master_keydata then copy key into first N bytes (rest stays zero)
    header.master_keydata = vec![0u8; MASTER_KEYDATA_SIZE];
    header.master_keydata[..key_bytes].copy_from_slice(&master_key);

    let mut hdr_bytes = vcrypt_format::ser::serialize_header_full(&header)
        .map_err(|e| VolumeError::FormatError(format!("ser: {}", e)))?;

    // Derive header key at max size (matching VeraCrypt's GetHeaderKeyDerivationSize).
    // Argon2id output depends on output length, so this must match what VeraCrypt uses
    // during open (always 192 bytes). PBKDF2 is prefix-consistent so this works for both.
    let mut max_key = vec![0u8; MAX_HEADER_KEY_SIZE];
    kdf.derive(password, &salt, iterations, &mut max_key)
        .map_err(|e| VolumeError::CryptoError(format!("KDF: {}", e)))?;
    let header_key = &max_key[..cipher.key_size() * 2];

    vcrypt_format::encrypt::encrypt_header_area(
        &mut hdr_bytes[..vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE],
        &header_key,
        cipher,
    ).map_err(|e| VolumeError::FormatError(format!("enc: {}", e)))?;

    file.write_all(&hdr_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;

    // Write backup header at end of file
    let pos = file.seek(SeekFrom::End(0))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("seek: {}", e) })?;
    let backup_offset = pos.saturating_sub(2 * VOLUME_HEADER_SIZE as u64);
    file.seek(SeekFrom::Start(backup_offset))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("seek: {}", e) })?;
    file.write_all(&hdr_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;

    Ok(())
}

/// Simplified create for PBKDF2 + AES (backward compat).
pub fn create_volume(
    file: &mut (impl Write + Seek),
    volume_size: u64,
    password: &[u8],
    kdf: &dyn KeyDerivation,
    kdf_type: KdfAlgorithm,
    iterations: u32,
) -> VolResult<()> {
    create_volume_full(file, volume_size, password, CipherType::Aes, kdf, kdf_type, iterations, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open::{open_volume_file_with_kdf, open_volume_with_iters};
    use vcrypt_core::kdf::{Argon2idKdf, Pbkdf2Sha256};

    #[test]
    fn test_create_and_open() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        f.set_len(VOLUME_HEADER_SIZE as u64 * 4).unwrap();
        create_volume(&mut f, 0, b"test", &Pbkdf2Sha256, KdfAlgorithm::Pbkdf2Sha256, 100).unwrap();
        let data = std::fs::read(tmp.path()).unwrap();
        assert!(open_volume_with_iters(&data, b"test", 100).is_ok());
        assert!(open_volume_with_iters(&data, b"wrong", 100).is_err());
    }

    #[test]
    fn test_create_cascade_argon2_roundtrip() {
        let kdf = Argon2idKdf::default();
        let pim = 1;

        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        let vol_size = 1024 * 1024; // 1 MiB
        let header_total = VOLUME_HEADER_SIZE as u64 * 4; // 256 KiB headers
        f.set_len(vol_size + header_total).unwrap();

        create_volume_full(
            &mut f,
            vol_size,
            b"test1234",
            CipherType::AesTwofish,
            &kdf,
            KdfAlgorithm::Argon2id,
            3,
            Some(65536),
        )
        .unwrap();

        let result = open_volume_file_with_kdf(
            tmp.path().to_str().unwrap(),
            b"test1234",
            &[],
            KdfAlgorithm::Argon2id,
            pim,
        )
        .unwrap();

        assert_eq!(result.kdf, KdfAlgorithm::Argon2id);
        assert_eq!(result.header_cipher, CipherType::AesTwofish);
        assert_eq!(result.data_cipher, CipherType::AesTwofish);
        assert_eq!(result.master_key.len(), 128);
    }
}
