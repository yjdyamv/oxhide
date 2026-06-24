//! Volume creation — generate keys, header, write encrypted volume

use super::error::{VolResult, VolumeError};
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::{KdfAlgorithm, KeyDerivation};
use vcrypt_core::rng;
use vcrypt_format::header::{MASTER_KEYDATA_SIZE, VolumeHeader, VOLUME_HEADER_SIZE};
use std::io::{Seek, SeekFrom, Write};

const MAX_HEADER_KEY_SIZE: usize = 192;

/// Progress callback type for volume creation.
pub type ProgressFn = Box<dyn Fn(&str) + Send>;

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
    progress: Option<&ProgressFn>,
) -> VolResult<()> {
    if let Some(p) = progress {
        p("Generating salt...");
    }
    let salt = rng::random_salt()
        .map_err(|e| VolumeError::CryptoError(format!("salt: {}", e)))?;

    let key_bytes = cipher.key_size() * 2;
    if let Some(p) = progress {
        p("Generating master key...");
    }
    let master_key = rng::random_bytes(key_bytes)
        .map_err(|e| VolumeError::CryptoError(format!("key: {}", e)))?;

    let mut header = VolumeHeader::new();
    header.salt = salt;
    header.volume_size = volume_size;
    header.encrypted_area_start = (VOLUME_HEADER_SIZE * 4) as u64;
    header.encrypted_area_length = volume_size;
    header.master_keydata = vec![0u8; MASTER_KEYDATA_SIZE];
    header.master_keydata[..key_bytes].copy_from_slice(&master_key);

    let mut hdr_bytes = vcrypt_format::ser::serialize_header_full(&header)
        .map_err(|e| VolumeError::FormatError(format!("ser: {}", e)))?;

    if let Some(p) = progress {
        p(&format!("Deriving header key ({} iterations)...", iterations));
    }
    let mut max_key = vec![0u8; MAX_HEADER_KEY_SIZE];
    kdf.derive(password, &salt, iterations, &mut max_key)
        .map_err(|e| VolumeError::CryptoError(format!("KDF: {}", e)))?;
    let header_key = &max_key[..cipher.key_size() * 2];

    if let Some(p) = progress {
        p("Encrypting header...");
    }
    vcrypt_format::encrypt::encrypt_header_area(
        &mut hdr_bytes[..vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE],
        &header_key,
        cipher,
    ).map_err(|e| VolumeError::FormatError(format!("enc: {}", e)))?;

    if let Some(p) = progress {
        p("Writing primary header...");
    }
    file.write_all(&hdr_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;

    if let Some(p) = progress {
        p("Writing backup header...");
    }
    let pos = file.seek(SeekFrom::End(0))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("seek: {}", e) })?;
    let backup_offset = pos.saturating_sub(2 * VOLUME_HEADER_SIZE as u64);
    file.seek(SeekFrom::Start(backup_offset))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("seek: {}", e) })?;
    file.write_all(&hdr_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;

    if let Some(p) = progress {
        p("Volume created successfully.");
    }

    // Write anti-forensic decoy hidden headers (per VeraCrypt V2 standard)
    write_decoy_header(file, cipher, progress)?;

    Ok(())
}

/// Write a decoy hidden header with random credentials to the hidden header slot.
/// This makes it impossible to determine whether a hidden volume exists.
fn write_decoy_header(
    file: &mut (impl Write + Seek),
    cipher: CipherType,
    progress: Option<&ProgressFn>,
) -> VolResult<()> {
    if let Some(p) = progress {
        p("Writing anti-forensic decoy headers...");
    }

    let decoy_salt = rng::random_salt()
        .map_err(|e| VolumeError::CryptoError(format!("decoy salt: {}", e)))?;
    let key_bytes = cipher.key_size() * 2;
    let decoy_key = rng::random_bytes(key_bytes)
        .map_err(|e| VolumeError::CryptoError(format!("decoy key: {}", e)))?;

    let mut decoy = VolumeHeader::new();
    decoy.salt = decoy_salt;
    decoy.hidden_volume_size = 0xDEADBEEF_DEADBEEFu64; // looks like hidden volume
    decoy.master_keydata = vec![0u8; MASTER_KEYDATA_SIZE];
    decoy.master_keydata[..key_bytes].copy_from_slice(&decoy_key);

    let mut decoy_bytes = vcrypt_format::ser::serialize_header_full(&decoy)
        .map_err(|e| VolumeError::FormatError(format!("decoy ser: {}", e)))?;

    // Encrypt with a random key (nobody can open this)
    let decoy_header_key = rng::random_bytes(cipher.key_size() * 2)
        .map_err(|e| VolumeError::CryptoError(format!("decoy hdr key: {}", e)))?;
    vcrypt_format::encrypt::encrypt_header_area(
        &mut decoy_bytes[..vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE],
        &decoy_header_key,
        cipher,
    ).map_err(|e| VolumeError::FormatError(format!("decoy enc: {}", e)))?;

    // Write at hidden header slot (offset 65536)
    file.seek(SeekFrom::Start(VOLUME_HEADER_SIZE as u64))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("decoy seek: {}", e) })?;
    file.write_all(&decoy_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("decoy write: {}", e) })?;

    // Write decoy backup at file_end - 65536
    let file_end = file.seek(SeekFrom::End(0))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("decoy seek: {}", e) })?;
    let decoy_backup = file_end.saturating_sub(VOLUME_HEADER_SIZE as u64);
    file.seek(SeekFrom::Start(decoy_backup))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("decoy seek: {}", e) })?;
    file.write_all(&decoy_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("decoy write: {}", e) })?;

    Ok(())
}

/// Create a hidden volume inside an existing outer (normal) volume file.
///
/// The hidden volume occupies the tail end of the file, starting at:
///   `file_end - 2 * VOLUME_HEADER_SIZE - hidden_size`
///
/// Headers are written at the hidden header slots (offset 65536 and file_end - 65536).
pub fn create_hidden_volume(
    file: &mut (impl Write + Seek),
    hidden_size: u64,
    password: &[u8],
    cipher: CipherType,
    kdf: &dyn KeyDerivation,
    _kdf_type: KdfAlgorithm,
    iterations: u32,
    _memory_cost_kib: Option<u32>,
    progress: Option<&ProgressFn>,
) -> VolResult<()> {
    let file_end = file.seek(SeekFrom::End(0))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("seek: {}", e) })?;

    let header_area = 2 * VOLUME_HEADER_SIZE as u64;
    if file_end < header_area + hidden_size {
        return Err(VolumeError::InvalidFormat(format!(
            "File too small: need at least {} bytes for {} byte hidden volume",
            header_area + hidden_size, hidden_size
        )));
    }

    if let Some(p) = progress {
        p("Generating salt...");
    }
    let salt = rng::random_salt()
        .map_err(|e| VolumeError::CryptoError(format!("salt: {}", e)))?;

    let key_bytes = cipher.key_size() * 2;
    if let Some(p) = progress {
        p("Generating master key...");
    }
    let master_key = rng::random_bytes(key_bytes)
        .map_err(|e| VolumeError::CryptoError(format!("key: {}", e)))?;

    // Hidden volume data occupies the tail, before backup headers
    let data_start = file_end - header_area - hidden_size;

    let mut header = VolumeHeader::new();
    header.salt = salt;
    header.volume_size = hidden_size;
    header.hidden_volume_size = hidden_size; // marks this as a hidden volume!
    header.encrypted_area_start = data_start;
    header.encrypted_area_length = hidden_size;
    header.master_keydata = vec![0u8; MASTER_KEYDATA_SIZE];
    header.master_keydata[..key_bytes].copy_from_slice(&master_key);

    let mut hdr_bytes = vcrypt_format::ser::serialize_header_full(&header)
        .map_err(|e| VolumeError::FormatError(format!("ser: {}", e)))?;

    if let Some(p) = progress {
        p(&format!("Deriving header key ({} iterations)...", iterations));
    }
    let mut max_key = vec![0u8; MAX_HEADER_KEY_SIZE];
    kdf.derive(password, &salt, iterations, &mut max_key)
        .map_err(|e| VolumeError::CryptoError(format!("KDF: {}", e)))?;
    let header_key = &max_key[..cipher.key_size() * 2];

    if let Some(p) = progress {
        p("Encrypting header...");
    }
    vcrypt_format::encrypt::encrypt_header_area(
        &mut hdr_bytes[..vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE],
        &header_key,
        cipher,
    ).map_err(|e| VolumeError::FormatError(format!("enc: {}", e)))?;

    // Write primary hidden header at offset 65536
    if let Some(p) = progress {
        p("Writing hidden header...");
    }
    file.seek(SeekFrom::Start(VOLUME_HEADER_SIZE as u64))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;
    file.write_all(&hdr_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;

    // Write backup hidden header at file_end - 65536
    if let Some(p) = progress {
        p("Writing backup hidden header...");
    }
    let backup_offset = file_end - VOLUME_HEADER_SIZE as u64;
    file.seek(SeekFrom::Start(backup_offset))
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;
    file.write_all(&hdr_bytes)
        .map_err(|e| VolumeError::WriteError { sector: 0, msg: format!("write: {}", e) })?;

    if let Some(p) = progress {
        p("Hidden volume created successfully.");
    }
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
    create_volume_full(file, volume_size, password, CipherType::Aes, kdf, kdf_type, iterations, None, None)
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
            None,
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
