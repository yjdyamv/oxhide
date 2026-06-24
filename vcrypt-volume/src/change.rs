//! Change volume password — re-encrypts headers with a new password/keyfiles/KDF/PIM.
//!
//! The master key (and thus all volume data) is NOT modified.
//! Only the header encryption key is changed, matching VeraCrypt's behaviour
//! (see CoreBase::ChangePassword in src/Core/CoreBase.cpp).

use crate::error::{VolResult, VolumeError};
use crate::open::OpenResult;
use std::io::{Read, Seek, SeekFrom, Write};
use vcrypt_core::kdf::{self, Argon2idKdf, KdfAlgorithm, KeyDerivation};
use vcrypt_format::encrypt::encrypt_header_area;
use vcrypt_format::header::{PKCS5_SALT_SIZE, VOLUME_HEADER_SIZE};

const MAX_HEADER_KEY_SIZE: usize = 192;

/// Change the password/keyfiles/KDF/PIM of an open volume.
///
/// Writes both the primary and backup headers with new credentials.
/// The master key (data encryption) is preserved.
pub fn change_volume_password(
    file: &mut (impl Read + Write + Seek),
    open_result: &OpenResult,
    new_password: &[u8],
    new_keyfiles: &[&str],
    new_kdf: KdfAlgorithm,
    new_pim: i32,
) -> VolResult<()> {
    // 1. Generate new salt
    let mut new_salt = [0u8; PKCS5_SALT_SIZE];
    vcrypt_core::rng::fill_random(&mut new_salt)
        .map_err(|e| VolumeError::CryptoError(format!("rng: {}", e)))?;

    // 2. Combine password with keyfiles
    let mut pw_bytes = new_password.to_vec();
    if !new_keyfiles.is_empty() {
        vcrypt_format::keyfile::apply_keyfiles(&mut pw_bytes, new_keyfiles)
            .map_err(|e| VolumeError::CryptoError(format!("keyfile: {}", e)))?;
    }

    // 3. Derive new header key (MAX_HEADER_KEY_SIZE = 192 bytes)
    let (kdf_impl, iterations, memory_cost_kib): (Box<dyn KeyDerivation>, u32, Option<u32>) =
        match new_kdf {
            KdfAlgorithm::Argon2id => {
                let (mem, t) = Argon2idKdf::params_for_pim(new_pim);
                (Box::new(Argon2idKdf::new(mem, t, 1)), t, Some(mem))
            }
            _ => {
                let imp: Box<dyn KeyDerivation> = kdf_box(new_kdf);
                let iters = imp.get_iteration_count(new_pim);
                (imp, iters, None)
            }
        };

    let mut header_key = vec![0u8; MAX_HEADER_KEY_SIZE];
    kdf_impl
        .derive(&pw_bytes, &new_salt, iterations, &mut header_key)
        .map_err(|e| VolumeError::CryptoError(format!("derive: {}", e)))?;

    let header_cipher_xts_key_size = open_result.header_cipher.key_size() * 2;
    let effective_key = &header_key[..header_cipher_xts_key_size];

    // 4. Re-serialize the header with the same VolumeHeader fields
    //    (master_keydata is preserved from open_result)
    let mut header_buf = vec![0u8; VOLUME_HEADER_SIZE];
    header_buf[..PKCS5_SALT_SIZE].copy_from_slice(&new_salt);

    let plaintext = vcrypt_format::ser::serialize_header(&open_result.header)
        .map_err(|e| VolumeError::FormatError(format!("serialize: {}", e)))?;
    // copy only the encrypted area (bytes 64..512), skip the salt
    header_buf[PKCS5_SALT_SIZE..512].copy_from_slice(&plaintext[PKCS5_SALT_SIZE..]);

    // 5. Encrypt header area with new key
    encrypt_header_area(&mut header_buf[..512], effective_key, open_result.header_cipher)
        .map_err(|e| VolumeError::CryptoError(format!("encrypt: {}", e)))?;

    // 6. Write backup header first — if this fails, primary stays intact
    let file_end = file.seek(SeekFrom::End(0))
        .map_err(|e| VolumeError::IoError(e))?;
    if file_end < 4 * VOLUME_HEADER_SIZE as u64 {
        return Err(VolumeError::InvalidFormat(
            "Volume file too small for header backup".into(),
        ));
    }
    let backup_offset = file_end - 2 * VOLUME_HEADER_SIZE as u64;
    file.seek(SeekFrom::Start(backup_offset))
        .map_err(|e| VolumeError::IoError(e))?;
    file.write_all(&header_buf)
        .map_err(|e| VolumeError::IoError(e))?;
    file.flush()
        .map_err(|e| VolumeError::IoError(e))?;

    // 7. Write primary header (offset 0)
    file.seek(SeekFrom::Start(0))
        .map_err(|e| VolumeError::IoError(e))?;
    file.write_all(&header_buf)
        .map_err(|e| VolumeError::IoError(e))?;
    file.flush()
        .map_err(|e| VolumeError::IoError(e))?;

    let _ = (iterations, memory_cost_kib); // used in structured logging below
    log::info!(
        "Password changed: KDF={} PIM={} iters={}",
        new_kdf.name(), new_pim, iterations,
    );

    Ok(())
}

fn kdf_box(kdf: KdfAlgorithm) -> Box<dyn KeyDerivation> {
    match kdf {
        KdfAlgorithm::Pbkdf2Sha512 => Box::new(kdf::Pbkdf2Sha512),
        KdfAlgorithm::Pbkdf2Sha256 => Box::new(kdf::Pbkdf2Sha256),
        KdfAlgorithm::Pbkdf2Blake2s => Box::new(kdf::Pbkdf2Blake2s),
        KdfAlgorithm::Pbkdf2Whirlpool => Box::new(kdf::Pbkdf2Whirlpool),
        KdfAlgorithm::Pbkdf2Streebog => Box::new(kdf::Pbkdf2Streebog),
        KdfAlgorithm::Argon2id => unreachable!("Argon2id handled in caller"),
    }
}
