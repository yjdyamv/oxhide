//! Header backup/restore — recovers a corrupted primary header from the backup.
//!
//! VeraCrypt V2 stores a backup header at file_end - 2*VOLUME_HEADER_SIZE.
//! This module reads the backup, validates it with the given credentials,
//! and writes it to the primary header position (offset 0).
//!
//! See src/Volume/VolumeLayout.cpp VolumeLayoutV2Normal::BackupHeaderOffset = -TC_VOLUME_HEADER_GROUP_SIZE.

use crate::error::{VolResult, VolumeError};
use crate::open::{self, make_kdf_candidate};
use std::io::{Read, Seek, SeekFrom, Write};
use vcrypt_core::kdf::KdfAlgorithm;
use vcrypt_format::header::VOLUME_HEADER_SIZE;

/// Restore the primary volume header from its backup copy.
///
/// Returns Ok(()) if the backup header was successfully validated and written.
pub fn restore_volume_header(
    file: &mut (impl Read + Write + Seek),
    password: &[u8],
    keyfiles: &[&str],
    kdf: Option<KdfAlgorithm>,
    pim: Option<i32>,
) -> VolResult<()> {
    let file_end = file
        .seek(SeekFrom::End(0))
        .map_err(|e| VolumeError::IoError(e))?;

    if file_end < 2 * VOLUME_HEADER_SIZE as u64 {
        return Err(VolumeError::InvalidFormat(
            "File too small to contain a backup header".into(),
        ));
    }

    let backup_offset = file_end - 2 * VOLUME_HEADER_SIZE as u64;

    // Read backup header
    let mut backup_header = vec![0u8; VOLUME_HEADER_SIZE];
    file.seek(SeekFrom::Start(backup_offset))
        .map_err(|e| VolumeError::IoError(e))?;
    file.read_exact(&mut backup_header)
        .map_err(|e| VolumeError::IoError(e))?;

    // Mix keyfiles
    let mut pw = password.to_vec();
    if !keyfiles.is_empty() {
        vcrypt_format::keyfile::apply_keyfiles(&mut pw, keyfiles)
            .map_err(|e| VolumeError::CryptoError(format!("keyfile: {}", e)))?;
    }

    // Validate backup header
    let effective = &backup_header[..vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE];

    if let Some(k) = kdf {
        let pim_val = pim.unwrap_or(0);
        let candidate = make_kdf_candidate(k, pim_val);
        open::try_open(effective, &pw, &[candidate], true)?;
    } else {
        let candidates = open::auto_kdf_candidates(pim);
        open::try_open(effective, &pw, &candidates, true)?;
    }

    // Validation passed — write to primary header position
    file.seek(SeekFrom::Start(0))
        .map_err(|e| VolumeError::IoError(e))?;
    file.write_all(&backup_header)
        .map_err(|e| VolumeError::IoError(e))?;
    file.flush()
        .map_err(|e| VolumeError::IoError(e))?;

    // Refresh backup header — best-effort, primary is already restored
    let _ = file.seek(SeekFrom::Start(backup_offset))
        .and_then(|_| file.write_all(&backup_header))
        .and_then(|_| file.flush());

    log::info!("Header restored: backup -> primary at offset 0");
    Ok(())
}
