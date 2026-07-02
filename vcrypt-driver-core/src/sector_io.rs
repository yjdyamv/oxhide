//! Sector-aligned encrypted I/O primitives.
//!
//! Extracted from `vcrypt-driver/src/encrypted_io_queue.rs`.  Provides the pure
//! algorithmic core of the READ/WRITE pipeline (alignment math + XTS
//! encrypt/decrypt loops) decoupled from WDK FFI calls.
//!
//! The callers (kernel driver or test harness) are responsible for:
//! - Allocating sector-aligned buffers
//! - Performing the actual host-file I/O (via `ZwReadFile`/`ZwWriteFile` or a
//!   memory-backed mock)
//! - Copying data to/from the user buffer (MDL or SystemBuffer)

use vcrypt_core::KernelSectorCipher;

/// Encryption data unit size (sector size for XTS mode).
pub const ENCRYPTION_DATA_UNIT_SIZE: u64 = 512;

/// Error type for sector I/O parameter computation.
#[derive(Debug, PartialEq, Eq)]
pub enum SectorIoError {
    /// The requested virtual offset + length exceeds the disk length.
    OutOfBounds,
    /// The length is zero (no-op, caller should handle gracefully).
    ZeroLength,
    /// The computed aligned length is not a multiple of 512.
    InvalidAlignment,
}

/// Parameters describing a sector-aligned I/O operation.
///
/// Callers use [`compute_sector_io_params`] to populate this from raw
/// virtual-offset/length values, then perform host I/O and encryption.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SectorIoParams {
    /// Offset in the host file where aligned I/O starts (always 512-byte aligned).
    pub aligned_host_offset: u64,
    /// Number of bytes to read/write at the host level (always a multiple of 512).
    pub aligned_length: u64,
    /// Offset within the aligned buffer where user data starts.
    pub user_data_offset: usize,
    /// Number of user-data bytes (may be less than `aligned_length` for partial
    /// sectors).
    pub user_data_length: usize,
    /// Total number of 512-byte sectors in the aligned buffer.
    pub sector_count: usize,
    /// XTS sector index of the first sector in the aligned buffer.
    pub first_sector_index: u64,
}

/// Compute the sector I/O parameters for a read or write operation.
///
/// Takes raw virtual-offset / length values and returns the aligned parameters
/// needed to perform a sector-aligned host I/O + XTS encrypt/decrypt.
///
/// # Arguments
/// * `vol_data_area_offset` — offset from the start of the host file to the
///   first byte of the encrypted volume data area.
/// * `first_data_unit_no` — XTS data-unit number of the first sector
///   (0 for file-hosted volumes).
/// * `virtual_offset` — byte offset within the virtual disk.
/// * `length` — number of bytes to read/write.
/// * `disk_length` — total virtual disk size in bytes.
pub fn compute_sector_io_params(
    vol_data_area_offset: u64,
    first_data_unit_no: u64,
    virtual_offset: u64,
    length: u64,
    disk_length: u64,
) -> Result<SectorIoParams, SectorIoError> {
    if length == 0 {
        return Err(SectorIoError::ZeroLength);
    }
    if virtual_offset + length > disk_length {
        return Err(SectorIoError::OutOfBounds);
    }

    let host_offset = vol_data_area_offset + virtual_offset;
    let unit = ENCRYPTION_DATA_UNIT_SIZE;

    // Align down to the nearest sector boundary
    let aligned_off = (host_offset / unit) * unit;
    // Align up to the nearest sector boundary
    let end_byte = host_offset + length;
    let aligned_end = ((end_byte + unit - 1) / unit) * unit;

    let buf_size = (aligned_end - aligned_off) as usize;
    let sector_count = buf_size / unit as usize;
    let user_off = (host_offset - aligned_off) as usize;

    // Verify alignment invariants
    if buf_size % unit as usize != 0 {
        return Err(SectorIoError::InvalidAlignment);
    }

    let base_unit = first_data_unit_no + (aligned_off - vol_data_area_offset) / unit;

    Ok(SectorIoParams {
        aligned_host_offset: aligned_off,
        aligned_length: buf_size as u64,
        user_data_offset: user_off,
        user_data_length: length as usize,
        sector_count,
        first_sector_index: base_unit,
    })
}

/// Encrypt `sector_count` sectors in `data` using XTS mode.
///
/// `data` must be at least `sector_count * 512` bytes.  Each 512-byte chunk
/// is encrypted sequentially with the corresponding `first_sector_index + i`
/// as the XTS tweak.
///
/// # Panics
/// Panics if `data` is shorter than `sector_count * 512`.
pub fn encrypt_sectors(
    cipher: &KernelSectorCipher,
    first_sector_index: u64,
    sector_count: usize,
    data: &mut [u8],
) -> Result<(), vcrypt_core::CryptoError> {
    let unit = ENCRYPTION_DATA_UNIT_SIZE as usize;
    assert!(data.len() >= sector_count * unit);

    for i in 0..sector_count {
        let start = i * unit;
        let sector = &mut data[start..start + unit];
        cipher.encrypt_sector(first_sector_index + i as u64, sector)?;
    }
    Ok(())
}

/// Decrypt `sector_count` sectors in `data` using XTS mode.
///
/// `data` must be at least `sector_count * 512` bytes.  Each 512-byte chunk
/// is decrypted sequentially with the corresponding `first_sector_index + i`
/// as the XTS tweak.
///
/// For cascade ciphers, decryption happens in reverse order (the
/// `KernelSectorCipher` handles this internally).
///
/// # Panics
/// Panics if `data` is shorter than `sector_count * 512`.
pub fn decrypt_sectors(
    cipher: &KernelSectorCipher,
    first_sector_index: u64,
    sector_count: usize,
    data: &mut [u8],
) -> Result<(), vcrypt_core::CryptoError> {
    let unit = ENCRYPTION_DATA_UNIT_SIZE as usize;
    assert!(data.len() >= sector_count * unit);

    for i in 0..sector_count {
        let start = i * unit;
        let sector = &mut data[start..start + unit];
        cipher.decrypt_sector(first_sector_index + i as u64, sector)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use vcrypt_core::ciphers::CipherType;
    use vcrypt_core::KernelSectorCipher;

    // ------------------------------------------------------------------
    // compute_sector_io_params unit tests
    // ------------------------------------------------------------------

    #[test]
    fn test_aligned_read() {
        let params = compute_sector_io_params(0, 0, 0, 512, 1024 * 1024).unwrap();
        assert_eq!(params.aligned_host_offset, 0);
        assert_eq!(params.aligned_length, 512);
        assert_eq!(params.user_data_offset, 0);
        assert_eq!(params.user_data_length, 512);
        assert_eq!(params.sector_count, 1);
        assert_eq!(params.first_sector_index, 0);
    }

    #[test]
    fn test_aligned_read_with_vol_offset() {
        let params =
            compute_sector_io_params(1_048_576, 0, 512, 512, 10 * 1024 * 1024).unwrap();
        assert_eq!(params.aligned_host_offset, 1_048_576 + 512);
        assert_eq!(params.aligned_length, 512);
        assert_eq!(params.user_data_offset, 0);
        assert_eq!(params.sector_count, 1);
        assert_eq!(params.first_sector_index, 1);
    }

    #[test]
    fn test_unaligned_read_spans_two_sectors() {
        let params = compute_sector_io_params(0, 0, 256, 512, 1024 * 1024).unwrap();
        assert_eq!(params.aligned_host_offset, 0);
        assert_eq!(params.aligned_length, 1024);
        assert_eq!(params.user_data_offset, 256);
        assert_eq!(params.user_data_length, 512);
        assert_eq!(params.sector_count, 2);
        assert_eq!(params.first_sector_index, 0);
    }

    #[test]
    fn test_unaligned_read_spans_three_sectors() {
        let params = compute_sector_io_params(0, 0, 100, 1000, 1024 * 1024).unwrap();
        assert_eq!(params.aligned_host_offset, 0);
        assert_eq!(params.aligned_length, 1536);
        assert_eq!(params.user_data_offset, 100);
        assert_eq!(params.user_data_length, 1000);
        assert_eq!(params.sector_count, 3);
    }

    #[test]
    fn test_read_at_end_of_disk() {
        let params = compute_sector_io_params(0, 0, 511, 1, 512).unwrap();
        assert_eq!(params.aligned_host_offset, 0);
        assert_eq!(params.aligned_length, 512);
        assert_eq!(params.user_data_offset, 511);
        assert_eq!(params.user_data_length, 1);
        assert_eq!(params.sector_count, 1);
    }

    #[test]
    fn test_zero_length_returns_error() {
        assert_eq!(
            compute_sector_io_params(0, 0, 0, 0, 1024),
            Err(SectorIoError::ZeroLength)
        );
    }

    #[test]
    fn test_out_of_bounds_returns_error() {
        assert_eq!(
            compute_sector_io_params(0, 0, 1000, 100, 1024),
            Err(SectorIoError::OutOfBounds)
        );
    }

    #[test]
    fn test_exactly_at_boundary() {
        let params = compute_sector_io_params(0, 0, 512, 512, 1024).unwrap();
        assert_eq!(params.sector_count, 1);
    }

    #[test]
    fn test_one_byte_past_boundary_fails() {
        assert_eq!(
            compute_sector_io_params(0, 0, 512, 513, 1024),
            Err(SectorIoError::OutOfBounds)
        );
    }

    #[test]
    fn test_first_data_unit_no_affects_sector_index() {
        let params = compute_sector_io_params(0, 5, 0, 512, 1024).unwrap();
        assert_eq!(params.first_sector_index, 5);
    }

    #[test]
    fn test_large_offset_within_bounds() {
        let disk_len: u64 = 10 * 1024 * 1024 * 1024;
        let params =
            compute_sector_io_params(0, 0, disk_len - 512, 512, disk_len).unwrap();
        assert_eq!(params.sector_count, 1);
    }

    // ------------------------------------------------------------------
    // encrypt_sectors / decrypt_sectors roundtrip tests
    // ------------------------------------------------------------------

    fn make_cipher(ct: CipherType) -> KernelSectorCipher {
        let key_len = ct.key_size() * 2;
        let key = vec![0x42u8; key_len];
        KernelSectorCipher::new(ct, &key).unwrap()
    }

    #[test]
    fn test_roundtrip_single_sector_aes() {
        let cipher = make_cipher(CipherType::Aes);
        let mut data = [0xABu8; 512];
        let orig = data;

        encrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
        assert_ne!(data, orig);
        decrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
        assert_eq!(data, orig);
    }

    #[test]
    fn test_roundtrip_multi_sector_aes() {
        let cipher = make_cipher(CipherType::Aes);
        let mut data = [0xCDu8; 2048];
        let orig = data;

        encrypt_sectors(&cipher, 0, 4, &mut data).unwrap();
        assert_ne!(data, orig);
        decrypt_sectors(&cipher, 0, 4, &mut data).unwrap();
        assert_eq!(data, orig);
    }

    #[test]
    fn test_different_sectors_produce_different_ciphertext() {
        let cipher = make_cipher(CipherType::Aes);
        let mut s0 = [0x00u8; 512];
        let mut s1 = [0x00u8; 512];

        encrypt_sectors(&cipher, 0, 1, &mut s0).unwrap();
        encrypt_sectors(&cipher, 1, 1, &mut s1).unwrap();
        assert_ne!(s0, s1);
    }

    #[test]
    fn test_roundtrip_all_single_ciphers() {
        for ct in &[
            CipherType::Aes,
            CipherType::Serpent,
            CipherType::Twofish,
            CipherType::Camellia,
            CipherType::Kuznyechik,
        ] {
            let cipher = make_cipher(*ct);
            let mut data = [0x55u8; 512];
            let orig = data;
            encrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
            assert_ne!(data, orig, "cipher {:?} did not change data", ct);
            decrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
            assert_eq!(data, orig, "cipher {:?} roundtrip failed", ct);
        }
    }

    #[test]
    fn test_roundtrip_cascade_aes_twofish() {
        let cipher = make_cipher(CipherType::AesTwofish);
        let mut data = [0x55u8; 512];
        let orig = data;
        encrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
        assert_ne!(data, orig);
        decrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
        assert_eq!(data, orig);
    }

    #[test]
    fn test_roundtrip_cascade_aes_twofish_serpent() {
        let cipher = make_cipher(CipherType::AesTwofishSerpent);
        let mut data = [0x66u8; 512];
        let orig = data;
        encrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
        assert_ne!(data, orig);
        decrypt_sectors(&cipher, 0, 1, &mut data).unwrap();
        assert_eq!(data, orig);
    }

    // ------------------------------------------------------------------
    // Integration: compute_sector_io_params + encrypt/decrypt roundtrip
    // ------------------------------------------------------------------

    #[test]
    fn test_full_read_write_roundtrip_single_sector() {
        let cipher = make_cipher(CipherType::Aes);
        let mut host = vec![0xCCu8; 512];

        let params = compute_sector_io_params(0, 0, 0, 512, 1024 * 1024).unwrap();
        let mut sector_buf = host.clone();
        let user_data = [0xDEu8; 512];
        sector_buf
            [params.user_data_offset..params.user_data_offset + params.user_data_length]
            .copy_from_slice(&user_data);
        encrypt_sectors(
            &cipher,
            params.first_sector_index,
            params.sector_count,
            &mut sector_buf,
        )
        .unwrap();
        host.copy_from_slice(&sector_buf);

        // Read back
        let params = compute_sector_io_params(0, 0, 0, 512, 1024 * 1024).unwrap();
        let mut sector_buf = host.clone();
        decrypt_sectors(
            &cipher,
            params.first_sector_index,
            params.sector_count,
            &mut sector_buf,
        )
        .unwrap();
        let result = &sector_buf
            [params.user_data_offset..params.user_data_offset + params.user_data_length];
        assert_eq!(result, user_data);
        assert_ne!(host.as_slice(), &user_data[..]);
    }

    #[test]
    fn test_full_read_write_roundtrip_unaligned() {
        let cipher = make_cipher(CipherType::Serpent);
        let disk_size: u64 = 10 * 1024 * 1024;
        let mut host = vec![0xAAu8; 512 * 3];

        let user_data = vec![0xBBu8; 600]; // spans sectors 0 and 1
        let params = compute_sector_io_params(0, 0, 300, 600, disk_size).unwrap();
        assert_eq!(params.sector_count, 2);
        assert_eq!(params.user_data_offset, 300);
        assert_eq!(params.aligned_length, 1024);

        let mut sector_buf = host[..params.aligned_length as usize].to_vec();
        sector_buf
            [params.user_data_offset..params.user_data_offset + params.user_data_length]
            .copy_from_slice(&user_data);
        encrypt_sectors(
            &cipher,
            params.first_sector_index,
            params.sector_count,
            &mut sector_buf,
        )
        .unwrap();
        host[..params.aligned_length as usize].copy_from_slice(&sector_buf);

        let mut sector_buf = host[..params.aligned_length as usize].to_vec();
        decrypt_sectors(
            &cipher,
            params.first_sector_index,
            params.sector_count,
            &mut sector_buf,
        )
        .unwrap();
        let result = &sector_buf
            [params.user_data_offset..params.user_data_offset + params.user_data_length];
        assert_eq!(result, user_data.as_slice());
    }

    #[test]
    fn test_full_roundtrip_cascade3() {
        let cipher = make_cipher(CipherType::AesTwofishSerpent);
        let disk_size: u64 = 1024 * 1024;
        let mut host = vec![0x00u8; 512 * 4];

        let user_data = vec![0x77u8; 1500];
        let params = compute_sector_io_params(0, 0, 100, 1500, disk_size).unwrap();

        let mut sector_buf = vec![0x00u8; params.aligned_length as usize];
        sector_buf
            [params.user_data_offset..params.user_data_offset + params.user_data_length]
            .copy_from_slice(&user_data);

        encrypt_sectors(
            &cipher,
            params.first_sector_index,
            params.sector_count,
            &mut sector_buf,
        )
        .unwrap();
        host[..params.aligned_length as usize].copy_from_slice(&sector_buf);

        let mut sector_buf = host[..params.aligned_length as usize].to_vec();
        decrypt_sectors(
            &cipher,
            params.first_sector_index,
            params.sector_count,
            &mut sector_buf,
        )
        .unwrap();
        let result = &sector_buf
            [params.user_data_offset..params.user_data_offset + params.user_data_length];
        assert_eq!(result, user_data.as_slice());
    }
}
