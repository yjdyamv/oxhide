//! Volume header serialization (Big-Endian binary format)
//!
//! Matches VeraCrypt on-disk format exactly.

use super::header::{self, VolumeHeader, ENCRYPTED_HEADER_SIZE, VOLUME_HEADER_EFFECTIVE_SIZE};
use super::error::FormatResult;
use crc::{Crc, CRC_32_ISO_HDLC};
use std::io::Write;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Serialize header to 512-byte effective buffer (Big-Endian)
pub fn serialize_header(header: &VolumeHeader) -> FormatResult<Vec<u8>> {
    let mut buf = Vec::with_capacity(VOLUME_HEADER_EFFECTIVE_SIZE);

    // Salt (64 bytes, unencrypted)
    buf.write_all(&header.salt)?;

    // Encrypted area (448 bytes)
    let mut enc = Vec::with_capacity(ENCRYPTED_HEADER_SIZE);

    // Magic + version fields
    enc.write_all(&header.magic.to_be_bytes())?;
    enc.write_all(&header.header_version.to_be_bytes())?;
    enc.write_all(&header.required_version.to_be_bytes())?;

    // Key area CRC (placeholder for now, computed after keydata)
    enc.write_all(&0u32.to_be_bytes())?;

    // Timestamps
    enc.write_all(&header.volume_creation_time.to_be_bytes())?;
    enc.write_all(&header.modification_time.to_be_bytes())?;

    // Volume geometry
    enc.write_all(&header.hidden_volume_size.to_be_bytes())?;
    enc.write_all(&header.volume_size.to_be_bytes())?;
    enc.write_all(&header.encrypted_area_start.to_be_bytes())?;
    enc.write_all(&header.encrypted_area_length.to_be_bytes())?;
    enc.write_all(&header.flags.to_be_bytes())?;
    enc.write_all(&header.sector_size.to_be_bytes())?;

    // Reserved area (120 bytes) — must be zero
    while enc.len() < header::offsets::HEADER_CRC {
        enc.push(0);
    }

    // Header CRC placeholder (computed below)
    let crc_pos = enc.len(); // = 188
    enc.write_all(&0u32.to_be_bytes())?;

    // Master key data (256 bytes at offset 192)
    while enc.len() < header::offsets::MASTER_KEYDATA {
        enc.push(0);
    }
    let kd_start = enc.len(); // should be 192
    let write_len = header.master_keydata.len().min(header::MASTER_KEYDATA_SIZE);
    enc.write_all(&header.master_keydata[..write_len])?;
    // Pad remaining keydata area with zeros
    while enc.len() < kd_start + header::MASTER_KEYDATA_SIZE {
        enc.push(0);
    }

    // Pad to full encrypted area
    enc.resize(ENCRYPTED_HEADER_SIZE, 0);

    // Compute key area CRC first (bytes 192..), then write to offset 8
    let key_crc = CRC32.checksum(&enc[kd_start..]);
    enc[header::offsets::KEY_AREA_CRC..header::offsets::KEY_AREA_CRC + 4]
        .copy_from_slice(&key_crc.to_be_bytes());

    // Compute header CRC (bytes 0..crc_pos), now includes correct key_crc at offset 8
    let header_crc = CRC32.checksum(&enc[..crc_pos]);
    enc[crc_pos..crc_pos + 4].copy_from_slice(&header_crc.to_be_bytes());

    buf.write_all(&enc)?;
    Ok(buf)
}

/// Serialize to full 64KB buffer
pub fn serialize_header_full(header: &VolumeHeader) -> FormatResult<Vec<u8>> {
    let effective = serialize_header(header)?;
    let mut full = vec![0u8; header::VOLUME_HEADER_SIZE];
    full[..VOLUME_HEADER_EFFECTIVE_SIZE].copy_from_slice(&effective);
    Ok(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size() {
        let h = VolumeHeader::new();
        let bytes = serialize_header(&h).unwrap();
        assert_eq!(bytes.len(), VOLUME_HEADER_EFFECTIVE_SIZE);
    }

    #[test]
    fn test_full_size() {
        let h = VolumeHeader::new();
        let bytes = serialize_header_full(&h).unwrap();
        assert_eq!(bytes.len(), header::VOLUME_HEADER_SIZE);
    }

    #[test]
    fn test_magic_be() {
        let h = VolumeHeader::new();
        let bytes = serialize_header(&h).unwrap();
        // Magic at offset 64-68 in big-endian: "VERA" = 0x56 0x45 0x52 0x41
        assert_eq!(&bytes[64..68], &[0x56, 0x45, 0x52, 0x41]);
    }
}
