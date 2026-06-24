//! Volume header deserialization (Big-Endian, CRC validated)

use super::header::{self, VolumeHeader, ENCRYPTED_HEADER_SIZE, PKCS5_SALT_SIZE, VOLUME_HEADER_EFFECTIVE_SIZE};
use super::error::{FormatError, FormatResult};
use crc::{Crc, CRC_32_ISO_HDLC};
use subtle::ConstantTimeEq;
use std::io::Read;

const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Deserialize header from 512-byte buffer
pub fn deserialize_header(data: &[u8]) -> FormatResult<VolumeHeader> {
    if data.len() < VOLUME_HEADER_EFFECTIVE_SIZE {
        return Err(FormatError::InvalidHeaderSize {
            expected: VOLUME_HEADER_EFFECTIVE_SIZE, actual: data.len(),
        });
    }

    let mut r = std::io::Cursor::new(data);

    // Salt (64 bytes)
    let mut salt = [0u8; PKCS5_SALT_SIZE];
    r.read_exact(&mut salt)?;

    // Encrypted area (448 bytes)
    let mut enc = [0u8; ENCRYPTED_HEADER_SIZE];
    r.read_exact(&mut enc)?;

    let mut cr = std::io::Cursor::new(&enc[..]);

    let magic = read_u32(&mut cr)?;
    if bool::from(magic.ct_ne(&header::VOLUME_MAGIC)) {
        return Err(FormatError::InvalidMagic {
            expected: header::VOLUME_MAGIC, actual: magic,
        });
    }

    let header_version = read_u16(&mut cr)?;
    let required_version = read_u16(&mut cr)?;
    let key_area_crc = read_u32(&mut cr)?;
    let volume_creation_time = read_u64(&mut cr)?;
    let modification_time = read_u64(&mut cr)?;
    let hidden_volume_size = read_u64(&mut cr)?;
    let volume_size = read_u64(&mut cr)?;
    let encrypted_area_start = read_u64(&mut cr)?;
    let encrypted_area_length = read_u64(&mut cr)?;
    let flags = read_u32(&mut cr)?;
    let sector_size = read_u32(&mut cr)?;

    // Validate sector size
    if sector_size < 512 || sector_size > 4096 || sector_size % 512 != 0 {
        return Err(FormatError::InvalidHeaderSize {
            expected: 512, actual: sector_size as usize,
        });
    }

    // Seek to header CRC
    cr.set_position(header::offsets::HEADER_CRC as u64);
    let stored_crc = read_u32(&mut cr)?;

    // Verify header CRC (constant-time, bytes 0..CRC offset)
    let computed_crc = CRC32.checksum(&enc[..header::offsets::HEADER_CRC]);
    if bool::from(stored_crc.ct_ne(&computed_crc)) {
        return Err(FormatError::InvalidCrc {
            expected: computed_crc, actual: stored_crc,
        });
    }

    // Read master key data
    let kd_off = header::offsets::MASTER_KEYDATA;
    let mut master_keydata = vec![0u8; header::MASTER_KEYDATA_SIZE];
    master_keydata.copy_from_slice(&enc[kd_off..kd_off + header::MASTER_KEYDATA_SIZE]);

    // Verify key area CRC
    let computed_key_crc = CRC32.checksum(&enc[kd_off..]);
    if key_area_crc != computed_key_crc {
        return Err(FormatError::InvalidCrc {
            expected: computed_key_crc, actual: key_area_crc,
        });
    }

    Ok(VolumeHeader {
        salt, magic: header::VOLUME_MAGIC, header_version, required_version,
        key_area_crc, volume_creation_time, modification_time,
        hidden_volume_size, volume_size, encrypted_area_start,
        encrypted_area_length, flags, sector_size, master_keydata,
        header_crc: stored_crc,
    })
}

fn read_u16(r: &mut std::io::Cursor<&[u8]>) -> FormatResult<u16> {
    let mut b = [0u8; 2]; r.read_exact(&mut b)?; Ok(u16::from_be_bytes(b))
}
fn read_u32(r: &mut std::io::Cursor<&[u8]>) -> FormatResult<u32> {
    let mut b = [0u8; 4]; r.read_exact(&mut b)?; Ok(u32::from_be_bytes(b))
}
fn read_u64(r: &mut std::io::Cursor<&[u8]>) -> FormatResult<u64> {
    let mut b = [0u8; 8]; r.read_exact(&mut b)?; Ok(u64::from_be_bytes(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_roundtrip() {
        let h = VolumeHeader::new();
        let bytes = crate::ser::serialize_header(&h).unwrap();
        let parsed = deserialize_header(&bytes).unwrap();
        assert!(parsed.verify_magic());
        assert_eq!(parsed.salt, h.salt);
    }

    #[test]
    fn test_size_error() {
        assert!(deserialize_header(&[0u8; 100]).is_err());
    }

    #[test]
    fn test_bad_magic() {
        let mut h = VolumeHeader::new();
        h.magic = 0xDEAD_BEEF;
        let bytes = crate::ser::serialize_header(&h).unwrap();
        assert!(deserialize_header(&bytes).is_err());
    }
}
