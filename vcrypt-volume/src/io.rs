//! Sector-level I/O with XTS encryption
//!
//! Sector-aligned read/write on VeraCrypt volumes. Each 512-byte data unit
//! is encrypted/decrypted using XTS with the data unit number as tweak.

use super::error::{VolResult, VolumeError};
use std::io::{Read, Seek, SeekFrom, Write};

pub const DATA_UNIT_SIZE: u64 = 512;

/// Trait for XTS sector encryption/decryption
pub trait SectorCipher: Send + Sync {
    fn encrypt_sector(&self, sector: u64, data: &mut [u8]) -> VolResult<()>;
    fn decrypt_sector(&self, sector: u64, data: &mut [u8]) -> VolResult<()>;
}

/// Read and decrypt sectors from a volume file
pub fn read_sectors<F: Read + Seek>(
    file: &mut F, data_offset: u64, sector: u64,
    buffer: &mut [u8], cipher: &dyn SectorCipher,
) -> VolResult<()> {
    let pos = data_offset + sector * DATA_UNIT_SIZE;
    file.seek(SeekFrom::Start(pos))
        .map_err(|e| VolumeError::ReadError { sector, msg: format!("seek: {}", e) })?;
    file.read_exact(buffer)
        .map_err(|e| VolumeError::ReadError { sector, msg: format!("read: {}", e) })?;
    cipher.decrypt_sector(sector, buffer)
}

/// Encrypt and write sectors to a volume file
pub fn write_sectors<F: Read + Write + Seek>(
    file: &mut F, data_offset: u64, sector: u64,
    buffer: &[u8], cipher: &dyn SectorCipher,
) -> VolResult<()> {
    let mut encrypted = buffer.to_vec();
    cipher.encrypt_sector(sector, &mut encrypted)?;
    let pos = data_offset + sector * DATA_UNIT_SIZE;
    file.seek(SeekFrom::Start(pos))
        .map_err(|e| VolumeError::WriteError { sector, msg: format!("seek: {}", e) })?;
    file.write_all(&encrypted)
        .map_err(|e| VolumeError::WriteError { sector, msg: format!("write: {}", e) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    struct MockCipher;
    impl SectorCipher for MockCipher {
        fn encrypt_sector(&self, _s: u64, d: &mut [u8]) -> VolResult<()> {
            for b in d.iter_mut() { *b ^= 0xFF; }
            Ok(())
        }
        fn decrypt_sector(&self, _s: u64, d: &mut [u8]) -> VolResult<()> {
            self.encrypt_sector(_s, d)
        }
    }

    #[test]
    fn test_read_roundtrip() {
        let cipher = MockCipher;
        let mut file = Cursor::new(vec![0xABu8; 512]);
        let mut buf = vec![0u8; 512];
        read_sectors(&mut file, 0, 0, &mut buf, &cipher).unwrap();
        assert_ne!(&buf, &[0xABu8; 512]);
        // Re-encrypt should restore
        cipher.encrypt_sector(0, &mut buf).unwrap();
        assert_eq!(&buf, &[0xABu8; 512]);
    }
}
