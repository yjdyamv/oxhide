//! Virtual encrypted disk filesystem backed by WinFSP (Windows) / FUSE (Linux).
//!
//! Presents an OpenVolume as a raw block device — a single root file
//! whose byte-range reads/writes are mapped to sector operations.

use parking_lot::Mutex;
use std::sync::Arc;
use vcrypt_volume::OpenVolume;

/// A raw encrypted block device exposed as a filesystem.
pub struct EncryptedDisk {
    vol: Arc<Mutex<OpenVolume>>,
    size: u64,
}

impl EncryptedDisk {
    pub fn new(vol: OpenVolume) -> Self {
        let size = vol.data_size();
        Self { vol: Arc::new(Mutex::new(vol)), size }
    }

    fn read_bytes(&self, offset: u64, buf: &mut [u8]) -> u32 {
        if offset >= self.size || buf.is_empty() {
            return 0;
        }
        let max_read = (self.size - offset).min(buf.len() as u64);

        // Align to 512-byte sectors with RMW for partial sectors
        let start_sector = offset / 512;
        let end_byte = offset + max_read;
        let end_sector = (end_byte + 511) / 512;
        let sector_count = end_sector - start_sector;

        let mut sector_buf = vec![0u8; sector_count as usize * 512];
        if let Err(_e) = self.vol.lock().read(start_sector, &mut sector_buf) {
            return 0;
        }

        let start_off = (offset % 512) as usize;
        let copy_len = max_read as usize;
        buf[..copy_len].copy_from_slice(&sector_buf[start_off..start_off + copy_len]);
        copy_len as u32
    }

    fn write_bytes(&self, offset: u64, buf: &[u8]) -> u32 {
        if offset >= self.size || buf.is_empty() {
            return 0;
        }
        let max_write = (self.size - offset).min(buf.len() as u64);

        // Read-modify-write for partial sectors
        let start_sector = offset / 512;
        let end_byte = offset + max_write;
        let end_sector = (end_byte + 511) / 512;
        let sector_count = end_sector - start_sector;

        let mut sector_buf = vec![0u8; sector_count as usize * 512];
        // Read existing sectors (to preserve unchanged parts)
        let _ = self.vol.lock().read(start_sector, &mut sector_buf);

        // Write new data into the buffer
        let start_off = (offset % 512) as usize;
        let copy_len = max_write as usize;
        sector_buf[start_off..start_off + copy_len].copy_from_slice(&buf[..copy_len]);

        if let Err(_e) = self.vol.lock().write(start_sector, &sector_buf) {
            return 0;
        }
        copy_len as u32
    }

    fn flush(&self) {
        // Flush is best-effort; OpenVolume writes are synchronous
    }
}

// ── Platform-specific mounting ──

#[cfg(windows)]
mod platform;
#[cfg(windows)]
pub use platform::mount_volume;

#[cfg(not(windows))]
pub fn mount_volume(
    _volume_path: &str, _password: &[u8], _keyfiles: &[&str],
    _kdf: Option<vcrypt_core::kdf::KdfAlgorithm>, _pim: Option<i32>,
    _mount_point: &str, _read_only: bool,
) -> Result<(), String> {
    Err("Filesystem mounting is only supported on Windows (WinFSP)".into())
}
