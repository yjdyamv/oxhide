//! WinFSP-based virtual disk mounting for Windows (via winfsp crate).

use super::EncryptedDisk;
use std::sync::Arc;
use vcrypt_core::kdf::KdfAlgorithm;
use vcrypt_volume::OpenVolume;
use winfsp::filesystem::{FileInfo, FileSystemContext, OpenFileInfo, VolumeInfo};
use winfsp::host::{FileSystemHost, VolumeParams};
use winfsp::Result as FspResult;

struct DiskFs {
    disk: Arc<EncryptedDisk>,
}

impl FileSystemContext for DiskFs {
    type FileContext = ();

    fn get_security_by_name(
        &self,
        _file_name: &winfsp::U16CStr,
        _security_descriptor: Option<&mut [std::ffi::c_void]>,
        _reparse_point_resolver: impl FnOnce(&winfsp::U16CStr) -> Option<winfsp::filesystem::FileSecurity>,
    ) -> FspResult<winfsp::filesystem::FileSecurity> {
        Ok(winfsp::filesystem::FileSecurity {
            reparse: false,
            sz_security_descriptor: 0,
            attributes: 0,
        })
    }

    fn open(
        &self,
        _file_name: &winfsp::U16CStr,
        _create_options: u32,
        _granted_access: u32,
        _file_info: &mut OpenFileInfo,
    ) -> FspResult<()> {
        Ok(())
    }

    fn close(&self, _context: ()) {}

    fn get_file_info(&self, _context: &(), file_info: &mut FileInfo) -> FspResult<()> {
        file_info.file_size = self.disk.size;
        file_info.file_attributes = 0x80;
        file_info.allocation_size = (self.disk.size + 511) / 512 * 512;
        Ok(())
    }

    fn read(&self, _context: &(), buffer: &mut [u8], offset: u64) -> FspResult<u32> {
        Ok(self.disk.read_bytes(offset, buffer))
    }

    fn write(
        &self,
        _context: &(),
        buffer: &[u8],
        offset: u64,
        _write_to_eof: bool,
        _constrained_io: bool,
        _file_info: &mut FileInfo,
    ) -> FspResult<u32> {
        Ok(self.disk.write_bytes(offset, buffer))
    }

    fn flush(&self, _context: Option<&()>, _file_info: &mut FileInfo) -> FspResult<()> {
        self.disk.flush();
        Ok(())
    }

    fn get_volume_info(&self, out_volume_info: &mut VolumeInfo) -> FspResult<()> {
        out_volume_info.total_size = self.disk.size;
        out_volume_info.free_size = 0;
        Ok(())
    }

    fn cleanup(&self, _context: &(), _file_name: Option<&winfsp::U16CStr>, _flags: u32) {}
}

/// Mount an encrypted volume as a virtual disk. Blocks until unmounted.
pub fn mount_volume(
    volume_path: &str,
    password: &[u8],
    keyfiles: &[&str],
    kdf: Option<KdfAlgorithm>,
    pim: Option<i32>,
    mount_point: &str,
    read_only: bool,
) -> Result<(), String> {
    let _init = winfsp::winfsp_init_or_die();

    let vol = if read_only {
        OpenVolume::open_read_only(volume_path, password, keyfiles, kdf, pim)
            .map_err(|e| format!("Cannot open volume: {}", e))?
    } else {
        OpenVolume::open(volume_path, password, keyfiles, kdf, pim)
            .map_err(|e| format!("Cannot open volume: {}", e))?
    };

    let disk = Arc::new(EncryptedDisk::new(vol));

    let mp_owned: std::ffi::OsString = mount_point.into();

    let mut vp = VolumeParams::new();
    // Fully initialize FSP_FSCTL_VOLUME_PARAMS via transmute
    unsafe {
        let raw: &mut winfsp_sys::FSP_FSCTL_VOLUME_PARAMS = std::mem::transmute(&mut vp);
        let sz = std::mem::size_of::<winfsp_sys::FSP_FSCTL_VOLUME_PARAMS>();
        raw.Version = sz as u16;
        raw.SectorSize = 512;
        raw.SectorsPerAllocationUnit = 1;
        raw.MaxComponentLength = 255;
        raw.VolumeCreationTime = 0;
        raw.FileInfoTimeout = 1000;
        // Disk device mode (empty prefix -> WinFsp.Disk)
        // The drive appears in Disk Management (diskmgmt.msc) as a virtual disk.
        // Initialize + format to assign a drive letter.
        raw.Prefix = [0u16; 192];
        // Set filesystem name
        let name = b"Oxhide\0\0";
        for (i, &b) in name.iter().enumerate() {
            raw.FileSystemName[i] = b as u16;
        }
    }
    if read_only {
        vp.read_only_volume(true);
    }

    let ctx = DiskFs { disk: disk.clone() };
    let mut host = FileSystemHost::new(vp, ctx)
        .map_err(|e| format!("WinFSP host error: {e}"))?;
    host.mount(&mp_owned)
        .map_err(|e| format!("WinFSP mount error: {e}"))?;

    println!("Volume mounted. Press Ctrl+C to unmount.");
    <FileSystemHost<DiskFs>>::start(&mut host)
        .map_err(|e| format!("WinFSP start error: {e}"))?;

    Ok(())
}
