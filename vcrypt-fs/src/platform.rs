//! WinFSP-based virtual disk mounting for Windows (via winfsp_wrs).

use super::EncryptedDisk;
use std::sync::Arc;
use vcrypt_core::kdf::KdfAlgorithm;
use vcrypt_volume::OpenVolume;
use winfsp_wrs::{
    FileAccessRights, FileAttributes, FileInfo, FileSystem, FileSystemInterface,
    OperationGuardStrategy, Params, VolumeInfo, VolumeParams, WriteMode,
};

struct DiskFs {
    disk: Arc<EncryptedDisk>,
    read_only: bool,
}

impl FileSystemInterface for DiskFs {
    type FileContext = Arc<EncryptedDisk>;

    const GET_SECURITY_BY_NAME_DEFINED: bool = true;
    fn get_security_by_name(
        &self,
        _file_name: &winfsp_wrs::U16CStr,
        _find_reparse_point: impl Fn() -> Option<FileAttributes>,
    ) -> Result<(FileAttributes, winfsp_wrs::PSecurityDescriptor, bool), windows_sys::Win32::Foundation::NTSTATUS> {
        Ok((FileAttributes(0x80), winfsp_wrs::PSecurityDescriptor::default(), false))
    }

    const OPEN_DEFINED: bool = true;
    fn open(
        &self,
        _file_name: &winfsp_wrs::U16CStr,
        _create_options: winfsp_wrs::CreateOptions,
        granted_access: FileAccessRights,
    ) -> Result<(Self::FileContext, FileInfo), windows_sys::Win32::Foundation::NTSTATUS> {
        if self.read_only && granted_access.0 & 0x2 != 0 {
            return Err(windows_sys::Win32::Foundation::STATUS_ACCESS_DENIED);
        }
        let mut fi = FileInfo::default();
        fi.set_file_attributes(FileAttributes(0x80));
        fi.set_file_size(self.disk.size);
        fi.set_allocation_size((self.disk.size + 511) / 512 * 512);
        let now = winfsp_wrs::filetime_now();
        fi.set_creation_time(now);
        fi.set_last_access_time(now);
        fi.set_last_write_time(now);
        fi.set_change_time(now);
        Ok((self.disk.clone(), fi))
    }

    const GET_FILE_INFO_DEFINED: bool = true;
    fn get_file_info(
        &self,
        _ctx: Self::FileContext,
    ) -> Result<FileInfo, windows_sys::Win32::Foundation::NTSTATUS> {
        let mut fi = FileInfo::default();
        fi.set_file_attributes(FileAttributes(0x80));
        fi.set_file_size(self.disk.size);
        fi.set_allocation_size((self.disk.size + 511) / 512 * 512);
        let now = winfsp_wrs::filetime_now();
        fi.set_creation_time(now);
        fi.set_last_access_time(now);
        fi.set_last_write_time(now);
        fi.set_change_time(now);
        Ok(fi)
    }

    const READ_DEFINED: bool = true;
    fn read(
        &self,
        _ctx: Self::FileContext,
        buffer: &mut [u8],
        offset: u64,
    ) -> Result<usize, windows_sys::Win32::Foundation::NTSTATUS> {
        Ok(self.disk.read_bytes(offset, buffer) as usize)
    }

    const WRITE_DEFINED: bool = true;
    fn write(
        &self,
        _ctx: Self::FileContext,
        buffer: &[u8],
        write_mode: WriteMode,
    ) -> Result<(usize, FileInfo), windows_sys::Win32::Foundation::NTSTATUS> {
        let offset = match write_mode {
            WriteMode::Normal { offset } => offset,
            WriteMode::ConstrainedIO { offset } => offset,
            WriteMode::WriteToEOF => self.disk.size,
        };
        let n = self.disk.write_bytes(offset, buffer) as usize;
        let mut fi = FileInfo::default();
        fi.set_file_size(self.disk.size);
        Ok((n, fi))
    }

    const CLEANUP_DEFINED: bool = true;
    fn cleanup(
        &self,
        _ctx: Self::FileContext,
        _file_name: Option<&winfsp_wrs::U16CStr>,
        _flags: winfsp_wrs::CleanupFlags,
    ) {}

    const CLOSE_DEFINED: bool = true;
    fn close(&self, _ctx: Self::FileContext) {}

    const GET_VOLUME_INFO_DEFINED: bool = true;
    fn get_volume_info(
        &self,
    ) -> Result<VolumeInfo, windows_sys::Win32::Foundation::NTSTATUS> {
        let mut vi = VolumeInfo::default();
        vi.set_total_size(self.disk.size);
        vi.set_free_size(0);
        let _ = vi.set_volume_label(&winfsp_wrs::U16String::from_str("Oxhide").as_ustr());
        Ok(vi)
    }

    const FLUSH_DEFINED: bool = true;
    fn flush(
        &self,
        _ctx: Self::FileContext,
    ) -> Result<FileInfo, windows_sys::Win32::Foundation::NTSTATUS> {
        self.disk.flush();
        let mut fi = FileInfo::default();
        fi.set_file_size(self.disk.size);
        Ok(fi)
    }
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
    winfsp_wrs::init().map_err(|e| format!("WinFSP init: {}", e))?;

    let vol = if read_only {
        OpenVolume::open_read_only(volume_path, password, keyfiles, kdf, pim)
            .map_err(|e| format!("Cannot open volume: {}", e))?
    } else {
        OpenVolume::open(volume_path, password, keyfiles, kdf, pim)
            .map_err(|e| format!("Cannot open volume: {}", e))?
    };

    let disk = Arc::new(EncryptedDisk::new(vol));

    let mut vp = VolumeParams::default();
    vp.set_sector_size(512);
    vp.set_sectors_per_allocation_unit(8);
    vp.set_max_component_length(255);
    vp.set_file_info_timeout(1000);
    let name = winfsp_wrs::U16CString::from_str("Oxhide Volume").unwrap();
    let _ = vp.set_file_system_name(&name);
    let prefix = winfsp_wrs::U16CString::from_str("Oxhide").unwrap();
    let _ = vp.set_prefix(&prefix);

    let params = Params {
        volume_params: vp,
        guard_strategy: OperationGuardStrategy::Fine,
    };

    let fs_ctx = DiskFs {
        disk: disk.clone(),
        read_only,
    };

    let _fs = FileSystem::start(params, None, fs_ctx)
        .map_err(|e| format!("WinFSP mount failed: NTSTATUS {:#x}", e))?;

    println!("Volume mounted. Press Ctrl+C to unmount.");
    loop {
        std::thread::sleep(std::time::Duration::from_secs(60));
    }
}
