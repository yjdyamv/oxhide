//! Volume device creation and disk IOCTL handlers.

use crate::debug;
use crate::driver;
use crate::irp_utils;
use crate::mount_mgr;
use crate::types;
use crate::wdk_bindings::*;
use vcrypt_core::KernelSectorCipher;

#[repr(C)]
pub struct VolumeExtension {
    pub b_root_device: u8,
    pub is_volume_device: u8,
    pub drive_no: i32,
    pub disk_length: u64,
    pub bytes_per_sector: u32,
    pub read_only: bool,
    pub removable: bool,
    pub b_shutting_down: bool,
    pub host_file_handle: HANDLE,
    pub data_offset: u64,
    pub cipher: KernelSectorCipher,
    pub number_of_cylinders: u32,
    pub tracks_per_cylinder: u32,
    pub sectors_per_track: u32,
    pub unique_volume_id: u32,
}

fn volume_device_name(drive_no: usize) -> [u16; 64] {
    let base = b"\\Device\\OxhideVolume";
    let mut buf = [0u16; 64];
    for (i, &b) in base.iter().enumerate() { buf[i] = b as u16; }
    buf[base.len()] = b'A' as u16 + drive_no as u16;
    buf
}

fn dos_link_name(drive_no: usize) -> [u16; 16] {
    let base = b"\\DosDevices\\";
    let mut buf = [0u16; 16];
    for (i, &b) in base.iter().enumerate() { buf[i] = b as u16; }
    let off = base.len();
    buf[off] = b'A' as u16 + drive_no as u16;
    buf[off + 1] = b':' as u16;
    buf
}

pub fn compute_disk_geometry(disk_length: u64) -> (u32, u32, u32) {
    let total_sectors = disk_length / 512;
    let spt: u32 = 63;
    let tpc: u32 = 255;
    let cyl = if total_sectors > 0 {
        (total_sectors / (spt as u64 * tpc as u64)) as u32
    } else {
        1
    };
    (cyl.max(1), tpc, spt)
}

pub fn create_volume_device(
    drive_no: i32, disk_length: u64, bytes_per_sector: u32,
    read_only: bool, removable: bool, host_file_handle: HANDLE,
    data_offset: u64, cipher: KernelSectorCipher,
) -> Result<(), NTSTATUS> {
    // Compile-time size check
    const _: () = assert!(core::mem::size_of::<VolumeExtension>() > 0, "VEXT too small");
    const VEXT_SZ: usize = core::mem::size_of::<VolumeExtension>();
    let d = drive_no as usize;
    if d >= types::MAX_DRIVE { return Err(STATUS_INVALID_PARAMETER); }

    let (cyl, tpc, spt) = compute_disk_geometry(disk_length);

    unsafe {
        let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
        let mut nt_name = UNICODE_STRING::default();
        let name_buf = volume_device_name(d);
        RtlInitUnicodeString(&mut nt_name, name_buf.as_ptr());

        let root_dev = driver::root_device();
        let driver_obj = if !root_dev.is_null() { (*root_dev).DriverObject } else { core::ptr::null_mut() };

        let dev_chars = FILE_DEVICE_SECURE_OPEN
            | if read_only { FILE_READ_ONLY_DEVICE } else { 0 }
            | if removable { FILE_REMOVABLE_MEDIA } else { 0 };

        let status = IoCreateDevice(driver_obj,
            VEXT_SZ as u32, &mut nt_name,
            FILE_DEVICE_DISK, dev_chars, FALSE, &mut device_object);
        if !NT_SUCCESS(status) {
            debug::kdbg_status("[Oxhide] IoCreateDevice FAILED", status);
            return Err(status);
        }

        (*device_object).Flags |= DO_DIRECT_IO;
        (*device_object).StackSize += 6;

        let ext = &mut *((*device_object).DeviceExtension as *mut VolumeExtension);
        core::ptr::write(ext, VolumeExtension {
            b_root_device: 0,
            is_volume_device: 1,
            drive_no,
            disk_length,
            bytes_per_sector,
            read_only,
            removable,
            b_shutting_down: false,
            host_file_handle,
            data_offset,
            cipher,
            number_of_cylinders: cyl,
            tracks_per_cylinder: tpc,
            sectors_per_track: spt,
            unique_volume_id: drive_no as u32,
        });

        let mut dos_name = UNICODE_STRING::default();
        let dos_buf = dos_link_name(d);
        RtlInitUnicodeString(&mut dos_name, dos_buf.as_ptr());
        if !NT_SUCCESS(IoCreateSymbolicLink(&mut dos_name, &mut nt_name)) {
            IoDeleteDevice(device_object);
            debug::kdbg("[Oxhide] IoCreateSymbolicLink FAILED\n");
            return Err(STATUS_UNSUCCESSFUL);
        }

        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
        driver::volume_devices_mut()[d] = device_object;

        // TODO: re-enable after debugging mount crash
        // mount_mgr::notify_volume_arrival(d);
        // mount_mgr::create_mount_point(d);

        debug::kdbg("[Oxhide] create_volume_device OK\n");
        Ok(())
    }
}

pub fn destroy_volume_device(drive_no: usize) {
    if drive_no >= types::MAX_DRIVE { return; }
    unsafe {
        let device = driver::volume_devices_mut()[drive_no];
        if device.is_null() { return; }
        driver::volume_devices_mut()[drive_no] = core::ptr::null_mut();
        let ext = &mut *((*device).DeviceExtension as *mut VolumeExtension);
        ext.b_shutting_down = true;
        if !ext.host_file_handle.is_null() {
            ZwClose(ext.host_file_handle);
            ext.host_file_handle = core::ptr::null_mut();
        }
        let mut dos_name = UNICODE_STRING::default();
        let dos_buf = dos_link_name(drive_no);
        RtlInitUnicodeString(&mut dos_name, dos_buf.as_ptr());
        // TODO: re-enable after debugging
        // mount_mgr::delete_mount_point(drive_no);
        IoDeleteSymbolicLink(&mut dos_name);
        IoDeleteDevice(device);
        debug::kdbg("[Oxhide] destroy_volume_device done\n");
    }
}

pub unsafe fn volume_extension(dev: *mut DEVICE_OBJECT) -> Option<&'static mut VolumeExtension> {
    if dev.is_null() { return None; }
    let ext = (*dev).DeviceExtension as *mut VolumeExtension;
    if ext.is_null() { return None; }
    if (*ext).is_volume_device != 1 { return None; }
    Some(&mut *ext)
}
