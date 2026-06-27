//! Mount Manager integration.
//!
//! Notifies the Windows Mount Manager when a virtual disk volume arrives or is
//! removed, and creates/destroys the drive-letter mount point.
//!
//! Reference: VeraCrypt `MountManagerMount` / `MountManagerUnmount`
//!            (`Ntdriver.c:3981-4033`).

use crate::debug;
use crate::names;
use crate::wdk_bindings::*;

/// Notify the Mount Manager that a new volume device has arrived.
pub fn notify_volume_arrival(drive_no: usize) {
    if drive_no >= 26 { return; }
    unsafe {
        let mut buf = [0u8; 512];
        let nt_name = names::volume_nt_name(drive_no);
        let nt_name_len = names::wcslen(&nt_name);

        let target = buf.as_mut_ptr() as *mut MOUNTMGR_TARGET_NAME;
        (*target).DeviceNameLength = (nt_name_len * 2) as u16;
        let dst = (*target).DeviceName.as_mut_ptr();
        core::ptr::copy_nonoverlapping(nt_name.as_ptr(), dst, nt_name_len);

        let in_size = 2 + (nt_name_len * 2) as u32;
        send_mountmgr_ioctl(
            IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION,
            &buf[..in_size as usize],
            core::ptr::null_mut(), 0,
        );
    }
}

/// Tell the Mount Manager to create a `\DosDevices\X:` mount point.
pub fn create_mount_point(drive_no: usize) {
    if drive_no >= 26 { return; }
    unsafe {
        let mut buf = [0u8; 512];
        let dos_name = names::volume_dos_name(drive_no);
        let dos_len = names::wcslen(&dos_name);
        let nt_name = names::volume_nt_name(drive_no);
        let nt_len = names::wcslen(&nt_name);

        let hdr_size = core::mem::size_of::<MOUNTMGR_CREATE_POINT_INPUT>();
        let point = buf.as_mut_ptr() as *mut MOUNTMGR_CREATE_POINT_INPUT;

        (*point).SymbolicLinkNameOffset = hdr_size as u16;
        (*point).SymbolicLinkNameLength = (dos_len * 2) as u16;
        (*point).DeviceNameOffset = (hdr_size + dos_len * 2) as u16;
        (*point).DeviceNameLength = (nt_len * 2) as u16;

        let sym_dst = buf.as_mut_ptr().add(hdr_size) as *mut u16;
        core::ptr::copy_nonoverlapping(dos_name.as_ptr(), sym_dst, dos_len);
        let dev_dst = buf.as_mut_ptr().add(hdr_size + dos_len * 2) as *mut u16;
        core::ptr::copy_nonoverlapping(nt_name.as_ptr(), dev_dst, nt_len);

        let total = hdr_size + dos_len * 2 + nt_len * 2;
        send_mountmgr_ioctl(
            IOCTL_MOUNTMGR_CREATE_POINT,
            &buf[..total],
            core::ptr::null_mut(), 0,
        );
    }
}

/// Tell the Mount Manager to remove the `\DosDevices\X:` mount point.
pub fn delete_mount_point(drive_no: usize) {
    if drive_no >= 26 { return; }
    unsafe {
        let mut buf = [0u8; 256];
        let dos_name = names::volume_dos_name(drive_no);
        let dos_len = names::wcslen(&dos_name);

        let hdr_size = core::mem::size_of::<MOUNTMGR_MOUNT_POINT>();
        let point = buf.as_mut_ptr() as *mut MOUNTMGR_MOUNT_POINT;

        (*point).SymbolicLinkNameOffset = hdr_size as u32;
        (*point).SymbolicLinkNameLength = (dos_len * 2) as u16;
        (*point).UniqueIdOffset = 0;
        (*point).UniqueIdLength = 0;
        (*point).DeviceNameOffset = 0;
        (*point).DeviceNameLength = 0;

        let sym_dst = buf.as_mut_ptr().add(hdr_size) as *mut u16;
        core::ptr::copy_nonoverlapping(dos_name.as_ptr(), sym_dst, dos_len);

        let total = hdr_size + dos_len * 2;
        let out_ptr = buf.as_mut_ptr() as PVOID;
        send_mountmgr_ioctl(
            IOCTL_MOUNTMGR_DELETE_POINTS,
            &buf[..total],
            out_ptr,
            256,
        );
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

unsafe fn send_mountmgr_ioctl(
    ioctl_code: u32,
    input: &[u8],
    output: PVOID,
    output_len: u32,
) {
    let name: [u16; 32] = {
        let mut buf = [0u16; 32];
        let src = MOUNTMGR_DEVICE_NAME.as_bytes();
        let len = src.len().min(31);
        for (i, &b) in src.iter().enumerate().take(len) {
            buf[i] = b as u16;
        }
        buf
    };

    let mut path_str = UNICODE_STRING::default();
    let name_len = names::wcslen(&name);
    path_str.Length = (name_len * 2) as u16;
    path_str.MaximumLength = 64;
    path_str.Buffer = name.as_ptr() as *mut u16;

    let mut oa: OBJECT_ATTRIBUTES = core::mem::zeroed();
    let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let mut handle: HANDLE = core::ptr::null_mut();

    InitializeObjectAttributes(&mut oa, &mut path_str,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        core::ptr::null_mut(), core::ptr::null_mut());

    let status = ZwCreateFile(
        &mut handle,
        FILE_READ_ATTRIBUTES | SYNCHRONIZE,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut(),
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        FILE_OPEN,
        FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    if !NT_SUCCESS(status) {
        debug::kdbg("[Oxhide] mountmgr: cannot open MountPointManager\n");
        return;
    }

    let mut dio_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let dio_status = ZwDeviceIoControlFile(
        handle,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        &mut dio_iosb,
        ioctl_code,
        input.as_ptr() as PVOID,
        input.len() as u32,
        output,
        output_len,
    );

    if !NT_SUCCESS(dio_status) {
        debug::kdbg_status("[Oxhide] mountmgr: ZwDeviceIoControlFile failed", dio_status);
    }

    ZwClose(handle);
}
