//! Root control device (`\Device\Oxhide`) and root IOCTL dispatch.
//!
//! 1:1 translation of VeraCrypt `TCCreateRootDeviceObject` and
//! `ProcessMainDeviceControlIrp` from `Ntdriver.c`.

use crate::debug;
use crate::driver;
use crate::irp_utils;
use crate::mount;
use crate::types::*;
use crate::wdk_bindings::*;

const ROOT_DEVICE_NAME: [u16; 16] = [
    0x5C, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5C,
    0x4F, 0x78, 0x68, 0x69, 0x64, 0x65, 0x00, 0x00,
];
const ROOT_DOS_NAME: [u16; 19] = [
    0x5C, 0x44, 0x6F, 0x73, 0x44, 0x65, 0x76, 0x69,
    0x63, 0x65, 0x73, 0x5C, 0x4F, 0x78, 0x68, 0x69,
    0x64, 0x65, 0x00,
];

/// Construct the dos device name UNICODE_STRING for the root device.
pub fn dos_device_name() -> UNICODE_STRING {
    let mut s = UNICODE_STRING::default();
    unsafe { RtlInitUnicodeString(&mut s, ROOT_DOS_NAME.as_ptr()); }
    s
}

/// Create the root control device (`\Device\Oxhide`) and its symbolic link
/// (`\DosDevices\Oxhide`), register for shutdown notification.
pub fn create_root_device(driver_object: *mut DRIVER_OBJECT) -> NTSTATUS {
    unsafe {
        let mut device_object: *mut DEVICE_OBJECT = core::ptr::null_mut();
        let mut nt_dev_name = UNICODE_STRING::default();
        RtlInitUnicodeString(&mut nt_dev_name, ROOT_DEVICE_NAME.as_ptr());
        let mut dos_name = UNICODE_STRING::default();
        RtlInitUnicodeString(&mut dos_name, ROOT_DOS_NAME.as_ptr());

        let status = IoCreateDevice(
            driver_object, 0, &mut nt_dev_name,
            FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &mut device_object,
        );
        if !NT_SUCCESS(status) { return status; }

        (*device_object).Flags |= DO_DIRECT_IO;

        let link_status = IoCreateSymbolicLink(&mut dos_name, &mut nt_dev_name);
        if !NT_SUCCESS(link_status) { IoDeleteDevice(device_object); return link_status; }

        IoRegisterShutdownNotification(device_object);

        (*device_object).Flags &= !DO_DEVICE_INITIALIZING;
        driver::set_root_device(device_object);
        debug::kdbg("[Oxhide] root device created\n");
        STATUS_SUCCESS
    }
}

/// Process an IRP sent to the root control device.
pub fn process_root_device_irp(_dev: *mut DEVICE_OBJECT, irp: *mut IRP) -> NTSTATUS {
    debug::kdbg("[Oxhide] process_root_device_irp called\n");
    let major = unsafe { (*IoGetCurrentIrpStackLocation(irp)).MajorFunction };
    match major {
        IRP_MJ_CREATE | IRP_MJ_CLOSE | IRP_MJ_CLEANUP => {
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 0);
            STATUS_SUCCESS
        }
        IRP_MJ_SHUTDOWN => {
            // Unmount all volumes, then complete.
            mount::handle_unmount_all_volumes(irp)
        }
        IRP_MJ_DEVICE_CONTROL => process_root_device_ioctl(irp),
        _ => {
            irp_utils::complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

/// Handle IOCTLs sent to the root device.
fn process_root_device_ioctl(irp: *mut IRP) -> NTSTATUS {
    let ioctl = irp_utils::get_ioctl_code(irp);
    match ioctl {
        TC_IOCTL_GET_DRIVER_VERSION => {
            let buf = irp_utils::get_system_buffer::<u32>(irp);
            if !buf.is_null() { unsafe { *buf = DRIVER_VERSION; } }
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 4);
            STATUS_SUCCESS
        }
        TC_IOCTL_IS_ANY_VOLUME_MOUNTED => {
            let buf = irp_utils::get_system_buffer::<u32>(irp);
            let any = driver::volume_devices().iter().any(|d| !d.is_null());
            if !buf.is_null() { unsafe { *buf = any as u32; } }
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 4);
            STATUS_SUCCESS
        }
        TC_IOCTL_GET_DEVICE_REFCOUNT => {
            let buf = irp_utils::get_system_buffer::<u32>(irp);
            let dev = driver::root_device();
            let count = if dev.is_null() { 0 } else { unsafe { (*dev).ReferenceCount } };
            if !buf.is_null() { unsafe { *buf = count as u32; } }
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 4);
            STATUS_SUCCESS
        }
        TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED => {
            let buf = irp_utils::get_system_buffer::<u8>(irp);
            if !buf.is_null() { unsafe { *buf = TRUE; } }
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 1);
            STATUS_SUCCESS
        }
        TC_IOCTL_MOUNT_VOLUME => mount::handle_mount_volume(irp),
        TC_IOCTL_UNMOUNT_VOLUME => mount::handle_unmount_volume(irp),
        TC_IOCTL_UNMOUNT_ALL_VOLUMES => mount::handle_unmount_all_volumes(irp),
        TC_IOCTL_GET_MOUNTED_VOLUMES => mount::handle_get_mounted_volumes(irp),
        _ => {
            irp_utils::complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}
