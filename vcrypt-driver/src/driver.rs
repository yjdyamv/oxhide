//! Driver entry point, global state, and IRP dispatch.
//!
//! 1:1 translation of VeraCrypt `DriverEntry`, `TCDispatchQueueIRP`,
//! `TCUnloadDriver`, `OnShutdownPending`.

use crate::debug;
use crate::device;
use crate::encrypted_io_queue;
use crate::extension::{self, Extension};
use crate::irp_utils;
use crate::types;
use crate::volume_ioctl;
use crate::volume_thread;
use crate::wdk_bindings::*;

static mut VOLUME_DEVICES: [*mut DEVICE_OBJECT; types::MAX_DRIVE] =
    [core::ptr::null_mut(); types::MAX_DRIVE];
static mut ROOT_DEVICE: *mut DEVICE_OBJECT = core::ptr::null_mut();
static mut LAST_VOLUME_ID: i32 = 0;

pub type DRIVER_DISPATCH = unsafe extern "system" fn(*mut DEVICE_OBJECT, *mut IRP) -> NTSTATUS;
pub type DRIVER_UNLOAD = unsafe extern "system" fn(*mut DRIVER_OBJECT);

#[export_name = "DriverEntry"]
pub unsafe extern "system" fn driver_entry(
    driver_object: *mut DRIVER_OBJECT,
    _registry_path: *mut UNICODE_STRING,
) -> NTSTATUS {
    // DIAGNOSIS: return failure immediately to confirm DriverEntry is called
    // return 0xC0000001u32 as i32; // STATUS_UNSUCCESSFUL

    // Use hardcoded offset 0x70 for MajorFunction (verified against WDK wdm.h
    // x64 layout).
    let major_func_base = (driver_object as *mut u8).add(0x70) as *mut PVOID;
    for i in 0..=IRP_MJ_MAXIMUM_FUNCTION as usize {
        *major_func_base.add(i) = tc_dispatch_queue_irp as PVOID;
    }
    // DriverUnload @ 0x68
    let driver_unload_ptr = (driver_object as *mut u8).add(0x68) as *mut PVOID;
    *driver_unload_ptr = tc_unload_driver as PVOID;

    // Verify the write succeeded
    let check = *major_func_base.add(IRP_MJ_DEVICE_CONTROL as usize);
    if check != tc_dispatch_queue_irp as PVOID {
        // MajorFunction write failed — return error
        return 0xC0000001u32 as i32;
    }

    device::create_root_device(driver_object)
}

unsafe extern "system" fn tc_unload_driver(_driver_object: *mut DRIVER_OBJECT) {
    for i in 0..types::MAX_DRIVE {
        let dev = VOLUME_DEVICES[i];
        if !dev.is_null() {
            VOLUME_DEVICES[i] = core::ptr::null_mut();
            let ext = &mut *((*dev).DeviceExtension as *mut Extension);
            ext.b_shutting_down = TRUE;
            volume_thread::tc_stop_volume_thread(ext);
            IoDeleteDevice(dev);
        }
    }

    if !ROOT_DEVICE.is_null() {
        IoUnregisterShutdownNotification(ROOT_DEVICE);
        let mut d = device::dos_device_name();
        IoDeleteSymbolicLink(&mut d);
        IoDeleteDevice(ROOT_DEVICE);
        ROOT_DEVICE = core::ptr::null_mut();
    }
}

unsafe extern "system" fn tc_dispatch_queue_irp(
    device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let is_root = device_object == ROOT_DEVICE;

    if is_root {
        return dispatch_root(device_object, irp);
    }

    // For non-root (volume) devices, handle create/close/cleanup simply
    // and complete everything else with invalid request for now.
    let major = (*IoGetCurrentIrpStackLocation(irp)).MajorFunction;
    match major {
        IRP_MJ_CREATE | IRP_MJ_CLOSE | IRP_MJ_CLEANUP => {
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 0);
            STATUS_SUCCESS
        }
        _ => {
            irp_utils::complete_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

unsafe fn dispatch_root(
    device_object: *mut DEVICE_OBJECT,
    irp: *mut IRP,
) -> NTSTATUS {
    let major = (*IoGetCurrentIrpStackLocation(irp)).MajorFunction;

    // Handle CREATE/CLOSE/CLEANUP directly
    if major == IRP_MJ_CREATE || major == IRP_MJ_CLOSE || major == IRP_MJ_CLEANUP {
        irp_utils::complete_irp(irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }

    // Handle SHUTDOWN
    if major == IRP_MJ_SHUTDOWN {
        for i in 0..types::MAX_DRIVE {
            let dev = VOLUME_DEVICES[i];
            if !dev.is_null() {
                VOLUME_DEVICES[i] = core::ptr::null_mut();
                let ext = &mut *((*dev).DeviceExtension as *mut Extension);
                ext.b_shutting_down = TRUE;
                volume_thread::tc_stop_volume_thread(ext);
                IoDeleteDevice(dev);
            }
        }
        irp_utils::complete_irp(irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }

    // For DEVICE_CONTROL and anything else, delegate to the root device handler
    device::process_root_device_irp(device_object, irp)
}

pub fn volume_devices() -> &'static [*mut DEVICE_OBJECT; types::MAX_DRIVE] {
    unsafe { &VOLUME_DEVICES }
}
pub fn volume_devices_mut() -> &'static mut [*mut DEVICE_OBJECT; types::MAX_DRIVE] {
    unsafe { &mut VOLUME_DEVICES }
}
pub fn root_device() -> *mut DEVICE_OBJECT { unsafe { ROOT_DEVICE } }
pub fn set_root_device(dev: *mut DEVICE_OBJECT) { unsafe { ROOT_DEVICE = dev; } }
pub fn next_volume_id() -> i32 {
    unsafe {
        LAST_VOLUME_ID += 1;
        LAST_VOLUME_ID
    }
}
