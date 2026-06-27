//! IRP utility helpers — safe wrappers around common IRP operations.

use crate::wdk_bindings::*;

/// `TCCompleteIrp` — complete an IRP with `IO_NO_INCREMENT`.
pub fn complete_irp(irp: *mut IRP, status: NTSTATUS, information: ULONG_PTR) {
    unsafe {
        let io_status = IoGetIoStatusBlock(irp);
        if !io_status.is_null() {
            (*io_status).Information = information;
            (*io_status).Status = status;
        }
        IoCompleteRequest(irp, IO_NO_INCREMENT);
    }
}

/// `TCCompleteDiskIrp` — complete a disk IRP: `IO_DISK_INCREMENT` on success,
/// `IO_NO_INCREMENT` on failure (matching VeraCrypt `Ntdriver.c`).
pub fn complete_disk_irp(irp: *mut IRP, status: NTSTATUS, information: ULONG_PTR) {
    unsafe {
        let io_status = IoGetIoStatusBlock(irp);
        if !io_status.is_null() {
            (*io_status).Information = information;
            (*io_status).Status = status;
        }
        let boost = if NT_SUCCESS(status) { IO_DISK_INCREMENT } else { IO_NO_INCREMENT };
        IoCompleteRequest(irp, boost);
    }
}

/// Mark the IRP pending (`IoMarkIrpPending`).
#[inline]
pub fn mark_pending(irp: *mut IRP) {
    unsafe { IoMarkIrpPending(irp) }
}

/// Extract the IOCTL code from the current IRP stack location (typed read).
pub fn get_ioctl_code(irp: *mut IRP) -> u32 {
    unsafe { (*IoGetCurrentIrpStackLocation(irp)).Parameters.DeviceIoControl.IoControlCode }
}

/// Get the system buffer for a buffered IOCTL.
pub fn get_system_buffer<T>(irp: *mut IRP) -> *mut T {
    unsafe { (*irp).AssociatedIrp.SystemBuffer as *mut T }
}

/// Get the input buffer length (typed read).
pub fn get_input_buffer_length(irp: *mut IRP) -> u32 {
    unsafe { (*IoGetCurrentIrpStackLocation(irp)).Parameters.DeviceIoControl.InputBufferLength }
}

/// Get the output buffer length (typed read).
pub fn get_output_buffer_length(irp: *mut IRP) -> u32 {
    unsafe { (*IoGetCurrentIrpStackLocation(irp)).Parameters.DeviceIoControl.OutputBufferLength }
}

/// Read the Read parameters (offset/length) from the current stack location.
pub unsafe fn get_read_params(irp: *mut IRP) -> (i64, u32) {
    let p = (*IoGetCurrentIrpStackLocation(irp)).Parameters.Read;
    (p.ByteOffset, p.Length)
}

/// Read the Write parameters (offset/length) from the current stack location.
pub unsafe fn get_write_params(irp: *mut IRP) -> (i64, u32) {
    let p = (*IoGetCurrentIrpStackLocation(irp)).Parameters.Write;
    (p.ByteOffset, p.Length)
}

/// Validate that the IRP's output buffer is at least `required` bytes; if not,
/// zero-fill the output buffer and complete with `STATUS_BUFFER_TOO_SMALL`.
/// Returns true if the buffer is large enough.
pub fn validate_output_size(irp: *mut IRP, required: usize) -> bool {
    let out_len = get_output_buffer_length(irp) as usize;
    if out_len < required {
        unsafe {
            let sys = get_system_buffer::<u8>(irp);
            if !sys.is_null() {
                let n = out_len.min(required.max(out_len));
                core::ptr::write_bytes(sys, 0, n.min(out_len));
            }
            complete_irp(irp, STATUS_BUFFER_TOO_SMALL, required as ULONG_PTR);
        }
        false
    } else {
        true
    }
}
