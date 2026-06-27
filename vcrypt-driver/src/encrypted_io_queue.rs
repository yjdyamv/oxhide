//! Synchronous encrypted I/O pipeline — a correct single-thread implementation
//! that replaces the previous buggy `io_queue.rs` stub.
//!
//! Architecture: IRPs are processed inline in the dispatch routine (no worker
//! threads).  READ / WRITE do sector-aligned host I/O with XTS decrypt/encrypt
//! via `KernelSectorCipher`; FLUSH calls `ZwFlushBuffersFile`.
//!
//! The struct definitions match VeraCrypt's `EncryptedIoQueue.h` so that a
//! future phase can split this into the full 3-thread async queue without
//! changing the public API shape.

use crate::extension::Extension;
use crate::irp_utils;
use crate::wdk_bindings::*;
use vcrypt_core::KernelSectorCipher;

const ENCRYPTION_DATA_UNIT_SIZE: u64 = 512;

pub const TC_ENC_IO_QUEUE_MAX_FRAGMENT_SIZE: u32 = 256 * 1024;
pub const TC_ENC_IO_QUEUE_PREALLOCATED_ITEM_COUNT: u32 = 8;
pub const TC_ENC_IO_QUEUE_PREALLOCATED_IO_REQUEST_COUNT: u32 = 16;
pub const VC_MAX_WORK_ITEMS: u32 = 1024;

// ---------------------------------------------------------------------------
// Structs (match VeraCrypt EncryptedIoQueue.h)
// ---------------------------------------------------------------------------

#[repr(C)]
pub struct EncryptedIoQueueBuffer {
    pub next_buffer: *mut EncryptedIoQueueBuffer,
    pub address: PVOID,
    pub size: u32,
    pub in_use: BOOLEAN,
}

#[repr(C)]
pub struct CompleteIrpWorkItem {
    pub work_item: PIO_WORKITEM,
    pub irp: PIRP,
    pub status: NTSTATUS,
    pub information: ULONG_PTR,
    pub item: PVOID,
    pub queue: *mut EncryptedIoQueue,
    pub release_lock_and_counters: BOOLEAN,
    pub list_entry: LIST_ENTRY,
}

#[repr(C)]
pub struct EncryptedIoQueueItem {
    pub queue: *mut EncryptedIoQueue,
    pub original_irp: PIRP,
    pub write: BOOLEAN,
    pub flush: BOOLEAN,
    pub original_length: u32,
    pub original_offset: i64,
    pub status: NTSTATUS,
    pub temp_user_mdl: PMDL,
}

#[repr(C)]
pub struct EncryptedIoRequest {
    pub item: *mut EncryptedIoQueueItem,
    pub complete_original_irp: BOOLEAN,
    pub offset: i64,
    pub length: u32,
    pub encrypted_offset: i64,
    pub encrypted_length: u32,
    pub data: *mut u8,
    pub orig_data_buffer_fragment: *mut u8,
    pub list_entry: LIST_ENTRY,
    pub completion_list_entry: LIST_ENTRY,
}

#[repr(C)]
pub struct EncryptedIoQueue {
    pub device_object: PDEVICE_OBJECT,
    pub buffer_pool_mutex: KMUTEX,
    pub first_pool_buffer: *mut EncryptedIoQueueBuffer,
    pub crypto_info: *mut KernelSectorCipher,
    pub host_file_handle: HANDLE,
    pub virtual_device_length: i64,
    pub remove_lock: IO_REMOVE_LOCK,
    pub main_thread: PKTHREAD,
    pub main_thread_queue: LIST_ENTRY,
    pub main_thread_queue_lock: KSPIN_LOCK,
    pub main_thread_queue_not_empty_event: KEVENT,
    pub io_thread: PKTHREAD,
    pub io_thread_queue: LIST_ENTRY,
    pub io_thread_queue_lock: KSPIN_LOCK,
    pub io_thread_queue_not_empty_event: KEVENT,
    pub completion_thread: PKTHREAD,
    pub completion_thread_queue: LIST_ENTRY,
    pub completion_thread_queue_lock: KSPIN_LOCK,
    pub completion_thread_queue_not_empty_event: KEVENT,
    pub fragment_buffer_a: *mut u8,
    pub fragment_buffer_b: *mut u8,
    pub fragment_buffer_a_free_event: KEVENT,
    pub fragment_buffer_b_free_event: KEVENT,
    pub read_ahead_buffer_valid: BOOLEAN,
    pub last_read_offset: i64,
    pub last_read_length: u32,
    pub read_ahead_offset: i64,
    pub read_ahead_length: u32,
    pub read_ahead_buffer: *mut u8,
    pub max_read_ahead_offset: i64,
    pub outstanding_io_count: i32,
    pub no_outstanding_io_event: KEVENT,
    pub io_thread_pending_request_count: i32,
    pub pool_buffer_free_event: KEVENT,
    pub total_bytes_read: i64,
    pub total_bytes_written: i64,
    pub start_pending: BOOLEAN,
    pub thread_exit_requested: BOOLEAN,
    pub suspended: BOOLEAN,
    pub suspend_pending: BOOLEAN,
    pub stop_pending: BOOLEAN,
    pub queue_resumed_event: KEVENT,
    pub thread_block_read_write: BOOLEAN,
    pub fragment_size: i32,
    pub work_item_pool: *mut CompleteIrpWorkItem,
    pub max_work_items: u32,
    pub free_work_items_list: LIST_ENTRY,
    pub work_item_semaphore: KSEMAPHORE,
    pub work_item_lock: KSPIN_LOCK,
    pub active_work_items: i32,
    pub no_active_work_items_event: KEVENT,
}

impl Default for EncryptedIoQueue {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

// ===========================================================================
// Public API
// ===========================================================================

/// Start the queue (synchronous mode: just initialise the remove lock and
/// set the host handles so that `add_irp` can access them).  The full 3-thread
/// async startup (buffer pool, fragment buffers, work-item pool, thread spawn)
/// will be added when the async mode is implemented.
pub fn start(queue: *mut EncryptedIoQueue) -> NTSTATUS {
    unsafe {
        let q = &mut *queue;
        let device = q.device_object;
        let ext = &*((*device).DeviceExtension as *const Extension);

        IoInitializeRemoveLockEx(
            &mut q.remove_lock,
            u32::from_ne_bytes(*b"OxRL"),
            0, 0,
            core::mem::size_of::<IO_REMOVE_LOCK>() as u32,
        );

        q.crypto_info = ext.crypto_info;
        q.host_file_handle = ext.h_device_file;
        q.virtual_device_length = ext.disk_length;
        q.stop_pending = FALSE;

        STATUS_SUCCESS
    }
}

pub fn stop(_queue: *mut EncryptedIoQueue) -> NTSTATUS {
    STATUS_SUCCESS
}

pub fn is_running(queue: *mut EncryptedIoQueue) -> bool {
    unsafe { (*queue).stop_pending == FALSE }
}

pub fn is_suspended(queue: *mut EncryptedIoQueue) -> bool {
    unsafe { (*queue).suspended != FALSE }
}

/// Process a READ/WRITE/FLUSH IRP synchronously (inline, no worker threads).
///
/// Must be called at `PASSIVE_LEVEL` (file I/O via `ZwReadFile`/`ZwWriteFile`
/// requires PASSIVE).  The dispatch routine runs at PASSIVE, so this is safe.
pub fn add_irp(queue: *mut EncryptedIoQueue, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        let q = &*queue;
        let stack = IoGetCurrentIrpStackLocation(irp);
        let major = (*stack).MajorFunction;

        match major {
            IRP_MJ_READ => process_read_irp(q, irp),
            IRP_MJ_WRITE => process_write_irp(q, irp),
            IRP_MJ_FLUSH_BUFFERS => process_flush_irp(q, irp),
            _ => {
                irp_utils::complete_disk_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
                STATUS_INVALID_DEVICE_REQUEST
            }
        }
    }
}

// ===========================================================================
// READ
// ===========================================================================

unsafe fn process_read_irp(queue: &EncryptedIoQueue, irp: *mut IRP) -> NTSTATUS {
    let device = queue.device_object;
    let ext = &*((*device).DeviceExtension as *const Extension);
    let cipher = &*ext.crypto_info;

    let (virtual_offset, length) = irp_utils::get_read_params(irp);
    if length == 0 {
        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    if virtual_offset < 0 {
        irp_utils::complete_disk_irp(irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }
    let voff = virtual_offset as u64;
    let l = length as u64;

    if voff + l > ext.disk_length as u64 {
        irp_utils::complete_disk_irp(irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    let host_offset = ext.vol_data_area_offset + voff;
    let aligned_off = (host_offset / ENCRYPTION_DATA_UNIT_SIZE) * ENCRYPTION_DATA_UNIT_SIZE;
    let end_byte = host_offset + l;
    let aligned_end = ((end_byte + ENCRYPTION_DATA_UNIT_SIZE - 1) / ENCRYPTION_DATA_UNIT_SIZE) * ENCRYPTION_DATA_UNIT_SIZE;
    let buf_size = (aligned_end - aligned_off) as usize;
    let sector_count = buf_size / ENCRYPTION_DATA_UNIT_SIZE as usize;

    let sector_buf = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        buf_size,
        u32::from_ne_bytes(*b"OxRd"),
    ) as *mut u8;
    if sector_buf.is_null() {
        irp_utils::complete_disk_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let sector_slice = core::slice::from_raw_parts_mut(sector_buf, buf_size);

    // Read from host file
    let mut byte_offset = aligned_off as i64;
    let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let status = ZwReadFile(
        ext.h_device_file,
        core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
        &mut iosb,
        sector_buf as PVOID, buf_size as u32,
        &mut byte_offset, core::ptr::null_mut(),
    );
    if !NT_SUCCESS(status) {
        ExFreePool(sector_buf as PVOID);
        irp_utils::complete_disk_irp(irp, status, 0);
        return status;
    }

    // XTS decrypt each 512-byte sector
    let base_unit = ext.first_data_unit_no + (aligned_off - ext.vol_data_area_offset) / ENCRYPTION_DATA_UNIT_SIZE;
    for i in 0..sector_count {
        let sd = &mut sector_slice[i * 512..(i + 1) * 512];
        if let Err(_e) = cipher.decrypt_sector(base_unit + i as u64, sd) {
            ExFreePool(sector_buf as PVOID);
            irp_utils::complete_disk_irp(irp, STATUS_DISK_CORRUPT_ERROR, 0);
            return STATUS_DISK_CORRUPT_ERROR;
        }
    }

    // Copy to user buffer
    let user_off = (host_offset - aligned_off) as usize;
    if !copy_to_user_buffer(irp, &sector_slice[user_off..user_off + l as usize]) {
        ExFreePool(sector_buf as PVOID);
        irp_utils::complete_disk_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    ExFreePool(sector_buf as PVOID);
    irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, l as ULONG_PTR);
    STATUS_SUCCESS
}

// ===========================================================================
// WRITE
// ===========================================================================
unsafe fn process_write_irp(queue: &EncryptedIoQueue, irp: *mut IRP) -> NTSTATUS {
    let device = queue.device_object;
    let ext = &*((*device).DeviceExtension as *const Extension);
    let cipher = &*ext.crypto_info;

    if ext.b_read_only != 0 {
        irp_utils::complete_disk_irp(irp, STATUS_MEDIA_WRITE_PROTECTED, 0);
        return STATUS_MEDIA_WRITE_PROTECTED;
    }

    let (virtual_offset, length) = irp_utils::get_write_params(irp);
    if length == 0 {
        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }
    if virtual_offset < 0 {
        irp_utils::complete_disk_irp(irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }
    let voff = virtual_offset as u64;
    let l = length as u64;

    if voff + l > ext.disk_length as u64 {
        irp_utils::complete_disk_irp(irp, STATUS_INVALID_PARAMETER, 0);
        return STATUS_INVALID_PARAMETER;
    }

    let host_offset = ext.vol_data_area_offset + voff;
    let aligned_off = (host_offset / ENCRYPTION_DATA_UNIT_SIZE) * ENCRYPTION_DATA_UNIT_SIZE;
    let end_byte = host_offset + l;
    let aligned_end = ((end_byte + ENCRYPTION_DATA_UNIT_SIZE - 1) / ENCRYPTION_DATA_UNIT_SIZE) * ENCRYPTION_DATA_UNIT_SIZE;
    let buf_size = (aligned_end - aligned_off) as usize;
    let sector_count = buf_size / ENCRYPTION_DATA_UNIT_SIZE as usize;

    let sector_buf = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        buf_size,
        u32::from_ne_bytes(*b"OxWr"),
    ) as *mut u8;
    if sector_buf.is_null() {
        irp_utils::complete_disk_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    let sector_slice = core::slice::from_raw_parts_mut(sector_buf, buf_size);

    // Read existing encrypted sectors (read-modify-write)
    let mut byte_offset = aligned_off as i64;
    let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let read_status = ZwReadFile(
        ext.h_device_file,
        core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
        &mut iosb,
        sector_buf as PVOID, buf_size as u32,
        &mut byte_offset, core::ptr::null_mut(),
    );
    if !NT_SUCCESS(read_status) {
        ExFreePool(sector_buf as PVOID);
        irp_utils::complete_disk_irp(irp, read_status, 0);
        return read_status;
    }

    // Overlay user data
    let user_off = (host_offset - aligned_off) as usize;
    if !copy_from_user_buffer(irp, &mut sector_slice[user_off..user_off + l as usize]) {
        ExFreePool(sector_buf as PVOID);
        irp_utils::complete_disk_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // XTS encrypt each 512-byte sector
    let base_unit = ext.first_data_unit_no + (aligned_off - ext.vol_data_area_offset) / ENCRYPTION_DATA_UNIT_SIZE;
    for i in 0..sector_count {
        let sd = &mut sector_slice[i * 512..(i + 1) * 512];
        if let Err(_e) = cipher.encrypt_sector(base_unit + i as u64, sd) {
            ExFreePool(sector_buf as PVOID);
            irp_utils::complete_disk_irp(irp, STATUS_DISK_CORRUPT_ERROR, 0);
            return STATUS_DISK_CORRUPT_ERROR;
        }
    }

    // Write back to host file
    let mut w_offset = aligned_off as i64;
    let mut w_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let w_status = ZwWriteFile(
        ext.h_device_file,
        core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
        &mut w_iosb,
        sector_buf as PVOID, buf_size as u32,
        &mut w_offset, core::ptr::null_mut(),
    );

    ExFreePool(sector_buf as PVOID);
    if !NT_SUCCESS(w_status) {
        irp_utils::complete_disk_irp(irp, w_status, 0);
        return w_status;
    }

    irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, l as ULONG_PTR);
    STATUS_SUCCESS
}

// ===========================================================================
// FLUSH
// ===========================================================================
unsafe fn process_flush_irp(queue: &EncryptedIoQueue, irp: *mut IRP) -> NTSTATUS {
    let device = queue.device_object;
    let ext = &*((*device).DeviceExtension as *const Extension);

    if ext.b_read_only != 0 {
        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
        return STATUS_SUCCESS;
    }

    let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let status = ZwFlushBuffersFile(ext.h_device_file, &mut iosb);
    if !NT_SUCCESS(status) {
        irp_utils::complete_disk_irp(irp, status, 0);
        return status;
    }

    irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
    STATUS_SUCCESS
}

// ===========================================================================
// Buffer mapping helpers
// ===========================================================================

/// Copy data from the sector buffer into the user’s buffer (MDL or SystemBuffer).
unsafe fn copy_to_user_buffer(irp: *mut IRP, data: &[u8]) -> bool {
    let mdl = (*irp).MdlAddress;
    if !mdl.is_null() {
        let user_va = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if user_va.is_null() { return false; }
        core::ptr::copy_nonoverlapping(data.as_ptr(), user_va as *mut u8, data.len());
        return true;
    }

    // Fallback: buffered I/O
    let sys = (*irp).AssociatedIrp.SystemBuffer;
    if !sys.is_null() {
        core::ptr::copy_nonoverlapping(data.as_ptr(), sys as *mut u8, data.len());
        return true;
    }

    false
}

/// Copy data from the user’s buffer (MDL or SystemBuffer) into the sector buffer.
unsafe fn copy_from_user_buffer(irp: *mut IRP, data: &mut [u8]) -> bool {
    let mdl = (*irp).MdlAddress;
    if !mdl.is_null() {
        let user_va = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
        if user_va.is_null() { return false; }
        core::ptr::copy_nonoverlapping(user_va as *const u8, data.as_mut_ptr(), data.len());
        return true;
    }

    let sys = (*irp).AssociatedIrp.SystemBuffer;
    if !sys.is_null() {
        core::ptr::copy_nonoverlapping(sys as *const u8, data.as_mut_ptr(), data.len());
        return true;
    }

    false
}
