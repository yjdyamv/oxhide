//! Per-volume worker thread (`VolumeThreadProc`) — 1:1 translation of
//! VeraCrypt `Ntdriver.c:3254`.
//!
//! Each mounted volume gets a dedicated system thread that:
//! 1. Normalises the mount path (prepends `\??\` to DOS paths).
//! 2. Calls `tc_open_volume` (file-hosted hybrid mode).
//! 3. Starts the `EncryptedIoQueue`.
//! 4. Enters a main loop: waits on `RequestSemaphore`, drains the
//!    `DEVICE_CONTROL` IRP queue (`ListEntry`), and dispatches each IRP
//!    to `process_volume_device_control`.
//! 5. On shutdown: stops the I/O queue, closes the volume, terminates itself.

use crate::debug;
use crate::encrypted_io_queue;
use crate::extension::Extension;
use crate::ntvol;
use crate::types;
use crate::wdk_bindings::*;

/// Context passed to `VolumeThreadProc` via `PsCreateSystemThread`.
#[repr(C)]
pub struct ThreadBlock {
    pub device_object: *mut DEVICE_OBJECT,
    pub nt_create_status: NTSTATUS, // set by VolumeThreadProc, read by starter
    pub mount: types::MountStruct,  // full packed struct (byte-copied from user buffer)
}

impl Default for ThreadBlock {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// Wrapper for a single IRP queued on `Extension.list_entry`.
#[repr(C)]
struct QueuedIrp {
    /// Must be the first field — `ExInterlockedRemoveHeadList` returns a
    /// pointer to this, and we recover the `QueuedIrp*` via cast.
    pub list_entry: LIST_ENTRY,
    pub irp: *mut IRP,
}

/// Enqueue a `DEVICE_CONTROL` IRP on a volume's request list (called from
/// the dispatch routine).  The caller must have already called
/// `IoAcquireRemoveLock` and `IoMarkIrpPending` on the IRP.
pub unsafe fn enqueue_device_control_irp(ext: &mut Extension, irp: *mut IRP) {
    let qirp = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        core::mem::size_of::<QueuedIrp>(),
        u32::from_ne_bytes(*b"OxQp"),
    ) as *mut QueuedIrp;
    if qirp.is_null() {
        // OOM — complete the IRP with an error.
        crate::irp_utils::complete_disk_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
        return;
    }
    (*qirp).irp = irp;
    ExInterlockedInsertTailList(
        &mut ext.list_entry,
        &mut (*qirp).list_entry,
        &mut ext.list_spin_lock,
    );
    KeReleaseSemaphore(&mut ext.request_semaphore, 0, 1, FALSE);
}

/// Create and start a volume worker thread.  Blocks until the thread signals
/// `keCreateEvent` (i.e. until `TCOpenVolume` completes or fails).
pub unsafe fn tc_start_volume_thread(
    device_object: *mut DEVICE_OBJECT,
    ext: &mut Extension,
    thread_block: *mut ThreadBlock,
) -> NTSTATUS {
    // Initialise the create-event (signaled by VolumeThreadProc on completion).
    KeInitializeEvent(&mut ext.ke_create_event, SynchronizationEvent, FALSE);

    (*thread_block).device_object = device_object;
    (*thread_block).nt_create_status = STATUS_PENDING;

    let mut thread_handle: HANDLE = core::ptr::null_mut();
    let status = PsCreateSystemThread(
        &mut thread_handle,
        GENERIC_ALL,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        core::ptr::null_mut(),
        volume_thread_proc as PKSTART_ROUTINE,
        thread_block as PVOID,
    );
    if !NT_SUCCESS(status) {
        debug::kdbg_status("[Oxhide] PsCreateSystemThread failed", status);
        return status;
    }

    // Wait for the thread to finish TCOpenVolume (signals keCreateEvent).
    // NULL timeout => infinite wait.
    KeWaitForSingleObject(
        &mut ext.ke_create_event as *mut KEVENT as PVOID,
        Executive,
        KernelMode,
        FALSE,
        core::ptr::null_mut(),
    );

    // Reference the thread object so we can stop it later.
    let mut thread_obj: PVOID = core::ptr::null_mut();
    ObReferenceObjectByHandle(
        thread_handle,
        GENERIC_ALL,
        core::ptr::null_mut(),
        KernelMode,
        &mut thread_obj,
        core::ptr::null_mut(),
    );
    ZwClose(thread_handle);

    ext.pe_thread = thread_obj as PKTHREAD;

    (*thread_block).nt_create_status
}

/// Signal the volume thread to stop, wait for it, and dereference.
pub unsafe fn tc_stop_volume_thread(ext: &mut Extension) {
    ext.b_thread_should_quit = TRUE;
    // Wake the thread if it is waiting on the request semaphore.
    KeReleaseSemaphore(&mut ext.request_semaphore, 0, 1, FALSE);

    if !ext.pe_thread.is_null() {
        // NULL timeout => infinite wait, ensuring the volume thread has fully
        // exited (and released the host file / cipher) before we delete the
        // device object.  A zero timeout would return immediately and let
        // IoDeleteDevice race the still-running thread.
        KeWaitForSingleObject(
            ext.pe_thread as PVOID,
            Executive,
            KernelMode,
            FALSE,
            core::ptr::null_mut(),
        );
        ObfDereferenceObject(ext.pe_thread as PVOID);
        ext.pe_thread = core::ptr::null_mut();
    }
}

/// Per-volume worker thread entry point.
///
/// 1. Copies the packed `MountStruct` from `context` → aligned stack buffer,
///    extracts the fields, calls `tc_open_volume`.
/// 2. On success, starts the `EncryptedIoQueue`.
/// 3. Main loop: drain `DEVICE_CONTROL` IRPs from `ListEntry`, dispatch to
///    `process_volume_device_control`, and `IoReleaseRemoveLock` each one.
/// 4. On `b_thread_should_quit`: stop the queue, close the volume, terminate.
unsafe extern "system" fn volume_thread_proc(context: PVOID) {
    let block = &mut *(context as *mut ThreadBlock);
    let device = block.device_object;
    let ext = &mut *((*device).DeviceExtension as *mut Extension);

    // Set low-realtime priority (matching VeraCrypt Ntdriver.c:3262).
    KeSetPriorityThread(PsGetCurrentThread(), LOW_REALTIME_PRIORITY);

    // --- Extract fields from the packed MountStruct ---
    let m = &block.mount;
    let drive_no = types::read_packed_i32(core::ptr::addr_of!(m.n_dos_drive_no));

    // Build host path from wsz_volume (raw bytes — read the u16 array as bytes).
    let wsz_ptr = core::ptr::addr_of!(m.wsz_volume) as *const u16;
    // Scan length
    let mut path_len = 0usize;
    while path_len < types::TC_MAX_PATH && *wsz_ptr.add(path_len) != 0 { path_len += 1; }
    // Build NT path (\??\prefix + user path)
    let prefix: [u16; 4] = [0x5C, 0x3F, 0x3F, 0x5C]; // \??\
    let _total_len = 4 + path_len + 1; // +1 for null
    let mut nt_path = [0u16; types::TC_MAX_PATH + 8]; // enough for \??\ + TC_MAX_PATH
    for (i, &c) in prefix.iter().enumerate() {
        nt_path[i] = c;
    }
    for i in 0..path_len {
        nt_path[4 + i] = *wsz_ptr.add(i);
    }
    nt_path[4 + path_len] = 0;

    let ea = types::read_packed_u32(core::ptr::addr_of!(m.ea));
    let key_len = {
        // Determine the cipher from ea to know key size
        match crate::crypto::cipher_type_from_ea(ea) {
            Some(ct) => (ct.key_size() * 2).min(types::MASTER_KEY_MAX_SIZE),
            None => 0,
        }
    };
    let key_src = core::ptr::addr_of!(m.master_key) as *const u8;
    let mut key_buf: [u8; types::MASTER_KEY_MAX_SIZE] = [0u8; types::MASTER_KEY_MAX_SIZE];
    if key_len > 0 {
        core::ptr::copy_nonoverlapping(key_src, key_buf.as_mut_ptr(), key_len);
    }
    let data_offset = types::read_packed_u64(core::ptr::addr_of!(m.data_offset));
    let disk_length = types::read_packed_u64(core::ptr::addr_of!(m.disk_length)) as u64;
    let bytes_per_sector = types::read_packed_u32(core::ptr::addr_of!(m.bytes_per_sector));
    let read_only = types::read_packed_u8(core::ptr::addr_of!(m.mount_read_only));
    let removable = types::read_packed_u8(core::ptr::addr_of!(m.mount_removable));
    let preserve_ts = types::read_packed_u8(core::ptr::addr_of!(m.preserve_timestamps)) != 0;
    let exclusive = true; // Default exclusive for now

    // --- TCOpenVolume ---
    let nt_status = ntvol::tc_open_volume(
        device,
        ext,
        nt_path.as_ptr(),
        ea,
        &key_buf[..key_len],
        data_offset,
        disk_length,
        bytes_per_sector,
        read_only,
        removable,
        true,   // mount_manager (always enabled per plan)
        preserve_ts,
        exclusive,
    );
    debug::kdbg_status("[Oxhide] tc_open_volume returned", nt_status);

    // Zeroize the local key buffer.
    key_buf.fill(0);

    block.nt_create_status = nt_status;

    if !NT_SUCCESS(nt_status) {
        // Signal starter and terminate.
        KeSetEvent(&mut ext.ke_create_event, 0, FALSE);
        PsTerminateSystemThread(nt_status);
        return;
    }

    // --- Start the EncryptedIoQueue ---
    ext.queue.device_object = device;
    let q_status = encrypted_io_queue::start(&mut ext.queue);
    if !NT_SUCCESS(q_status) {
        tc_close_and_cleanup(ext);
        block.nt_create_status = q_status;
        KeSetEvent(&mut ext.ke_create_event, 0, FALSE);
        PsTerminateSystemThread(q_status);
        return;
    }

    ext.n_dos_drive_no = drive_no;
    ext.b_mount_manager = TRUE;

    // Signal the starter (TCStartVolumeThread) that we're done.
    KeSetEvent(&mut ext.ke_create_event, 0, FALSE);

    // The THREAD_BLOCK may be freed by the starter after keCreateEvent;
    // do not access `block` or `m` beyond this point.
    // (block is allocated by TCStartVolumeThread and freed after the wait.)

    // ===================================================================
    // Main loop — service DEVICE_CONTROL IRPs
    // ===================================================================
    loop {
        // Block until an IRP is queued (infinite wait via NULL timeout).
        KeWaitForSingleObject(
            &mut ext.request_semaphore as *mut KSEMAPHORE as PVOID,
            Executive,
            KernelMode,
            FALSE,
            core::ptr::null_mut(), // NULL = infinite wait
        );

        if ext.b_thread_should_quit != 0 {
            break;
        }

        // Drain all queued IRPs.
        loop {
            let entry = ExInterlockedRemoveHeadList(
                &mut ext.list_entry,
                &mut ext.list_spin_lock,
            );
            if entry.is_null() {
                break;
            }

            // entry points to the LIST_ENTRY embedded in our QueuedIrp wrapper.
            // Recover the QueuedIrp pointer (LIST_ENTRY is the first field).
            let qirp = entry as *mut QueuedIrp;
            let irp = (*qirp).irp;

            crate::volume_ioctl::process_volume_device_control(ext, irp);

            // Release the remove lock that the dispatch acquired.
            IoReleaseRemoveLockEx(
                &mut ext.queue.remove_lock,
                core::ptr::null_mut(),
                core::mem::size_of::<IO_REMOVE_LOCK>() as u32,
            );

            // Free the wrapper struct.
            ExFreePool(qirp as PVOID);
        }

        if ext.b_thread_should_quit != 0 {
            break;
        }
    }

    // ===================================================================
    // Cleanup
    // ===================================================================
    tc_close_and_cleanup(ext);
    PsTerminateSystemThread(STATUS_SUCCESS);
}

/// Helper called both on mount failure and normal shutdown.
unsafe fn tc_close_and_cleanup(ext: &mut Extension) {
    encrypted_io_queue::stop(&mut ext.queue);
    ntvol::tc_close_volume(ext);
}
