//! `EXTENSION` — the per-device device-extension, embedded in
//! `DeviceObject.DeviceExtension`.  Mirrors VeraCrypt's `EXTENSION`
//! (`Ntdriver.h:48-119`) for the file-container subset.
//!
//! The struct is `#[repr(C)]` (natural alignment) so the kernel's zero-fill of
//! the extension by `IoCreateDevice` places every field at the correct offset.
//! Fields that must not be left zeroed (e.g. `KernelSectorCipher`) are stored
//! as raw pointers and allocated / freed explicitly in `TCOpenVolume` /
//! `TCCloseVolume`.

use crate::encrypted_io_queue::EncryptedIoQueue;
use crate::wdk_bindings::*;
use vcrypt_core::KernelSectorCipher;

#[repr(C)]
pub struct Extension {
    // ---------- Identity flags (must be first for root-device dispatch) ----------
    pub b_root_device: BOOLEAN,          // 1 for the root control device
    pub is_volume_device: BOOLEAN,       // 1 for a mounted volume device

    // ---------- Mount metadata ----------
    pub unique_volume_id: i32,           // monotonically increasing mount id
    pub n_dos_drive_no: i32,             // 0..25

    // ---------- Shutdown / thread control ----------
    pub b_shutting_down: BOOLEAN,
    pub b_thread_should_quit: BOOLEAN,

    pub pe_thread: PKTHREAD,             // referenced KTHREAD (VolumeThreadProc)
    pub ke_create_event: KEVENT,         // signalled when TCOpenVolume returns

    // ---------- DEVICE_CONTROL IRP queue (serviced by VolumeThreadProc) ----------
    pub list_spin_lock: KSPIN_LOCK,
    pub list_entry: LIST_ENTRY,          // head of queued IRP_MJ_DEVICE_CONTROL IRPs
    pub request_semaphore: KSEMAPHORE,   // wakes VolumeThreadProc

    // ---------- Host file ----------
    pub h_device_file: HANDLE,           // ZwCreateFile handle for the container file
    pub pfo_device_file: PFILE_OBJECT,   // ObReferenceObjectByHandle dup

    // ---------- Crypto ----------
    /// Heap-allocated `KernelSectorCipher` (Box → raw pointer).  Owned by the
    /// extension: freed + zeroized in `TCCloseVolume`.  NULL until `TCOpenVolume`.
    pub crypto_info: *mut KernelSectorCipher,

    /// Offset inside the host file where the encrypted data area begins.
    pub vol_data_area_offset: u64,
    /// The first XTS data-unit number for this volume (usually 0, or the number
    /// of sectors between volume start and the first encrypted byte for
    /// header-hidden volumes).
    pub first_data_unit_no: u64,

    // ---------- Dimensions / geometry ----------
    pub host_length: i64,                // host file size
    pub disk_length: i64,                // virtual disk size (data area length)
    pub number_of_cylinders: i64,
    pub tracks_per_cylinder: u32,
    pub sectors_per_track: u32,
    pub bytes_per_sector: u32,           // virtual sector size

    // ---------- Host device parameters (stored for IOCTL responses) ----------
    pub host_bytes_per_sector: u32,
    pub host_bytes_per_physical_sector: u32,
    pub host_maximum_transfer_length: u32,
    pub host_maximum_physical_pages: u32,
    pub host_alignment_mask: u32,
    pub host_device_number: u32,          // STORAGE_GET_DEVICE_NUMBER for extent reporting
    pub host_incurs_seek_penalty: BOOLEAN,
    pub host_trim_enabled: BOOLEAN,

    // ---------- Host IOCTL completion event (TCSendHostDeviceIoControlRequest) ----------
    pub ke_volume_event: KEVENT,

    // ---------- Embedded async encrypted-I/O engine ----------
    pub queue: EncryptedIoQueue,

    // ---------- Volume flags ----------
    pub b_read_only: BOOLEAN,
    pub b_removable: BOOLEAN,
    pub b_mount_manager: BOOLEAN,

    /// Host path (DOS form, e.g. `C:\foo.hc`).  Must be `TC_MAX_PATH` elements
    /// for `MOUNT_LIST_STRUCT` compatibility.
    pub wsz_volume: [u16; crate::types::TC_MAX_PATH],
    pub wsz_label: [u16; 33],
    pub volume_id: [u8; crate::types::VOLUME_ID_SIZE],  // SHA-256 of effective header

    // ---------- File timestamps (for preservation on unmount) ----------
    pub file_creation_time: i64,
    pub file_last_access_time: i64,
    pub file_last_write_time: i64,
    pub file_last_change_time: i64,
    pub b_timestamp_valid: BOOLEAN,
    pub b_preserve_timestamp: BOOLEAN,
}

impl Default for Extension {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

/// Access the extension from a device object, validating the `is_volume_device`
/// marker.  Returns `None` for the root device or a stale pointer.
pub unsafe fn volume_extension(dev: *mut DEVICE_OBJECT) -> Option<&'static mut Extension> {
    if dev.is_null() { return None; }
    let ext = (*dev).DeviceExtension as *mut Extension;
    if ext.is_null() { return None; }
    if (*ext).is_volume_device == 0 { return None; }
    Some(&mut *ext)
}

/// Access the extension from a device object without the `is_volume_device`
/// check (used by the root device dispatch, where the first byte is the
/// `b_root_device` flag but no full `Extension` is allocated).
pub unsafe fn root_extension(dev: *mut DEVICE_OBJECT) -> &'static mut Extension {
    &mut *((*dev).DeviceExtension as *mut Extension)
}
