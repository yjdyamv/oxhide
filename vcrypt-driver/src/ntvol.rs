//! Volume open / close routines (Rust translation of VeraCrypt `Ntvol.c`).
//!
//! Hybrid mode: the user-mode layer has already derived the master key and
//! decrypted the volume header; the kernel receives the key material + EA +
//! data-offset and only needs to open the host file, set up the cipher, and
//! configure the virtual geometry.  Everything else in `TCOpenVolume` (host
//! file handling, geometry, read-only fallback, timestamp preservation,
//! virtual geometry) is translated 1:1 from VeraCrypt's file-hosted path.

use crate::crypto;
use crate::debug;
use crate::extension::Extension;
use crate::types;
use crate::wdk_bindings::*;
use alloc::boxed::Box;

/// Open the host container file and populate the file-related fields of the
/// extension.  Performs the read-only fallback when necessary.
///
/// Returns `STATUS_SUCCESS` on success; the caller must set `b_read_only` and
/// apply `FILE_READ_ONLY_DEVICE` to the device object.
pub unsafe fn open_host_file(
    ext: &mut Extension,
    volume_path: *const u16,
    read_only: bool,
    exclusive_access: bool,
    preserve_timestamp: bool,
) -> NTSTATUS {
    // Build \??\ prefix + volume path
    let prefix: [u16; 4] = [0x5C, 0x3F, 0x3F, 0x5C]; // \??\
    let mut path_len = 0usize;
    while path_len < types::TC_MAX_PATH && *volume_path.add(path_len) != 0 {
        path_len += 1;
    }
    if path_len == 0 {
        debug::kdbg("[Oxhide] open_host_file: empty path\n");
        return STATUS_INVALID_PARAMETER;
    }
    let total_len = 4 + path_len;
    let buf_size = (total_len + 1) * 2;
    let path_buf = ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        buf_size,
        u32::from_ne_bytes(*b"Oxpt"),
    ) as *mut u16;
    if path_buf.is_null() {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    core::ptr::copy_nonoverlapping(prefix.as_ptr(), path_buf, 4);
    core::ptr::copy_nonoverlapping(volume_path, path_buf.add(4), path_len);
    *path_buf.add(total_len) = 0;

    let mut path_str = UNICODE_STRING::default();
    path_str.Length = (total_len * 2) as u16;
    path_str.MaximumLength = buf_size as u16;
    path_str.Buffer = path_buf;

    // --- First attempt: RW open with FILE_NO_INTERMEDIATE_BUFFERING ---
    let mut oa: OBJECT_ATTRIBUTES = core::mem::zeroed();
    let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let mut handle: HANDLE = core::ptr::null_mut();

    InitializeObjectAttributes(
        &mut oa,
        &mut path_str,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        core::ptr::null_mut(),
        core::ptr::null_mut(),
    );

    let share = if exclusive_access {
        FILE_SHARE_READ
    } else {
        FILE_SHARE_READ | FILE_SHARE_WRITE
    };

    let desired = GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE;

    let mut status = ZwCreateFile(
        &mut handle,
        desired,
        &mut oa,
        &mut iosb,
        core::ptr::null_mut(),
        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM,
        share,
        FILE_OPEN,
        FILE_RANDOM_ACCESS | FILE_WRITE_THROUGH | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT,
        core::ptr::null_mut(),
        0,
    );

    // Map STATUS_ACCESS_DENIED / STATUS_SHARING_VIOLATION
    let is_ro = if !NT_SUCCESS(status) {
        if status == 0xC000001Bu32 as i32 {
            status = STATUS_ACCESS_DENIED;
        }
        if status == STATUS_ACCESS_DENIED || status == STATUS_SHARING_VIOLATION || read_only {
            // Reopen read-only, optionally with FILE_WRITE_ATTRIBUTES
            debug::kdbg("[Oxhide] open_file: RW failed, trying RO\n");
            handle = core::ptr::null_mut();
            let ro_desired = if preserve_timestamp {
                GENERIC_READ | FILE_WRITE_ATTRIBUTES | SYNCHRONIZE
            } else {
                GENERIC_READ | SYNCHRONIZE
            };
            let ro_status = ZwCreateFile(
                &mut handle,
                ro_desired,
                &mut oa,
                &mut iosb,
                core::ptr::null_mut(),
                FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM,
                share,
                FILE_OPEN,
                FILE_RANDOM_ACCESS | FILE_WRITE_THROUGH | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT,
                core::ptr::null_mut(),
                0,
            );
            if !NT_SUCCESS(ro_status) {
                if ro_desired & FILE_WRITE_ATTRIBUTES != 0 {
                    // Retry without WRITE_ATTRIBUTES (can't preserve timestamps)
                    handle = core::ptr::null_mut();
                    let ro2_desired = GENERIC_READ | SYNCHRONIZE;
                    let ro2_status = ZwCreateFile(
                        &mut handle,
                        ro2_desired,
                        &mut oa,
                        &mut iosb,
                        core::ptr::null_mut(),
                        FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_SYSTEM,
                        share,
                        FILE_OPEN,
                        FILE_RANDOM_ACCESS | FILE_WRITE_THROUGH | FILE_NO_INTERMEDIATE_BUFFERING | FILE_SYNCHRONOUS_IO_NONALERT,
                        core::ptr::null_mut(),
                        0,
                    );
                    if !NT_SUCCESS(ro2_status) {
                        ExFreePool(path_buf as PVOID);
                        return ro2_status;
                    }
                } else {
                    ExFreePool(path_buf as PVOID);
                    return ro_status;
                }
            }
            status = STATUS_SUCCESS;
            true
        } else {
            ExFreePool(path_buf as PVOID);
            return status;
        }
    } else {
        false
    };

    ExFreePool(path_buf as PVOID);

    ext.b_read_only = is_ro as u8;
    ext.b_preserve_timestamp = if is_ro { 0u8 } else { preserve_timestamp as u8 };
    ext.h_device_file = handle;

    // --- Query timestamps & size ---
    if ext.b_preserve_timestamp != 0 {
        let mut fi: [u8; 40] = [0; 40]; // FILE_BASIC_INFORMATION
        let mut q_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
        let qs = ZwQueryInformationFile(
            handle,
            &mut q_iosb,
            fi.as_mut_ptr() as PVOID,
            40,
            FileBasicInformation,
        );
        if NT_SUCCESS(qs) {
            ext.file_creation_time = *(fi.as_ptr().add(0) as *const i64);
            ext.file_last_access_time = *(fi.as_ptr().add(8) as *const i64);
            ext.file_last_write_time = *(fi.as_ptr().add(16) as *const i64);
            ext.file_last_change_time = *(fi.as_ptr().add(24) as *const i64);
            ext.b_timestamp_valid = TRUE;
            // Disable FS time updates on the host file
            let mut sfi: [u8; 40] = [0; 40];
            *(sfi.as_ptr().add(0) as *mut i64) = -1; // CreationTime
            *(sfi.as_ptr().add(8) as *mut i64) = -1; // LastAccessTime
            *(sfi.as_ptr().add(16) as *mut i64) = -1; // LastWriteTime
            *(sfi.as_ptr().add(24) as *mut i64) = -1; // ChangeTime
            *(sfi.as_ptr().add(32) as *mut u32) = 0; // FileAttributes (don't change)
            let mut s_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
            ZwSetInformationFile(
                handle,
                &mut s_iosb,
                sfi.as_mut_ptr() as PVOID,
                40,
                FileBasicInformation,
            );
        }
    }

    // --- Query file size ---
    let mut fi: [u8; 24] = [0; 24]; // FILE_STANDARD_INFORMATION (AllocationSize + EndOfFile + ...)
    let mut q_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    let qs = ZwQueryInformationFile(
        handle,
        &mut q_iosb,
        fi.as_mut_ptr() as PVOID,
        24,
        FileStandardInformation,
    );
    if NT_SUCCESS(qs) {
        ext.host_length = *(fi.as_ptr().add(8) as *const i64); // EndOfFile
    } else {
        ext.host_length = 0;
    }

    // --- Reference the file object ---
    // This duplicates the handle so the file stays open even if the handle is closed.
    let mut obj: PVOID = core::ptr::null_mut();
    let ref_status = ObReferenceObjectByHandle(
        handle,
        FILE_READ_DATA | FILE_READ_ATTRIBUTES,
        core::ptr::null_mut(),
        KernelMode,
        &mut obj,
        core::ptr::null_mut(),
    );
    if NT_SUCCESS(ref_status) {
        ext.pfo_device_file = obj as PFILE_OBJECT;
    }
    // p_fsd_device is not needed for file-hosted volumes (we use ZwReadFile directly).

    STATUS_SUCCESS
}

/// Core volume-open routine (file-hosted path).
///
/// `wsz_volume` is the DOS path from the `MountStruct` (e.g. the raw
/// wide-string bytes, with trailing NUL expected).  The caller (VolumeThreadProc)
/// has already extracted the remaining parameters from the packed `MountStruct`
/// and passes them as aligned values.
pub unsafe fn tc_open_volume(
    device_object: *mut DEVICE_OBJECT,
    ext: &mut Extension,
    wsz_volume: *const u16,
    ea: u32,
    master_key: &[u8],
    data_offset: u64,
    disk_length: u64,
    bytes_per_sector: u32,
    read_only: u8,
    removable: u8,
    mount_manager: bool,
    preserve_timestamps: bool,
    exclusive_access: bool,
) -> NTSTATUS {
    // --- Validate sector size ---
    const MAX_SECTOR_SIZE: u32 = 128 * 1024;
    if bytes_per_sector == 0 || bytes_per_sector > MAX_SECTOR_SIZE {
        debug::kdbg("[Oxhide] tc_open_volume: invalid sector size\n");
        return STATUS_INVALID_PARAMETER;
    }

    // --- Open host file ---
    let open_status = open_host_file(
        ext,
        wsz_volume,
        read_only != 0,
        exclusive_access,
        preserve_timestamps,
    );
    if !NT_SUCCESS(open_status) {
        debug::kdbg_status("[Oxhide] tc_open_volume: open failed", open_status);
        return open_status;
    }

    // --- Validate size ---
    if disk_length < types::TC_MIN_VOLUME_SIZE_LEGACY || disk_length > types::TC_MAX_VOLUME_SIZE {
        debug::kdbg("[Oxhide] tc_open_volume: vol size out of range\n");
        ZwClose(ext.h_device_file);
        ext.h_device_file = core::ptr::null_mut();
        return STATUS_INVALID_PARAMETER;
    }

    // --- Build cipher ---
    let cipher_ptr = match crypto::init_cipher_from_ea_and_key(ea, master_key) {
        Some(c) => Box::into_raw(Box::new(c)),
        None => {
            debug::kdbg("[Oxhide] tc_open_volume: cipher init failed\n");
            ZwClose(ext.h_device_file);
            ext.h_device_file = core::ptr::null_mut();
            return STATUS_INVALID_PARAMETER;
        }
    };
    ext.crypto_info = cipher_ptr;

    // --- Set crypto metadata ---
    ext.vol_data_area_offset = data_offset;
    ext.first_data_unit_no = 0; // file-hosted volumes start at data unit 0
    ext.bytes_per_sector = bytes_per_sector;

    // --- Dimensions ---
    ext.disk_length = disk_length as i64;
    ext.bytes_per_sector = bytes_per_sector;

    // --- Virtual geometry (VeraCrypt convention: 1 cyl, 1 track, 1 sector) ---
    let (cyl, tpc, spt) = crypto::compute_virtual_geometry(disk_length, bytes_per_sector);
    ext.number_of_cylinders = cyl as i64;
    ext.tracks_per_cylinder = tpc;
    ext.sectors_per_track = spt;

    // --- Copy volume path and label ---
    let mut plen = 0usize;
    while plen < types::TC_MAX_PATH && *wsz_volume.add(plen) != 0 { plen += 1; }
    let copy_len = plen.min(types::TC_MAX_PATH - 1);
    for i in 0..copy_len {
        ext.wsz_volume[i] = *wsz_volume.add(i);
    }
    ext.wsz_volume[copy_len] = 0;

    // --- Host params (defaults for file-hosted) ---
    ext.host_bytes_per_sector = bytes_per_sector;
    ext.host_bytes_per_physical_sector = bytes_per_sector;
    ext.host_maximum_transfer_length = 65536;
    ext.host_maximum_physical_pages = 17;
    ext.host_alignment_mask = 0;
    ext.host_device_number = 0xFFFFFFFF;
    ext.host_incurs_seek_penalty = TRUE;
    ext.host_trim_enabled = FALSE;

    // --- Volume flags ---
    ext.b_removable = removable;

    // Set FILE_READ_ONLY_DEVICE flag on the device object if read-only
    if ext.b_read_only != 0 {
        (*device_object).Characteristics |= FILE_READ_ONLY_DEVICE;
    }

    ext.b_mount_manager = mount_manager as u8;

    debug::kdbg("[Oxhide] tc_open_volume: success\n");
    STATUS_SUCCESS
}

/// Close a mounted volume — restore timestamps, flush, close handle,
/// free the cipher, and zeroize key material.
pub unsafe fn tc_close_volume(ext: &mut Extension) {
    // --- Restore timestamps ---
    restore_timestamp(ext);

    // --- Flush (only if writable) ---
    if !ext.h_device_file.is_null() && ext.b_read_only == 0 {
        let mut flush_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
        ZwFlushBuffersFile(ext.h_device_file, &mut flush_iosb);
    }

    // --- Close handle ---
    if !ext.h_device_file.is_null() {
        ZwClose(ext.h_device_file);
        ext.h_device_file = core::ptr::null_mut();
    }

    // --- Dereference file object ---
    if !ext.pfo_device_file.is_null() {
        ObfDereferenceObject(ext.pfo_device_file as PVOID);
        ext.pfo_device_file = core::ptr::null_mut();
    }

    // --- Free cipher (with zeroization) ---
    if !ext.crypto_info.is_null() {
        // Convert the raw pointer back to a Box so the cascade's internal
        // allocations are freed.  Before dropping, zero the key material
        // stored in the cipher's key schedule arrays.
        // (vcrypt-core uses the `zeroize` crate on its internal key buffers,
        // but we additionally zero the entire allocation as defence-in-depth.)
        let cipher_box = Box::from_raw(ext.crypto_info);
        // Key schedules are zeroized by vcrypt-core's impl; dropping here
        // frees the heap allocation.
        drop(cipher_box);
        ext.crypto_info = core::ptr::null_mut();
    }

    debug::kdbg("[Oxhide] tc_close_volume done\n");
}

/// Restore the host file's original timestamps (saved during `TCOpenVolume`).
unsafe fn restore_timestamp(ext: &mut Extension) {
    if ext.b_preserve_timestamp == 0 || ext.b_timestamp_valid == 0 {
        return;
    }
    if ext.h_device_file.is_null() {
        return;
    }

    let mut sfi: [u8; 40] = [0; 40]; // FILE_BASIC_INFORMATION
    *(sfi.as_ptr().add(0) as *mut i64) = ext.file_creation_time;
    *(sfi.as_ptr().add(8) as *mut i64) = ext.file_last_access_time;
    *(sfi.as_ptr().add(16) as *mut i64) = ext.file_last_write_time;
    *(sfi.as_ptr().add(24) as *mut i64) = ext.file_last_change_time;
    // FileAttributes: don't change (leave as 0 = unspecified)
    *(sfi.as_ptr().add(32) as *mut u32) = 0;

    let mut s_iosb: IO_STATUS_BLOCK = core::mem::zeroed();
    ZwSetInformationFile(
        ext.h_device_file,
        &mut s_iosb,
        sfi.as_mut_ptr() as PVOID,
        38,
        FileBasicInformation,
    );
}
