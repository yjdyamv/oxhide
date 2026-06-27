//! I/O pipeline — synchronous inline read/write with XTS encrypt/decrypt.
//!
//! This is the Phase 4 synchronous implementation.  IRPs are processed inline
//! in the dispatch routine.  A future phase will replace this with an
//! asynchronous EncryptedIoQueue (main/io/completion worker threads).
//!
//! Buffer access: volume devices use DO_DIRECT_IO, so the user buffer is
//! described by IRP->MdlAddress.  We map it to a kernel VA via
//! MmGetSystemAddressForMdlSafe.

use crate::irp_utils;
use crate::volume::VolumeExtension;
use crate::wdk_bindings::*;

const SECTOR_SIZE: u64 = 512;

/// Handle IRP_MJ_READ: read from host file, XTS-decrypt, copy to user buffer.
pub fn process_read_irp(ext: &VolumeExtension, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        let stack = IoGetCurrentIrpStackLocation(irp);
        let offset = (*stack).Parameters.Read.ByteOffset;
        let length = (*stack).Parameters.Read.Length;

        if length == 0 {
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }

        let virtual_offset = offset as u64;
        if virtual_offset + length as u64 > ext.disk_length {
            irp_utils::complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
            return STATUS_INVALID_PARAMETER;
        }

        let host_offset = ext.data_offset + virtual_offset;
        let start_sector = virtual_offset / SECTOR_SIZE;
        let end_byte = virtual_offset + length as u64;
        let (sector_count, buf_size) = compute_sector_params(end_byte, start_sector);

        // Allocate non-paged buffer for sector-aligned I/O
        let sector_buf = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, buf_size, u32::from_ne_bytes(*b"Oxhd"),
        ) as *mut u8;
        if sector_buf.is_null() {
            irp_utils::complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let sector_slice = core::slice::from_raw_parts_mut(sector_buf, buf_size);

        // Read from host file at sector-aligned offset
        let aligned_host = (host_offset / SECTOR_SIZE) * SECTOR_SIZE;
        let mut byte_offset = aligned_host as i64;
        let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
        let status = ZwReadFile(
            ext.host_file_handle,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
            &mut iosb,
            sector_buf as PVOID, buf_size as u32,
            &mut byte_offset, core::ptr::null_mut(),
        );
        if !NT_SUCCESS(status) {
            ExFreePool(sector_buf as PVOID);
            irp_utils::complete_irp(irp, status, 0);
            return status;
        }

        // XTS-decrypt each sector
        for i in 0..sector_count {
            let sd = &mut sector_slice[i * 512..(i + 1) * 512];
            let _ = ext.cipher.decrypt_sector(start_sector + i as u64, sd);
        }

        // Copy decrypted data to user buffer (via MDL)
        let user_offset = (virtual_offset % SECTOR_SIZE) as usize;
        copy_to_user(irp, &sector_slice[user_offset..user_offset + length as usize]);

        ExFreePool(sector_buf as PVOID);
        irp_utils::complete_irp(irp, STATUS_SUCCESS, length as ULONG_PTR);
        STATUS_SUCCESS
    }
}

/// Handle IRP_MJ_WRITE: read-modify-write with XTS encryption.
pub fn process_write_irp(ext: &VolumeExtension, irp: *mut IRP) -> NTSTATUS {
    unsafe {
        let stack = IoGetCurrentIrpStackLocation(irp);
        let offset = (*stack).Parameters.Write.ByteOffset;
        let length = (*stack).Parameters.Write.Length;

        if ext.read_only {
            irp_utils::complete_irp(irp, STATUS_MEDIA_WRITE_PROTECTED, 0);
            return STATUS_MEDIA_WRITE_PROTECTED;
        }

        if length == 0 {
            irp_utils::complete_irp(irp, STATUS_SUCCESS, 0);
            return STATUS_SUCCESS;
        }

        let virtual_offset = offset as u64;
        if virtual_offset + length as u64 > ext.disk_length {
            irp_utils::complete_irp(irp, STATUS_INVALID_PARAMETER, 0);
            return STATUS_INVALID_PARAMETER;
        }

        let host_offset = ext.data_offset + virtual_offset;
        let start_sector = virtual_offset / SECTOR_SIZE;
        let end_byte = virtual_offset + length as u64;
        let (sector_count, buf_size) = compute_sector_params(end_byte, start_sector);

        // Allocate non-paged buffer for sector-aligned I/O
        let sector_buf = ExAllocatePool2(
            POOL_FLAG_NON_PAGED, buf_size, u32::from_ne_bytes(*b"Oxhw"),
        ) as *mut u8;
        if sector_buf.is_null() {
            irp_utils::complete_irp(irp, STATUS_INSUFFICIENT_RESOURCES, 0);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        let sector_slice = core::slice::from_raw_parts_mut(sector_buf, buf_size);

        let aligned_host = (host_offset / SECTOR_SIZE) * SECTOR_SIZE;

        // If the write is not sector-aligned, we need to read the existing
        // sector(s) first (read-modify-write)
        let needs_read = (virtual_offset % SECTOR_SIZE != 0)
            || (length as u64 % SECTOR_SIZE != 0 && end_byte % SECTOR_SIZE != 0);
        // Simplification: always read existing data first (safe for any alignment)
        let _ = needs_read; // always read for safety

        let mut byte_offset = aligned_host as i64;
        let mut iosb: IO_STATUS_BLOCK = core::mem::zeroed();
        let read_status = ZwReadFile(
            ext.host_file_handle,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
            &mut iosb,
            sector_buf as PVOID, buf_size as u32,
            &mut byte_offset, core::ptr::null_mut(),
        );
        if !NT_SUCCESS(read_status) {
            ExFreePool(sector_buf as PVOID);
            irp_utils::complete_irp(irp, read_status, 0);
            return read_status;
        }

        // Copy user data over the relevant portion of the sector buffer
        let user_offset = (virtual_offset % SECTOR_SIZE) as usize;
        copy_from_user(irp, &mut sector_slice[user_offset..user_offset + length as usize]);

        // XTS-encrypt each sector
        for i in 0..sector_count {
            let sd = &mut sector_slice[i * 512..(i + 1) * 512];
            let _ = ext.cipher.encrypt_sector(start_sector + i as u64, sd);
        }

        // Write encrypted data back to host file
        let mut w_byte_offset = aligned_host as i64;
        let mut wiosb: IO_STATUS_BLOCK = core::mem::zeroed();
        let wstatus = ZwWriteFile(
            ext.host_file_handle,
            core::ptr::null_mut(), core::ptr::null_mut(), core::ptr::null_mut(),
            &mut wiosb,
            sector_buf as PVOID, buf_size as u32,
            &mut w_byte_offset, core::ptr::null_mut(),
        );

        ExFreePool(sector_buf as PVOID);
        if !NT_SUCCESS(wstatus) {
            irp_utils::complete_irp(irp, wstatus, 0);
            return wstatus;
        }

        irp_utils::complete_irp(irp, STATUS_SUCCESS, length as ULONG_PTR);
        STATUS_SUCCESS
    }
}

#[inline]
fn compute_sector_params(end_byte: u64, start_sector: u64) -> (usize, usize) {
    let end_sector = (end_byte + SECTOR_SIZE - 1) / SECTOR_SIZE;
    let sector_count = (end_sector - start_sector) as usize;
    let buf_size = sector_count * 512;
    (sector_count, buf_size)
}

/// Copy decrypted data from sector buffer to the user's MDL buffer.
unsafe fn copy_to_user(irp: *mut IRP, data: &[u8]) {
    let mdl = (*irp).MdlAddress;
    if mdl.is_null() { return; }
    let user_buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if user_buf.is_null() { return; }
    let dst = core::slice::from_raw_parts_mut(user_buf as *mut u8, data.len());
    dst.copy_from_slice(data);
}

/// Copy data from the user's MDL buffer into the sector buffer.
unsafe fn copy_from_user(irp: *mut IRP, data: &mut [u8]) {
    let mdl = (*irp).MdlAddress;
    if mdl.is_null() { return; }
    let user_buf = MmGetSystemAddressForMdlSafe(mdl, NormalPagePriority);
    if user_buf.is_null() { return; }
    let src = core::slice::from_raw_parts(user_buf as *const u8, data.len());
    data.copy_from_slice(src);
}
