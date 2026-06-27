//! Disk geometry and storage IOCTL handlers for volume (disk) devices.
//!
//! 1:1 translation of `ProcessVolumeDeviceControlIrp` from VeraCrypt
//! `Ntdriver.c:986` for the file-container subset.

use crate::extension::Extension;
use crate::irp_utils;
use crate::names;
use crate::wdk_bindings::*;

/// Handle `IRP_MJ_DEVICE_CONTROL` for a mounted volume device.
/// Called from `VolumeThreadProc` with the extension reference.
pub fn process_volume_device_control(ext: &Extension, irp: *mut IRP) {
    let ioctl = irp_utils::get_ioctl_code(irp);
    unsafe {
        let stack = IoGetCurrentIrpStackLocation(irp);
        let out_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength as usize;
        let sys_buf = (*irp).AssociatedIrp.SystemBuffer;

        match ioctl {
            // --- Geometry ---
            IOCTL_DISK_GET_DRIVE_GEOMETRY => {
                let sz = core::mem::size_of::<DISK_GEOMETRY>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut DISK_GEOMETRY;
                (*buf).MediaType = if ext.b_removable != 0 { RemovableMedia } else { FixedMedia };
                (*buf).Cylinders = ext.number_of_cylinders;
                (*buf).TracksPerCylinder = ext.tracks_per_cylinder;
                (*buf).SectorsPerTrack = ext.sectors_per_track;
                (*buf).BytesPerSector = ext.bytes_per_sector;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_DISK_GET_DRIVE_GEOMETRY_EX => {
                let sz = core::mem::size_of::<DISK_GEOMETRY_EX>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut DISK_GEOMETRY_EX;
                core::ptr::write_bytes(sys_buf, 0, sz);
                (*buf).Geometry.MediaType = if ext.b_removable != 0 { RemovableMedia } else { FixedMedia };
                (*buf).Geometry.Cylinders = ext.number_of_cylinders;
                (*buf).Geometry.TracksPerCylinder = ext.tracks_per_cylinder;
                (*buf).Geometry.SectorsPerTrack = ext.sectors_per_track;
                (*buf).Geometry.BytesPerSector = ext.bytes_per_sector;
                (*buf).DiskSize = ext.disk_length + (1024 * 1024); // +1MB headroom (1:1 VeraCrypt)
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_DISK_GET_LENGTH_INFO => {
                let sz = core::mem::size_of::<GET_LENGTH_INFORMATION>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut GET_LENGTH_INFORMATION;
                (*buf).Length = ext.disk_length;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_DISK_GET_PARTITION_INFO => {
                let sz = core::mem::size_of::<PARTITION_INFORMATION>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut PARTITION_INFORMATION;
                (*buf).StartingOffset = 0;
                (*buf).PartitionLength = ext.disk_length;
                (*buf).HiddenSectors = 0;
                (*buf).PartitionNumber = 1;
                (*buf).PartitionType = 7; // PARTITION_IFS (NTFS/exFAT)
                (*buf).BootIndicator = FALSE;
                (*buf).RecognizedPartition = TRUE;
                (*buf).RewritePartition = FALSE;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_DISK_IS_WRITABLE => {
                let st = if ext.b_read_only != 0 { STATUS_MEDIA_WRITE_PROTECTED } else { STATUS_SUCCESS };
                irp_utils::complete_disk_irp(irp, st, 0);
            }

            IOCTL_DISK_UPDATE_PROPERTIES | IOCTL_DISK_UPDATE_DRIVE_SIZE => {
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            IOCTL_STORAGE_CHECK_VERIFY | IOCTL_STORAGE_CHECK_VERIFY2 | IOCTL_DISK_CHECK_VERIFY => {
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            IOCTL_STORAGE_GET_DEVICE_NUMBER => {
                let sz = core::mem::size_of::<STORAGE_DEVICE_NUMBER>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut STORAGE_DEVICE_NUMBER;
                (*buf).DeviceType = FILE_DEVICE_DISK;
                (*buf).DeviceNumber = ext.host_device_number;
                (*buf).PartitionNumber = 0xFFFFFFFF;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS => {
                let sz = core::mem::size_of::<VOLUME_DISK_EXTENTS>() + core::mem::size_of::<DISK_EXTENT>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut VOLUME_DISK_EXTENTS;
                (*buf).NumberOfDiskExtents = 1;
                let ext_ptr = sys_buf.add(core::mem::size_of::<VOLUME_DISK_EXTENTS>()) as *mut DISK_EXTENT;
                (*ext_ptr).DiskNumber = ext.host_device_number;
                (*ext_ptr).StartingOffset = 1024 * 1024; // 1 MB offset (emulated MBR)
                (*ext_ptr).ExtentLength = ext.disk_length;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_VOLUME_ONLINE | IOCTL_VOLUME_POST_ONLINE => {
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            IOCTL_DISK_VERIFY => {
                // Verify reads the specified range from the host. We can skip
                // (return success) — the data is encrypted in the container.
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            IOCTL_DISK_GET_PARTITION_INFO_EX => {
                let sz = core::mem::size_of::<PARTITION_INFORMATION_EX>();
                if out_len < sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut PARTITION_INFORMATION_EX;
                core::ptr::write_bytes(buf, 0, 1);
                (*buf).PartitionStyle = PARTITION_STYLE_MBR;
                (*buf).StartingOffset = 0;
                (*buf).PartitionLength = ext.disk_length;
                (*buf).PartitionNumber = 1;
                (*buf).RewritePartition = FALSE;
                (*buf).IsServicePartition = FALSE;
                (*buf).Mbr.PartitionType = 7; // PARTITION_IFS
                (*buf).Mbr.BootIndicator = FALSE;
                (*buf).Mbr.RecognizedPartition = TRUE;
                (*buf).Mbr.HiddenSectors = 0;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
            }

            IOCTL_STORAGE_QUERY_PROPERTY => {
                let qs = core::mem::size_of::<STORAGE_PROPERTY_QUERY>();
                let in_len = (*stack).Parameters.DeviceIoControl.InputBufferLength as usize;
                if sys_buf.is_null() || in_len < qs {
                    irp_utils::complete_disk_irp(irp, STATUS_INVALID_PARAMETER, 0);
                    return;
                }
                let query = sys_buf as *const STORAGE_PROPERTY_QUERY;
                let prop_id = (*query).PropertyId;
                let query_type = (*query).QueryType;

                match prop_id {
                    StorageDeviceProperty => {
                        let sz = core::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>();
                        if out_len < sz {
                            irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, sz as ULONG_PTR);
                            return;
                        }
                        let buf = sys_buf as *mut STORAGE_DEVICE_DESCRIPTOR;
                        core::ptr::write_bytes(buf, 0, 1);
                        (*buf).Version = sz as u32;
                        (*buf).Size = sz as u32;
                        (*buf).DeviceType = FILE_DEVICE_DISK as u8;
                        (*buf).DeviceTypeModifier = 0;
                        (*buf).RemovableMedia = if ext.b_removable != 0 { 1 } else { 0 };
                        (*buf).BusType = BusTypeFileBackedVirtual;
                        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, sz as ULONG_PTR);
                    }
                    StorageAccessAlignmentProperty => {
                        const SZ: usize = 24; // STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR (3 × u32)
                        if out_len < SZ {
                            irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, SZ as ULONG_PTR);
                            return;
                        }
                        let buf = sys_buf as *mut STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR;
                        (*buf).Version = SZ as u32;
                        (*buf).Size = SZ as u32;
                        (*buf).BytesPerLogicalSector = ext.bytes_per_sector;
                        (*buf).BytesPerPhysicalSector = ext.host_bytes_per_physical_sector;
                        (*buf).BytesOffsetForSectorAlignment = 0;
                        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, SZ as ULONG_PTR);
                    }
                    StorageDeviceSeekPenaltyProperty => {
                        const SZ: usize = 12; // DEVICE_SEEK_PENALTY_DESCRIPTOR
                        if out_len < SZ {
                            irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, SZ as ULONG_PTR);
                            return;
                        }
                        let buf = sys_buf as *mut DEVICE_SEEK_PENALTY_DESCRIPTOR;
                        (*buf).Version = SZ as u32;
                        (*buf).Size = SZ as u32;
                        (*buf).IncursSeekPenalty = ext.host_incurs_seek_penalty;
                        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, SZ as ULONG_PTR);
                    }
                    StorageDeviceTrimProperty => {
                        const SZ: usize = 8; // DEVICE_TRIM_DESCRIPTOR
                        if out_len < SZ {
                            irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, SZ as ULONG_PTR);
                            return;
                        }
                        let buf = sys_buf as *mut DEVICE_TRIM_DESCRIPTOR;
                        (*buf).Version = SZ as u32;
                        (*buf).Size = SZ as u32;
                        (*buf).TrimEnabled = ext.host_trim_enabled;
                        irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, SZ as ULONG_PTR);
                    }
                    _ => {
                        if query_type == PropertyExistsQuery {
                            irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
                        } else {
                            irp_utils::complete_disk_irp(irp, STATUS_NOT_IMPLEMENTED, 0);
                        }
                    }
                }
            }

            // --- Filesystem control codes (pass-through / success) ---
            FSCTL_DISMOUNT_VOLUME | FSCTL_LOCK_VOLUME | FSCTL_UNLOCK_VOLUME | FSCTL_IS_VOLUME_MOUNTABLE => {
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            IOCTL_DISK_GET_MEDIA_TYPES_EX => {
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            IOCTL_DISK_GET_DRIVE_LAYOUT => {
                const SZ: usize = core::mem::size_of::<DRIVE_LAYOUT_INFORMATION>();
                if out_len < SZ {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_TOO_SMALL, SZ as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut DRIVE_LAYOUT_INFORMATION;
                (*buf).PartitionCount = 1;
                (*buf).Signature = 0;
                (*buf).PartitionEntry[0].StartingOffset = 0;
                (*buf).PartitionEntry[0].PartitionLength = ext.disk_length;
                (*buf).PartitionEntry[0].HiddenSectors = 0;
                (*buf).PartitionEntry[0].PartitionNumber = 1;
                (*buf).PartitionEntry[0].PartitionType = 7;
                (*buf).PartitionEntry[0].BootIndicator = FALSE;
                (*buf).PartitionEntry[0].RecognizedPartition = TRUE;
                (*buf).PartitionEntry[0].RewritePartition = FALSE;
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, SZ as ULONG_PTR);
            }

            IOCTL_DISK_MEDIA_REMOVAL | IOCTL_STORAGE_MEDIA_REMOVAL => {
                if ext.b_removable != 0 {
                    irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
                } else {
                    irp_utils::complete_disk_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
                }
            }

            // --- Volume IOCTL noops ---
            IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS_EX
                | IOCTL_VOLUME_QUERY_VOLUME_INFORMATION
                | IOCTL_VOLUME_LOGICAL_TO_PHYSICAL
                | IOCTL_VOLUME_PHYSICAL_TO_LOGICAL
                | IOCTL_VOLUME_IS_CLUSTER_CAPABLE => {
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            // --- Mountdev ---
            IOCTL_MOUNTDEV_QUERY_DEVICE_NAME => {
                let minsz = core::mem::size_of::<MOUNTDEV_NAME>();
                if out_len < minsz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_OVERFLOW, minsz as ULONG_PTR);
                    return;
                }
                let nt_name = names::volume_nt_name(ext.n_dos_drive_no as usize);
                let name_len_u16 = names::wcslen(&nt_name);
                let out_sz = 2 + name_len_u16 * 2;
                if out_len < out_sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_OVERFLOW, minsz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut MOUNTDEV_NAME;
                (*buf).NameLength = (name_len_u16 * 2) as u16;
                core::ptr::copy_nonoverlapping(nt_name.as_ptr(), (*buf).Name.as_mut_ptr(), name_len_u16);
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, out_sz as ULONG_PTR);
            }

            IOCTL_MOUNTDEV_QUERY_UNIQUE_ID => {
                let minsz = core::mem::size_of::<MOUNTDEV_UNIQUE_ID>();
                if out_len < minsz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_OVERFLOW, minsz as ULONG_PTR);
                    return;
                }
                let mut id_buf = [0u8; 32];
                let prefix = b"OxhideVolume";
                let drive_letter = b'A' + ext.n_dos_drive_no as u8;
                let id_len = prefix.len().min(31) + 1;
                id_buf[..prefix.len()].copy_from_slice(&prefix[..prefix.len()]);
                id_buf[prefix.len()] = drive_letter;
                let out_sz = 2 + id_len;
                if out_len < out_sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_OVERFLOW, minsz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut MOUNTDEV_UNIQUE_ID;
                (*buf).UniqueIdLength = id_len as u16;
                core::ptr::copy_nonoverlapping(id_buf.as_ptr(), (*buf).UniqueId.as_mut_ptr(), id_len);
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, out_sz as ULONG_PTR);
            }

            IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME => {
                let minsz = core::mem::size_of::<MOUNTDEV_SUGGESTED_LINK_NAME>();
                if out_len < minsz {
                    irp_utils::complete_disk_irp(irp, STATUS_INVALID_PARAMETER, 0);
                    return;
                }
                let dos_name = names::volume_dos_name(ext.n_dos_drive_no as usize);
                let name_len = names::wcslen(&dos_name);
                let name_offset: usize = 4; // FIELD_OFFSET(MOUNTDEV_SUGGESTED_LINK_NAME, Name)
                let out_sz = name_offset + name_len * 2;
                if out_len < out_sz {
                    irp_utils::complete_disk_irp(irp, STATUS_BUFFER_OVERFLOW, minsz as ULONG_PTR);
                    return;
                }
                let buf = sys_buf as *mut MOUNTDEV_SUGGESTED_LINK_NAME;
                (*buf).UseOnlyIfThereAreNoOtherLinks = FALSE;
                (*buf).NameLength = (name_len * 2) as u16;
                core::ptr::copy_nonoverlapping(dos_name.as_ptr(), (*buf).Name.as_mut_ptr(), name_len);
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, out_sz as ULONG_PTR);
            }

            IOCTL_DISK_GET_CLUSTER_INFO => {
                irp_utils::complete_disk_irp(irp, STATUS_NOT_SUPPORTED, 0);
            }

            IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES => {
                // TRIM / UNMAP — pass-through to host file (future enhancement).
                // For now, succeed silently.
                irp_utils::complete_disk_irp(irp, STATUS_SUCCESS, 0);
            }

            // --- Unknown IOCTL: fail (1:1 VeraCrypt, fixes old catch-all success) ---
            _ => {
                irp_utils::complete_disk_irp(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            }
        }
    }
}
