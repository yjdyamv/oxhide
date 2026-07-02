//! IOCTL codes, wire structs, and constants.
//!
//! `MountStruct` / `UnmountStruct` use Oxhide's hybrid wire format (the
//! user-mode layer decrypts the volume header and hands the driver a
//! pre-derived master key + EA + data offset, instead of a password).  This
//! differs from VeraCrypt's `MOUNT_STRUCT` and is **not** binary-compatible
//! with VeraCrypt user-mode tools — it is only compatible with Oxhide's own
//! `vcrypt-cli` (`kernel_ioctl.rs`), which must use the identical layout.
//!
//! `MOUNT_LIST_STRUCT` / `VOLUME_PROPERTIES_STRUCT` mirror VeraCrypt's
//! `Apidrvr.h` layouts so that queries are structured (the CLI does not
//! currently consume these, but they are provided for completeness).

use crate::wdk_bindings::*;
use crate::CTL_CODE;

// ---------------------------------------------------------------------------
// IOCTL code generation (matches VeraCrypt's TC_IOCTL macro)
//   TC_IOCTL(CODE) = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800 + CODE, METHOD_BUFFERED, FILE_ANY_ACCESS)
// ---------------------------------------------------------------------------
const FILE_DEVICE_UNKNOWN: u32 = 0x0000_0022;
const TC_IOCTL_BASE: u32 = 0x800;

const fn tc_ioctl(code: u32) -> u32 {
    CTL_CODE!(FILE_DEVICE_UNKNOWN, TC_IOCTL_BASE + code, METHOD_BUFFERED, FILE_ANY_ACCESS)
}

pub const TC_IOCTL_GET_DRIVER_VERSION: u32 = tc_ioctl(1);
pub const TC_IOCTL_GET_BOOT_LOADER_VERSION: u32 = tc_ioctl(2);
pub const TC_IOCTL_MOUNT_VOLUME: u32 = tc_ioctl(3);
pub const TC_IOCTL_UNMOUNT_VOLUME: u32 = tc_ioctl(4);
pub const TC_IOCTL_UNMOUNT_ALL_VOLUMES: u32 = tc_ioctl(5);
pub const TC_IOCTL_GET_MOUNTED_VOLUMES: u32 = tc_ioctl(6);
pub const TC_IOCTL_GET_VOLUME_PROPERTIES: u32 = tc_ioctl(7);
pub const TC_IOCTL_GET_DEVICE_REFCOUNT: u32 = tc_ioctl(8);
pub const TC_IOCTL_IS_DRIVER_UNLOAD_DISABLED: u32 = tc_ioctl(9);
pub const TC_IOCTL_IS_ANY_VOLUME_MOUNTED: u32 = tc_ioctl(10);
pub const TC_IOCTL_GET_PASSWORD_CACHE_STATUS: u32 = tc_ioctl(11);
pub const TC_IOCTL_WIPE_PASSWORD_CACHE: u32 = tc_ioctl(12);
pub const TC_IOCTL_OPEN_TEST: u32 = tc_ioctl(13);
pub const TC_IOCTL_GET_DRIVE_PARTITION_INFO: u32 = tc_ioctl(14);
pub const TC_IOCTL_GET_DRIVE_GEOMETRY: u32 = tc_ioctl(15);
pub const TC_IOCTL_PROBE_REAL_DRIVE_SIZE: u32 = tc_ioctl(16);
pub const TC_IOCTL_GET_RESOLVED_SYMLINK: u32 = tc_ioctl(17);
pub const TC_IOCTL_DISK_IS_WRITABLE: u32 = tc_ioctl(29);
pub const TC_IOCTL_GET_WARNING_FLAGS: u32 = tc_ioctl(35);
pub const TC_IOCTL_REREAD_DRIVER_CONFIG: u32 = tc_ioctl(37);
pub const TC_IOCTL_ABORT_MOUNT_VOLUME: u32 = tc_ioctl(44);
pub const VC_IOCTL_GET_DRIVE_GEOMETRY_EX: u32 = tc_ioctl(40);

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------
pub const TC_MAX_PATH: usize = 260;
pub const MAX_PASSWORD: usize = 64;
/// Maximum concatenated master-key size (data + tweak halves for a 3-cipher
/// cascade = 96 * 2 = 192).  Matches `vcrypt-cli::kernel_ioctl::MASTER_KEY_MAX`.
pub const MASTER_KEY_MAX_SIZE: usize = 192;
pub const VOLUME_ID_SIZE: usize = 32;
pub const MAX_DRIVE: usize = 26;
pub const MAX_MOUNTED_VOLUME_DRIVE_NUMBER: usize = 25;
/// Driver version reported to user-mode (major.minor encoded).
pub const DRIVER_VERSION: u32 = 0x0001_0A00; // 1.10.0

// ---------------------------------------------------------------------------
// VeraCrypt return codes (Tcdefs.h) — values written to `nReturnCode`.
// ---------------------------------------------------------------------------
pub const ERR_SUCCESS: i32 = 0;
pub const ERR_OS_ERROR: i32 = 1;
pub const ERR_OUTOFMEMORY: i32 = 2;
pub const ERR_PASSWORD_WRONG: i32 = 3;
pub const ERR_VOL_FORMAT_BAD: i32 = 4;
pub const ERR_DRIVE_NOT_FOUND: i32 = 5;
pub const ERR_FILES_OPEN: i32 = 6;
pub const ERR_VOL_SIZE_WRONG: i32 = 7;
pub const ERR_COMPRESSION_NOT_SUPPORTED: i32 = 8;
pub const ERR_VOL_SEEKING: i32 = 11;
pub const ERR_VOL_WRITING: i32 = 12;
pub const ERR_VOL_READING: i32 = 14;
pub const ERR_DRIVER_VERSION: i32 = 15;
pub const ERR_CIPHER_INIT_FAILURE: i32 = 17;
pub const ERR_CIPHER_INIT_WEAK_KEY: i32 = 18;
pub const ERR_SELF_TESTS_FAILED: i32 = 19;
pub const ERR_SECTOR_SIZE_INCOMPATIBLE: i32 = 20;
pub const ERR_VOL_ALREADY_MOUNTED: i32 = 21;
pub const ERR_NO_FREE_DRIVES: i32 = 22;
pub const ERR_FILE_OPEN_FAILED: i32 = 23;
pub const ERR_VOL_MOUNT_FAILED: i32 = 24;
pub const ERR_ACCESS_DENIED: i32 = 26;
pub const ERR_PARAMETER_INCORRECT: i32 = 30;
pub const ERR_USER_ABORT: i32 = 33;

// Volume size bounds (bytes) — VeraCrypt Volumes.h
pub const TC_MIN_VOLUME_SIZE_LEGACY: u64 = 256 * 1024;          // 256 KB
pub const TC_MAX_VOLUME_SIZE: u64 = (1u64 << 63) - 1;
pub const TC_VOLUME_HEADER_GROUP_SIZE: u64 = 256 * 1024;

// ---------------------------------------------------------------------------
// MountStruct — Oxhide hybrid wire format (must match vcrypt-cli).
// Field order/offsets are byte-identical to the previous driver layout so the
// existing CLI mount path keeps working.  `#[repr(C, packed(1))]` means all
// field access must go through byte copies / `read_unaligned`.
// ---------------------------------------------------------------------------
#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub struct MountStruct {
    pub return_code: i32,
    pub filesystem_dirty: u8,
    pub volume_password: [u16; MAX_PASSWORD],
    pub mount_read_only: u8,
    pub mount_removable: u8,
    pub partition_in_inactive_sys_enc_scope: u8,
    pub mount_disable_write_cache: u8,
    pub protected_volume_password: [u16; MAX_PASSWORD],
    pub use_hidden_volume_protection: u8,
    pub preserve_timestamps: u8,
    pub part_slot_number: u32,
    pub volume_creation_time: i64,
    pub volume_serial_number: u32,
    pub dummy: [u8; 4],
    pub wsz_volume: [u16; TC_MAX_PATH],
    pub n_dos_drive_no: i32,
    pub bytes_per_sector: u32,
    pub disk_length: i64,
    pub ea: u32,
    pub master_key: [u8; MASTER_KEY_MAX_SIZE],
    pub data_offset: u64,
    pub raw_device: u8,
    pub volume_pim: i32,
    pub wsz_label: [u16; 33],
    pub max_xfer_len: u32,
    pub max_phys_pages: u32,
    pub align_mask: u32,
}

// ---------------------------------------------------------------------------
// UnmountStruct — Oxhide wire format (must match vcrypt-cli).  Kept at 8 bytes
// (return_code + n_dos_drive_no) so the existing CLI unmount path keeps working.
// Force-unmount / ignore-open-files is not exposed through this struct yet.
// ---------------------------------------------------------------------------
#[repr(C, packed(1))]
#[derive(Clone, Copy)]
pub struct UnmountStruct {
    pub return_code: i32,
    pub n_dos_drive_no: i32,
}

// ---------------------------------------------------------------------------
// MOUNT_LIST_STRUCT — VeraCrypt-compatible (Apidrvr.h), returned by
// TC_IOCTL_GET_MOUNTED_VOLUMES.  `#[repr(C)]` (not packed: VeraCrypt wraps the
// whole header in pack(1), but the natural-alignment layout here matches the
// packed layout because every field is already 1/2/4/8-aligned in order).
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MountListStruct {
    pub ul_mounted_drives: u32,                  // bitmask of mounted drive letters
    pub wsz_volume: [[u16; TC_MAX_PATH]; MAX_DRIVE],
    pub wsz_label: [[u16; 33]; MAX_DRIVE],
    pub volume_id: [[u8; VOLUME_ID_SIZE]; MAX_DRIVE],
    pub disk_length: [u64; MAX_DRIVE],
    pub ea: [i32; MAX_DRIVE],
    pub volume_type: [i32; MAX_DRIVE],
    pub reserved: [u8; MAX_DRIVE],               // BOOL[26]
}

impl Default for MountListStruct {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

// ---------------------------------------------------------------------------
// VOLUME_PROPERTIES_STRUCT — VeraCrypt-compatible (Apidrvr.h), returned by
// TC_IOCTL_GET_VOLUME_PROPERTIES.
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct VolumePropertiesStruct {
    pub drive_no: i32,
    pub unique_id: i32,
    pub wsz_volume: [u16; TC_MAX_PATH],
    pub disk_length: u64,
    pub ea: i32,
    pub mode: i32,
    pub pkcs5: i32,
    pub pkcs5_iterations: i32,
    pub hidden_volume: u8,        // BOOL
    pub read_only: u8,            // BOOL
    pub removable: u8,            // BOOL
    pub partition_in_inactive_sys_enc_scope: u8, // BOOL
    pub volume_header_flags: u32,
    pub total_bytes_read: u64,
    pub total_bytes_written: u64,
    pub hidden_vol_protection: i32,
    pub vol_format_version: i32,
    pub volume_pim: i32,
    pub wsz_label: [u16; 33],
    pub b_driver_set_label: u8,   // BOOL
    pub volume_id: [u8; VOLUME_ID_SIZE],
    pub mount_disabled: u8,       // BOOL
}

impl Default for VolumePropertiesStruct {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

// ---------------------------------------------------------------------------
// Helpers for packed-struct field access (read/write through byte pointers).
// ---------------------------------------------------------------------------
// Packed-struct field access helpers — delegated to vcrypt-driver-core.

pub use vcrypt_driver_core::copy_into_packed;
pub use vcrypt_driver_core::copy_wide_into_packed;
pub use vcrypt_driver_core::read_packed_i32;
pub use vcrypt_driver_core::read_packed_i64;
pub use vcrypt_driver_core::read_packed_u32;
pub use vcrypt_driver_core::read_packed_u64;
pub use vcrypt_driver_core::read_packed_u8;
pub use vcrypt_driver_core::write_packed_i32;
