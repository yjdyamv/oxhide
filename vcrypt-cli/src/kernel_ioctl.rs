//! User-mode IOCTL communication with the Oxhide kernel driver.
//! Windows-only — compiled behind `#[cfg(windows)]`.

#![allow(unused)]

use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ffi::OsStr;
use std::ptr::addr_of_mut;
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::KdfAlgorithm;

// Pre-computed IOCTL codes (CTL_CODE macro expanded)
// CTL_CODE(0x22, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
const TC_IOCTL_MOUNT_VOLUME: u32 = 0x0022200C;
// CTL_CODE(0x22, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)
const TC_IOCTL_UNMOUNT_VOLUME: u32 = 0x00222010;

// Windows FFI
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::DeviceIoControl;

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;
const FILE_DEVICE_UNKNOWN: u32 = 0x22;
const METHOD_BUFFERED: u32 = 0;
const FILE_ANY_ACCESS: u32 = 0;

const TC_MAX_PATH: usize = 260;
const MAX_PASSWORD: usize = 64;
const MASTER_KEY_MAX: usize = 192;

#[repr(C, packed(1))]
#[derive(Clone, Copy)]
struct MountStruct {
    return_code: i32, filesystem_dirty: u8,
    volume_password: [u16; MAX_PASSWORD],
    mount_read_only: u8, mount_removable: u8,
    partition_in_inactive_sys_enc_scope: u8, mount_disable_write_cache: u8,
    protected_volume_password: [u16; MAX_PASSWORD],
    use_hidden_volume_protection: u8, preserve_timestamps: u8,
    part_slot_number: u32, volume_creation_time: i64, volume_serial_number: u32,
    dummy: [u8; 4], wsz_volume: [u16; TC_MAX_PATH],
    n_dos_drive_no: i32, bytes_per_sector: u32, disk_length: i64,
    ea: u32, master_key: [u8; MASTER_KEY_MAX],
    data_offset: u64, raw_device: u8, volume_pim: i32,
    wsz_label: [u16; 33], max_xfer_len: u32, max_phys_pages: u32, align_mask: u32,
}

#[repr(C, packed(1))]
#[derive(Clone, Copy)]
struct UnmountStruct { return_code: i32, n_dos_drive_no: i32 }

fn cipher_to_ea(ct: CipherType) -> u32 {
    match ct {
        CipherType::Aes => 0x01, CipherType::Serpent => 0x02,
        CipherType::Twofish => 0x03, CipherType::Camellia => 0x04,
        CipherType::Kuznyechik => 0x05, CipherType::AesTwofish => 0x11,
        CipherType::AesTwofishSerpent => 0x12, CipherType::SerpentAes => 0x13,
        CipherType::SerpentTwofishAes => 0x14, CipherType::TwofishSerpent => 0x15,
        CipherType::CamelliaKuznyechik => 0x16, CipherType::CamelliaSerpent => 0x17,
        CipherType::KuznyechikAes => 0x18,
        CipherType::KuznyechikSerpentCamellia => 0x19,
        CipherType::KuznyechikTwofish => 0x1A,
    }
}

pub fn mount_via_driver(
    volume_path: &str, drive_letter: char, password: &[u8],
    keyfiles: &[&str], kdf: Option<KdfAlgorithm>, pim: Option<i32>,
    read_only: bool,
) -> Result<(), String> {
    let open_result = vcrypt_volume::open_volume_file(volume_path, password, keyfiles, pim)
        .or_else(|_| {
            if let Some(k) = kdf {
                vcrypt_volume::open_volume_file_with_kdf(
                    volume_path, password, keyfiles, k, pim.unwrap_or(0))
            } else {
                Err(vcrypt_volume::VolumeError::OpenError("cannot open volume".into()))
            }
        })
        .map_err(|e| format!("Failed to open volume: {}", e))?;

    let drive_no = drive_letter.to_ascii_uppercase() as u8 - b'A';
    if drive_no > 25 { return Err(format!("Invalid drive letter: {}", drive_letter)); }

    let mut mount: MountStruct = unsafe { mem::zeroed() };
    // Write to packed struct via raw pointers to avoid alignment UB
    let mptr: *mut MountStruct = &mut mount;
    unsafe {
        (*mptr).n_dos_drive_no = drive_no as i32;
        (*mptr).bytes_per_sector = 512;
        (*mptr).disk_length = open_result.data_length as i64;
        (*mptr).ea = cipher_to_ea(open_result.data_cipher);
        (*mptr).data_offset = open_result.data_offset;
        (*mptr).mount_read_only = read_only as u8;
        (*mptr).mount_removable = 1;
        (*mptr).volume_pim = open_result.pim;

        let key_len = open_result.master_key.len().min(MASTER_KEY_MAX);
        core::ptr::copy_nonoverlapping(
            open_result.master_key.as_ptr(),
            addr_of_mut!((*mptr).master_key).cast::<u8>(),
            key_len,
        );

        let wide_path: Vec<u16> = OsStr::new(volume_path).encode_wide()
            .chain(std::iter::once(0)).collect();
        let plen = wide_path.len().min(TC_MAX_PATH);
        // Copy as raw bytes — packed struct field at odd offset is unaligned for u16
        core::ptr::copy_nonoverlapping(
            wide_path.as_ptr() as *const u8,
            addr_of_mut!((*mptr).wsz_volume).cast::<u8>(),
            plen * 2,
        );
    }

    let handle = open_driver()?;
    let result = send_mount_ioctl(handle, &mount);
    unsafe { CloseHandle(handle); }
    result
}

pub fn unmount_via_driver(drive_letter: char) -> Result<(), String> {
    let drive_no = drive_letter.to_ascii_uppercase() as u8 - b'A';
    if drive_no > 25 { return Err(format!("Invalid drive letter: {}", drive_letter)); }
    let mut u: UnmountStruct = unsafe { mem::zeroed() };
    unsafe { (*addr_of_mut!(u)).n_dos_drive_no = drive_no as i32; }
    let handle = open_driver()?;
    let result = send_unmount_ioctl(handle, &u);
    unsafe { CloseHandle(handle); }
    result
}

fn open_driver() -> Result<HANDLE, String> {
    let name: Vec<u16> = OsStr::new("\\\\.\\Oxhide").encode_wide()
        .chain(std::iter::once(0)).collect();
    let h = unsafe {
        CreateFileW(name.as_ptr(), GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE, std::ptr::null(),
            OPEN_EXISTING, 0, std::ptr::null_mut())
    };
    if h == INVALID_HANDLE_VALUE { Err("Cannot open \\\\.\\Oxhide — driver loaded?".into()) }
    else { Ok(h) }
}

fn send_mount_ioctl(h: HANDLE, m: &MountStruct) -> Result<(), String> {
    let mut out = *m; let mut br: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(h, TC_IOCTL_MOUNT_VOLUME,
            m as *const _ as *const std::ffi::c_void, mem::size_of::<MountStruct>() as u32,
            &mut out as *mut _ as *mut std::ffi::c_void, mem::size_of::<MountStruct>() as u32,
            &mut br, std::ptr::null_mut())
    };
    if ok == 0 { return Err(format!("IOCTL failed: {}", std::io::Error::last_os_error())); }
    match out.return_code {
        0 => Ok(()),
        -1 => Err("Drive letter in use".into()),
        -2 => Err("Cannot open container file".into()),
        -3 => Err("Unsupported cipher".into()),
        rc => Err(format!("Driver error: {}", rc)),
    }
}

fn send_unmount_ioctl(h: HANDLE, u: &UnmountStruct) -> Result<(), String> {
    let mut out = *u; let mut br: u32 = 0;
    let ok = unsafe {
        DeviceIoControl(h, TC_IOCTL_UNMOUNT_VOLUME,
            u as *const _ as *const std::ffi::c_void, mem::size_of::<UnmountStruct>() as u32,
            &mut out as *mut _ as *mut std::ffi::c_void, mem::size_of::<UnmountStruct>() as u32,
            &mut br, std::ptr::null_mut())
    };
    if ok == 0 { return Err(format!("IOCTL failed: {}", std::io::Error::last_os_error())); }
    match out.return_code { 0 => Ok(()), rc => Err(format!("Driver error: {}", rc)) }
}
