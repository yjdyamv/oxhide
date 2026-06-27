//! Thin wrapper around `vcrypt_core::KernelSectorCipher` for the driver.
//!
//! The kernel does **not** perform KDF/hashing/header-decryption (those live
//! in the user-mode `vcrypt-volume` crate).  It receives a pre-derived master
//! key + encryption-algorithm (`ea`) from user-mode via `MountStruct` and
//! constructs the appropriate `KernelSectorCipher`.

use crate::debug;
use crate::types::{self, MountStruct, MASTER_KEY_MAX_SIZE};
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::KernelSectorCipher;

/// Initialise a `KernelSectorCipher` from the fields of a packed `MountStruct`.
///
/// The master key is copied to an aligned stack buffer before cipher
/// construction (AES key expansion issues unaligned loads that fault with
/// the x64 AC flag set).
///
/// Returns `Some` on success, `None` if the `ea` value is unknown or the key
/// length is wrong.
pub fn init_cipher_from_mount(mount: &MountStruct) -> Option<KernelSectorCipher> {
    let ea = unsafe { types::read_packed_u32(core::ptr::addr_of!(mount.ea)) };
    let ct = cipher_type_from_ea(ea)?;
    let key_len = ct.key_size() * 2;
    let key_src = core::ptr::addr_of!(mount.master_key) as *const u8;
    let mut key_buf: [u8; MASTER_KEY_MAX_SIZE] = [0u8; MASTER_KEY_MAX_SIZE];
    let klen = key_len.min(MASTER_KEY_MAX_SIZE);
    unsafe {
        for i in 0..klen {
            key_buf[i] = *key_src.add(i);
        }
    }
    let cipher = KernelSectorCipher::new(ct, &key_buf[..klen]).ok()?;
    // Zeroize the stack buffer holding the key.
    key_buf.fill(0);
    Some(cipher)
}

/// Initialise a `KernelSectorCipher` from an EA value and raw key bytes.
/// Used by the mount thread after the `MountStruct` may have been released.
pub fn init_cipher_from_ea_and_key(ea: u32, key: &[u8]) -> Option<KernelSectorCipher> {
    let ct = cipher_type_from_ea(ea)?;
    let key_len = ct.key_size() * 2;
    let k = &key[..key_len.min(key.len())];
    debug::kdbg("[Oxhide] crypto: init_cipher_from_ea_and_key\n");
    KernelSectorCipher::new(ct, k).ok()
}

/// Map a VeraCrypt encryption-algorithm ID (`ea`) to `CipherType`.
pub fn cipher_type_from_ea(ea: u32) -> Option<CipherType> {
    match ea {
        0x01 => Some(CipherType::Aes),
        0x02 => Some(CipherType::Serpent),
        0x03 => Some(CipherType::Twofish),
        0x04 => Some(CipherType::Camellia),
        0x05 => Some(CipherType::Kuznyechik),
        0x11 => Some(CipherType::AesTwofish),
        0x12 => Some(CipherType::AesTwofishSerpent),
        0x13 => Some(CipherType::SerpentAes),
        0x14 => Some(CipherType::SerpentTwofishAes),
        0x15 => Some(CipherType::TwofishSerpent),
        0x16 => Some(CipherType::CamelliaKuznyechik),
        0x17 => Some(CipherType::CamelliaSerpent),
        0x18 => Some(CipherType::KuznyechikAes),
        0x19 => Some(CipherType::KuznyechikSerpentCamellia),
        0x1A => Some(CipherType::KuznyechikTwofish),
        _ => None,
    }
}

/// Compute the virtual disk geometry following VeraCrypt's convention:
/// - 1 track per cylinder, 1 sector per track
/// - `NumberOfCylinders = DiskLength / BytesPerSector`
/// - All 512-byte sector alignment for virtual geometry.
pub fn compute_virtual_geometry(disk_length: u64, bytes_per_sector: u32) -> (u64, u32, u32) {
    let sector_count = disk_length / bytes_per_sector as u64;
    let cylinders = sector_count.max(1);
    (cylinders, 1, 1)
}
