//! Integration tests for the encrypted volume mount flow.
//!
//! These tests exercise the create→open→MountStruct chain WITHOUT
//! requiring the kernel driver.  Uses small volumes and low iteration
//! counts to avoid long runtimes.
//!
//! Kernel-dependent tests (actual IOCTL calls) belong in `driver_mount.rs`.

use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::{KdfAlgorithm, Pbkdf2Sha256, Pbkdf2Sha512, Pbkdf2Whirlpool};
use vcrypt_format::header::VOLUME_HEADER_SIZE;
use vcrypt_volume::{create_volume_full, open_volume_file, OpenVolume, VolumeError};

const PASSWORD: &[u8] = b"test1234";
const VOL_SIZE: u64 = 256 * 1024; // 256 KiB — minimum valid volume
const HEADERS: u64 = VOLUME_HEADER_SIZE as u64 * 4;
const ITERS: u32 = 100; // minimal iterations for speed

fn setup_file() -> (std::fs::File, tempfile::TempPath) {
    let t = tempfile::NamedTempFile::new().unwrap();
    let path = t.into_temp_path();
    let f = std::fs::File::create(&path).unwrap();
    (f, path)
}

// ----- B1: AES + PBKDF2-SHA512 (fast, basic smoke test) -------------------

#[test]
fn test_create_open_aes_sha512() {
    let (mut f, path) = setup_file();
    f.set_len(HEADERS + VOL_SIZE).unwrap();

    create_volume_full(
        &mut f, VOL_SIZE, PASSWORD, CipherType::Aes,
        &Pbkdf2Sha512, KdfAlgorithm::Pbkdf2Sha512, ITERS, None, None,
    )
    .unwrap();

    let r = open_volume_file(path.to_str().unwrap(), PASSWORD, &[], None).unwrap();
    assert_eq!(r.data_cipher, CipherType::Aes);
    assert_eq!(r.master_key.len(), CipherType::Aes.key_size() * 2);
    assert_eq!(r.data_length, VOL_SIZE);

    let _vol = OpenVolume::open(path.to_str().unwrap(), PASSWORD, &[], None, None).unwrap();
}

// ----- B2: Twofish + PBKDF2-SHA256 ----------------------------------------

#[test]
fn test_create_open_twofish_sha256() {
    let (mut f, path) = setup_file();
    f.set_len(HEADERS + VOL_SIZE).unwrap();

    create_volume_full(
        &mut f, VOL_SIZE, PASSWORD, CipherType::Twofish,
        &Pbkdf2Sha256, KdfAlgorithm::Pbkdf2Sha256, ITERS, None, None,
    )
    .unwrap();

    let r = open_volume_file(path.to_str().unwrap(), PASSWORD, &[], None).unwrap();
    assert_eq!(r.data_cipher, CipherType::Twofish);
    assert_eq!(r.master_key.len(), CipherType::Twofish.key_size() * 2);

    let _vol = OpenVolume::open(path.to_str().unwrap(), PASSWORD, &[], None, None).unwrap();
}

// ----- B3: Serpent + PBKDF2-Whirlpool -------------------------------------

#[test]
fn test_create_open_serpent_whirlpool() {
    let (mut f, path) = setup_file();
    f.set_len(HEADERS + VOL_SIZE).unwrap();

    create_volume_full(
        &mut f, VOL_SIZE, PASSWORD, CipherType::Serpent,
        &Pbkdf2Whirlpool, KdfAlgorithm::Pbkdf2Whirlpool, ITERS, None, None,
    )
    .unwrap();

    let r = open_volume_file(path.to_str().unwrap(), PASSWORD, &[], None).unwrap();
    assert_eq!(r.data_cipher, CipherType::Serpent);
    assert_eq!(r.master_key.len(), CipherType::Serpent.key_size() * 2);

    let _vol = OpenVolume::open(path.to_str().unwrap(), PASSWORD, &[], None, None).unwrap();
}

// ----- B4: Wrong password → AuthFailed ------------------------------------

#[test]
fn test_wrong_password_fails() {
    let (mut f, path) = setup_file();
    f.set_len(HEADERS + VOL_SIZE).unwrap();

    create_volume_full(
        &mut f, VOL_SIZE, PASSWORD, CipherType::Aes,
        &Pbkdf2Sha256, KdfAlgorithm::Pbkdf2Sha256, ITERS, None, None,
    )
    .unwrap();

    match open_volume_file(path.to_str().unwrap(), b"wrong-pass", &[], None) {
        Err(VolumeError::AuthFailed(_)) => {} // expected
        other => panic!("expected AuthFailed, got {:?}", other.map(|_| ())),
    }
}

// ----- B5: Cascade cipher roundtrip (AES-Twofish) --------------------------

#[test]
fn test_create_open_cascade_aes_twofish() {
    let (mut f, path) = setup_file();
    f.set_len(HEADERS + VOL_SIZE).unwrap();

    create_volume_full(
        &mut f, VOL_SIZE, PASSWORD, CipherType::AesTwofish,
        &Pbkdf2Sha256, KdfAlgorithm::Pbkdf2Sha256, ITERS, None, None,
    )
    .unwrap();

    let r = open_volume_file(path.to_str().unwrap(), PASSWORD, &[], None).unwrap();
    assert_eq!(r.data_cipher, CipherType::AesTwofish);
    // Cascade-2 key size = 2 × single_key_size × 2 (data+tweak) = 2 × 32 × 2 = 128
    assert_eq!(r.master_key.len(), CipherType::AesTwofish.key_size() * 2);

    let _vol = OpenVolume::open(path.to_str().unwrap(), PASSWORD, &[], None, None).unwrap();
}
