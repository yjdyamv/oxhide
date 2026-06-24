use std::path::Path;
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::KdfAlgorithm;
use vcrypt_volume::OpenVolume;

const TEST_VOLUME: &str = "E:\\test.hc";

#[test]
fn compat_open_veracrypt_volume() {
    if !Path::new(TEST_VOLUME).exists() {
        eprintln!("SKIP: {} not found", TEST_VOLUME);
        return;
    }

    let result = vcrypt_volume::open_volume_file_with_kdf(
        TEST_VOLUME,
        b"test1234",
        &[],
        KdfAlgorithm::Argon2id,
        0,
    )
    .expect("should open VeraCrypt-created volume");

    assert_eq!(result.header_cipher, CipherType::AesTwofish);
    assert_eq!(result.data_cipher, CipherType::AesTwofish);
    assert_eq!(result.kdf, KdfAlgorithm::Argon2id);
    assert_eq!(result.master_key.len(), 128);
    assert!(result.data_length > 0);
    assert!(!result.used_backup_header, "should use primary header, not backup");
}

#[test]
fn compat_read_sector_zero() {
    if !Path::new(TEST_VOLUME).exists() {
        eprintln!("SKIP: {} not found", TEST_VOLUME);
        return;
    }

    let mut vol = OpenVolume::open(
        TEST_VOLUME,
        b"test1234",
        &[],
        Some(KdfAlgorithm::Argon2id),
        Some(0),
    )
    .expect("should open volume");

    assert_eq!(vol.cipher(), CipherType::AesTwofish);
    assert!(vol.data_size() > 0);

    let mut buf = vec![0u8; 512];
    vol.read(0, &mut buf).expect("should read sector 0");

    let all_zero = buf.iter().all(|&b| b == 0);
    assert!(!all_zero, "sector 0 should contain filesystem data, not all zeros");
}
