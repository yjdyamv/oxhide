//! Volume opening — header decryption + key extraction

use super::error::{VolResult, VolumeError};
use super::layout::HeaderLayout;
use std::time::Instant;
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::{
    Argon2idKdf, KdfAlgorithm, KeyDerivation, Pbkdf2Blake2s, Pbkdf2Sha256, Pbkdf2Sha512,
    Pbkdf2Streebog, Pbkdf2Whirlpool,
};
use vcrypt_format::header::{PKCS5_SALT_SIZE, VOLUME_HEADER_EFFECTIVE_SIZE};

const MAX_HEADER_KEY_SIZE: usize = 192;

pub struct OpenResult {
    pub header_cipher: CipherType,
    pub data_cipher: CipherType,
    pub kdf: KdfAlgorithm,
    pub pim: i32,
    pub iterations: u32,
    pub memory_cost_kib: Option<u32>,
    pub master_key: Vec<u8>,
    pub data_offset: u64,
    pub data_length: u64,
}

struct KdfCandidate {
    algorithm: KdfAlgorithm,
    implementation: Box<dyn KeyDerivation>,
    pim: i32,
    iterations: u32,
    memory_cost_kib: Option<u32>,
}

/// Open a volume file with an explicit KDF and PIM.
pub fn open_volume_file_with_kdf(
    path: &str,
    password: &[u8],
    keyfiles: &[&str],
    kdf: KdfAlgorithm,
    pim: i32,
) -> VolResult<OpenResult> {
    let data = std::fs::read(path)
        .map_err(|e| VolumeError::OpenError(format!("read: {}", e)))?;

    log::trace!("open_volume_file_with_kdf: file_size={}", data.len());

    let mut pw = password.to_vec();
    if !keyfiles.is_empty() {
        vcrypt_format::keyfile::apply_keyfiles(&mut pw, keyfiles)
            .map_err(|e| VolumeError::CryptoError(format!("keyfile: {}", e)))?;
    }

    let layouts = HeaderLayout::candidates(data.len() as u64);
    for layout in &layouts {
        for offset in candidate_offsets(layout, data.len() as u64) {
            log::debug!("trying layout={:?} offset={}", layout, offset);

            let read_size = layout.read_size.min(data.len().saturating_sub(offset as usize));
            if read_size < VOLUME_HEADER_EFFECTIVE_SIZE {
                continue;
            }

            let header = &data[offset as usize..offset as usize + read_size];
            let result = open_volume_single_kdf(header, &pw, kdf, pim);
            match result {
                Ok(r) => return Ok(r),
                Err(VolumeError::AuthFailed(_)) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    Err(VolumeError::AuthFailed("Password incorrect or volume corrupted".into()))
}

/// Auto-detect KDF and open a volume file.
pub fn open_volume_file(
    path: &str,
    password: &[u8],
    keyfiles: &[&str],
    pim: Option<i32>,
) -> VolResult<OpenResult> {
    let data = std::fs::read(path)
        .map_err(|e| VolumeError::OpenError(format!("read: {}", e)))?;

    log::trace!("open_volume_file: file_size={}", data.len());

    let mut pw = password.to_vec();
    if !keyfiles.is_empty() {
        vcrypt_format::keyfile::apply_keyfiles(&mut pw, keyfiles)
            .map_err(|e| VolumeError::CryptoError(format!("keyfile: {}", e)))?;
    }

    let layouts = HeaderLayout::candidates(data.len() as u64);
    for layout in &layouts {
        for offset in candidate_offsets(layout, data.len() as u64) {
            log::debug!("trying layout={:?} offset={}", layout, offset);

            let read_size = layout.read_size.min(data.len().saturating_sub(offset as usize));
            if read_size < VOLUME_HEADER_EFFECTIVE_SIZE {
                continue;
            }

            let header = &data[offset as usize..offset as usize + read_size];
            match open_volume_auto(header, &pw, pim) {
                Ok(r) => return Ok(r),
                Err(VolumeError::AuthFailed(_)) => continue,
                Err(e) => return Err(e),
            }
        }
    }

    Err(VolumeError::AuthFailed("Password incorrect or volume corrupted".into()))
}

// ---------------------------------------------------------------------------
// Core open logic — every public opener funnels through here
// ---------------------------------------------------------------------------

/// Derive MAX_HEADER_KEY_SIZE (192 bytes) once per KDF candidate, then try
/// every supported cipher by slicing the derived key to `cipher.key_size() * 2`.
fn try_open(header: &[u8], password: &[u8], candidates: &[KdfCandidate]) -> VolResult<OpenResult> {
    if header.len() < VOLUME_HEADER_EFFECTIVE_SIZE {
        return Err(VolumeError::InvalidFormat("Header too small".into()));
    }

    let salt: &[u8; PKCS5_SALT_SIZE] = header[..PKCS5_SALT_SIZE]
        .try_into()
        .map_err(|_| VolumeError::InvalidFormat("Bad salt".into()))?;

    let total_start = Instant::now();
    let mut attempt = 0u32;

    for kdf in candidates {
        attempt += 1;
        log::debug!(
            "attempt #{}: KDF={} max_key=192 iters={}",
            attempt, kdf.algorithm.name(), kdf.iterations,
        );

        let mut key = vec![0u8; MAX_HEADER_KEY_SIZE];
        let derive_start = Instant::now();
        if kdf.implementation.derive(password, salt, kdf.iterations, &mut key).is_err() {
            log::debug!("  derive failed after {:?}", derive_start.elapsed());
            continue;
        }
        log::debug!("  derive took {:?}", derive_start.elapsed());

        for &cipher in supported_volume_algorithms() {
            let needed = cipher.key_size() * 2;
            if let Ok(result) = try_decrypt(header, cipher, &key[..needed], kdf) {
                log::debug!(
                    "  cipher={} OK (total {:?}, {} attempts)",
                    cipher.name(), total_start.elapsed(), attempt,
                );
                return Ok(result);
            }
            log::debug!("  cipher={} mismatch", cipher.name());
        }
    }

    log::debug!(
        "all {} attempts exhausted in {:?} — auth failed",
        attempt, total_start.elapsed()
    );
    Err(VolumeError::AuthFailed("Password incorrect or volume corrupted".into()))
}

// ---------------------------------------------------------------------------
// Public openers (each one just builds a candidate list and calls try_open)
// ---------------------------------------------------------------------------

fn open_volume_auto(header: &[u8], password: &[u8], pim: Option<i32>) -> VolResult<OpenResult> {
    try_open(header, password, &auto_kdf_candidates(pim))
}

fn open_volume_single_kdf(header: &[u8], password: &[u8], kdf: KdfAlgorithm, pim: i32) -> VolResult<OpenResult> {
    try_open(header, password, &[make_kdf_candidate(kdf, pim)])
}

pub fn open_volume_with_pim(header: &[u8], password: &[u8], pim: i32) -> VolResult<OpenResult> {
    open_volume_auto(header, password, Some(pim))
}

pub fn open_volume_with_iters(header: &[u8], password: &[u8], iterations: u32) -> VolResult<OpenResult> {
    let implementation = kdf_impl(KdfAlgorithm::Pbkdf2Sha256);
    let candidate = KdfCandidate {
        algorithm: KdfAlgorithm::Pbkdf2Sha256,
        implementation,
        pim: 0,
        iterations,
        memory_cost_kib: None,
    };
    try_open(header, password, &[candidate])
}

fn try_decrypt(
    data: &[u8],
    header_cipher: CipherType,
    header_key: &[u8],
    kdf: &KdfCandidate,
) -> VolResult<OpenResult> {
    let mut decrypted = data[..VOLUME_HEADER_EFFECTIVE_SIZE].to_vec();
    vcrypt_format::encrypt::decrypt_header_area(&mut decrypted, header_key, header_cipher)
        .map_err(|_| VolumeError::AuthFailed("header decrypt".into()))?;

    let header = vcrypt_format::deser::deserialize_header(&decrypted)
        .map_err(|_| VolumeError::AuthFailed("header parse".into()))?;

    let data_cipher = infer_data_cipher(header_cipher, &header.master_keydata)?;
    let expected_key_bytes = data_cipher.key_size() * 2;
    if header.master_keydata.len() < expected_key_bytes {
        return Err(VolumeError::InvalidFormat(format!(
            "Master key area too small for {}",
            data_cipher.name()
        )));
    }

    let master_key = header.master_keydata[..expected_key_bytes].to_vec();

    Ok(OpenResult {
        header_cipher,
        data_cipher,
        kdf: kdf.algorithm,
        pim: kdf.pim,
        iterations: kdf.iterations,
        memory_cost_kib: kdf.memory_cost_kib,
        master_key,
        data_offset: header.encrypted_area_start,
        data_length: if header.encrypted_area_length > 0 {
            header.encrypted_area_length
        } else {
            header.volume_size
        },
    })
}

fn candidate_offsets(layout: &HeaderLayout, file_size: u64) -> Vec<u64> {
    let mut offsets = vec![layout.header_offset];
    if let Some(backup) = layout.backup_offset {
        if backup < file_size && !offsets.contains(&backup) {
            offsets.push(backup);
        }
    }
    offsets
}

/// KDFs tried during auto-detection, ordered from fastest to slowest.
fn auto_kdf_candidates(pim: Option<i32>) -> Vec<KdfCandidate> {
    let kdfs = [
        KdfAlgorithm::Pbkdf2Sha512,
        KdfAlgorithm::Pbkdf2Sha256,
        KdfAlgorithm::Pbkdf2Blake2s,
        KdfAlgorithm::Pbkdf2Whirlpool,
        KdfAlgorithm::Pbkdf2Streebog,
        KdfAlgorithm::Argon2id,
    ];

    kdfs.iter()
        .map(|&alg| make_kdf_candidate(alg, pim_for_algorithm(alg, pim)))
        .collect()
}

fn pim_for_algorithm(_alg: KdfAlgorithm, pim: Option<i32>) -> i32 {
    pim.unwrap_or(0)
}

fn make_kdf_candidate(kdf: KdfAlgorithm, pim: i32) -> KdfCandidate {
    let (implementation, iterations, memory_cost_kib) = match kdf {
        KdfAlgorithm::Argon2id => {
            let (memory_cost_kib, time_cost) = Argon2idKdf::params_for_pim(pim);
            (
                Box::new(Argon2idKdf::new(memory_cost_kib, time_cost, 1)) as Box<dyn KeyDerivation>,
                time_cost,
                Some(memory_cost_kib),
            )
        }
        _ => {
            let implementation = kdf_impl(kdf);
            let iterations = implementation.get_iteration_count(pim);
            (implementation, iterations, None)
        }
    };

    KdfCandidate {
        algorithm: kdf,
        implementation,
        pim,
        iterations,
        memory_cost_kib,
    }
}

fn kdf_impl(algorithm: KdfAlgorithm) -> Box<dyn KeyDerivation> {
    match algorithm {
        KdfAlgorithm::Pbkdf2Sha512 => Box::new(Pbkdf2Sha512),
        KdfAlgorithm::Pbkdf2Whirlpool => Box::new(Pbkdf2Whirlpool),
        KdfAlgorithm::Pbkdf2Sha256 => Box::new(Pbkdf2Sha256),
        KdfAlgorithm::Pbkdf2Blake2s => Box::new(Pbkdf2Blake2s),
        KdfAlgorithm::Pbkdf2Streebog => Box::new(Pbkdf2Streebog),
        KdfAlgorithm::Argon2id => {
            let (memory_cost, time_cost) = Argon2idKdf::params_for_pim(0);
            Box::new(Argon2idKdf::new(memory_cost, time_cost, 1))
        }
    }
}

fn supported_volume_algorithms() -> &'static [CipherType] {
    CipherType::all_supported()
}

fn infer_data_cipher(header_cipher: CipherType, _master_keydata: &[u8]) -> VolResult<CipherType> {
    Ok(header_cipher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::create::create_volume;
    use vcrypt_core::kdf::Pbkdf2Sha256;
    use vcrypt_core::rng;
    use vcrypt_format::encrypt::derive_header_key;
    use vcrypt_format::header::{VolumeHeader, VOLUME_HEADER_SIZE};

    const T: u32 = 100;

    #[test]
    fn test_open_basic() {
        let salt = rng::random_salt().unwrap();
        let key = derive_header_key(&Pbkdf2Sha256, b"test", &salt, T, CipherType::Aes).unwrap();
        let mut hdr = VolumeHeader::new();
        hdr.salt = salt;
        let hdr_bytes = vcrypt_format::ser::serialize_header(&hdr).unwrap();
        let mut vol = vec![0u8; vcrypt_format::header::VOLUME_HEADER_SIZE];
        vol[..512].copy_from_slice(&hdr_bytes);
        vcrypt_format::encrypt::encrypt_header_area(&mut vol[..512], &key, CipherType::Aes).unwrap();
        assert!(open_volume_with_iters(&vol, b"wrong", T).is_err());
        let opened = open_volume_with_iters(&vol, b"test", T).unwrap();
        assert_eq!(opened.header_cipher, CipherType::Aes);
        assert_eq!(opened.data_cipher, CipherType::Aes);
    }

    #[test]
    fn test_open_pim() {
        let salt = rng::random_salt().unwrap();
        let iters = Pbkdf2Sha256.get_iteration_count(5);
        let key = derive_header_key(&Pbkdf2Sha256, b"pimtest", &salt, iters, CipherType::Aes).unwrap();
        let mut hdr = VolumeHeader::new();
        hdr.salt = salt;
        let hdr_bytes = vcrypt_format::ser::serialize_header(&hdr).unwrap();
        let mut vol = vec![0u8; vcrypt_format::header::VOLUME_HEADER_SIZE];
        vol[..512].copy_from_slice(&hdr_bytes);
        vcrypt_format::encrypt::encrypt_header_area(&mut vol[..512], &key, CipherType::Aes).unwrap();
        let opened = open_volume_with_pim(&vol, b"pimtest", 5).unwrap();
        assert_eq!(opened.pim, 5);
    }

    #[test]
    fn test_open_cascade_header() {
        let salt = rng::random_salt().unwrap();
        let cipher = CipherType::AesTwofishSerpent;
        let key = derive_header_key(&Pbkdf2Sha256, b"test", &salt, T, cipher).unwrap();
        let mut hdr = VolumeHeader::new();
        hdr.salt = salt;
        hdr.master_keydata[..cipher.key_size() * 2].fill(0xAA);

        let hdr_bytes = vcrypt_format::ser::serialize_header(&hdr).unwrap();
        let mut vol = vec![0u8; VOLUME_HEADER_SIZE];
        vol[..512].copy_from_slice(&hdr_bytes);
        vcrypt_format::encrypt::encrypt_header_area(&mut vol[..512], &key, cipher).unwrap();

        let opened = open_volume_with_iters(&vol, b"test", T).unwrap();
        assert_eq!(opened.header_cipher, cipher);
        assert_eq!(opened.data_cipher, cipher);
        assert_eq!(opened.master_key.len(), cipher.key_size() * 2);
    }

    #[test]
    fn test_open_auto_argon2_default_pim() {
        use vcrypt_core::kdf::Argon2idKdf;

        let salt = rng::random_salt().unwrap();
        let kdf = Argon2idKdf::default();
        let time_cost = 3;
        let mut max_key = vec![0u8; MAX_HEADER_KEY_SIZE];
        kdf.derive(b"argon2", &salt, time_cost, &mut max_key).unwrap();
        let key = &max_key[..64];

        let mut hdr = VolumeHeader::new();
        hdr.salt = salt;
        hdr.master_keydata[..64].fill(0x11);

        let hdr_bytes = vcrypt_format::ser::serialize_header(&hdr).unwrap();
        let mut vol = vec![0u8; VOLUME_HEADER_SIZE];
        vol[..512].copy_from_slice(&hdr_bytes);
        vcrypt_format::encrypt::encrypt_header_area(&mut vol[..512], &key, CipherType::Aes).unwrap();

        let opened = open_volume_single_kdf(&vol, b"argon2", KdfAlgorithm::Argon2id, 1).unwrap();
        assert_eq!(opened.kdf, KdfAlgorithm::Argon2id);
        assert_eq!(opened.pim, 1);
        assert_eq!(opened.memory_cost_kib, Some(65536));
    }

    #[test]
    fn test_create_and_open() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let mut f = std::fs::File::create(tmp.path()).unwrap();
        f.set_len(VOLUME_HEADER_SIZE as u64 * 4).unwrap();
        create_volume(
            &mut f,
            0,
            b"test",
            &Pbkdf2Sha256,
            KdfAlgorithm::Pbkdf2Sha256,
            100,
        )
        .unwrap();
        let data = std::fs::read(tmp.path()).unwrap();
        assert!(open_volume_with_iters(&data, b"test", 100).is_ok());
        assert!(open_volume_with_iters(&data, b"wrong", 100).is_err());
    }
}
