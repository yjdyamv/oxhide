//! Cryptographic benchmark — measures cipher, KDF, and hash performance.

use std::time::Instant;
use vcrypt_core::ciphers::{AesCipher, BlockCipher, CamelliaCipher, CipherType,
    KuznyechikCipher, SerpentCipher, TwofishCipher};
use vcrypt_core::hash::{Blake2sHash, HashFunction, Sha256Hash, Sha512Hash,
    StreebogHash, WhirlpoolHash};
use vcrypt_core::kdf::{Argon2idKdf, KeyDerivation,
    Pbkdf2Blake2s, Pbkdf2Sha256, Pbkdf2Sha512, Pbkdf2Streebog, Pbkdf2Whirlpool};
use vcrypt_core::xts::XtsMode;
use vcrypt_core::CryptoError;

const BUF_MB: usize = 16;
const MIN_TIME_MS: u128 = 200;

pub fn run_benchmark(kind: &str) {
    match kind {
        "cipher" => bench_ciphers(),
        "kdf" => bench_kdfs(),
        "hash" => bench_hashes(),
        _ => {
            bench_ciphers();
            println!();
            bench_kdfs();
            println!();
            bench_hashes();
        }
    }
}

fn bench_ciphers() {
    println!("==> Encryption Benchmark (XTS, {BUF_MB} MB, >{MIN_TIME_MS} ms)");
    println!("{:<32} {:>10} {:>10} {:>10}", "Algorithm", "Enc MB/s", "Dec MB/s", "Mean");
    println!("{:-<64}", "");

    let mut results: Vec<(String, f64, f64)> = Vec::new();

    for &ct in CipherType::all_supported() {
        let ks = ct.key_size() * 2;
        let key = vec![0xAAu8; ks.min(128)];
        let data = vec![0x42u8; BUF_MB * 1024 * 1024];

        let enc = measure_xts(ct, &key, &data, true);
        let dec = measure_xts(ct, &key, &data, false);
        if let (Some(e), Some(d)) = (enc, dec) {
            results.push((ct.name().to_string(), e, d));
        }
    }

    results.sort_by(|a, b| b.2.partial_cmp(&a.2).unwrap());
    for (name, enc, dec) in &results {
        let mean = (enc + dec) / 2.0;
        println!("{:<32} {:>8.0}   {:>8.0}   {:>8.0}", name, enc, dec, mean);
    }
}

fn measure_xts(ct: CipherType, key: &[u8], data: &[u8], encrypt: bool) -> Option<f64> {
    let need = ct.key_size() * 2;
    let k = &key[..need.min(key.len())];

    match ct {
        CipherType::Aes => {
            let xts = XtsMode::new(k, |kb| {
                AesCipher::new(kb).map_err(|e| CryptoError::CipherInitFailed(format!("aes: {}", e)))
            }).ok()?;
            measure_xts_loop(&xts, data, encrypt)
        }
        CipherType::Serpent => {
            let xts = XtsMode::new(k, |kb| {
                SerpentCipher::new(kb).map_err(|e| CryptoError::CipherInitFailed(format!("serpent: {}", e)))
            }).ok()?;
            measure_xts_loop(&xts, data, encrypt)
        }
        CipherType::Twofish => {
            let xts = XtsMode::new(k, |kb| {
                TwofishCipher::new(kb).map_err(|e| CryptoError::CipherInitFailed(format!("twofish: {}", e)))
            }).ok()?;
            measure_xts_loop(&xts, data, encrypt)
        }
        CipherType::Camellia => {
            let xts = XtsMode::new(k, |kb| {
                CamelliaCipher::new(kb).map_err(|e| CryptoError::CipherInitFailed(format!("camellia: {}", e)))
            }).ok()?;
            measure_xts_loop(&xts, data, encrypt)
        }
        CipherType::Kuznyechik => {
            let xts = XtsMode::new(k, |kb| {
                KuznyechikCipher::new(kb).map_err(|e| CryptoError::CipherInitFailed(format!("kuznyechik: {}", e)))
            }).ok()?;
            measure_xts_loop(&xts, data, encrypt)
        }
        _ => {
            let sc = vcrypt_volume::create_sector_cipher(ct, k).ok()?;
            measure_sector_loop(sc.as_ref(), data, encrypt)
        }
    }
}

fn measure_xts_loop<C: BlockCipher>(xts: &XtsMode<C>, data: &[u8], encrypt: bool) -> Option<f64> {
    let mut buf = data.to_vec();
    let start = Instant::now();
    let mut loops = 0u64;
    let mut sector = 0u64;

    while start.elapsed().as_millis() < MIN_TIME_MS {
        for chunk in buf.chunks_mut(512) {
            if encrypt {
                xts.encrypt(sector, chunk).ok()?;
            } else {
                xts.decrypt(sector, chunk).ok()?;
            }
            sector += 1;
        }
        sector %= (buf.len() / 512) as u64;
        loops += 1;
    }

    let ms = start.elapsed().as_millis().max(1);
    let bytes = loops * buf.len() as u64;
    Some(bytes as f64 / 1024.0 / 1024.0 / (ms as f64 / 1000.0))
}

fn measure_sector_loop(cipher: &dyn vcrypt_volume::io::SectorCipher, data: &[u8], encrypt: bool) -> Option<f64> {
    let mut buf = data.to_vec();
    let start = Instant::now();
    let mut loops = 0u64;
    let mut sector = 0u64;

    while start.elapsed().as_millis() < MIN_TIME_MS {
        for chunk in buf.chunks_mut(512) {
            if encrypt {
                cipher.encrypt_sector(sector, chunk).ok()?;
            } else {
                cipher.decrypt_sector(sector, chunk).ok()?;
            }
            sector += 1;
        }
        sector %= (buf.len() / 512) as u64;
        loops += 1;
    }

    let ms = start.elapsed().as_millis().max(1);
    let bytes = loops * buf.len() as u64;
    Some(bytes as f64 / 1024.0 / 1024.0 / (ms as f64 / 1000.0))
}

fn bench_kdfs() {
    println!("==> KDF Benchmark (192-byte key, 21-char passphrase)");
    println!("{:<30} {:>8} {:>10}", "Algorithm", "Time", "Iterations");
    println!("{:-<50}", "");

    let password = b"benchmark-password-21";
    let salt = [0xABu8; 64];
    let mut results: Vec<(String, u128, u32)> = Vec::new();

    for (name, iters, kdf) in [
        ("PBKDF2-HMAC-SHA-512", Pbkdf2Sha512.get_iteration_count(0),
         Box::new(Pbkdf2Sha512) as Box<dyn KeyDerivation>),
        ("PBKDF2-HMAC-SHA-256", Pbkdf2Sha256.get_iteration_count(0),
         Box::new(Pbkdf2Sha256)),
        ("PBKDF2-HMAC-BLAKE2s", Pbkdf2Blake2s.get_iteration_count(0),
         Box::new(Pbkdf2Blake2s)),
        ("PBKDF2-HMAC-Whirlpool", Pbkdf2Whirlpool.get_iteration_count(0),
         Box::new(Pbkdf2Whirlpool)),
        ("PBKDF2-HMAC-Streebog", Pbkdf2Streebog.get_iteration_count(0),
         Box::new(Pbkdf2Streebog)),
    ] {
        let ms = bench_one_kdf(&*kdf, password, &salt, iters);
        results.push((name.to_string(), ms, iters));
    }

    {
        let (mem, time) = Argon2idKdf::params_for_pim(0);
        let kdf = Argon2idKdf::new(mem, time, 1);
        let ms = bench_one_kdf(&kdf, password, &salt, time);
        results.push(("Argon2id".to_string(), ms, time));
    }

    results.sort_by(|a, b| a.1.cmp(&b.1));
    for (name, ms, iters) in &results {
        println!("{:<30} {:>5} ms  {:>8}", name, ms, iters);
    }
}

fn bench_one_kdf(kdf: &dyn KeyDerivation, pwd: &[u8], salt: &[u8; 64], iters: u32) -> u128 {
    let start = Instant::now();
    let mut out = vec![0u8; 192];
    if kdf.derive(pwd, salt, iters, &mut out).is_err() {
        return 0;
    }
    start.elapsed().as_millis()
}

fn bench_hashes() {
    println!("==> Hash Benchmark (1 KB blocks, >1s)");
    println!("{:<25} {:>10}", "Algorithm", "MB/s");
    println!("{:-<37}", "");

    let data = [0x55u8; 1024];
    let mut results: Vec<(String, f64)> = Vec::new();

    for (name, hash_fn) in [
        ("SHA-512", Box::new(|d: &[u8]| Sha512Hash::hash(d).to_vec()) as Box<dyn Fn(&[u8]) -> Vec<u8>>),
        ("SHA-256", Box::new(|d| Sha256Hash::hash(d).to_vec())),
        ("BLAKE2s", Box::new(|d| Blake2sHash::hash(d).to_vec())),
        ("Whirlpool", Box::new(|d| WhirlpoolHash::hash(d).to_vec())),
        ("Streebog", Box::new(|d| StreebogHash::hash(d).to_vec())),
    ] {
        let start = Instant::now();
        let mut n = 0u64;
        while start.elapsed().as_millis() < 1000 {
            let _ = hash_fn(&data);
            n += 1;
        }
        let ms = start.elapsed().as_millis().max(1);
        let gb = n as f64 * 1024.0 / (1024.0 * 1024.0 * 1024.0);
        let speed = gb * 1024.0 / (ms as f64 / 1000.0);
        results.push((name.to_string(), speed));
    }

    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
    for (name, speed) in &results {
        println!("{:<25} {:>8.0}", name, speed);
    }
}
