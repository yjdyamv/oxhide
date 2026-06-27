//! Cryptographic benchmark — measures cipher, KDF, and hash performance.
//!
//! Cipher benchmarks run both **serial** (single-threaded) and **parallel**
//! (rayon multi-threaded) to show the speedup from multi-core XTS processing.
//! Each 512-byte sector is independent in XTS mode, so parallelization is
//! safe and produces identical results.

use std::time::Instant;
use rayon::prelude::*;
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::hash::{Blake2sHash, HashFunction, Sha256Hash, Sha512Hash,
    StreebogHash, WhirlpoolHash};
use vcrypt_core::kdf::{Argon2idKdf, KeyDerivation,
    Pbkdf2Blake2s, Pbkdf2Sha256, Pbkdf2Sha512, Pbkdf2Streebog, Pbkdf2Whirlpool};
use vcrypt_volume::io::SectorCipher;

const BUF_MB: usize = 16;
const MIN_TIME_MS: u128 = 200;

pub fn run_benchmark(kind: &str) {
    match kind {
        "cipher" => bench_ciphers(false),
        "cipher-parallel" => bench_ciphers(true),
        "kdf" => bench_kdfs(),
        "hash" => bench_hashes(),
        _ => {
            bench_ciphers(true);
            println!();
            bench_kdfs();
            println!();
            bench_hashes();
        }
    }
}

// -----------------------------------------------------------------------
// Cipher benchmark (serial + parallel)
// -----------------------------------------------------------------------

fn bench_ciphers(show_parallel: bool) {
    let title = if show_parallel {
        format!("Encryption Benchmark (XTS, {BUF_MB} MB, serial + parallel, >{MIN_TIME_MS} ms)")
    } else {
        format!("Encryption Benchmark (XTS, {BUF_MB} MB, serial only, >{MIN_TIME_MS} ms)")
    };
    println!("==> {title}");

    if show_parallel {
        println!(
            "{:<28} {:>10} {:>10} {:>10} {:>10} {:>8}",
            "Algorithm", "Enc Ser", "Dec Ser", "Enc Par", "Dec Par", "Speedup"
        );
    } else {
        println!("{:<28} {:>10} {:>10} {:>10}", "Algorithm", "Enc MB/s", "Dec MB/s", "Mean");
    }
    println!("{:-<80}", "");

    let mut results: Vec<(String, f64, f64, Option<f64>, Option<f64>)> = Vec::new();

    for &ct in CipherType::all_supported() {
        let ks = ct.key_size() * 2;
        let key = vec![0xAAu8; ks.min(128)];
        let data = vec![0x42u8; BUF_MB * 1024 * 1024];

        let enc_s = measure_xts(ct, &key, &data, true, false);
        let dec_s = measure_xts(ct, &key, &data, false, false);

        let (enc_p, dec_p) = if show_parallel {
            (
                measure_xts(ct, &key, &data, true, true),
                measure_xts(ct, &key, &data, false, true),
            )
        } else {
            (None, None)
        };

        if let (Some(es), Some(ds)) = (enc_s, dec_s) {
            results.push((ct.name().to_string(), es, ds, enc_p, dec_p));
        }
    }

    // Sort by serial mean (descending)
    results.sort_by(|a, b| {
        let ma = (a.1 + a.2) / 2.0;
        let mb = (b.1 + b.2) / 2.0;
        mb.partial_cmp(&ma).unwrap()
    });

    for (name, enc_s, dec_s, enc_p, dec_p) in &results {
        if show_parallel {
            let speedup = enc_p
                .and_then(|p| if enc_s > &0.0 { Some(p / enc_s) } else { None })
                .unwrap_or(0.0);
            println!(
                "{:<28} {:>8.0}   {:>8.0}   {:>8.0}   {:>8.0}   {:>6.1}x",
                name, enc_s, dec_s,
                enc_p.unwrap_or(0.0),
                dec_p.unwrap_or(0.0),
                speedup
            );
        } else {
            let mean = (enc_s + dec_s) / 2.0;
            println!("{:<28} {:>8.0}   {:>8.0}   {:>8.0}", name, enc_s, dec_s, mean);
        }
    }

    if show_parallel {
        let nthreads = rayon::current_num_threads();
        println!("\n  Parallel: {} threads | {} MB buffer | {} ciphers tested",
            nthreads, BUF_MB, results.len());
    }
}

fn measure_xts(
    ct: CipherType,
    key: &[u8],
    data: &[u8],
    encrypt: bool,
    parallel: bool,
) -> Option<f64> {
    let need = ct.key_size() * 2;
    let k = &key[..need.min(key.len())];
    let sc = vcrypt_volume::create_sector_cipher(ct, k).ok()?;

    if parallel {
        measure_sector_parallel(sc.as_ref(), data, encrypt)
    } else {
        measure_sector_loop(sc.as_ref(), data, encrypt)
    }
}

/// Serial benchmark — process sectors one by one in a single thread.
fn measure_sector_loop(cipher: &dyn SectorCipher, data: &[u8], encrypt: bool) -> Option<f64> {
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

/// Parallel benchmark — use rayon to process sectors across all CPU cores.
///
/// Each 512-byte sector is independent in XTS mode (the sector index is the
/// tweak), so parallelization is safe with no shared mutable state.  The
/// cipher object is `Send + Sync` (read-only during encryption), and each
/// chunk gets a unique `&mut [u8]` slice.
fn measure_sector_parallel(cipher: &dyn SectorCipher, data: &[u8], encrypt: bool) -> Option<f64> {
    let mut buf = data.to_vec();
    let start = Instant::now();
    let mut loops = 0u64;

    while start.elapsed().as_millis() < MIN_TIME_MS {
        // Split the buffer into 512-byte sectors and process in parallel.
        // enumerate() gives us the sector index for the XTS tweak.
        buf.par_chunks_mut(512).enumerate().for_each(|(i, chunk)| {
            let sector = i as u64;
            if encrypt {
                let _ = cipher.encrypt_sector(sector, chunk);
            } else {
                let _ = cipher.decrypt_sector(sector, chunk);
            }
        });
        loops += 1;
    }

    let ms = start.elapsed().as_millis().max(1);
    let bytes = loops * buf.len() as u64;
    Some(bytes as f64 / 1024.0 / 1024.0 / (ms as f64 / 1000.0))
}

// -----------------------------------------------------------------------
// KDF benchmark
// -----------------------------------------------------------------------

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

// -----------------------------------------------------------------------
// Hash benchmark
// -----------------------------------------------------------------------

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
