use clap::{Parser, Subcommand};
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::KdfAlgorithm;
use vcrypt_volume::OpenVolume;

mod bench;

#[derive(Parser)]
#[command(name = "vcrypt", version = "0.1.0", about = "VeraCrypt-compatible Rust CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Create {
        volume: String,
        #[arg(short, long)]
        size: Option<String>,
        #[arg(short, long, default_value = "aes-twofish")]
        cipher: String,
        #[arg(short = 'k', long, default_value = "argon2")]
        kdf: String,
        #[arg(short = 'm', long, default_value = "0")]
        pim: i32,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short = 'f', long)]
        keyfile: Vec<String>,
    },
    Info {
        volume: String,
        #[arg(short, long)]
        backup: bool,
    },
    Probe {
        volume: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short = 'k', long)]
        kdf: Option<String>,
        #[arg(short = 'm', long)]
        pim: Option<i32>,
        #[arg(short = 'f', long)]
        keyfile: Vec<String>,
    },
    Dump {
        volume: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short = 'k', long)]
        kdf: Option<String>,
        #[arg(short = 'm', long)]
        pim: Option<i32>,
        #[arg(short = 'f', long)]
        keyfile: Vec<String>,
        #[arg(short, long, default_value = "0")]
        sector: u64,
        #[arg(short = 'c', long, default_value = "1")]
        count: u64,
    },
    Test,
    Benchmark {
        #[arg(default_value = "all")]
        kind: String,
    },
    Change {
        volume: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long)]
        new_password: Option<String>,
        #[arg(short = 'k', long)]
        kdf: Option<String>,
        #[arg(short = 'm', long)]
        pim: Option<i32>,
        #[arg(short = 'f', long)]
        keyfile: Vec<String>,
        #[arg(long)]
        new_keyfile: Vec<String>,
    },
    Restore {
        volume: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short = 'k', long)]
        kdf: Option<String>,
        #[arg(short = 'm', long)]
        pim: Option<i32>,
        #[arg(short = 'f', long)]
        keyfile: Vec<String>,
    },
}

fn main() {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Create { volume, size, cipher, kdf, pim, password, keyfile } => {
            cmd_create(&volume, size.as_deref(), &cipher, &kdf, pim, password, &keyfile);
        }
        Commands::Info { volume, backup } => {
            cmd_info(&volume, backup);
        }
        Commands::Probe { volume, password, kdf, pim, keyfile } => {
            cmd_probe(&volume, password, kdf.as_deref(), pim, &keyfile);
        }
        Commands::Dump { volume, password, kdf, pim, keyfile, sector, count } => {
            cmd_dump(&volume, password, kdf.as_deref(), pim, &keyfile, sector, count);
        }
        Commands::Test => {
            cmd_test();
        }
        Commands::Benchmark { kind } => {
            bench::run_benchmark(&kind);
        }
        Commands::Change { volume, password, new_password, kdf, pim, keyfile, new_keyfile } => {
            cmd_change(&volume, password, new_password, kdf.as_deref(), pim, &keyfile, &new_keyfile);
        }
        Commands::Restore { volume, password, kdf, pim, keyfile } => {
            cmd_restore(&volume, password, kdf.as_deref(), pim, &keyfile);
        }
    }
}

fn read_password(prompt: &str) -> String {
    rpassword::prompt_password(prompt).unwrap_or_else(|e| {
        eprintln!("Error reading password: {}", e);
        std::process::exit(1);
    })
}

fn parse_cipher(s: &str) -> Option<CipherType> {
    match s.to_lowercase().as_str() {
        "aes" => Some(CipherType::Aes),
        "serpent" => Some(CipherType::Serpent),
        "twofish" => Some(CipherType::Twofish),
        "aes-twofish" => Some(CipherType::AesTwofish),
        "aes-twofish-serpent" => Some(CipherType::AesTwofishSerpent),
        "serpent-aes" => Some(CipherType::SerpentAes),
        "serpent-twofish-aes" => Some(CipherType::SerpentTwofishAes),
        "twofish-serpent" => Some(CipherType::TwofishSerpent),
        "camellia-kuznyechik" => Some(CipherType::CamelliaKuznyechik),
        "camellia-serpent" => Some(CipherType::CamelliaSerpent),
        "kuznyechik-aes" => Some(CipherType::KuznyechikAes),
        "kuznyechik-serpent-camellia" => Some(CipherType::KuznyechikSerpentCamellia),
        "kuznyechik-twofish" => Some(CipherType::KuznyechikTwofish),
        _ => None,
    }
}

fn parse_kdf(s: &str) -> Option<KdfAlgorithm> {
    match s.to_lowercase().as_str() {
        "sha512" => Some(KdfAlgorithm::Pbkdf2Sha512),
        "sha256" => Some(KdfAlgorithm::Pbkdf2Sha256),
        "blake2s" => Some(KdfAlgorithm::Pbkdf2Blake2s),
        "whirlpool" => Some(KdfAlgorithm::Pbkdf2Whirlpool),
        "streebog" => Some(KdfAlgorithm::Pbkdf2Streebog),
        "argon2" | "argon2id" => Some(KdfAlgorithm::Argon2id),
        _ => None,
    }
}

fn keyfile_refs(keyfile: &[String]) -> Vec<&str> {
    keyfile.iter().map(String::as_str).collect()
}

fn cmd_create(
    volume: &str, size: Option<&str>, cipher_str: &str, kdf_str: &str, pim: i32,
    password: Option<String>, keyfile: &[String],
) {
    println!("==> Creating volume: {}", volume);
    let size_str = size.unwrap_or("100M");
    let volume_size = parse_size(size_str);
    println!("    Size:     {} ({} bytes)", size_str, volume_size);
    println!("    Cipher:   {}", cipher_str);
    println!("    KDF:      {}", kdf_str);
    println!("    PIM:      {}", pim);

    let cipher = match parse_cipher(cipher_str) {
        Some(c) => c,
        None => { println!("    Error: unknown cipher '{}'", cipher_str); return; }
    };
    let kdf = match parse_kdf(kdf_str) {
        Some(k) => k,
        None => { println!("    Error: unknown KDF '{}'", kdf_str); return; }
    };

    let pw = password.unwrap_or_else(|| read_password("Password: "));
    if pw.is_empty() {
        println!("    Error: empty password not allowed");
        return;
    }

    let mut pw_bytes = pw.into_bytes();
    if !keyfile.is_empty() {
        let kf = keyfile_refs(keyfile);
        if let Err(e) = vcrypt_format::keyfile::apply_keyfiles(&mut pw_bytes, &kf) {
            println!("    Error: keyfile: {}", e);
            return;
        }
    }

    let mut file = match std::fs::File::create(volume) {
        Ok(f) => f,
        Err(e) => { println!("    Error: {}", e); return; }
    };

    let total_size = volume_size + vcrypt_format::header::VOLUME_HEADER_SIZE as u64 * 4;
    if let Err(e) = file.set_len(total_size) {
        println!("    Error setting size: {}", e); return;
    }

    use vcrypt_core::kdf::KeyDerivation;
    let (kdf_impl, kdf_iterations): (Box<dyn KeyDerivation>, u32) = match kdf {
        KdfAlgorithm::Argon2id => {
            let (mem, t) = vcrypt_core::kdf::Argon2idKdf::params_for_pim(pim);
            (Box::new(vcrypt_core::kdf::Argon2idKdf::new(mem, t, 1)), t)
        }
        _ => {
            let imp: Box<dyn KeyDerivation> = match kdf {
                KdfAlgorithm::Pbkdf2Sha512 => Box::new(vcrypt_core::kdf::Pbkdf2Sha512),
                KdfAlgorithm::Pbkdf2Sha256 => Box::new(vcrypt_core::kdf::Pbkdf2Sha256),
                KdfAlgorithm::Pbkdf2Blake2s => Box::new(vcrypt_core::kdf::Pbkdf2Blake2s),
                KdfAlgorithm::Pbkdf2Whirlpool => Box::new(vcrypt_core::kdf::Pbkdf2Whirlpool),
                KdfAlgorithm::Pbkdf2Streebog => Box::new(vcrypt_core::kdf::Pbkdf2Streebog),
                _ => { println!("    Error: unsupported KDF for create"); return; }
            };
            let iters = imp.get_iteration_count(pim);
            (imp, iters)
        }
    };

    let progress: vcrypt_volume::create::ProgressFn = Box::new(|msg: &str| {
        println!("    {}", msg);
    });

    match vcrypt_volume::create_volume_full(
        &mut file, volume_size, &pw_bytes,
        cipher, kdf_impl.as_ref(), kdf, kdf_iterations, None,
        Some(&progress),
    ) {
        Ok(()) => println!("    Status:   Volume created successfully"),
        Err(e) => println!("    Error:   {}", e),
    }
}

fn parse_size(s: &str) -> u64 {
    let s = s.to_uppercase();
    let num: String = s.chars().take_while(|c| c.is_digit(10)).collect();
    let n: u64 = num.parse().unwrap_or(100);
    if s.ends_with("G") || s.ends_with("GB") { n.saturating_mul(1024 * 1024 * 1024) }
    else if s.ends_with("M") || s.ends_with("MB") { n.saturating_mul(1024 * 1024) }
    else if s.ends_with("K") || s.ends_with("KB") { n.saturating_mul(1024) }
    else { n }
}

fn cmd_info(volume: &str, backup: bool) {
    println!("==> Volume info: {}", volume);
    let data = match std::fs::read(volume) {
        Ok(d) => d,
        Err(e) => { println!("    Error: Cannot read volume: {}", e); return; }
    };
    if data.len() < vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE {
        println!("    Error: File too small"); return;
    }
    let offset = if backup { vcrypt_format::header::VOLUME_HEADER_SIZE } else { 0 };
    let hdr = &data[offset..offset + vcrypt_format::header::VOLUME_HEADER_EFFECTIVE_SIZE];
    let salt = &hdr[..vcrypt_format::header::PKCS5_SALT_SIZE];
    println!("    File size: {} bytes", data.len());
    println!("    Salt:      {}...", hex::encode(&salt[..16]).to_uppercase());

    match vcrypt_format::deser::deserialize_header(hdr) {
        Ok(h) => println!("    Header:    v{}, sector={}, size={} (decrypted)", h.header_version, h.sector_size, h.volume_size),
        Err(_) => println!("    Header:    encrypted (CRC fail — needs password)"),
    }
}

fn cmd_probe(
    volume: &str, password: Option<String>, kdf: Option<&str>, pim: Option<i32>,
    keyfile: &[String],
) {
    println!("==> Probing volume: {}", volume);

    let pw = password.unwrap_or_else(|| read_password("Password: "));
    let kf = keyfile_refs(keyfile);

    let result = if let Some(kdf_str) = kdf {
        let kdf = match parse_kdf(kdf_str) {
            Some(k) => k,
            None => {
                println!("    Error: unknown KDF '{}' (try sha512/sha256/blake2s/whirlpool/streebog/argon2)", kdf_str);
                return;
            }
        };
        vcrypt_volume::open_volume_file_with_kdf(
            volume, pw.as_bytes(), &kf, kdf, pim.unwrap_or(0),
        )
    } else {
        vcrypt_volume::open_volume_file(volume, pw.as_bytes(), &kf, pim)
    };

    print_probe_result(result);
}

fn print_probe_result(result: vcrypt_volume::VolResult<vcrypt_volume::open::OpenResult>) {
    match result {
        Ok(r) => {
            println!("    Status:    success");
            println!("    KDF:       {:?}", r.kdf);
            println!("    PIM:       {}", r.pim);
            println!("    Cipher:    {}", r.header_cipher.name());
            println!("    Iter:      {}", r.iterations);
            if let Some(memory) = r.memory_cost_kib {
                println!("    Argon2Mem: {} KiB", memory);
            }
            if r.used_backup_header {
                println!("    Header:    backup");
            }
            println!("    Data off:  {}", r.data_offset);
            println!("    Data len:  {}", r.data_length);
            println!("    Key bytes: {}", r.master_key.len());
        }
        Err(e) => {
            println!("    Status:    failed");
            println!("    Error:     {}", e);
        }
    }
}

fn cmd_dump(
    volume: &str, password: Option<String>, kdf: Option<&str>, pim: Option<i32>,
    keyfile: &[String], sector: u64, count: u64,
) {
    println!("==> Dumping volume: {}", volume);
    println!("    Sector:    {}", sector);
    println!("    Count:     {}", count);

    let pw = password.unwrap_or_else(|| read_password("Password: "));
    let kf = keyfile_refs(keyfile);

    let kdf_alg = kdf.and_then(parse_kdf);

    let mut vol = match OpenVolume::open(volume, pw.as_bytes(), &kf, kdf_alg, pim) {
        Ok(v) => v,
        Err(e) => { println!("    Error: {}", e); return; }
    };

    let max = vol.max_sector();
    if sector >= max {
        println!("    Error: sector {} out of range (max {})", sector, max);
        return;
    }
    let end = (sector + count).min(max);
    let actual_count = end - sector;

    let mut buf = vec![0u8; 512 * actual_count as usize];
    if let Err(e) = vol.read(sector, &mut buf) {
        println!("    Error reading: {}", e);
        return;
    }

    for i in 0..actual_count {
        let sector_num = sector + i;
        let start = i as usize * 512;
        let end = start + 512;
        hexdump(&buf[start..end], sector_num * 512);
    }
}

fn hexdump(data: &[u8], offset: u64) {
    for (i, chunk) in data.chunks(16).enumerate() {
        let addr = offset + i as u64 * 16;
        print!("    {:08x}  ", addr);

        for j in 0..16 {
            if j < chunk.len() {
                print!("{:02x} ", chunk[j]);
            } else {
                print!("   ");
            }
            if j == 7 {
                print!(" ");
            }
        }

        print!(" |");
        for &b in chunk {
            if b.is_ascii_graphic() || b == b' ' {
                print!("{}", b as char);
            } else {
                print!(".");
            }
        }
        for _ in chunk.len()..16 {
            print!(" ");
        }
        println!("|");
    }
}

fn cmd_change(
    volume: &str, password: Option<String>, new_password: Option<String>,
    kdf: Option<&str>, pim: Option<i32>,
    keyfile: &[String], new_keyfile: &[String],
) {
    println!("==> Changing password: {}", volume);

    let pw = password.unwrap_or_else(|| read_password("Old password: "));
    let new_pw = new_password.unwrap_or_else(|| read_password("New password: "));
    if new_pw.is_empty() {
        println!("    Error: empty password not allowed");
        return;
    }

    let new_kdf = kdf.map(|s| parse_kdf(s).unwrap_or_else(|| {
        eprintln!("Error: unknown KDF '{}'", s);
        std::process::exit(1);
    }));

    let kf = keyfile_refs(keyfile);
    let new_kf = keyfile_refs(new_keyfile);

    // Auto-detect old KDF (like probe), then re-encrypt with new credentials
    let open_result = match vcrypt_volume::open_volume_file(
        volume, pw.as_bytes(), &kf, pim,
    ) {
        Ok(r) => r,
        Err(e) => {
            println!("    Error opening: {}", e);
            return;
        }
    };

    // New KDF defaults to same as old
    let actual_new_kdf = new_kdf.unwrap_or(open_result.kdf);
    let actual_new_pim = pim.unwrap_or(0);

    // Re-encrypt headers
    let mut file = match std::fs::OpenOptions::new().read(true).write(true).open(volume) {
        Ok(f) => f,
        Err(e) => { println!("    Error: {}", e); return; }
    };

    match vcrypt_volume::change_volume_password(
        &mut file, &open_result,
        new_pw.as_bytes(), &new_kf,
        actual_new_kdf, actual_new_pim,
    ) {
        Ok(()) => println!("    Status:    password changed successfully"),
        Err(e) => println!("    Error:     {}", e),
    }
}

fn cmd_restore(
    volume: &str, password: Option<String>, kdf: Option<&str>, pim: Option<i32>,
    keyfile: &[String],
) {
    println!("==> Restoring header: {}", volume);

    let pw = password.unwrap_or_else(|| read_password("Password: "));
    let kf = keyfile_refs(keyfile);

    let mut file = match std::fs::OpenOptions::new().read(true).write(true).open(volume) {
        Ok(f) => f,
        Err(e) => { println!("    Error: {}", e); return; }
    };

    let kdf_alg = kdf.and_then(parse_kdf);
    match vcrypt_volume::restore_volume_header(&mut file, pw.as_bytes(), &kf, kdf_alg, pim) {
        Ok(()) => println!("    Status:    header restored from backup"),
        Err(e) => println!("    Error:     {}", e),
    }
}

fn cmd_test() {
    println!("==> Cryptographic Self-Tests");

    use vcrypt_core::ciphers::{AesCipher, BlockCipher};
    let key = [0u8; 32];
    let cipher = AesCipher::new(&key).unwrap();
    let mut data = [0x12u8; 16];
    let orig = data;
    cipher.encrypt_block(&mut data).unwrap();
    assert_ne!(data, orig);
    cipher.decrypt_block(&mut data).unwrap();
    assert_eq!(data, orig);
    println!("  ok AES-256 encrypt/decrypt");

    use vcrypt_core::hash::{Sha256Hash, HashFunction};
    let hash = Sha256Hash::hash(b"abc");
    assert_eq!(hex::encode(&hash),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    println!("  ok SHA-256 KAT");

    use vcrypt_core::kdf::{Pbkdf2Sha256, KeyDerivation};
    let mut out = [0u8; 32];
    Pbkdf2Sha256.derive(b"password", b"salt", 1000, &mut out).unwrap();
    assert_ne!(out, [0u8; 32]);
    println!("  ok PBKDF2-HMAC-SHA-256");

    println!("\nAll self-tests passed ok");
}
