# VeraCrypt Rust Rewrite Implementation Plan

## Project Overview

Rewrite VeraCrypt in Rust to create a modern, memory-safe implementation while maintaining **100% format compatibility** with existing VeraCrypt volumes. This ensures users can seamlessly mount volumes created with either implementation.

**Codebase Analysis:**
- Original: ~262,000 lines of C/C++ code
- Core components: Crypto, Volume management, Boot loader, Platform-specific drivers
- Supported platforms: Windows, Linux, macOS, FreeBSD, OpenBSD

## Goals

1. **Format Compatibility**: Read/write existing VeraCrypt volumes without modification
2. **Security**: Leverage Rust's memory safety to eliminate buffer overflows and use-after-free bugs
3. **Cross-platform**: Support Linux, Windows, and macOS
4. **Performance**: Match or exceed original performance using Rust's zero-cost abstractions
5. **Maintainability**: Clean, idiomatic Rust code with comprehensive documentation

## Non-Goals (Initial Release)

- System encryption (full disk encryption with pre-boot authentication)
- Boot loader implementation
- Windows kernel driver (focus on FUSE-based userspace implementation initially)
- GUI application (CLI first, GUI later)

## Architecture Overview

```
veracrypt-rust/
├── vcrypt-core/          # Core cryptographic library (no_std compatible)
│   ├── ciphers/          # AES, Serpent, Twofish, Camellia, Kuznyechik
│   ├── hash/             # SHA-256/512, BLAKE2s, Whirlpool, Streebog
│   ├── kdf/              # PBKDF2, Argon2
│   └── xts/              # XTS mode implementation
├── vcrypt-format/        # Volume format handling
│   ├── header/           # Volume header parsing/creation
│   ├── layout/           # Volume layouts (normal, hidden)
│   └── crypto_info/      # Encryption metadata structures
├── vcrypt-volume/        # Volume operations
│   ├── mount/            # Volume mounting logic
│   ├── io/               # Sector-based I/O
│   └── protection/       # Hidden volume protection
├── vcrypt-fs/            # Filesystem integration
│   ├── fuse/             # FUSE implementation (Linux/macOS)
│   └── dokan/            # Dokan implementation (Windows)
├── vcrypt-cli/           # Command-line interface
└── vcrypt-tools/         # Utilities (format, keyfile, etc.)
```

## Phase 1: Core Cryptographic Library (4-6 weeks)

### 1.1 Cipher Implementations

**Approach**: Use existing, audited Rust crypto crates where possible, implement missing algorithms.

**Ciphers to support:**
- **AES**: Use `aes` crate (RustCrypto) - hardware acceleration via AES-NI
- **Serpent**: Use `serpent` crate or port from VeraCrypt
- **Twofish**: Use `twofish` crate or port from VeraCrypt  
- **Camellia**: Port from VeraCrypt (limited Rust support)
- **Kuznyechik**: Port from VeraCrypt (Russian GOST standard)

**Key structures:**
```rust
pub trait BlockCipher: Send + Sync {
    const BLOCK_SIZE: usize;
    const KEY_SIZE: usize;
    
    fn encrypt_block(&self, block: &mut [u8]);
    fn decrypt_block(&self, block: &mut [u8]);
}

pub struct CipherCascade {
    ciphers: Vec<Box<dyn BlockCipher>>,
}
```

**Tasks:**
- [ ] Define BlockCipher trait with encrypt/decrypt operations
- [ ] Implement or integrate AES (use aes crate + aes-ni feature)
- [ ] Integrate/port Serpent cipher
- [ ] Integrate/port Twofish cipher
- [ ] Port Camellia cipher from C
- [ ] Port Kuznyechik cipher from C
- [ ] Implement cipher cascading (AES-Twofish-Serpent, etc.)
- [ ] Write unit tests against VeraCrypt test vectors
- [ ] Benchmark performance vs original

### 1.2 Hash Functions and KDF

**Hash functions:**
- **SHA-256/512**: Use `sha2` crate (RustCrypto)
- **BLAKE2s**: Use `blake2` crate
- **Whirlpool**: Port from VeraCrypt or find Rust implementation
- **Streebog**: Port from VeraCrypt (Russian GOST standard)

**KDF implementations:**
- **PBKDF2**: Use `pbkdf2` crate with custom PRF support
- **Argon2**: Use `argon2` crate (verify parameters match VeraCrypt)

**Key derivation structure:**
```rust
pub trait Kdf: Send + Sync {
    fn derive_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iterations: u32,
        output: &mut [u8],
    ) -> Result<()>;
}

pub enum PrfAlgorithm {
    Sha512,
    Sha256,
    Blake2s,
    Whirlpool,
    Streebog,
    Argon2,
}
```

**Tasks:**
- [ ] Define Kdf trait
- [ ] Implement PBKDF2 with HMAC-SHA512
- [ ] Implement PBKDF2 with HMAC-SHA256
- [ ] Implement PBKDF2 with HMAC-BLAKE2s
- [ ] Port/integrate Whirlpool hash
- [ ] Port/integrate Streebog hash
- [ ] Integrate Argon2id (verify memory cost parameters)
- [ ] Implement PIM (Personal Iterations Multiplier) calculation
- [ ] Test against VeraCrypt key derivation test vectors

### 1.3 XTS Mode Implementation

**XTS-AES mode**: The core encryption mode used by VeraCrypt.

**Structure:**
```rust
pub struct XtsMode<C: BlockCipher> {
    cipher1: C,  // Primary cipher
    cipher2: C,  // Tweak cipher
}

impl<C: BlockCipher> XtsMode<C> {
    pub fn encrypt_sector(
        &self,
        sector_number: u64,
        data: &mut [u8],
    ) -> Result<()>;
    
    pub fn decrypt_sector(
        &self,
        sector_number: u64,
        data: &mut [u8],
    ) -> Result<()>;
}
```

**Tasks:**
- [ ] Implement XTS mode encryption/decryption
- [ ] Support 512-byte data units (VeraCrypt standard)
- [ ] Handle sector numbering (first data unit number)
- [ ] Support cipher cascades in XTS mode
- [ ] Optimize with SIMD where possible
- [ ] Test against VeraCrypt XTS test vectors
- [ ] Verify performance (should be within 10% of C version)

### 1.4 Random Number Generation

**Requirements:**
- Cryptographically secure RNG for key generation
- Support for hardware RNG (RDRAND/RDSEED)
- Fallback to OS RNG

**Tasks:**
- [ ] Use `rand` crate with `getrandom` for OS RNG
- [ ] Detect and use RDRAND/RDSEED when available
- [ ] Implement secure key material generation
- [ ] Add entropy mixing (user mouse movements, etc. - for volume creation)

## Phase 2: Volume Format Implementation (3-4 weeks)

### 2.1 Volume Header Structures

**Header format** (from Volumes.h analysis):
- Total size: 64 KB (two copies: main + backup)
- Effective size: 512 bytes
- Magic number: 0x56455241 ("VERA")
- Salt: 64 bytes (PKCS5_SALT_SIZE)
- Encrypted data: 448 bytes containing master keys and metadata

**Structure:**
```rust
pub struct VolumeHeader {
    pub salt: [u8; 64],
    pub version: u16,
    pub required_program_version: u16,
    pub key_area_crc: u32,
    pub volume_creation_time: u64,
    pub header_creation_time: u64,
    pub hidden_volume_size: u64,
    pub volume_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    pub master_keydata: [u8; 256],
}

pub const VOLUME_HEADER_SIZE: usize = 64 * 1024;
pub const VOLUME_HEADER_EFFECTIVE_SIZE: usize = 512;
pub const PKCS5_SALT_SIZE: usize = 64;
pub const MASTER_KEYDATA_SIZE: usize = 256;
pub const ENCRYPTION_DATA_UNIT_SIZE: usize = 512;
```

**Tasks:**
- [ ] Define VolumeHeader struct matching C layout
- [ ] Implement header serialization (write)
- [ ] Implement header deserialization (read)
- [ ] Handle byte order (little-endian as per VeraCrypt)
- [ ] Implement CRC32 calculation for key area
- [ ] Support legacy volume formats (pre-6.0)
- [ ] Implement header encryption/decryption with all PRFs
- [ ] Test against actual VeraCrypt volume headers

### 2.2 Volume Header Detection and Parsing

**Mounting process:**
1. Try each PRF (SHA-512, SHA-256, BLAKE2s, Whirlpool, Streebog, Argon2)
2. Try each combination of ciphers
3. Decrypt header candidate
4. Verify magic number and CRC

**Structure:**
```rust
pub struct VolumeReader {
    file: File,
    header: VolumeHeader,
    crypto_info: CryptoInfo,
}

pub struct CryptoInfo {
    pub encryption_algorithm: EncryptionAlgorithm,
    pub mode: EncryptionMode,
    pub kdf: Box<dyn Kdf>,
    pub master_keys: Vec<u8>,
    pub sector_size: usize,
}
```

**Tasks:**
- [ ] Implement multi-PRF brute force header decryption
- [ ] Try all cipher combinations (AES, Serpent, Twofish, Camellia, Kuznyechik, cascades)
- [ ] Verify magic number (0x56455241)
- [ ] Validate CRC32 of decrypted key area
- [ ] Extract master keys and setup encryption
- [ ] Support backup header (at offset 64KB)
- [ ] Handle hidden volume headers
- [ ] Implement proper error handling (wrong password vs corrupted)

### 2.3 Volume Layouts

**Layout types:**
- Standard volume (single encrypted volume)
- Hidden volume (outer + inner volume)
- System encrypted volume (not in initial release)

**Tasks:**
- [ ] Define VolumeLayout trait
- [ ] Implement NormalVolumeLayout
- [ ] Implement HiddenVolumeLayout
- [ ] Calculate data area offsets correctly
- [ ] Handle volume size constraints

### 2.4 Volume Creation

**Format process:**
1. Generate random master keys
2. Derive header key from password using KDF
3. Encrypt header with derived key
4. Write encrypted header to volume
5. (Optional) Wipe volume data area

**Tasks:**
- [ ] Implement volume creation with all supported ciphers
- [ ] Support custom PIM values
- [ ] Generate secure random master keys
- [ ] Write both header copies (main + backup)
- [ ] Support hidden volume creation
- [ ] Implement fast format (header only) vs full format
- [ ] Add progress reporting for large volumes

## Phase 3: Volume I/O Operations (3-4 weeks)

### 3.1 Sector-Based I/O

**Sector operations:**
- Read encrypted sectors from file/device
- Decrypt using XTS mode with sector number
- Write plaintext data
- Encrypt and write back to volume

**Structure:**
```rust
pub struct Volume {
    reader: VolumeReader,
    data_offset: u64,
    data_size: u64,
    sector_size: usize,
    xts_cipher: XtsMode<CipherCascade>,
}

impl Volume {
    pub fn read_sectors(&mut self, sector: u64, buffer: &mut [u8]) -> Result<()>;
    pub fn write_sectors(&mut self, sector: u64, buffer: &[u8]) -> Result<()>;
    pub fn flush(&mut self) -> Result<()>;
}
```

**Tasks:**
- [ ] Implement sector-aligned read operations
- [ ] Implement sector-aligned write operations
- [ ] Handle partial sector reads/writes (read-modify-write)
- [ ] Implement sector number calculation (data unit numbers)
- [ ] Add buffer caching for performance
- [ ] Handle file vs block device I/O differences
- [ ] Ensure thread-safety for concurrent I/O

### 3.2 Hidden Volume Protection

**Protection mechanism:**
- When mounting outer volume with protection password
- Track writes to outer volume
- Detect if write would overwrite hidden volume
- Return error to prevent hidden volume damage

**Tasks:**
- [ ] Implement hidden volume size/offset tracking
- [ ] Check write operations against protected range
- [ ] Return appropriate errors when protection triggered
- [ ] Test protection mechanism thoroughly

## Phase 4: Filesystem Integration (4-5 weeks)

### 4.1 FUSE Implementation (Linux/macOS)

**FUSE approach:**
- Expose volume as virtual block device or filesystem
- Handle read/write/flush operations
- Map filesystem operations to sector I/O

**Tasks:**
- [ ] Integrate `fuser` crate (pure Rust FUSE)
- [ ] Implement filesystem trait methods
- [ ] Map file operations to sector operations
- [ ] Handle mount/unmount lifecycle
- [ ] Support read-only mounting
- [ ] Test with various filesystems (FAT32, NTFS, ext4)
- [ ] Handle permission and ownership correctly

### 4.2 Dokan Implementation (Windows)

**Dokan approach:**
- Use Dokan library for Windows filesystem integration
- Similar architecture to FUSE

**Tasks:**
- [ ] Research Rust Dokan bindings or create FFI wrapper
- [ ] Implement Dokan callbacks
- [ ] Test on Windows 10/11
- [ ] Handle Windows-specific permissions
- [ ] Support drive letter assignment

### 4.3 Platform Abstraction

**Cross-platform I/O:**
```rust
pub trait VolumeFile: Read + Write + Seek + Send {
    fn size(&self) -> Result<u64>;
    fn sync(&mut self) -> Result<()>;
    fn is_device(&self) -> bool;
}
```

**Tasks:**
- [ ] Abstract file vs device I/O
- [ ] Handle platform-specific device access (Linux /dev/loop, macOS /dev/disk)
- [ ] Implement permission checks
- [ ] Support exclusive locking to prevent concurrent mounts

## Phase 5: Command-Line Interface (2-3 weeks)

### 5.1 CLI Commands

**Basic commands:**
```bash
vcrypt create <volume> --size <size> --cipher <cipher> --hash <hash>
vcrypt mount <volume> <mountpoint> [--password-file <file>]
vcrypt unmount <mountpoint>
vcrypt change-password <volume>
vcrypt volume-info <volume>
```

**Tasks:**
- [ ] Use `clap` crate for argument parsing
- [ ] Implement create command with all options
- [ ] Implement mount command (interactive password entry)
- [ ] Implement unmount command
- [ ] Implement password change command
- [ ] Implement volume info command
- [ ] Support keyfiles (--keyfile option)
- [ ] Support PIM parameter
- [ ] Add verbose/debug output modes
- [ ] Implement secure password input (no echo)

### 5.2 Keyfile Support

**Keyfile processing:**
- Read keyfile(s) and derive key material
- Combine with password
- Support multiple keyfiles

**Tasks:**
- [ ] Implement keyfile reading and hashing
- [ ] Support multiple keyfiles
- [ ] Test keyfile compatibility with VeraCrypt
- [ ] Handle keyfile path resolution

## Phase 6: Testing and Validation (Ongoing)

### 6.1 Unit Tests

**Test coverage:**
- Each cipher implementation
- Hash functions and KDFs
- XTS mode operations
- Header parsing and generation
- Volume I/O operations

**Tasks:**
- [ ] Create test vectors from VeraCrypt
- [ ] Unit test each cipher with known plaintexts
- [ ] Test key derivation against VeraCrypt outputs
- [ ] Test XTS encryption/decryption
- [ ] Test header encryption with all PRFs
- [ ] Achieve >80% code coverage

### 6.2 Integration Tests

**Cross-compatibility tests:**
1. Create volume with VeraCrypt, mount with Rust implementation
2. Create volume with Rust, mount with VeraCrypt
3. Test all cipher combinations
4. Test all hash function combinations
5. Test hidden volumes
6. Test large volumes (>1TB)
7. Test various sector sizes

**Tasks:**
- [ ] Set up test harness with VeraCrypt binary
- [ ] Create volumes with VeraCrypt CLI
- [ ] Mount and verify data with Rust implementation
- [ ] Create volumes with Rust implementation
- [ ] Mount and verify with VeraCrypt
- [ ] Test on all target platforms
- [ ] Test edge cases (corrupted headers, wrong passwords, etc.)

### 6.3 Performance Testing

**Benchmarks:**
- Cipher performance (MB/s)
- Key derivation time
- Volume mount time
- Sequential read/write throughput
- Random I/O performance

**Tasks:**
- [ ] Implement benchmarks with `criterion` crate
- [ ] Compare against VeraCrypt performance
- [ ] Profile and optimize hot paths
- [ ] Test with different volume sizes
- [ ] Measure memory usage

### 6.4 Security Audit

**Security considerations:**
- Memory wiping (sensitive data cleanup)
- Side-channel resistance
- Password handling
- Key material protection

**Tasks:**
- [ ] Use `zeroize` crate for sensitive data
- [ ] Implement constant-time comparisons where needed
- [ ] Audit for potential information leaks
- [ ] Review cryptographic implementation
- [ ] Consider external security audit

## Phase 7: Documentation and Release (2-3 weeks)

### 7.1 Documentation

**Documentation requirements:**
- API documentation (rustdoc)
- User guide
- Format specification
- Migration guide from VeraCrypt

**Tasks:**
- [ ] Write comprehensive rustdoc comments
- [ ] Create user guide with examples
- [ ] Document volume format for transparency
- [ ] Create compatibility matrix
- [ ] Write troubleshooting guide

### 7.2 Packaging

**Distribution:**
- Cargo crate publication
- Binary releases for major platforms
- Package manager integration (apt, brew, choco)

**Tasks:**
- [ ] Set up CI/CD (GitHub Actions)
- [ ] Create release builds for Linux (x86_64, aarch64)
- [ ] Create release builds for Windows (x86_64)
- [ ] Create release builds for macOS (x86_64, aarch64)
- [ ] Publish to crates.io
- [ ] Create installation instructions

## Dependencies

**Core dependencies:**
```toml
[dependencies]
# Cryptography
aes = "0.8"              # AES cipher
sha2 = "0.10"            # SHA-256/512
blake2 = "0.10"          # BLAKE2s
argon2 = "0.5"           # Argon2 KDF
pbkdf2 = "0.12"          # PBKDF2 KDF
rand = "0.8"             # Random number generation
getrandom = "0.2"        # OS random
zeroize = "1.7"          # Secure memory wiping

# I/O and filesystem
fuser = "0.14"           # FUSE (Linux/macOS)
libc = "0.2"             # System calls

# Utilities
clap = "4.4"             # CLI parsing
anyhow = "1.0"           # Error handling
thiserror = "1.0"        # Error types
log = "0.4"              # Logging
env_logger = "0.11"      # Logging backend

# Testing
criterion = "0.5"        # Benchmarking
tempfile = "3.8"         # Test utilities
```

## Risk Assessment

### High Risk
- **Format compatibility**: Critical that volumes are 100% compatible
  - *Mitigation*: Extensive cross-testing with VeraCrypt, byte-level comparison
  
- **Cryptographic correctness**: Errors could compromise security
  - *Mitigation*: Use audited libraries where possible, comprehensive testing, external audit

### Medium Risk
- **Performance**: Rust implementation might be slower than optimized C
  - *Mitigation*: Profile and optimize, use SIMD, hardware acceleration

- **Platform support**: FUSE/Dokan integration complexity
  - *Mitigation*: Start with Linux, iterate on other platforms

### Low Risk
- **Maintenance**: Keeping up with VeraCrypt format changes
  - *Mitigation*: Monitor VeraCrypt releases, maintain compatibility tests

## Success Criteria

1. ✅ Mount volumes created by VeraCrypt 1.26.x
2. ✅ Create volumes mountable by VeraCrypt 1.26.x
3. ✅ Support all current cipher combinations
4. ✅ Support all current hash functions (PRFs)
5. ✅ Pass all cross-compatibility tests
6. ✅ Performance within 20% of native VeraCrypt
7. ✅ Zero memory safety vulnerabilities
8. ✅ Cross-platform support (Linux, Windows, macOS)

## Timeline Summary

- **Phase 1** (Crypto): 4-6 weeks
- **Phase 2** (Format): 3-4 weeks
- **Phase 3** (I/O): 3-4 weeks
- **Phase 4** (Filesystem): 4-5 weeks
- **Phase 5** (CLI): 2-3 weeks
- **Phase 6** (Testing): Ongoing, 3-4 weeks focused effort
- **Phase 7** (Release): 2-3 weeks

**Total estimated time**: 21-29 weeks (5-7 months)

## Future Enhancements (Post-Initial Release)

1. **GUI Application**: Desktop app with Qt or egui
2. **System Encryption**: Full disk encryption with boot loader
3. **Mobile Support**: Android/iOS libraries
4. **Hardware Security**: TPM, YubiKey integration
5. **Performance**: Further optimization, GPU acceleration
6. **Format Extensions**: New ciphers (ChaCha20), new KDFs
7. **Cloud Integration**: Native cloud storage backend support

## Conclusion

This plan provides a structured approach to rewriting VeraCrypt in Rust while maintaining complete format compatibility. The phased approach allows for incremental development and testing, with the most critical components (cryptography and format handling) developed first.

The key to success is rigorous testing against the original VeraCrypt implementation at every stage, ensuring that volumes created by either implementation are fully interoperable.
