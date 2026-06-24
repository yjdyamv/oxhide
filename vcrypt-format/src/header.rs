//! Volume header structures — VeraCrypt v5 compatible
//!
//! Header is 65536 bytes on disk but only first 512 bytes are used.
//! Layout: 64 bytes salt (unencrypted) + 448 bytes encrypted area.
//!
//! Field byte order: **Big-Endian** (network byte order, matching VeraCrypt)

/// Total V2 header size on disk
pub const VOLUME_HEADER_SIZE: usize = 65536;

/// Effective header data (salt + encrypted area)
pub const VOLUME_HEADER_EFFECTIVE_SIZE: usize = 512;

/// PKCS5 salt size
pub const PKCS5_SALT_SIZE: usize = 64;

/// Encrypted header area size
pub const ENCRYPTED_HEADER_SIZE: usize = VOLUME_HEADER_EFFECTIVE_SIZE - PKCS5_SALT_SIZE;

/// Max master key data (256 bytes for 3-cipher cascades)
pub const MASTER_KEYDATA_SIZE: usize = 256;

/// Magic number "VERA"
pub const VOLUME_MAGIC: u32 = 0x5645_5241;

/// Current header version
pub const HEADER_VERSION: u16 = 0x0005;

/// Offset within encrypted area (relative to byte 64)
pub mod offsets {
    /// Magic (4 bytes)
    pub const MAGIC: usize = 0;
    /// Header version (2 bytes)
    pub const HEADER_VERSION: usize = 4;
    /// Required program version (2 bytes)
    pub const REQUIRED_VERSION: usize = 6;
    /// CRC-32 of master key data area (4 bytes)
    pub const KEY_AREA_CRC: usize = 8;
    /// Volume creation time, Unix timestamp (8 bytes)
    pub const VOLUME_CREATION_TIME: usize = 12;
    /// Header modification time, Unix timestamp (8 bytes)
    pub const MODIFICATION_TIME: usize = 20;
    /// Hidden volume data size, 0=normal (8 bytes)
    pub const HIDDEN_VOLUME_SIZE: usize = 28;
    /// Total volume data size (8 bytes)
    pub const VOLUME_SIZE: usize = 36;
    /// Encrypted data area start offset (8 bytes)
    pub const ENCRYPTED_AREA_START: usize = 44;
    /// Encrypted data area length (8 bytes)
    pub const ENCRYPTED_AREA_LENGTH: usize = 52;
    /// Flags (4 bytes)
    pub const FLAGS: usize = 60;
    /// Sector size (4 bytes)
    pub const SECTOR_SIZE: usize = 64;
    /// Reserved area (120 bytes, must be zero)
    pub const RESERVED: usize = 68;
    /// Header CRC-32 of bytes 64-251 (4 bytes)
    pub const HEADER_CRC: usize = 188; // = 252 - 64
    /// Master key data offset within encrypted area
    pub const MASTER_KEYDATA: usize = 192; // = 256 - 64
}

/// Volume header
#[derive(Debug, Clone)]
pub struct VolumeHeader {
    pub salt: [u8; PKCS5_SALT_SIZE],
    pub magic: u32,
    pub header_version: u16,
    pub required_version: u16,
    pub key_area_crc: u32,
    pub volume_creation_time: u64,
    pub modification_time: u64,
    pub hidden_volume_size: u64,
    pub volume_size: u64,
    pub encrypted_area_start: u64,
    pub encrypted_area_length: u64,
    pub flags: u32,
    pub sector_size: u32,
    pub master_keydata: Vec<u8>,
    /// Computed CRC-32 of encrypted area (offsets 0..188)
    pub header_crc: u32,
}

impl VolumeHeader {
    pub fn new() -> Self {
        VolumeHeader {
            salt: [0u8; PKCS5_SALT_SIZE],
            magic: VOLUME_MAGIC,
            header_version: HEADER_VERSION,
            required_version: 0x010b,
            key_area_crc: 0,
            volume_creation_time: 0,
            modification_time: 0,
            hidden_volume_size: 0,
            volume_size: 0,
            encrypted_area_start: 0,
            encrypted_area_length: 0,
            flags: 0,
            sector_size: 512,
            master_keydata: vec![0u8; MASTER_KEYDATA_SIZE],
            header_crc: 0,
        }
    }

    pub fn verify_magic(&self) -> bool {
        self.magic == VOLUME_MAGIC
    }
}

impl Default for VolumeHeader {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_constants() {
        assert_eq!(VOLUME_MAGIC, 0x5645_5241);
        assert_eq!(PKCS5_SALT_SIZE, 64);
        assert_eq!(VOLUME_HEADER_EFFECTIVE_SIZE, 512);
        assert_eq!(offsets::MASTER_KEYDATA, 192);
        assert_eq!(offsets::HEADER_CRC, 188);
    }

    #[test]
    fn test_creation() {
        let h = VolumeHeader::new();
        assert!(h.verify_magic());
        assert_eq!(h.header_version, 0x0005);
    }
}
