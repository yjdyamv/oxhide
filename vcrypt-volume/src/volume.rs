use super::error::{VolResult, VolumeError};
use super::io::{self, SectorCipher, DATA_UNIT_SIZE};
use super::open::{open_volume_file, open_volume_file_with_kdf, OpenResult};
use super::sector_cipher::create_sector_cipher;
use vcrypt_core::ciphers::CipherType;
use vcrypt_core::kdf::KdfAlgorithm;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

pub struct OpenVolume {
    inner: OpenResult,
    file: File,
    cipher: Box<dyn SectorCipher>,
    read_only: bool,
}

impl OpenVolume {
    pub fn open(
        path: &str,
        password: &[u8],
        keyfiles: &[&str],
        kdf: Option<KdfAlgorithm>,
        pim: Option<i32>,
    ) -> VolResult<Self> {
        let result = match kdf {
            Some(k) => open_volume_file_with_kdf(path, password, keyfiles, k, pim.unwrap_or(0)),
            None => open_volume_file(path, password, keyfiles, pim),
        }?;

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .map_err(|e| VolumeError::OpenError(format!("{}", e)))?;

        let cipher = create_sector_cipher(result.data_cipher, &result.master_key)?;

        Ok(OpenVolume {
            inner: result,
            file,
            cipher,
            read_only: false,
        })
    }

    pub fn open_read_only(
        path: &str,
        password: &[u8],
        keyfiles: &[&str],
        kdf: Option<KdfAlgorithm>,
        pim: Option<i32>,
    ) -> VolResult<Self> {
        let result = match kdf {
            Some(k) => open_volume_file_with_kdf(path, password, keyfiles, k, pim.unwrap_or(0)),
            None => open_volume_file(path, password, keyfiles, pim),
        }?;

        let file = OpenOptions::new()
            .read(true)
            .write(false)
            .open(path)
            .map_err(|e| VolumeError::OpenError(format!("{}", e)))?;

        let cipher = create_sector_cipher(result.data_cipher, &result.master_key)?;

        Ok(OpenVolume {
            inner: result,
            file,
            cipher,
            read_only: true,
        })
    }

    pub fn read(&mut self, sector: u64, buf: &mut [u8]) -> VolResult<()> {
        if buf.len() % DATA_UNIT_SIZE as usize != 0 {
            return Err(VolumeError::Unsupported(
                "read buffer must be sector-aligned (multiple of 512)".into(),
            ));
        }
        io::read_sectors(
            &mut self.file,
            self.inner.data_offset,
            sector,
            buf,
            self.cipher.as_ref(),
        )
    }

    pub fn write(&mut self, sector: u64, buf: &[u8]) -> VolResult<()> {
        if self.read_only {
            return Err(VolumeError::Unsupported("volume opened read-only".into()));
        }
        if buf.len() % DATA_UNIT_SIZE as usize != 0 {
            return Err(VolumeError::Unsupported(
                "write buffer must be sector-aligned (multiple of 512)".into(),
            ));
        }
        io::write_sectors(
            &mut self.file,
            self.inner.data_offset,
            sector,
            buf,
            self.cipher.as_ref(),
        )
    }

    pub fn data_size(&self) -> u64 {
        self.inner.data_length
    }

    pub fn max_sector(&self) -> u64 {
        self.inner.data_length / DATA_UNIT_SIZE
    }

    pub fn data_offset(&self) -> u64 {
        self.inner.data_offset
    }

    pub fn cipher(&self) -> CipherType {
        self.inner.data_cipher
    }

    pub fn kdf(&self) -> KdfAlgorithm {
        self.inner.kdf
    }

    pub fn close(self) -> VolResult<()> {
        drop(self.file);
        Ok(())
    }
}

impl Read for OpenVolume {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        let end = (self.inner.data_offset + self.inner.data_length) as usize;
        let current = self.file.seek(SeekFrom::Current(0))
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))? as usize;
        if current >= end {
            return Ok(0);
        }
        let available = end - current;
        let n = buf.len().min(available);
        self.file.read(&mut buf[..n])
    }
}

impl Seek for OpenVolume {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let start = self.inner.data_offset;
        let end = start + self.inner.data_length;
        let target = match pos {
            SeekFrom::Start(p) => start + p,
            SeekFrom::End(p) => ((end as i64) + p) as u64,
            SeekFrom::Current(p) => {
                let cur = self.file.seek(SeekFrom::Current(0))
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;
                ((cur as i64) + p) as u64
            }
        };
        if target < start || target > end {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek out of data area",
            ));
        }
        self.file.seek(SeekFrom::Start(target))
    }
}

impl Write for OpenVolume {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.file.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.file.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_volume_create_read_write() {
        use crate::create::create_volume;
        use vcrypt_core::kdf::{Pbkdf2Sha256, KeyDerivation};
        use vcrypt_format::header::VOLUME_HEADER_SIZE;
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let iters = Pbkdf2Sha256.get_iteration_count(0);

        {
            let mut f = File::create(path).unwrap();
            f.set_len(VOLUME_HEADER_SIZE as u64 * 4 + 512).unwrap();
            create_volume(
                &mut f,
                512,
                b"test",
                &Pbkdf2Sha256,
                KdfAlgorithm::Pbkdf2Sha256,
                iters,
            )
            .unwrap();
        }

        let mut vol = OpenVolume::open(
            path,
            b"test",
            &[],
            Some(KdfAlgorithm::Pbkdf2Sha256),
            Some(0),
        )
        .unwrap();

        assert_eq!(vol.data_size(), 512);

        // Write known data to sector 0
        let plaintext = vec![0xABu8; 512];
        vol.write(0, &plaintext).unwrap();

        // Read back and verify
        let mut buf = vec![0u8; 512];
        vol.read(0, &mut buf).unwrap();
        assert_eq!(&buf, &plaintext);

        // Verify persisted at file level (reads should match after drop + reopen)
        drop(vol);

        let mut vol2 = OpenVolume::open(
            path,
            b"test",
            &[],
            Some(KdfAlgorithm::Pbkdf2Sha256),
            Some(0),
        )
        .unwrap();
        let mut buf2 = vec![0u8; 512];
        vol2.read(0, &mut buf2).unwrap();
        assert_eq!(&buf2, &plaintext);
    }

    #[test]
    fn test_open_read_only_rejects_write() {
        use crate::create::create_volume;
        use vcrypt_core::kdf::{Pbkdf2Sha256, KeyDerivation};
        use vcrypt_format::header::VOLUME_HEADER_SIZE;
        use tempfile::NamedTempFile;

        let tmp = NamedTempFile::new().unwrap();
        let path = tmp.path().to_str().unwrap();
        let iters = Pbkdf2Sha256.get_iteration_count(0);

        {
            let mut f = File::create(path).unwrap();
            f.set_len(VOLUME_HEADER_SIZE as u64 * 4 + 512).unwrap();
            create_volume(
                &mut f,
                512,
                b"test",
                &Pbkdf2Sha256,
                KdfAlgorithm::Pbkdf2Sha256,
                iters,
            )
            .unwrap();
        }

        let mut vol = OpenVolume::open_read_only(
            path,
            b"test",
            &[],
            Some(KdfAlgorithm::Pbkdf2Sha256),
            Some(0),
        )
        .unwrap();

        assert_eq!(vol.data_size(), 512);

        let mut buf = vec![0u8; 512];
        vol.read(0, &mut buf).unwrap();

        assert!(vol.write(0, &[0u8; 512]).is_err());
    }

    #[test]
    fn test_default_volume_creation() {
        use crate::config::VolumeConfig;
        let cfg = VolumeConfig::default();
        assert_eq!(cfg.cipher, vcrypt_core::ciphers::CipherType::Aes);
        assert_eq!(cfg.iterations, 500_000);
    }

    #[test]
    fn test_cipher_customization() {
        use crate::config::VolumeConfig;
        let cfg = VolumeConfig::new()
            .with_cipher(vcrypt_core::ciphers::CipherType::Twofish);
        assert_eq!(cfg.cipher, vcrypt_core::ciphers::CipherType::Twofish);
    }
}
