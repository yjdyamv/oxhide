//! Keyfile processing — VeraCrypt-compatible CRC-32 password mixing

use crc::{Crc, CRC_32_ISO_HDLC};

const POOL_SIZE: usize = 128;
const MAX_READ: usize = 1_048_576;

/// Apply keyfiles to password (mod 256 addition from 128-byte CRC pool)
pub fn apply_keyfiles(password: &mut Vec<u8>, paths: &[impl AsRef<std::path::Path>]) -> std::io::Result<()> {
    if paths.is_empty() { return Ok(()); }
    let crc_alg = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let mut pool = vec![0u8; POOL_SIZE];
    let mut total = 0usize;

    for path in paths {
        let data = std::fs::read(path.as_ref())?;
        let n = data.len().min(MAX_READ.saturating_sub(total));
        if n == 0 { break; }
        let mut crc = 0u32;
        let mut i = 0usize;
        for &b in &data[..n] {
            let mut d = crc_alg.digest_with_initial(crc);
            d.update(&[b]);
            crc = d.finalize();
            pool[i % POOL_SIZE] = pool[i % POOL_SIZE].wrapping_add((crc >> 24) as u8); i += 1;
            pool[i % POOL_SIZE] = pool[i % POOL_SIZE].wrapping_add((crc >> 16) as u8); i += 1;
            pool[i % POOL_SIZE] = pool[i % POOL_SIZE].wrapping_add((crc >>  8) as u8); i += 1;
            pool[i % POOL_SIZE] = pool[i % POOL_SIZE].wrapping_add(crc as u8); i += 1;
        }
        total += n;
    }

    if password.len() < POOL_SIZE { password.resize(POOL_SIZE, 0); }
    for i in 0..POOL_SIZE { password[i] = password[i].wrapping_add(pool[i]); }
    zeroize::Zeroize::zeroize(&mut pool);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn test_empty() {
        let mut pw = b"test".to_vec();
        apply_keyfiles(&mut pw, &[] as &[&str]).unwrap();
        assert_eq!(pw, b"test");
    }

    #[test]
    fn test_modifies() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"keyfile data").unwrap();
        let mut pw = b"mypassword".to_vec();
        apply_keyfiles(&mut pw, &[f.path()]).unwrap();
        assert_eq!(pw.len(), 128);
        assert_ne!(&pw[..11], b"mypassword");
    }

    #[test]
    fn test_deterministic() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(b"data").unwrap();
        let mut a = b"base".to_vec();
        let mut b = b"base".to_vec();
        apply_keyfiles(&mut a, &[f.path()]).unwrap();
        apply_keyfiles(&mut b, &[f.path()]).unwrap();
        assert_eq!(a, b);
    }
}
