//! XTS (XEX-based tweaked-codebook mode) implementation
//!
//! XTS is the block cipher mode used by VeraCrypt for disk encryption.
//! Data length must be a multiple of the cipher block size (16 bytes) —
//! matching VeraCrypt's requirement (see Xts.c EncryptBufferXTS).

use crate::{ciphers::BlockCipher, CryptoError, Result};

#[cfg(all(feature = "kernel", not(feature = "std")))]
use alloc::vec::Vec;

/// XTS mode encryption/decryption
pub struct XtsMode<C: BlockCipher> {
	cipher1: C,
	cipher2: C,
}

impl<C: BlockCipher> XtsMode<C> {
	/// Create a new XTS mode instance
	///
	/// # Arguments
	/// * `key` - Combined key (must be 2x the cipher's key size)
	///
	/// The key is split into two halves:
	/// - First half for data encryption
	/// - Second half for tweak encryption
	pub fn new(key: &[u8], cipher_new: impl Fn(&[u8]) -> Result<C>) -> Result<Self> {
		let key_size = C::KEY_SIZE;
		if key.len() != key_size * 2 {
			return Err(CryptoError::InvalidKeySize {
				expected: key_size * 2,
				actual: key.len(),
			});
		}

		let cipher1 = cipher_new(&key[..key_size])?;
		let cipher2 = cipher_new(&key[key_size..])?;

		Ok(Self { cipher1, cipher2 })
	}

	/// Encrypt data using XTS mode — batch path (like VeraCrypt's EncryptBufferXTSParallel).
	pub fn encrypt(&self, sector_index: u64, data: &mut [u8]) -> Result<()> {
		validate_data_length::<C>(data)?;

		let n_blocks = data.len() / C::BLOCK_SIZE;
		let tweaks = precompute_tweaks::<C>(self, sector_index, n_blocks)?;
		batch_xor_blocks(data, &tweaks, n_blocks);
		self.cipher1.encrypt_blocks(data)?;
		batch_xor_blocks(data, &tweaks, n_blocks);

		Ok(())
	}

	/// Decrypt data using XTS mode — batch path.
	pub fn decrypt(&self, sector_index: u64, data: &mut [u8]) -> Result<()> {
		validate_data_length::<C>(data)?;

		let n_blocks = data.len() / C::BLOCK_SIZE;
		let tweaks = precompute_tweaks::<C>(self, sector_index, n_blocks)?;
		batch_xor_blocks(data, &tweaks, n_blocks);
		self.cipher1.decrypt_blocks(data)?;
		batch_xor_blocks(data, &tweaks, n_blocks);

		Ok(())
	}

	/// Process exactly one standard 512-byte sector (32 × 16-byte blocks).
	///
	/// Uses **stack-allocated** tweak storage, making it suitable for
	/// `no_std` / kernel-mode contexts where heap allocation is unavailable
	/// or undesirable.
	pub fn process_sector(&self, sector_index: u64, data: &mut [u8], encrypt: bool) -> Result<()> {
		debug_assert_eq!(data.len(), 512, "XTS sector must be 512 bytes");
		validate_data_length::<C>(data)?;

		let n_blocks = 32; // 512 / 16
		let mut tweaks = [0u8; 512]; // 32 blocks × 16 bytes = 512 bytes on stack
		precompute_tweaks_into::<C>(self, sector_index, n_blocks, &mut tweaks)?;
		batch_xor_blocks(data, &tweaks, n_blocks);
		if encrypt {
			self.cipher1.encrypt_blocks(data)?;
		} else {
			self.cipher1.decrypt_blocks(data)?;
		}
		batch_xor_blocks(data, &tweaks, n_blocks);

		Ok(())
	}

	/// Process arbitrary-length data with a **caller-provided** tweak buffer.
	///
	/// The tweak buffer must be at least `n_blocks × 16` bytes where
	/// `n_blocks = data.len() / 16`.  This variant avoids all heap
	/// allocation and is safe for kernel-mode use.
	pub fn process_arbitrary(
		&self,
		sector_index: u64,
		data: &mut [u8],
		encrypt: bool,
		tweak_buf: &mut [u8],
	) -> Result<()> {
		validate_data_length::<C>(data)?;
		let n_blocks = data.len() / C::BLOCK_SIZE;
		let needed = n_blocks * C::BLOCK_SIZE;
		if tweak_buf.len() < needed {
			return Err(CryptoError::InvalidDataLength(
				format!("tweak buffer too small: need {needed}, got {}", tweak_buf.len()),
			));
		}

		precompute_tweaks_into::<C>(self, sector_index, n_blocks, tweak_buf)?;
		batch_xor_blocks(data, tweak_buf, n_blocks);
		if encrypt {
			self.cipher1.encrypt_blocks(data)?;
		} else {
			self.cipher1.decrypt_blocks(data)?;
		}
		batch_xor_blocks(data, tweak_buf, n_blocks);

		Ok(())
	}

	/// Compute the initial tweak value for a sector
	fn compute_tweak(&self, sector_index: u64) -> Result<[u8; 16]> {
		let mut tweak = [0u8; 16];
		tweak[..8].copy_from_slice(&sector_index.to_le_bytes());
		self.cipher2.encrypt_block(&mut tweak)?;
		Ok(tweak)
	}
}

/// Validate that `data` is a non-zero multiple of the cipher block size.
fn validate_data_length<C: BlockCipher>(data: &[u8]) -> Result<()> {
	if data.len() < C::BLOCK_SIZE {
		return Err(CryptoError::InvalidBlockSize {
			expected: C::BLOCK_SIZE,
			actual: data.len(),
		});
	}
	if data.len() % C::BLOCK_SIZE != 0 {
		return Err(CryptoError::InvalidDataLength(format!(
			"XTS requires data length to be a multiple of {} (got {})",
			C::BLOCK_SIZE,
			data.len()
		)));
	}
	Ok(())
}

/// Precompute all tweaks into a **caller-provided** buffer.
///
/// The buffer must be at least `n_blocks * 16` bytes.  This variant avoids
/// heap allocation and is safe for `no_std` / kernel-mode contexts.
fn precompute_tweaks_into<C: BlockCipher>(
	xts: &XtsMode<C>,
	sector_index: u64,
	n_blocks: usize,
	tweaks: &mut [u8],
) -> Result<()> {
	debug_assert!(tweaks.len() >= n_blocks * 16);
	let mut t = xts.compute_tweak(sector_index)?;
	for i in 0..n_blocks {
		tweaks[i * 16..(i + 1) * 16].copy_from_slice(&t);
		multiply_tweak(&mut t);
	}
	Ok(())
}

/// Precompute all tweaks for `n_blocks` blocks starting at `sector_index`.
///
/// Returns a heap-allocated `Vec` — use [`precompute_tweaks_into`] in
/// `no_std` contexts.
fn precompute_tweaks<C: BlockCipher>(xts: &XtsMode<C>, sector_index: u64, n_blocks: usize) -> Result<Vec<u8>> {
	let mut tweaks = vec![0u8; n_blocks * 16];
	precompute_tweaks_into(xts, sector_index, n_blocks, &mut tweaks)?;
	Ok(tweaks)
}

/// Batch XOR: `data[i] ^= tweaks[i]` for `n_blocks` 16-byte blocks (u128 per block).
///
/// Uses unaligned reads/writes so that the caller does not need to guarantee
/// 16-byte alignment of `data` or `tweaks` (important for stack-allocated
/// buffers in kernel-mode or test code).
fn batch_xor_blocks(data: &mut [u8], tweaks: &[u8], n_blocks: usize) {
	for i in 0..n_blocks {
		let off = i * 16;
		unsafe {
			let d_ptr = data.as_mut_ptr().add(off) as *mut u128;
			let t_ptr = tweaks.as_ptr().add(off) as *const u128;
			let d_val = core::ptr::read_unaligned(d_ptr);
			let t_val = core::ptr::read_unaligned(t_ptr);
			core::ptr::write_unaligned(d_ptr, d_val ^ t_val);
		}
	}
}

/// Multiply tweak by α in GF(2^128) — little-endian byte order
fn multiply_tweak(tweak: &mut [u8]) {
	debug_assert_eq!(tweak.len(), 16);
	unsafe {
		let t = &mut *(tweak.as_mut_ptr() as *mut [u64; 2]);
		let low = t[0];
		let high = t[1];
		t[0] = low << 1;
		t[1] = (high << 1) | (low >> 63);
		if (high >> 63) & 1 != 0 {
			tweak[0] ^= 0x87;
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::ciphers::AesCipher;

	#[test]
	fn test_xts_encrypt_decrypt() {
		let key = [0u8; 64]; // 64 bytes for AES-256 XTS
		let xts = XtsMode::new(&key, |k| AesCipher::new(k)).unwrap();

		let mut data = vec![0x42u8; 512];
		let original = data.clone();

		xts.encrypt(0, &mut data).unwrap();
		assert_ne!(data, original);

		xts.decrypt(0, &mut data).unwrap();
		assert_eq!(data, original);
	}

	#[test]
	fn test_xts_different_sectors() {
		let key = [1u8; 64];
		let xts = XtsMode::new(&key, |k| AesCipher::new(k)).unwrap();

		let mut data1 = vec![0x42u8; 512];
		let mut data2 = data1.clone();

		xts.encrypt(0, &mut data1).unwrap();
		xts.encrypt(1, &mut data2).unwrap();

		// Different sectors should produce different ciphertext
		assert_ne!(data1, data2);
	}

	#[test]
	fn test_process_sector() {
		let key = [0u8; 64];
		let xts = XtsMode::new(&key, |k| AesCipher::new(k)).unwrap();

		let mut data = [0x42u8; 512];
		let original = data;

		xts.process_sector(0, &mut data, true).unwrap();
		assert_ne!(data, original);

		xts.process_sector(0, &mut data, false).unwrap();
		assert_eq!(data, original);
	}
}
