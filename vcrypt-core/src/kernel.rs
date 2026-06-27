//! Kernel-mode sector cipher dispatcher.
//!
//! This module provides [`KernelSectorCipher`], an enum-based dispatcher that
//! replaces the `Box<dyn SectorCipher>` pattern used in user-mode
//! (`vcrypt-volume`).  Enum dispatch avoids trait-object heap allocations
//! while keeping the cipher selection runtime-flexible.
//!
//! The dispatcher is designed for `no_std` Windows kernel-driver contexts
//! (enabled via the `kernel` feature of `vcrypt-core`).

use crate::ciphers::{
	AesCipher, CamelliaCipher, CascadeMode, CipherType, KuznyechikCipher, SerpentCipher,
	TwofishCipher,
};
use crate::xts::XtsMode;
use crate::{CryptoError, Result};

#[cfg(all(feature = "kernel", not(feature = "std")))]
use alloc::{boxed::Box, vec::Vec};

/// An enum-based sector cipher suitable for `no_std` / kernel-mode contexts.
///
/// Each variant holds one or more [`XtsMode`] instances, avoiding
/// `Box<dyn SectorCipher>` trait objects.  Cascade-2 and cascade-3 variants
/// use `Box` for indirection so the enum stays reasonably sized.
pub enum KernelSectorCipher {
	/// AES-256 XTS.
	Aes(XtsMode<AesCipher>),
	/// Serpent XTS.
	Serpent(XtsMode<SerpentCipher>),
	/// Twofish XTS.
	Twofish(XtsMode<TwofishCipher>),
	/// Camellia-256 XTS.
	Camellia(XtsMode<CamelliaCipher>),
	/// Kuznyechik XTS.
	Kuznyechik(XtsMode<KuznyechikCipher>),
	/// Two-cipher cascade.
	Cascade2 {
		/// First (outer) XTS pass.
		first: Box<KernelSectorCipher>,
		/// Second (inner) XTS pass.
		second: Box<KernelSectorCipher>,
	},
	/// Three-cipher cascade.
	Cascade3 {
		/// First (outer) XTS pass.
		first: Box<KernelSectorCipher>,
		/// Second (middle) XTS pass.
		second: Box<KernelSectorCipher>,
		/// Third (inner) XTS pass.
		third: Box<KernelSectorCipher>,
	},
}

impl KernelSectorCipher {
	/// Create a `KernelSectorCipher` for `cipher_type` using `key`.
	///
	/// `key` must be exactly `cipher_type.key_size() * 2` bytes (XTS needs
	/// a data-key + tweak-key per cipher, and cascades multiply this).
	pub fn new(cipher_type: CipherType, key: &[u8]) -> Result<Self> {
		match cipher_type {
			CipherType::Aes => {
				Ok(Self::Aes(XtsMode::new(key, AesCipher::new)?))
			}
			CipherType::Serpent => {
				Ok(Self::Serpent(XtsMode::new(key, SerpentCipher::new)?))
			}
			CipherType::Twofish => {
				Ok(Self::Twofish(XtsMode::new(key, TwofishCipher::new)?))
			}
			CipherType::Camellia => {
				Ok(Self::Camellia(XtsMode::new(key, CamelliaCipher::new)?))
			}
			CipherType::Kuznyechik => {
				Ok(Self::Kuznyechik(XtsMode::new(key, KuznyechikCipher::new)?))
			}
			// Cascades
			cipher_type => {
				let mode = match cipher_type {
					CipherType::AesTwofish => CascadeMode::AesTwofish,
					CipherType::AesTwofishSerpent => CascadeMode::AesTwofishSerpent,
					CipherType::SerpentAes => CascadeMode::SerpentAes,
					CipherType::SerpentTwofishAes => CascadeMode::SerpentTwofishAes,
					CipherType::TwofishSerpent => CascadeMode::TwofishSerpent,
					CipherType::CamelliaKuznyechik => CascadeMode::CamelliaKuznyechik,
					CipherType::CamelliaSerpent => CascadeMode::CamelliaSerpent,
					CipherType::KuznyechikAes => CascadeMode::KuznyechikAes,
					CipherType::KuznyechikSerpentCamellia => CascadeMode::KuznyechikSerpentCamellia,
					CipherType::KuznyechikTwofish => CascadeMode::KuznyechikTwofish,
					_ => {
						return Err(CryptoError::UnsupportedCipher(
							format!("unknown cipher type: {}", cipher_type.name()),
						));
					}
				};
				Self::build_cascade(mode, key)
			}
		}
	}

	/// Encrypt one 512-byte sector.
	pub fn encrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<()> {
		match self {
			Self::Aes(xts) => xts.process_sector(sector_index, data, true),
			Self::Serpent(xts) => xts.process_sector(sector_index, data, true),
			Self::Twofish(xts) => xts.process_sector(sector_index, data, true),
			Self::Camellia(xts) => xts.process_sector(sector_index, data, true),
			Self::Kuznyechik(xts) => xts.process_sector(sector_index, data, true),
			Self::Cascade2 { first, second } => {
				first.encrypt_sector(sector_index, data)?;
				second.encrypt_sector(sector_index, data)
			}
			Self::Cascade3 { first, second, third } => {
				first.encrypt_sector(sector_index, data)?;
				second.encrypt_sector(sector_index, data)?;
				third.encrypt_sector(sector_index, data)
			}
		}
	}

	/// Decrypt one 512-byte sector.
	pub fn decrypt_sector(&self, sector_index: u64, data: &mut [u8]) -> Result<()> {
		match self {
			Self::Aes(xts) => xts.process_sector(sector_index, data, false),
			Self::Serpent(xts) => xts.process_sector(sector_index, data, false),
			Self::Twofish(xts) => xts.process_sector(sector_index, data, false),
			Self::Camellia(xts) => xts.process_sector(sector_index, data, false),
			Self::Kuznyechik(xts) => xts.process_sector(sector_index, data, false),
			Self::Cascade2 { first, second } => {
				// Decrypt in reverse order
				second.decrypt_sector(sector_index, data)?;
				first.decrypt_sector(sector_index, data)
			}
			Self::Cascade3 { first, second, third } => {
				// Decrypt in reverse order
				third.decrypt_sector(sector_index, data)?;
				second.decrypt_sector(sector_index, data)?;
				first.decrypt_sector(sector_index, data)
			}
		}
	}

	// ------------------------------------------------------------------
	// Internal helpers
	// ------------------------------------------------------------------

	/// Build a cascade from `mode` using `key`.
	fn build_cascade(mode: CascadeMode, key: &[u8]) -> Result<Self> {
		let single_key_len = mode.key_size();
		let total_expected = single_key_len * 2; // data half + tweak half
		if key.len() != total_expected {
			return Err(CryptoError::InvalidKeySize {
				expected: total_expected,
				actual: key.len(),
			});
		}

		let (data_half, tweak_half) = key.split_at(single_key_len);
		let passes: Vec<(CipherType, usize)> = mode.veracrypt_order();

		// Build per-pass XTS instances
		let mut xts_passes: Vec<KernelSectorCipher> = Vec::new();
		for (ct, offset) in &passes {
			let mut combined = [0u8; 64]; // 32 data + 32 tweak
			combined[..32].copy_from_slice(&data_half[*offset..*offset + 32]);
			combined[32..].copy_from_slice(&tweak_half[*offset..*offset + 32]);
			xts_passes.push(KernelSectorCipher::new(*ct, &combined)?);
		}

		match xts_passes.len() {
			2 => {
				let mut iter = xts_passes.into_iter();
				Ok(Self::Cascade2 {
					first: Box::new(iter.next().unwrap()),
					second: Box::new(iter.next().unwrap()),
				})
			}
			3 => {
				let mut iter = xts_passes.into_iter();
				Ok(Self::Cascade3 {
					first: Box::new(iter.next().unwrap()),
					second: Box::new(iter.next().unwrap()),
					third: Box::new(iter.next().unwrap()),
				})
			}
			_ => Err(CryptoError::UnsupportedCipher(
				format!("unexpected cascade length: {}", xts_passes.len()),
			)),
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn test_single_aes_roundtrip() {
		let key = [0u8; 64];
		let cipher = KernelSectorCipher::new(CipherType::Aes, &key).unwrap();
		let mut data = [0x42u8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}

	#[test]
	fn test_single_serpent_roundtrip() {
		let key = [1u8; 64];
		let cipher = KernelSectorCipher::new(CipherType::Serpent, &key).unwrap();
		let mut data = [0xAAu8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}

	#[test]
	fn test_single_twofish_roundtrip() {
		let key = [2u8; 64];
		let cipher = KernelSectorCipher::new(CipherType::Twofish, &key).unwrap();
		let mut data = [0xBBu8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}

	#[test]
	fn test_single_camellia_roundtrip() {
		let key = [3u8; 64];
		let cipher = KernelSectorCipher::new(CipherType::Camellia, &key).unwrap();
		let mut data = [0xCCu8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}

	#[test]
	fn test_single_kuznyechik_roundtrip() {
		let key = [4u8; 64];
		let cipher = KernelSectorCipher::new(CipherType::Kuznyechik, &key).unwrap();
		let mut data = [0xDDu8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}

	#[test]
	fn test_cascade2_aes_twofish_roundtrip() {
		let key = [5u8; 128]; // 64 data + 64 tweak
		let cipher = KernelSectorCipher::new(CipherType::AesTwofish, &key).unwrap();
		let mut data = [0xEEu8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}

	#[test]
	fn test_cascade3_roundtrip() {
		let key = [6u8; 192]; // 96 data + 96 tweak
		let cipher =
			KernelSectorCipher::new(CipherType::AesTwofishSerpent, &key).unwrap();
		let mut data = [0xFFu8; 512];
		let orig = data;

		cipher.encrypt_sector(0, &mut data).unwrap();
		assert_ne!(data, orig);
		cipher.decrypt_sector(0, &mut data).unwrap();
		assert_eq!(data, orig);
	}
}
