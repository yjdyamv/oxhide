//! # vcrypt-core
//!
//! Core cryptographic library for VeraCrypt Rust implementation.
//!
//! This crate provides:
//! - Block ciphers (AES, Serpent, Twofish, Camellia, Kuznyechik)
//! - Hash functions (SHA-256, SHA-512, BLAKE2s, Whirlpool, Streebog)
//! - Key derivation functions (PBKDF2, Argon2)
//! - XTS encryption mode
//! - Cipher cascading support

#![cfg_attr(all(feature = "kernel", not(feature = "std")), no_std)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

// alloc is needed for String/Box/Vec when compiled without std (kernel driver)
// #[macro_use] is needed for format! and vec! macros
#[cfg(all(feature = "kernel", not(feature = "std")))]
#[macro_use]
extern crate alloc;

pub mod ciphers;
pub mod error;
#[cfg(feature = "std")]
pub mod hash;
#[cfg(feature = "std")]
pub mod kdf;
pub mod kernel;
#[cfg(feature = "std")]
pub mod rng;
pub mod xts;

pub use ciphers::{AesCipher, CamelliaCipher, CascadeCipher, CascadeMode, CipherType, KuznyechikCipher, SerpentCipher, TwofishCipher};
pub use error::{CryptoError, Result};
pub use kernel::KernelSectorCipher;
#[cfg(feature = "std")]
pub use hash::HashAlgorithm;
#[cfg(feature = "std")]
pub use kdf::{KdfAlgorithm, KeyDerivation, Argon2idKdf, Pbkdf2Sha256, Pbkdf2Sha512, Pbkdf2Blake2s, Pbkdf2Whirlpool, Pbkdf2Streebog};
