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

#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod ciphers;
pub mod error;
pub mod hash;
pub mod kdf;
pub mod rng;
pub mod xts;

pub use ciphers::{AesCipher, CamelliaCipher, CascadeCipher, CascadeMode, CipherType, KuznyechikCipher, SerpentCipher, TwofishCipher};
pub use error::{CryptoError, Result};
