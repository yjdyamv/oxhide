//! # vcrypt-format
//!
//! VeraCrypt volume format handling.
//!
//! This crate implements:
//! - Volume header structures and constants
//! - Binary serialization/deserialization of volume headers
//! - TODO: Header encryption/decryption (XTS mode with header key)
//! - TODO: Keyfile parsing (XML and binary formats)
//! - TODO: Backup header read/write support

pub mod error;
pub mod header;
pub mod ser;
pub mod deser;
pub mod encrypt;
pub mod keyfile;

pub use error::{FormatError, FormatResult};
pub use header::VolumeHeader;
