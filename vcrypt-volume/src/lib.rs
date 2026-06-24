//! # vcrypt-volume
//!
//! VeraCrypt volume management — create, open, read/write encrypted volumes.
//!
//! Provides:
//! - Volume configuration (cipher, hash, KDF selection)
//! - Volume opening (header decryption, key extraction)
//! - Sector-level I/O with XTS encryption
//! - Volume creation

pub mod config;
pub mod create;
pub mod error;
pub mod io;
pub mod layout;
pub mod open;
pub mod sector_cipher;
pub mod volume;
pub mod change;
pub mod restore;

pub use config::VolumeConfig;
pub use create::{create_volume, create_volume_full, create_hidden_volume, ProgressFn};
pub use change::change_volume_password;
pub use error::{VolResult, VolumeError};
pub use layout::VolumeType;
pub use open::{open_volume_file, open_volume_file_with_kdf, open_volume_with_iters, open_volume_with_pim};
pub use restore::restore_volume_header;
pub use sector_cipher::create_sector_cipher;
pub use volume::OpenVolume;
