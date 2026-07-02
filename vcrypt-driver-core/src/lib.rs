//! # vcrypt-driver-core
//!
//! Pure `no_std` logic shared between the `vcrypt-driver` Windows kernel driver
//! and user-mode test harnesses.
//!
//! This crate contains no WDK FFI — only algorithmic logic that can be
//! compiled and tested on any platform (including Linux CI).

#![no_std]

#[cfg(test)]
extern crate std;

extern crate alloc;

mod ea_mapping;
mod geometry;
mod mount_struct;
pub mod sector_io;

pub use ea_mapping::cipher_type_from_ea;
pub use geometry::compute_virtual_geometry;
pub use mount_struct::{
    copy_into_packed, copy_wide_into_packed, read_packed_i32, read_packed_i64, read_packed_u32,
    read_packed_u64, read_packed_u8, write_packed_i32,
};
pub use sector_io::{compute_sector_io_params, decrypt_sectors, encrypt_sectors, SectorIoParams};
