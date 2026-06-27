//! # vcrypt-driver
//!
//! Windows kernel driver (WDM) that creates virtual disk devices backed by
//! VeraCrypt-compatible encrypted container files.
//!
//! ## Building
//!
//! Requires nightly Rust + WDK + cargo-wdk.
//!
//! ## Architecture
//!
//! The driver is a 1:1 translation of VeraCrypt's `Ntdriver.c` / `Ntvol.c` /
//! `EncryptedIoQueue.c` for the file-container-only subset.

#![no_std]

extern crate alloc;

extern crate wdk_sys;

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

mod crypto;
mod debug;
mod device;
mod driver;
mod encrypted_io_queue;
mod extension;
mod irp_utils;
mod mount;
mod mount_mgr;
mod names;
mod ntvol;
mod types;
mod volume_ioctl;
mod volume_thread;
mod wdk_bindings;
