//! Kernel debug output — sends trace messages via DbgPrintEx.
//!
//! Captured by DebugView (Sysinternals) with "Capture Kernel" enabled.
//! Uses fixed-format strings (方案A) because Rust cannot declare C varargs externs.

use crate::wdk_bindings::{DbgPrintEx, DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL};

/// Print a fixed string to the kernel debug output.
#[inline]
pub fn kdbg(msg: &str) {
    // DbgPrintEx expects a NUL-terminated C string.
    // We copy into a stack buffer to add the NUL.
    let mut buf = [0u8; 256];
    let len = msg.len().min(254);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    buf[len] = 0; // NUL terminator
    unsafe {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, buf.as_ptr());
    }
}

/// Print a string with a hex status code appended.
#[inline]
pub fn kdbg_status(msg: &str, status: i32) {
    let mut buf = [0u8; 300];
    let len = msg.len().min(260);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    let s = format_hex_status(status);
    let total = len + 19;
    buf[len..total].copy_from_slice(&s[..19]);
    buf[total] = 0;
    unsafe {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, buf.as_ptr());
    }
}

/// Print a string with a u64 value appended.
#[inline]
pub fn kdbg_u64(msg: &str, val: u64) {
    let mut buf = [0u8; 300];
    let len = msg.len().min(260);
    buf[..len].copy_from_slice(&msg.as_bytes()[..len]);
    let s = format_u64(val);
    // Find the actual length of the formatted number (starts at buf[1])
    let mut slen = 1;
    while slen < 20 && s[slen] != 0 { slen += 1; }
    let total = len + slen;
    buf[len..total].copy_from_slice(&s[..slen]);
    buf[total] = 0;
    unsafe {
        DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, buf.as_ptr());
    }
}

fn format_hex_status(val: i32) -> [u8; 19] {
    let mut buf = [0u8; 19];
    let prefix = b" status=0x";
    buf[..11].copy_from_slice(&prefix[..]);
    let v = val as u32;
    for i in 0..8 {
        let nibble = ((v >> (28 - i * 4)) & 0xF) as u8;
        buf[11 + i] = if nibble < 10 { b'0' + nibble } else { b'A' + nibble - 10 };
    }
    buf
}

fn format_u64(val: u64) -> [u8; 21] {
    let mut buf = [0u8; 21];
    let mut digits = [0u8; 20];
    let mut val = val;
    let mut n = 0;
    if val == 0 {
        buf[0] = b' ';
        buf[1] = b'0';
        return buf;
    }
    while val > 0 {
        digits[n] = b'0' + (val % 10) as u8;
        val /= 10;
        n += 1;
    }
    buf[0] = b' ';
    for i in 0..n {
        buf[1 + i] = digits[n - 1 - i];
    }
    buf
}

// Suppress unused warnings for the u64 formatter (used by kdbg_u64)
#[allow(dead_code)]
fn _ensure_used() {
    let _ = format_u64(0);
}
