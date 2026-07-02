//! Helpers for reading/writing fields inside `#[repr(C, packed(1))]` structs.
//!
//! Extracted from `vcrypt-driver/src/types.rs`.  Packed structs cannot have
//! references taken to their fields (alignment UB), so all access must go
//! through raw-pointer byte copies.

/// Read a `u32` from a packed struct field by address (unaligned-safe).
#[inline]
pub unsafe fn read_packed_u32<T>(addr: *const T) -> u32 {
    let p = addr as *const u8;
    u32::from_le_bytes([*p, *p.add(1), *p.add(2), *p.add(3)])
}

/// Read a `u64` from a packed struct field by address (unaligned-safe).
#[inline]
pub unsafe fn read_packed_u64<T>(addr: *const T) -> u64 {
    let p = addr as *const u8;
    let mut b = [0u8; 8];
    core::ptr::copy_nonoverlapping(p, b.as_mut_ptr(), 8);
    u64::from_le_bytes(b)
}

/// Read an `i64` from a packed struct field by address (unaligned-safe).
#[inline]
pub unsafe fn read_packed_i64<T>(addr: *const T) -> i64 {
    read_packed_u64(addr) as i64
}

/// Read a `u8` from a packed struct field by address.
#[inline]
pub unsafe fn read_packed_u8<T>(addr: *const T) -> u8 {
    *(addr as *const u8)
}

/// Read an `i32` from a packed struct field by address (unaligned-safe).
#[inline]
pub unsafe fn read_packed_i32<T>(addr: *const T) -> i32 {
    read_packed_u32(addr) as i32
}

/// Write an `i32` to a packed struct field by address (unaligned-safe).
#[inline]
pub unsafe fn write_packed_i32<T>(addr: *mut T, val: i32) {
    let p = addr as *mut u8;
    let b = val.to_le_bytes();
    *p = b[0];
    *p.add(1) = b[1];
    *p.add(2) = b[2];
    *p.add(3) = b[3];
}

/// Copy `src[..len]` into a packed `[u8; N]` field by address.
#[inline]
pub unsafe fn copy_into_packed<T>(addr: *mut T, src: &[u8], len: usize) {
    let p = addr as *mut u8;
    core::ptr::copy_nonoverlapping(src.as_ptr(), p, len);
}

/// Copy a UTF-16 buffer into a packed `[u16; N]` field by address (raw bytes).
#[inline]
pub unsafe fn copy_wide_into_packed<T>(addr: *mut T, src: *const u16, len_ch: usize) {
    let p = addr as *mut u8;
    core::ptr::copy_nonoverlapping(src as *const u8, p, len_ch * 2);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[repr(C, packed(1))]
    struct TestPacked {
        a: u8,
        b: u32,
        c: u64,
        d: i32,
    }

    #[test]
    fn test_read_packed_u8() {
        let t = TestPacked {
            a: 0xAB,
            b: 0,
            c: 0,
            d: 0,
        };
        let val = unsafe { read_packed_u8(core::ptr::addr_of!(t.a)) };
        assert_eq!(val, 0xAB);
    }

    #[test]
    fn test_read_packed_u32() {
        let t = TestPacked {
            a: 0,
            b: 0xDEAD_BEEF,
            c: 0,
            d: 0,
        };
        let val = unsafe { read_packed_u32(core::ptr::addr_of!(t.b)) };
        assert_eq!(val, 0xDEAD_BEEF);
    }

    #[test]
    fn test_read_packed_u64() {
        let t = TestPacked {
            a: 0,
            b: 0,
            c: 0x0123_4567_89AB_CDEF,
            d: 0,
        };
        let val = unsafe { read_packed_u64(core::ptr::addr_of!(t.c)) };
        assert_eq!(val, 0x0123_4567_89AB_CDEF);
    }

    #[test]
    fn test_read_packed_i32_negative() {
        let t = TestPacked {
            a: 0,
            b: 0,
            c: 0,
            d: -42,
        };
        let val = unsafe { read_packed_i32(core::ptr::addr_of!(t.d)) };
        assert_eq!(val, -42);
    }

    #[test]
    fn test_write_packed_i32() {
        let mut t = TestPacked {
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        };
        unsafe { write_packed_i32(core::ptr::addr_of_mut!(t.d), -99) };
        let val = unsafe { read_packed_i32(core::ptr::addr_of!(t.d)) };
        assert_eq!(val, -99);
    }

    #[test]
    fn test_read_packed_i64() {
        let neg_val = -0x1234_5678_9ABC_DEF0i64;
        let t = TestPacked {
            a: 0,
            b: 0,
            c: neg_val as u64,
            d: 0,
        };
        let val = unsafe { read_packed_i64(core::ptr::addr_of!(t.c)) };
        assert_eq!(val, neg_val);
    }

    #[test]
    fn test_copy_into_packed() {
        let mut buf = [0xFFu8; 8];
        let src = [0x11, 0x22, 0x33, 0x44];
        unsafe { copy_into_packed(buf.as_mut_ptr(), &src, 4) };
        assert_eq!(buf[0], 0x11);
        assert_eq!(buf[1], 0x22);
        assert_eq!(buf[2], 0x33);
        assert_eq!(buf[3], 0x44);
        assert_eq!(buf[4], 0xFF); // untouched
    }
}
