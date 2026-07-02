//! User-mode IOCTL client for the `test-wdm` WDM kernel driver.
//!
//! Provides [`WdmTestClient`] to open `\\\\.\\TWDM`, query the driver, and
//! execute kernel-mode self-tests via IOCTL.
//!
//! # Example
//!
//! ```ignore
//! let client = WdmTestClient::open()?;
//! println!("Driver version: {:#x}", client.get_version()?);
//! let results = client.run_all_tests()?;
//! for r in &results {
//!     println!("  {}  {}", if r.passed() { "PASS" } else { "FAIL" }, r.name());
//! }
//! ```

use std::ffi::OsStr;
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::IO::DeviceIoControl;
use windows_sys::Win32::Storage::FileSystem::{
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};

// CreateFileW requires granular feature gating in windows-sys;
// declare it directly to avoid feature-resolution issues.
extern "system" {
    fn CreateFileW(
        lpFileName: *const u16,
        dwDesiredAccess: u32,
        dwShareMode: u32,
        lpSecurityAttributes: *const std::ffi::c_void,
        dwCreationDisposition: u32,
        dwFlagsAndAttributes: u32,
        hTemplateFile: HANDLE,
    ) -> HANDLE;
}

const GENERIC_READ: u32 = 0x80000000;
const GENERIC_WRITE: u32 = 0x40000000;

// IOCTL codes — must match test-wdm/src/lib.rs exactly.
// CTL_CODE(0x22, 0x800+N, METHOD_BUFFERED, FILE_ANY_ACCESS)
const IOCTL_TEST_GET_VERSION: u32 = 0x00222004; // N=1
const IOCTL_TEST_COUNT: u32 = 0x00222008; // N=2
const IOCTL_TEST_RUN_ALL: u32 = 0x0022200C; // N=3
const IOCTL_TEST_RUN_ONE: u32 = 0x00222010; // N=4

// ---------------------------------------------------------------------------
// TestResult — must match the #[repr(C)] layout in test-wdm/src/lib.rs
// ---------------------------------------------------------------------------

/// Mirrors `TestResult` in test-wdm.  Must be layout-compatible.
#[repr(C)]
#[derive(Clone)]
pub struct TestResult {
    /// UTF-16LE test name (null-terminated, max 64 u16 code units).
    pub name: [u16; 64],
    /// 0 = pass, -1 = fail, -2 = skipped.
    pub status: i32,
    /// Line number where failure occurred (0 if passed).
    pub error_line: u32,
}

impl TestResult {
    /// Whether the test passed.
    pub fn passed(&self) -> bool {
        self.status == 0
    }

    /// Whether the test was skipped.
    pub fn skipped(&self) -> bool {
        self.status == -2
    }

    /// The test name as a `String` (lossy UTF-16 → UTF-8 conversion).
    pub fn name(&self) -> String {
        let end = self
            .name
            .iter()
            .position(|&c| c == 0)
            .unwrap_or(self.name.len());
        String::from_utf16_lossy(&self.name[..end])
    }
}

/// Header returned at the beginning of the IOCTL_TEST_RUN_ALL buffer.
#[repr(C)]
struct TestRunHeader {
    count: u32,
    total: u32,
    passed: u32,
    failed: u32,
}

// ---------------------------------------------------------------------------
// WdmTestClient
// ---------------------------------------------------------------------------

/// A handle to the test-wdm kernel driver.
pub struct WdmTestClient {
    handle: HANDLE,
}

impl WdmTestClient {
    /// Open a connection to the test-wdm driver via `\\\\.\\TWDM`.
    ///
    /// Returns an error if the driver is not loaded or accessible.
    pub fn open() -> Result<Self, String> {
        let name: Vec<u16> = OsStr::new("\\\\.\\TWDM")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let h = unsafe {
            CreateFileW(
                name.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };

        if h == INVALID_HANDLE_VALUE {
            Err(format!(
                "Cannot open \\\\.\\TWDM — is the test-wdm driver loaded? ({})",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(Self { handle: h })
        }
    }

    /// Get the driver version number.
    pub fn get_version(&self) -> Result<u32, String> {
        let mut version: u32 = 0;
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_TEST_GET_VERSION,
                ptr::null_mut(),
                0,
                &mut version as *mut u32 as *mut std::ffi::c_void,
                4,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(format!(
                "IOCTL_GET_VERSION failed: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(version)
        }
    }

    /// Get the number of registered self-tests.
    pub fn test_count(&self) -> Result<u32, String> {
        let mut count: u32 = 0;
        let mut bytes_returned: u32 = 0;
        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_TEST_COUNT,
                ptr::null_mut(),
                0,
                &mut count as *mut u32 as *mut std::ffi::c_void,
                4,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };
        if ok == 0 {
            Err(format!(
                "IOCTL_TEST_COUNT failed: {}",
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(count)
        }
    }

    /// Run all registered self-tests and return the results.
    ///
    /// Allocates a buffer large enough for the maximum expected response.
    pub fn run_all_tests(&self) -> Result<Vec<TestResult>, String> {
        const MAX_RESULTS: usize = 16;
        let buf_size =
            mem::size_of::<TestRunHeader>() + MAX_RESULTS * mem::size_of::<TestResult>();
        let mut buf: Vec<u8> = vec![0u8; buf_size];
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_TEST_RUN_ALL,
                ptr::null_mut(),
                0,
                buf.as_mut_ptr() as *mut std::ffi::c_void,
                buf_size as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == 0 {
            return Err(format!(
                "IOCTL_TEST_RUN_ALL failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        // Parse the header
        if (bytes_returned as usize) < mem::size_of::<TestRunHeader>() {
            return Err("IOCTL_TEST_RUN_ALL returned too few bytes for header".into());
        }

        let header = unsafe { &*(buf.as_ptr() as *const TestRunHeader) };
        let count = header.count as usize;
        let results_offset = mem::size_of::<TestRunHeader>();
        let expected = results_offset + count * mem::size_of::<TestResult>();

        if (bytes_returned as usize) < expected {
            return Err(format!(
                "IOCTL_TEST_RUN_ALL: expected {} bytes, got {}",
                expected, bytes_returned
            ));
        }

        let mut results = Vec::with_capacity(count);
        for i in 0..count {
            let offset = results_offset + i * mem::size_of::<TestResult>();
            let result = unsafe { &*(buf.as_ptr().add(offset) as *const TestResult) };
            results.push(result.clone());
        }

        Ok(results)
    }

    /// Run a single test by index.
    pub fn run_one_test(&self, index: u32) -> Result<TestResult, String> {
        let mut result: TestResult = unsafe { mem::zeroed() };
        let mut bytes_returned: u32 = 0;

        let ok = unsafe {
            DeviceIoControl(
                self.handle,
                IOCTL_TEST_RUN_ONE,
                &index as *const u32 as *const std::ffi::c_void,
                4,
                &mut result as *mut TestResult as *mut std::ffi::c_void,
                mem::size_of::<TestResult>() as u32,
                &mut bytes_returned,
                ptr::null_mut(),
            )
        };

        if ok == 0 {
            Err(format!(
                "IOCTL_TEST_RUN_ONE({}) failed: {}",
                index,
                std::io::Error::last_os_error()
            ))
        } else {
            Ok(result)
        }
    }
}

impl Drop for WdmTestClient {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}

// ---------------------------------------------------------------------------
// Integration tests (opt-in — require driver loaded with testsigning)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "requires test-wdm driver loaded with testsigning on"]
    fn test_driver_version() {
        let client = WdmTestClient::open().expect("failed to open \\\\.\\TWDM");
        let version = client.get_version().expect("get_version failed");
        assert_eq!(version, 0x00010000);
    }

    #[test]
    #[ignore = "requires test-wdm driver loaded with testsigning on"]
    fn test_driver_test_count() {
        let client = WdmTestClient::open().expect("failed to open \\\\.\\TWDM");
        let count = client.test_count().expect("test_count failed");
        assert_eq!(count, 5);
    }

    #[test]
    #[ignore = "requires test-wdm driver loaded with testsigning on"]
    fn test_driver_run_all() {
        let client = WdmTestClient::open().expect("failed to open \\\\.\\TWDM");
        let results = client.run_all_tests().expect("run_all_tests failed");
        assert_eq!(results.len(), 5);
        for r in &results {
            assert!(
                r.passed(),
                "test '{}' failed (status={}, line={})",
                r.name(),
                r.status,
                r.error_line
            );
        }
    }

    #[test]
    #[ignore = "requires test-wdm driver loaded with testsigning on"]
    fn test_driver_run_one_each() {
        let client = WdmTestClient::open().expect("failed to open \\\\.\\TWDM");
        let count = client.test_count().expect("test_count failed");
        for i in 0..count {
            let r = client
                .run_one_test(i)
                .unwrap_or_else(|e| panic!("run_one_test({}) failed: {}", i, e));
            assert!(
                r.passed(),
                "test '{}' (index {}) failed (status={}, line={})",
                r.name(),
                i,
                r.status,
                r.error_line
            );
        }
    }

    #[test]
    #[ignore = "requires test-wdm driver loaded with testsigning on"]
    fn test_invalid_index() {
        let client = WdmTestClient::open().expect("failed to open \\\\.\\TWDM");
        let r = client.run_one_test(999).expect("run_one_test(999) IOCTL failed");
        assert!(r.skipped(), "expected index 999 to be skipped, got status={}", r.status);
    }
}
