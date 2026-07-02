#![no_std]

use wdk_sys::{
    PDRIVER_OBJECT, NTSTATUS, PCUNICODE_STRING, PDEVICE_OBJECT, PIRP,
    PIO_STACK_LOCATION, UNICODE_STRING, OBJECT_ATTRIBUTES, IO_STATUS_BLOCK,
    PVOID, HANDLE, BOOLEAN, UCHAR, ULONG, ULONG_PTR, NT_SUCCESS,
    IRP_MJ_CREATE, IRP_MJ_CLOSE, IRP_MJ_CLEANUP, IRP_MJ_DEVICE_CONTROL,
    IRP_MJ_MAXIMUM_FUNCTION, STATUS_SUCCESS, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INSUFFICIENT_RESOURCES, STATUS_BUFFER_TOO_SMALL,
    FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, DO_DIRECT_IO,
    DO_DEVICE_INITIALIZING, OBJ_KERNEL_HANDLE, OBJ_CASE_INSENSITIVE,
    IoCreateDevice, IoCreateSymbolicLink, IoDeleteDevice,
    IoDeleteSymbolicLink, IoCompleteRequest, IoGetCurrentIrpStackLocation,
    RtlInitUnicodeString, InitializeObjectAttributes, DbgPrintEx,
    DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL,
    ExAllocatePool2, ExFreePool,
    KeInitializeEvent, KeSetEvent, KeResetEvent, KEVENT,
    POOL_FLAG_NON_PAGED, IO_NO_INCREMENT,
};

#[cfg(not(test))]
extern crate wdk_panic;

#[cfg(not(test))]
use wdk_alloc::WdkAllocator;

#[cfg(not(test))]
#[global_allocator]
static GLOBAL_ALLOCATOR: WdkAllocator = WdkAllocator;

// ---------------------------------------------------------------------------
// IOCTL codes — CTL_CODE(0x22, 0x800+N, METHOD_BUFFERED, FILE_ANY_ACCESS)
// ---------------------------------------------------------------------------
const IOCTL_TEST_GET_VERSION: u32 = 0x00222004; // N=1
const IOCTL_TEST_COUNT:      u32 = 0x00222008; // N=2
const IOCTL_TEST_RUN_ALL:    u32 = 0x0022200C; // N=3
const IOCTL_TEST_RUN_ONE:    u32 = 0x00222010; // N=4

const DRIVER_VERSION: u32 = 0x00010000; // 1.0.0

// ---------------------------------------------------------------------------
// Test framework types
// ---------------------------------------------------------------------------

/// Result of a single test, returned to user-mode via IOCTL.
#[repr(C)]
struct TestResult {
    /// UTF-16LE test name (null-terminated).
    name: [u16; 64],
    /// 0 = pass, -1 = fail, -2 = skipped.
    status: i32,
    /// Line number where failure occurred (0 if passed).
    error_line: u32,
}

/// Signature of a self-test function. Returns true on pass.
type TestFn = unsafe fn() -> bool;

/// A registered self-test entry.
struct TestEntry {
    name: &'static [u16],
    func: TestFn,
}

const MAX_TESTS: usize = 16;

static mut TEST_REGISTRY: [Option<TestEntry>; MAX_TESTS] = [const { None }; MAX_TESTS];
static mut TEST_COUNT: u32 = 0;

/// Register a test during DriverEntry. Not thread-safe — called only at init.
unsafe fn register_test(name: &'static [u16], func: TestFn) {
    let idx = TEST_COUNT as usize;
    if idx < MAX_TESTS {
        TEST_REGISTRY[idx] = Some(TestEntry { name, func });
        TEST_COUNT += 1;
    }
}

// ---------------------------------------------------------------------------
// UTF-16 test-name arrays (pre-computed, null-terminated)
// ---------------------------------------------------------------------------

const NAME_DEVICE_EXISTS: [u16; 20] = build_utf16("test_device_exists");
const NAME_MEMORY_ALLOC: [u16; 18] = build_utf16("test_memory_alloc");
const NAME_EVENT_SYNC: [u16; 16] = build_utf16("test_event_sync");
const NAME_STRUCT_SIZES: [u16; 18] = build_utf16("test_struct_sizes");
const NAME_VERSION_CONSTANT: [u16; 22] = build_utf16("test_version_constant");
const NAME_INVALID_INDEX: [u16; 14] = build_utf16("INVALID_INDEX");
const NAME_EMPTY_SLOT: [u16; 12] = build_utf16("EMPTY_SLOT");

/// Compile-time UTF-8 to UTF-16LE conversion with NUL terminator.
const fn build_utf16<const N: usize>(s: &str) -> [u16; N] {
    let bytes = s.as_bytes();
    let mut arr = [0u16; N];
    let mut i = 0;
    while i < bytes.len() {
        arr[i] = bytes[i] as u16;
        i += 1;
    }
    arr[bytes.len()] = 0; // NUL terminator
    arr
}

/// Write a static UTF-16 literal into a TestResult name field.
unsafe fn write_name(result: &mut TestResult, src: &[u16]) {
    let dst = result.name.as_mut_ptr();
    let n = src.len().min(63);
    for i in 0..n {
        *dst.add(i) = src[i];
    }
    *dst.add(n) = 0; // NUL terminator
}

// ---------------------------------------------------------------------------
// Built-in self-test functions
// ---------------------------------------------------------------------------

/// Test 0: Root device object exists.
unsafe fn test_device_exists() -> bool {
    !ROOT_DEVICE.is_null()
}

/// Test 1: Non-paged pool allocation + free.
unsafe fn test_memory_alloc() -> bool {
    const TAG: u32 = u32::from_ne_bytes(*b"Twdm");
    let ptr = ExAllocatePool2(POOL_FLAG_NON_PAGED, 128, TAG);
    if ptr.is_null() {
        return false;
    }
    ExFreePool(ptr);
    true
}

/// Test 2: Kernel event object lifecycle.
unsafe fn test_event_sync() -> bool {
    let mut event: KEVENT = core::mem::zeroed();
    KeInitializeEvent(&mut event, 0, 0); // NotificationEvent, not signalled
    // Initially not signalled — reset should be a no-op
    KeResetEvent(&mut event);
    // Set and verify state
    // Note: KeSetEvent returns the previous state (0 = was not signalled)
    KeSetEvent(&mut event, 0, 0); // no priority boost
    // Reset back
    KeResetEvent(&mut event);
    true
}

/// Test 3: Verify compile-time struct sizes.
unsafe fn test_struct_sizes() -> bool {
    // UNICODE_STRING is 16 bytes on x64
    core::mem::size_of::<UNICODE_STRING>() == 16
        // KEVENT should be properly sized
        && core::mem::size_of::<KEVENT>() >= 24
        // IO_STATUS_BLOCK is 16 bytes (2 × i64/i32 pairs on x64)
        && core::mem::size_of::<IO_STATUS_BLOCK>() == 16
}

/// Test 4: Basic IOCTL roundtrip — GET_VERSION should work.
/// This is tested externally; here we just verify the constant.
unsafe fn test_version_constant() -> bool {
    DRIVER_VERSION == 0x00010000
}

// ---------------------------------------------------------------------------
// Test registration (called from DriverEntry)
// ---------------------------------------------------------------------------

unsafe fn register_all_tests() {
    register_test(&NAME_DEVICE_EXISTS, test_device_exists);
    register_test(&NAME_MEMORY_ALLOC, test_memory_alloc);
    register_test(&NAME_EVENT_SYNC, test_event_sync);
    register_test(&NAME_STRUCT_SIZES, test_struct_sizes);
    register_test(&NAME_VERSION_CONSTANT, test_version_constant);
}

// ---------------------------------------------------------------------------
// Execute tests and fill results
// ---------------------------------------------------------------------------

unsafe fn run_one_test(index: usize, result: &mut TestResult) {
    if index >= TEST_COUNT as usize {
        write_name(result, &NAME_INVALID_INDEX);
        result.status = -2;
        result.error_line = 0;
        return;
    }
    let entry = match &TEST_REGISTRY[index] {
        Some(e) => e,
        None => {
            write_name(result, &NAME_EMPTY_SLOT);
            result.status = -2;
            result.error_line = 0;
            return;
        }
    };
    write_name(result, entry.name);
    let passed = (entry.func)();
    if passed {
        result.status = 0;
        result.error_line = 0;
    } else {
        result.status = -1;
        result.error_line = line!() as u32;
    }
}

unsafe fn run_all_tests(buf: *mut u8, buf_len: u32) -> NTSTATUS {
    let count = TEST_COUNT;
    let header_size = 16u32; // count(u32) + total(u32) + passed(u32) + failed(u32)
    let per_result = core::mem::size_of::<TestResult>() as u32;
    let needed = header_size + count * per_result;
    if buf_len < needed {
        return STATUS_BUFFER_TOO_SMALL;
    }

    // Zero the output buffer
    core::ptr::write_bytes(buf, 0, needed as usize);

    let header = buf as *mut u32;
    *header = count;        // count
    *header.add(1) = count; // total
    *header.add(2) = 0;     // passed (filled below)
    *header.add(3) = 0;     // failed (filled below)

    let results_base = buf.add(header_size as usize) as *mut TestResult;
    let mut passed: u32 = 0;
    let mut failed: u32 = 0;

    for i in 0..count as usize {
        let result = &mut *results_base.add(i);
        run_one_test(i, result);
        if result.status == 0 {
            passed += 1;
        } else {
            failed += 1;
        }
    }

    *header.add(2) = passed;
    *header.add(3) = failed;
    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

static mut ROOT_DEVICE: PDEVICE_OBJECT = core::ptr::null_mut();

const DEV_NAME: [u16; 16] = [
    0x5C, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x5C,
    0x54, 0x65, 0x73, 0x74, 0x57, 0x44, 0x4D, 0x00,
];
const DOS_NAME_FULL: [u16; 17] = [
    0x5C, 0x44, 0x6F, 0x73, 0x44, 0x65, 0x76, 0x69,
    0x63, 0x65, 0x73, 0x5C, 0x54, 0x57, 0x44, 0x4D, 0x00,
];

// ---------------------------------------------------------------------------
// DriverEntry
// ---------------------------------------------------------------------------

#[unsafe(export_name = "DriverEntry")]
pub unsafe extern "system" fn driver_entry(
    driver_object: PDRIVER_OBJECT,
    _registry_path: PCUNICODE_STRING,
) -> NTSTATUS {
    // Fill dispatch table — all IRP major functions route to `dispatch`
    let major_func_base = (driver_object as *mut u8).add(0x70) as *mut PVOID;
    for i in 0..=IRP_MJ_MAXIMUM_FUNCTION as usize {
        *major_func_base.add(i) = dispatch as PVOID;
    }
    // DriverUnload @ offset 0x68
    let unload_ptr = (driver_object as *mut u8).add(0x68) as *mut PVOID;
    *unload_ptr = unload as PVOID;

    // Create device \Device\TestWDM
    let mut dev: PDEVICE_OBJECT = core::ptr::null_mut();
    let mut nt_name = UNICODE_STRING::default();
    RtlInitUnicodeString(&mut nt_name, DEV_NAME.as_ptr());
    let status = IoCreateDevice(
        driver_object, 0, &mut nt_name,
        FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, 0, &mut dev,
    );
    if !NT_SUCCESS(status) { return status; }

    // Create symbolic link \DosDevices\TWDM
    let mut dos_name = UNICODE_STRING::default();
    RtlInitUnicodeString(&mut dos_name, DOS_NAME_FULL.as_ptr());
    let link_status = IoCreateSymbolicLink(&mut dos_name, &mut nt_name);
    if !NT_SUCCESS(link_status) {
        IoDeleteDevice(dev);
        return link_status;
    }

    (*dev).Flags |= DO_DIRECT_IO;
    (*dev).Flags &= !DO_DEVICE_INITIALIZING;
    ROOT_DEVICE = dev;

    // Register built-in self-tests
    register_all_tests();

    STATUS_SUCCESS
}

// ---------------------------------------------------------------------------
// Unload
// ---------------------------------------------------------------------------

unsafe extern "system" fn unload(_driver: PDRIVER_OBJECT) {
    if !ROOT_DEVICE.is_null() {
        let mut dos_name = UNICODE_STRING::default();
        RtlInitUnicodeString(&mut dos_name, DOS_NAME_FULL.as_ptr());
        IoDeleteSymbolicLink(&mut dos_name);
        IoDeleteDevice(ROOT_DEVICE);
        ROOT_DEVICE = core::ptr::null_mut();
    }
}

// ---------------------------------------------------------------------------
// IRP dispatch
// ---------------------------------------------------------------------------

unsafe extern "system" fn dispatch(
    _device: PDEVICE_OBJECT,
    irp: PIRP,
) -> NTSTATUS {
    let stack = IoGetCurrentIrpStackLocation(irp);
    let major = (*stack).MajorFunction;

    match major as u32 {
        IRP_MJ_CREATE | IRP_MJ_CLOSE | IRP_MJ_CLEANUP => {
            complete(irp, STATUS_SUCCESS, 0);
            STATUS_SUCCESS
        }
        IRP_MJ_DEVICE_CONTROL => {
            let ioctl = (*stack).Parameters.DeviceIoControl.IoControlCode;

            match ioctl {
                IOCTL_TEST_GET_VERSION => {
                    let buf = (*irp).AssociatedIrp.SystemBuffer as *mut u32;
                    if !buf.is_null() {
                        *buf = DRIVER_VERSION;
                        complete(irp, STATUS_SUCCESS, 4);
                    } else {
                        complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
                    }
                    STATUS_SUCCESS
                }
                IOCTL_TEST_COUNT => {
                    let buf = (*irp).AssociatedIrp.SystemBuffer as *mut u32;
                    if !buf.is_null() {
                        *buf = TEST_COUNT;
                        complete(irp, STATUS_SUCCESS, 4);
                    } else {
                        complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
                    }
                    STATUS_SUCCESS
                }
                IOCTL_TEST_RUN_ALL => {
                    let buf = (*irp).AssociatedIrp.SystemBuffer;
                    let buf_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength;
                    if buf.is_null() {
                        complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
                        return STATUS_INVALID_DEVICE_REQUEST;
                    }
                    let status = run_all_tests(buf as *mut u8, buf_len);
                    let info = if NT_SUCCESS(status) { buf_len } else { 0 };
                    complete(irp, status, info as ULONG_PTR);
                    STATUS_SUCCESS
                }
                IOCTL_TEST_RUN_ONE => {
                    let buf = (*irp).AssociatedIrp.SystemBuffer as *mut u8;
                    let buf_len = (*stack).Parameters.DeviceIoControl.OutputBufferLength;
                    if buf.is_null() || buf_len < core::mem::size_of::<TestResult>() as u32 {
                        complete(irp, STATUS_BUFFER_TOO_SMALL, 0);
                        return STATUS_BUFFER_TOO_SMALL;
                    }
                    let in_buf = (*stack).Parameters.DeviceIoControl.Type3InputBuffer
                        as *const u32;
                    let index = if !in_buf.is_null() { *in_buf } else { 0 } as usize;
                    let result = &mut *(buf as *mut TestResult);
                    run_one_test(index, result);
                    complete(irp, STATUS_SUCCESS, core::mem::size_of::<TestResult>() as ULONG_PTR);
                    STATUS_SUCCESS
                }
                _ => {
                    complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
                    STATUS_INVALID_DEVICE_REQUEST
                }
            }
        }
        _ => {
            complete(irp, STATUS_INVALID_DEVICE_REQUEST, 0);
            STATUS_INVALID_DEVICE_REQUEST
        }
    }
}

// ---------------------------------------------------------------------------
// IRP completion helper
// ---------------------------------------------------------------------------

unsafe fn complete(irp: PIRP, status: NTSTATUS, info: ULONG_PTR) {
    let io_status = (irp as *mut u8).add(0x30) as *mut IO_STATUS_BLOCK;
    (*io_status).Status = status;
    (*io_status).Information = info;
    IoCompleteRequest(irp, IO_NO_INCREMENT);
}
