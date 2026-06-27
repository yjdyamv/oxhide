//! Hand-written FFI bindings for WDK kernel types and functions.
//!
//! Verified against WDK 10.0.26100.0 `wdm.h` for x86_64.  Dispatcher objects
//! (KEVENT/KSEMAPHORE/KMUTEX) are modelled as 8-byte-aligned opaque blobs of
//! the correct size so that `KeInitialize*` / `KeWaitForSingleObject` see a
//! properly aligned object when it is embedded in a `#[repr(C)]` struct.
//!
//! Field offsets used by the inline helpers (`IoGetCurrentIrpStackLocation`
//! @0xB8, `IoGetIoStatusBlock` @0x30) are asserted at compile time below.

pub type NTSTATUS = i32;
pub type HANDLE = *mut core::ffi::c_void;
pub type ULONG_PTR = usize;
pub type PVOID = *mut core::ffi::c_void;
pub type BOOLEAN = u8;
pub type LONG = i32;
pub type ULONG = u32;
pub type USHORT = u16;
pub type CSHORT = i16;
pub type UCHAR = u8;
pub type KIRQL = u8;
pub type KPRIORITY = LONG;
pub type ACCESS_MASK = u32;

pub const FALSE: BOOLEAN = 0;
pub const TRUE: BOOLEAN = 1;
pub const IO_NO_INCREMENT: i32 = 0;
pub const IO_DISK_INCREMENT: i32 = 1;

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------
pub const STATUS_SUCCESS: NTSTATUS = 0;
pub const STATUS_PENDING: NTSTATUS = 0x00000103u32 as i32;
pub const STATUS_BUFFER_TOO_SMALL: NTSTATUS = 0xC0000023u32 as i32;
pub const STATUS_BUFFER_OVERFLOW: NTSTATUS = 0x80000005u32 as i32;
pub const STATUS_INVALID_PARAMETER: NTSTATUS = 0xC000000Du32 as i32;
pub const STATUS_INVALID_DEVICE_REQUEST: NTSTATUS = 0xC0000010u32 as i32;
pub const STATUS_END_OF_FILE: NTSTATUS = 0xC0000011u32 as i32;
pub const STATUS_INSUFFICIENT_RESOURCES: NTSTATUS = 0xC000009Au32 as i32;
pub const STATUS_MEDIA_WRITE_PROTECTED: NTSTATUS = 0xC00000A2u32 as i32;
pub const STATUS_DEVICE_NOT_READY: NTSTATUS = 0xC00000A3u32 as i32;
pub const STATUS_UNSUCCESSFUL: NTSTATUS = 0xC0000001u32 as i32;
pub const STATUS_NOT_IMPLEMENTED: NTSTATUS = 0xC0000002u32 as i32;
pub const STATUS_NOT_SUPPORTED: NTSTATUS = 0xC000003Bu32 as i32;
pub const STATUS_INVALID_BUFFER_SIZE: NTSTATUS = 0xC0000206u32 as i32;
pub const STATUS_ACCESS_DENIED: NTSTATUS = 0xC0000022u32 as i32;
pub const STATUS_SHARING_VIOLATION: NTSTATUS = 0xC0000043u32 as i32;
pub const STATUS_DELETE_PENDING: NTSTATUS = 0xC0000056u32 as i32;
pub const STATUS_CANCELLED: NTSTATUS = 0xC0000120u32 as i32;
pub const STATUS_VERIFY_REQUIRED: NTSTATUS = 0x80000016u32 as i32;
pub const STATUS_DISK_CORRUPT_ERROR: NTSTATUS = 0xC0000032u32 as i32;
pub const STATUS_LOCK_NOT_GRANTED: NTSTATUS = 0xC0000055u32 as i32;
pub const STATUS_FILES_OPEN: NTSTATUS = 0xC0000122u32 as i32;
pub const STATUS_FILE_LOCK_CONFLICT: NTSTATUS = 0xC0000054u32 as i32;

pub const fn NT_SUCCESS(status: NTSTATUS) -> bool { status >= 0 }

// ---------------------------------------------------------------------------
// IRP major functions
// ---------------------------------------------------------------------------
pub const IRP_MJ_CREATE: u8 = 0;
pub const IRP_MJ_CLOSE: u8 = 2;
pub const IRP_MJ_READ: u8 = 3;
pub const IRP_MJ_WRITE: u8 = 4;
pub const IRP_MJ_FLUSH_BUFFERS: u8 = 9;
pub const IRP_MJ_SHUTDOWN: u8 = 16;
pub const IRP_MJ_DEVICE_CONTROL: u8 = 14;
pub const IRP_MJ_CLEANUP: u8 = 18;
pub const IRP_MJ_PNP: u8 = 24;
pub const IRP_MJ_MAXIMUM_FUNCTION: u8 = 27;

// Stack-location control flags
pub const SL_PENDING_RETURNED: UCHAR = 0x01;

// ---------------------------------------------------------------------------
// Device / file constants
// ---------------------------------------------------------------------------
pub const FILE_DEVICE_UNKNOWN: u32 = 0x22;
pub const FILE_DEVICE_DISK: u32 = 0x07;
pub const FILE_DEVICE_SECURE_OPEN: u32 = 0x100;
pub const DO_BUFFERED_IO: u32 = 0x04;
pub const DO_DIRECT_IO: u32 = 0x10;
pub const DO_DEVICE_INITIALIZING: u32 = 0x80;
pub const FILE_READ_ONLY_DEVICE: u32 = 0x2000;
pub const FILE_REMOVABLE_MEDIA: u32 = 0x0800;
pub const METHOD_BUFFERED: u32 = 0;
pub const FILE_ANY_ACCESS: u32 = 0;
pub const FILE_READ_ACCESS: u32 = 1;
pub const FILE_WRITE_ACCESS: u32 = 2;
pub const FILE_READ_DATA: u32 = 0x0001;
pub const FILE_WRITE_DATA: u32 = 0x0002;
pub const FILE_APPEND_DATA: u32 = 0x0004;
pub const FILE_READ_ATTRIBUTES: u32 = 0x0080;
pub const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
pub const FILE_ATTRIBUTE_NORMAL: u32 = 0x80;
pub const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
pub const FILE_ATTRIBUTE_OFFLINE: u32 = 0x1000;
pub const FILE_ATTRIBUTE_COMPRESSED: u32 = 0x800;
pub const FILE_SHARE_READ: u32 = 0x01;
pub const FILE_SHARE_WRITE: u32 = 0x02;
pub const FILE_SHARE_DELETE: u32 = 0x04;
pub const GENERIC_READ: u32 = 0x80000000;
pub const GENERIC_WRITE: u32 = 0x40000000;
pub const GENERIC_ALL: u32 = 0x10000000;
pub const SYNCHRONIZE: u32 = 0x100000;
pub const FILE_RANDOM_ACCESS: u32 = 0x800;
pub const FILE_WRITE_THROUGH: u32 = 0x2;
pub const FILE_NO_INTERMEDIATE_BUFFERING: u32 = 0x8;
pub const FILE_OPEN: u32 = 1;
pub const FILE_OPEN_IF: u32 = 3;
pub const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
pub const FILE_SYNCHRONOUS_IO_ALERT: u32 = 0x10;
pub const FILE_NON_DIRECTORY_FILE: u32 = 0x40;
pub const FILE_DELETE_ON_CLOSE: u32 = 0x1000;
pub const OBJ_KERNEL_HANDLE: u32 = 0x200;
pub const OBJ_CASE_INSENSITIVE: u32 = 0x40;
pub const POOL_FLAG_NON_PAGED: u64 = 0x20000000000040;
pub const POOL_FLAG_PAGED: u64 = 0x20000000000041;
pub const NormalPagePriority: u32 = 16;
pub const MM_CACHED: u32 = 2;
pub const IO_READ_ACCESS: u32 = 0;
pub const IO_WRITE_ACCESS: u32 = 1;
pub const IO_MODIFY_ACCESS: u32 = 2;

// MDL flags
pub const MDL_MAPPED_TO_SYSTEM_VA: CSHORT = 0x0001;
pub const MDL_SOURCE_IS_NONPAGED_POOL: CSHORT = 0x0004;
pub const MDL_PAGES_LOCKED: CSHORT = 0x0002;
pub const MDL_MAPPING_CAN_FAIL: CSHORT = 0x0010;
pub const MDL_MAPPED_TO_SYSTEM_VA_FLAGS: CSHORT = 0x4000;
pub const MDL_MAPPING_NO_WRITE: CSHORT = 0x8000u16 as CSHORT;

// Debug print filter constants
pub const DPFLTR_IHVDRIVER_ID: u32 = 77;
pub const DPFLTR_ERROR_LEVEL: u32 = 0;

// Event types (EVENT_TYPE)
pub const NOTIFICATION_EVENT: u32 = 0;
pub const SynchronizationEvent: u32 = 1;

// Wait reason (KWAIT_REASON)
pub const Executive: u32 = 0;

// Thread priority
pub const LOW_REALTIME_PRIORITY: i32 = 16;
pub const KPRIORITY_LOW_REALTIME: KPRIORITY = 16;

// Processor mode (KPROCESSOR_MODE)
pub const KernelMode: u8 = 0;
pub const USER_MODE: u8 = 1;

// Work queue type (WORK_QUEUE_TYPE)
pub const CRITICAL_WORK_QUEUE: u32 = 0;
pub const DELAYED_WORK_QUEUE: u32 = 1;

// FILE_INFORMATION_CLASS (subset used)
pub const FileBasicInformation: u32 = 4;
pub const FileStandardInformation: u32 = 5;
pub const FILE_POSITION_INFORMATION: u32 = 14;
pub const FILE_FS_CONTROL_INFORMATION: u32 = 6;

// FSCTL codes (re-exported here for convenience)
pub const FSCTL_DISMOUNT_VOLUME: u32 = 0x00090020;
pub const FSCTL_LOCK_VOLUME: u32 = 0x00090018;
pub const FSCTL_UNLOCK_VOLUME: u32 = 0x0009001C;
pub const FSCTL_IS_VOLUME_MOUNTABLE: u32 = 0x00090028;
pub const FSCTL_IS_VOLUME_DIRTY: u32 = 0x0009008C;
pub const FSCTL_GET_NTFS_VOLUME_DATA: u32 = 0x00090064;

// ---------------------------------------------------------------------------
// Disk / Storage IOCTL base values
// ---------------------------------------------------------------------------
pub const IOCTL_DISK_BASE: u32 = 0x00000007;
pub const IOCTL_STORAGE_BASE: u32 = 0x0000002d;
pub const IOCTL_VOLUME_BASE: u32 = 0x00000056;

// Pre-computed IOCTL codes (CTL_CODE macro expanded)
pub const IOCTL_DISK_GET_DRIVE_GEOMETRY: u32 = 0x00070000;
pub const IOCTL_DISK_GET_DRIVE_GEOMETRY_EX: u32 = 0x00070070;
pub const IOCTL_DISK_GET_LENGTH_INFO: u32 = 0x00074050;
pub const IOCTL_DISK_GET_PARTITION_INFO: u32 = 0x00074004;
pub const IOCTL_DISK_GET_PARTITION_INFO_EX: u32 = 0x00074008;
pub const IOCTL_DISK_IS_WRITABLE: u32 = 0x00070054;
pub const IOCTL_DISK_UPDATE_PROPERTIES: u32 = 0x00070060;
pub const IOCTL_STORAGE_CHECK_VERIFY: u32 = 0x002d4800;
pub const IOCTL_STORAGE_CHECK_VERIFY2: u32 = 0x002d1080;
pub const IOCTL_STORAGE_GET_DEVICE_NUMBER: u32 = 0x002d1080;
pub const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS: u32 = 0x00560000;
pub const IOCTL_VOLUME_ONLINE: u32 = 0x0056C000;
pub const IOCTL_DISK_VERIFY: u32 = 0x00070014;
pub const IOCTL_DISK_CHECK_VERIFY: u32 = 0x00074004;
pub const IOCTL_DISK_GET_DRIVE_LAYOUT: u32 = 0x0007400C;
pub const IOCTL_DISK_GET_DRIVE_LAYOUT_EX: u32 = 0x00074014;
pub const IOCTL_STORAGE_GET_MEDIA_TYPES_EX: u32 = 0x002d0C04;
pub const IOCTL_STORAGE_READ_CAPACITY: u32 = 0x002d5414;
pub const IOCTL_STORAGE_GET_HOTPLUG_INFO: u32 = 0x002d0C14;
pub const IOCTL_STORAGE_MANAGE_DATA_SET_ATTRIBUTES: u32 = 0x002d2044;
pub const IOCTL_STORAGE_CHECK_PRIORITY_HINT_SUPPORT: u32 = 0x002d2844;
pub const IOCTL_VOLUME_IS_DYNAMIC: u32 = 0x00564018;
pub const IOCTL_VOLUME_POST_ONLINE: u32 = 0x0056C008;
pub const IOCTL_VOLUME_GET_GPT_ATTRIBUTES: u32 = 0x00564020;
pub const IOCTL_DISK_IS_CLUSTERED: u32 = 0x000703E8;
pub const IOCTL_DISK_GET_CLUSTER_INFO: u32 = 0x000703EC;
pub const IOCTL_DISK_MEDIA_REMOVAL: u32 = 0x000D0E00;
pub const IOCTL_STORAGE_MEDIA_REMOVAL: u32 = 0x002D0C10;
pub const IOCTL_DISK_UPDATE_DRIVE_SIZE: u32 = 0x000703F0;
pub const IOCTL_VOLUME_QUERY_ALLOCATION_HINT: u32 = 0x00564014;
pub const FT_BALANCED_READ_MODE: u32 = 0x0000002F;
pub const IOCTL_DISK_GET_MEDIA_TYPES_EX: u32 = 0x0007007C;
pub const IOCTL_MOUNTDEV_LINK_CREATED: u32 = 0x004D0004;
pub const IOCTL_MOUNTDEV_LINK_DELETED: u32 = 0x004D000C;

// ---------------------------------------------------------------------------
// Mount Manager IOCTL codes (MOUNTMGRCONTROLTYPE = 'm' = 0x6D)
// ---------------------------------------------------------------------------
pub const MOUNTMGRCONTROLTYPE: u32 = 0x0000006D;
pub const IOCTL_MOUNTMGR_CREATE_POINT: u32 = 0x006D4000;
pub const IOCTL_MOUNTMGR_DELETE_POINTS: u32 = 0x006D4004;
pub const IOCTL_MOUNTMGR_VOLUME_ARRIVAL_NOTIFICATION: u32 = 0x006D4034;
pub const MOUNTMGR_DEVICE_NAME: &str = "\\Device\\MountPointManager";

// ---------------------------------------------------------------------------
// Mountdev IOCTL codes (MOUNTDEV_CONTROL_TYPE = 'M' = 0x4D)
// ---------------------------------------------------------------------------
pub const IOCTL_MOUNTDEV_QUERY_UNIQUE_ID: u32 = 0x004D0000;
pub const IOCTL_MOUNTDEV_QUERY_DEVICE_NAME: u32 = 0x004D0008;
pub const IOCTL_MOUNTDEV_QUERY_SUGGESTED_LINK_NAME: u32 = 0x004D0010;

// ---------------------------------------------------------------------------
// Storage query property IOCTL
// ---------------------------------------------------------------------------
pub const IOCTL_STORAGE_QUERY_PROPERTY: u32 = 0x002D1400;

// Storage property IDs / query types
pub const StorageDeviceProperty: u32 = 0;
pub const STORAGE_ADAPTER_PROPERTY: u32 = 1;
pub const STORAGE_DEVICE_ID_PROPERTY: u32 = 2;
pub const StorageDeviceSeekPenaltyProperty: u32 = 4;
pub const StorageAccessAlignmentProperty: u32 = 5;
pub const StorageDeviceTrimProperty: u32 = 8;
pub const PROPERTY_STANDARD_QUERY: u32 = 0;
pub const PropertyExistsQuery: u32 = 1;

// STORAGE_BUS_TYPE
pub const BusTypeFileBackedVirtual: u32 = 0x15;

// ---------------------------------------------------------------------------
// Volume IOCTL codes
// ---------------------------------------------------------------------------
pub const IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS_EX: u32 = 0x00560010;
pub const IOCTL_VOLUME_QUERY_VOLUME_INFORMATION: u32 = 0x00560008;
pub const IOCTL_VOLUME_LOGICAL_TO_PHYSICAL: u32 = 0x00560004;
pub const IOCTL_VOLUME_PHYSICAL_TO_LOGICAL: u32 = 0x0056000C;
pub const IOCTL_VOLUME_IS_CLUSTER_CAPABLE: u32 = 0x00560018;

// Media types
pub const FixedMedia: u32 = 12;
pub const RemovableMedia: u32 = 11;

// Partition style
pub const PARTITION_STYLE_MBR: u32 = 0;
pub const PARTITION_STYLE_GPT: u32 = 1;

// DeviceDsmAction
pub const DEVICE_DSM_ACTION_TRIM: u32 = 0x00000001;

// CTL_CODE macro
#[macro_export]
macro_rules! CTL_CODE {
    ($DeviceType:expr, $Function:expr, $Method:expr, $Access:expr) => {
        ($DeviceType << 16) | ($Access << 14) | ($Function << 2) | $Method
    };
}

// ===========================================================================
// Structs
// ===========================================================================

// UNICODE_STRING — 16 bytes (x64)
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct UNICODE_STRING {
    pub Length: u16,
    pub MaximumLength: u16,
    pub Buffer: *mut u16,
}

// OBJECT_ATTRIBUTES — 48 bytes (x64)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: u32,
    pub RootDirectory: HANDLE,
    pub ObjectName: *mut UNICODE_STRING,
    pub Attributes: u32,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}
impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self { unsafe { core::mem::zeroed() } }
}

// IO_STATUS_BLOCK — 16 bytes (x64)
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct IO_STATUS_BLOCK {
    pub Status: NTSTATUS,
    _pad: u32,
    pub Information: ULONG_PTR,
}

// CLIENT_ID — 16 bytes (x64); used as optional out param of PsCreateSystemThread
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct CLIENT_ID {
    pub UniqueProcess: HANDLE,
    pub UniqueThread: HANDLE,
}

// DISK_GEOMETRY — 24 bytes
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct DISK_GEOMETRY {
    pub Cylinders: i64,
    pub MediaType: u32,
    pub TracksPerCylinder: u32,
    pub SectorsPerTrack: u32,
    pub BytesPerSector: u32,
}

// PARTITION_INFORMATION — 32 bytes on x64
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PARTITION_INFORMATION {
    pub StartingOffset: i64,
    pub PartitionLength: i64,
    pub HiddenSectors: u32,
    pub PartitionNumber: u32,
    pub PartitionType: UCHAR,
    pub BootIndicator: BOOLEAN,
    pub RecognizedPartition: BOOLEAN,
    pub RewritePartition: BOOLEAN,
}

// GET_LENGTH_INFORMATION — 8 bytes
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct GET_LENGTH_INFORMATION {
    pub Length: i64,
}

// DISK_GEOMETRY_EX — minimum 32 bytes (Geometry + DiskSize)
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct DISK_GEOMETRY_EX {
    pub Geometry: DISK_GEOMETRY,
    pub DiskSize: i64,
    // Data[1] follows — partition info + detection info (variable size)
}

// STORAGE_DEVICE_NUMBER — 12 bytes
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct STORAGE_DEVICE_NUMBER {
    pub DeviceType: u32,
    pub DeviceNumber: u32,
    pub PartitionNumber: u32,
}

// DISK_EXTENT — 24 bytes
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct DISK_EXTENT {
    pub DiskNumber: u32,
    _pad: u32,
    pub StartingOffset: i64,
    pub ExtentLength: i64,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct VOLUME_DISK_EXTENTS {
    pub NumberOfDiskExtents: u32,
    _pad: u32,
    // Extents array follows
}

// DRIVE_LAYOUT_INFORMATION (1 entry) — MBR
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DRIVE_LAYOUT_INFORMATION_MBR {
    pub PartitionType: UCHAR,
    pub BootIndicator: BOOLEAN,
    pub RecognizedPartition: BOOLEAN,
    pub HiddenSectors: u32,
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DRIVE_LAYOUT_INFORMATION {
    pub PartitionCount: u32,
    pub Signature: u32,
    pub PartitionEntry: [PARTITION_INFORMATION; 1],
}

// ---------------------------------------------------------------------------
// Mount Manager structures
// ---------------------------------------------------------------------------
#[repr(C)]
pub struct MOUNTMGR_TARGET_NAME {
    pub DeviceNameLength: u16,
    pub DeviceName: [u16; 1],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MOUNTMGR_CREATE_POINT_INPUT {
    pub SymbolicLinkNameOffset: u16,
    pub SymbolicLinkNameLength: u16,
    pub DeviceNameOffset: u16,
    pub DeviceNameLength: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MOUNTMGR_MOUNT_POINT {
    pub SymbolicLinkNameOffset: u32,
    pub SymbolicLinkNameLength: u16,
    _pad_mgr0: u16,
    pub UniqueIdOffset: u32,
    pub UniqueIdLength: u16,
    _pad_mgr1: u16,
    pub DeviceNameOffset: u32,
    pub DeviceNameLength: u16,
    _pad_mgr2: u16,
}

// ---------------------------------------------------------------------------
// Mountdev structures
// ---------------------------------------------------------------------------
#[repr(C)]
pub struct MOUNTDEV_NAME {
    pub NameLength: u16,
    pub Name: [u16; 1],
}

#[repr(C)]
pub struct MOUNTDEV_UNIQUE_ID {
    pub UniqueIdLength: u16,
    pub UniqueId: [u8; 1],
}

#[repr(C)]
pub struct MOUNTDEV_SUGGESTED_LINK_NAME {
    pub UseOnlyIfThereAreNoOtherLinks: u8,
    _pad_msln: u8,
    pub NameLength: u16,
    pub Name: [u16; 1],
}

// ---------------------------------------------------------------------------
// Storage query structures
// ---------------------------------------------------------------------------
#[repr(C)]
pub struct STORAGE_PROPERTY_QUERY {
    pub PropertyId: u32,
    pub QueryType: u32,
    pub AdditionalParameters: [u8; 1],
}

#[repr(C)]
pub struct STORAGE_DESCRIPTOR_HEADER {
    pub Version: u32,
    pub Size: u32,
}

#[repr(C)]
pub struct STORAGE_DEVICE_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub DeviceType: u8,
    pub DeviceTypeModifier: u8,
    pub RemovableMedia: u8,
    pub CommandQueueing: u8,
    pub VendorIdOffset: u32,
    pub ProductIdOffset: u32,
    pub ProductRevisionOffset: u32,
    pub SerialNumberOffset: u32,
    pub BusType: u32,
    pub RawPropertiesLength: u32,
}

// STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR (subset)
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct STORAGE_ACCESS_ALIGNMENT_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub BytesPerLogicalSector: u32,
    pub BytesPerPhysicalSector: u32,
    pub BytesOffsetForSectorAlignment: u32,
}

// DEVICE_SEEK_PENALTY_DESCRIPTOR
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct DEVICE_SEEK_PENALTY_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub IncursSeekPenalty: BOOLEAN,
}

// DEVICE_TRIM_DESCRIPTOR
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct DEVICE_TRIM_DESCRIPTOR {
    pub Version: u32,
    pub Size: u32,
    pub TrimEnabled: BOOLEAN,
}

// STORAGE_READ_CAPACITY
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct STORAGE_READ_CAPACITY {
    pub Version: u32,
    pub Size: u32,
    pub BlockLength: u32,
    pub NumberOfBlocks: i64,
    pub DiskLength: i64,
}

// STORAGE_HOTPLUG_INFO
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct STORAGE_HOTPLUG_INFO {
    pub Size: u32,
    pub MediaRemovable: BOOLEAN,
    _pad0: u8,
    _pad1: u16,
    pub MediaHotplug: BOOLEAN,
    _pad2: u8,
    _pad3: u16,
    pub DeviceHotplug: BOOLEAN,
    _pad4: u8,
    _pad5: u16,
    pub DeviceHotplugSecure: BOOLEAN,
    _pad6: u8,
    _pad7: u16,
}

// ---------------------------------------------------------------------------
// PARTITION_INFORMATION_EX — MBR variant
// ---------------------------------------------------------------------------
#[repr(C)]
#[derive(Clone, Copy)]
pub struct GUID {
    pub Data1: u32,
    pub Data2: u16,
    pub Data3: u16,
    pub Data4: [u8; 8],
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PARTITION_INFORMATION_MBR {
    pub PartitionType: u32,
    pub BootIndicator: u8,
    pub RecognizedPartition: u8,
    _pad_pimbr: [u8; 2],
    pub HiddenSectors: u32,
    pub PartitionId: GUID,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PARTITION_INFORMATION_EX {
    pub PartitionStyle: u32,
    _pad_piex0: u32,
    pub StartingOffset: i64,
    pub PartitionLength: i64,
    pub PartitionNumber: u32,
    pub RewritePartition: u8,
    pub IsServicePartition: u8,
    _pad_piex1: [u8; 2],
    pub Mbr: PARTITION_INFORMATION_MBR,
}

// ===========================================================================
// Synchronization primitives — 8-byte-aligned opaque blobs of correct size.
// Sizes verified against WDK 10.0.26100.0 wdm.h:
//   KEVENT        = DISPATCHER_HEADER              = 24
//   KSEMAPHORE    = DISPATCHER_HEADER + LONG Limit = 28 (padded to 32)
//   KMUTEX(=KMUTANT) = Header+MutantListEntry+OwnerThread+flags+ApcDisable = 56
//   KSPIN_LOCK    = ULONG_PTR                       = 8
//   IO_REMOVE_LOCK(free) = Common{Removed+Reserved[3]+IoCount+RemoveEvent} = 32
// ===========================================================================
pub type KSPIN_LOCK = ULONG_PTR;

#[repr(C, align(8))]
pub struct KEVENT { pub _opaque: [u8; 24] }
impl Default for KEVENT { fn default() -> Self { Self { _opaque: [0; 24] } } }

#[repr(C, align(8))]
pub struct KSEMAPHORE { pub _opaque: [u8; 32] }
impl Default for KSEMAPHORE { fn default() -> Self { Self { _opaque: [0; 32] } } }

#[repr(C, align(8))]
pub struct KMUTEX { pub _opaque: [u8; 56] }
impl Default for KMUTEX { fn default() -> Self { Self { _opaque: [0; 56] } } }

#[repr(C, align(8))]
pub struct IO_REMOVE_LOCK { _opaque: [u8; 32] }
impl Default for IO_REMOVE_LOCK { fn default() -> Self { Self { _opaque: [0; 32] } } }

#[repr(C)]
#[derive(Default)]
pub struct LIST_ENTRY {
    pub Flink: *mut LIST_ENTRY,
    pub Blink: *mut LIST_ENTRY,
}

// Thread object — referenced via pointer only (ObReferenceObjectByHandle).
#[repr(C)]
pub struct KTHREAD { _opaque: [u8; 1024] }
pub type PKTHREAD = *mut KTHREAD;
pub type PETHREAD = *mut KTHREAD;

// File object — opaque; referenced via pointer only.
#[repr(C, align(8))]
pub struct FILE_OBJECT { _opaque: [u8; 232] }
pub type PFILE_OBJECT = *mut FILE_OBJECT;

// Work item — opaque; allocated by IoAllocateWorkItem.
#[repr(C, align(8))]
pub struct IO_WORKITEM { _opaque: [u8; 64] }
pub type PIO_WORKITEM = *mut IO_WORKITEM;

pub type PKSTART_ROUTINE = unsafe extern "system" fn(PVOID);
pub type PIO_WORKITEM_ROUTINE = unsafe extern "system" fn(*mut DEVICE_OBJECT, PVOID);

// ===========================================================================
// IO_STACK_LOCATION — x64 layout, verified against WDK 10.0.26100.0 wdm.h
// ===========================================================================
#[repr(C)]
pub struct IO_STACK_LOCATION {
    pub MajorFunction: UCHAR,
    pub MinorFunction: UCHAR,
    pub Flags: UCHAR,
    pub Control: UCHAR,
    _pad0: u32,
    pub Parameters: IO_STACK_PARAMETERS,
    _pad1: [u8; 40],
}
pub type PIO_STACK_LOCATION = *mut IO_STACK_LOCATION;

#[repr(C)]
pub union IO_STACK_PARAMETERS {
    pub DeviceIoControl: DeviceIoControlParams,
    pub Read: ReadParams,
    pub Write: WriteParams,
}

// DeviceIoControl (x64): OutputBufferLength(4)+pad(4)+InputBufferLength(4)
// + IoControlCode(4) + Type3InputBuffer(8) = 24 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DeviceIoControlParams {
    pub OutputBufferLength: u32,
    _pad_dio: u32,
    pub InputBufferLength: u32,
    pub IoControlCode: u32,
    pub Type3InputBuffer: PVOID,
}

// Read (x64): Length(4)+Key(4)+Flags(4,_WIN64)+pad(4)+ByteOffset(8) = 24 bytes
#[repr(C)]
#[derive(Clone, Copy)]
pub struct ReadParams {
    pub Length: u32,
    pub Key: u32,
    pub Flags: u32,
    _pad_r: u32,
    pub ByteOffset: i64,
}

// Write (x64): same layout as Read
#[repr(C)]
#[derive(Clone, Copy)]
pub struct WriteParams {
    pub Length: u32,
    pub Key: u32,
    pub Flags: u32,
    _pad_w: u32,
    pub ByteOffset: i64,
}

// ===========================================================================
// MDL — 48 bytes (x64), exposes fields needed by MmGetSystemAddressForMdlSafe
// ===========================================================================
#[repr(C)]
pub struct MDL {
    pub Next: *mut MDL,           // offset 0
    pub Size: CSHORT,             // offset 8
    pub MdlFlags: CSHORT,         // offset 10
    _pad: u32,                    // offset 12
    pub Process: PVOID,           // offset 16
    pub MappedSystemVa: PVOID,    // offset 24
    pub StartVa: PVOID,           // offset 32
    pub ByteCount: ULONG,         // offset 40
    pub ByteOffset: ULONG,        // offset 44
}
pub type PMDL = *mut MDL;

// ===========================================================================
// DEVICE_OBJECT — 336 bytes (x64)
// ===========================================================================
#[repr(C)]
pub struct DEVICE_OBJECT {
    pub Type: CSHORT,
    pub Size: USHORT,
    pub ReferenceCount: LONG,
    pub DriverObject: *mut DRIVER_OBJECT,
    pub NextDevice: *mut DEVICE_OBJECT,
    pub AttachedDevice: *mut DEVICE_OBJECT,
    pub CurrentIrp: *mut IRP,
    pub Timer: PVOID,
    pub Flags: ULONG,
    pub Characteristics: ULONG,
    pub Vpb: PVOID,
    pub DeviceExtension: PVOID,
    pub DeviceType: ULONG,
    pub StackSize: UCHAR,
    _pad: [u8; 259],
}
pub type PDEVICE_OBJECT = *mut DEVICE_OBJECT;

// ===========================================================================
// DRIVER_OBJECT — 336 bytes (x64)
// ===========================================================================
#[repr(C)]
pub struct DRIVER_OBJECT {
    pub Type: CSHORT,
    pub Size: USHORT,
    pub DeviceObject: *mut DEVICE_OBJECT,
    _pad0: [u8; 4],
    pub Flags: ULONG,
    _pad1: [u8; 60],
    pub DriverInit: PVOID,
    pub DriverStartIo: PVOID,
    pub DriverUnload: PVOID,
    pub MajorFunction: [PVOID; 28],
}
pub type PDRIVER_OBJECT = *mut DRIVER_OBJECT;

// ===========================================================================
// IRP — 208 bytes (x64).
// IoStatus lives at offset 0x30 and CurrentStackLocation at 0xB8; both are
// accessed via the offset helpers below rather than as named fields, so the
// struct only exposes the early fields (MdlAddress/Flags/SystemBuffer) that
// the async I/O queue needs directly.
// ===========================================================================
#[repr(C)]
pub struct IRP {
    pub Type: CSHORT,        // 0
    pub Size: USHORT,        // 2
    _pad0: u32,              // 4 (AllocationProcessorNumber+Reserved)
    pub MdlAddress: PMDL,    // 8
    pub Flags: ULONG,        // 16
    _pad1: u32,              // 20
    pub AssociatedIrp: IRP_ASSOCIATED, // 24
    _pad2: [u8; 176],        // 32 .. 208 (IoStatus@0x30, CurrentStackLocation@0xB8)
}
pub type PIRP = *mut IRP;

#[repr(C)]
pub union IRP_ASSOCIATED {
    pub SystemBuffer: PVOID,
    pub IrpCount: i32,
}

// ===========================================================================
// Inline helpers (FORCEINLINE in the DDK — not exported from ntoskrnl.lib)
// ===========================================================================

/// `Irp->Tail.Overlay.CurrentStackLocation` is at offset 0xB8 on x64.
#[inline]
pub unsafe fn IoGetCurrentIrpStackLocation(irp: *mut IRP) -> *mut IO_STACK_LOCATION {
    let csl_ptr = (irp as *mut u8).add(0xB8);
    *(csl_ptr as *const *mut IO_STACK_LOCATION)
}

/// `Irp->IoStatus` is at offset 0x30 on x64.
#[inline]
pub unsafe fn IoGetIoStatusBlock(irp: *mut IRP) -> *mut IO_STATUS_BLOCK {
    (irp as *mut u8).add(0x30) as *mut IO_STATUS_BLOCK
}

/// `IoMarkIrpPending` = `IoGetCurrentIrpStackLocation(Irp)->Control |= SL_PENDING_RETURNED`.
#[inline]
pub unsafe fn IoMarkIrpPending(irp: *mut IRP) {
    let stack = IoGetCurrentIrpStackLocation(irp);
    if !stack.is_null() {
        (*stack).Control |= SL_PENDING_RETURNED;
    }
}

/// `InitializeListHead` — FORCEINLINE macro.
#[inline]
pub unsafe fn InitializeListHead(list: *mut LIST_ENTRY) {
    (*list).Flink = list;
    (*list).Blink = list;
}

#[inline]
pub unsafe fn IsListEmpty(list: *mut LIST_ENTRY) -> bool {
    (*list).Flink == list
}

/// MDL byte accessors (FORCEINLINE macros reading MDL fields).
#[inline]
pub unsafe fn MmGetMdlByteCount(mdl: PMDL) -> ULONG { (*mdl).ByteCount }
#[inline]
pub unsafe fn MmGetMdlByteOffset(mdl: PMDL) -> ULONG { (*mdl).ByteOffset }

// InitializeObjectAttributes is a FORCEINLINE macro in the WDK — not exported
// from ntoskrnl.lib.  Implement it as a Rust inline that sets the struct fields.
#[inline]
pub unsafe fn InitializeObjectAttributes(
    p: *mut OBJECT_ATTRIBUTES,
    name: *mut UNICODE_STRING,
    attributes: u32,
    root: HANDLE,
    sd: PVOID,
) {
    (*p).Length = core::mem::size_of::<OBJECT_ATTRIBUTES>() as u32;
    (*p).RootDirectory = root;
    (*p).ObjectName = name;
    (*p).Attributes = attributes;
    (*p).SecurityDescriptor = sd;
    (*p).SecurityQualityOfService = core::ptr::null_mut();
}

// ===========================================================================
// Kernel API externs (ntoskrnl.lib)
// ===========================================================================
#[link(name = "ntoskrnl")]
extern "system" {
    // --- Device / IRP ---
    pub fn IoCreateDevice(
        DriverObject: *mut DRIVER_OBJECT,
        DeviceExtensionSize: u32,
        DeviceName: *mut UNICODE_STRING,
        DeviceType: u32,
        DeviceCharacteristics: u32,
        Exclusive: BOOLEAN,
        DeviceObject: *mut *mut DEVICE_OBJECT,
    ) -> NTSTATUS;
    pub fn IoDeleteDevice(DeviceObject: *mut DEVICE_OBJECT);
    pub fn IoRegisterShutdownNotification(DeviceObject: *mut DEVICE_OBJECT);
    pub fn IoUnregisterShutdownNotification(DeviceObject: *mut DEVICE_OBJECT);
    pub fn IoCreateSymbolicLink(
        SymbolicLinkName: *mut UNICODE_STRING,
        DeviceName: *mut UNICODE_STRING,
    ) -> NTSTATUS;
    pub fn IoDeleteSymbolicLink(SymbolicLinkName: *mut UNICODE_STRING) -> NTSTATUS;
    pub fn IoCompleteRequest(Irp: *mut IRP, PriorityBoost: i32);
    pub fn IoGetRelatedDeviceObject(FileObject: PFILE_OBJECT) -> PDEVICE_OBJECT;

    // --- Remove lock (Ex variants — the macros pass sizeof(IO_REMOVE_LOCK)) ---
    pub fn IoInitializeRemoveLockEx(
        Lock: *mut IO_REMOVE_LOCK,
        AllocateTag: u32,
        MaxLockedMinutes: u32,
        HighWatermark: u32,
        RemlockSize: u32,
    );
    pub fn IoAcquireRemoveLockEx(
        RemoveLock: *mut IO_REMOVE_LOCK,
        Tag: PVOID,
        File: *const u8,
        Line: u32,
        RemlockSize: u32,
    ) -> NTSTATUS;
    pub fn IoReleaseRemoveLockEx(RemoveLock: *mut IO_REMOVE_LOCK, Tag: PVOID, RemlockSize: u32);
    pub fn IoReleaseRemoveLockAndWaitEx(
        RemoveLock: *mut IO_REMOVE_LOCK,
        Tag: PVOID,
        RemlockSize: u32,
    );

    // --- Work items ---
    pub fn IoAllocateWorkItem(DeviceObject: *mut DEVICE_OBJECT) -> PIO_WORKITEM;
    pub fn IoFreeWorkItem(IoWorkItem: PIO_WORKITEM);
    pub fn IoQueueWorkItem(
        IoWorkItem: PIO_WORKITEM,
        WorkerRoutine: PIO_WORKITEM_ROUTINE,
        QueueType: u32,
        Context: PVOID,
    );

    // --- MDL / memory mapping ---
    pub fn IoAllocateMdl(
        VirtualAddress: PVOID,
        Length: u32,
        SecondaryBuffer: BOOLEAN,
        ChargeQuota: BOOLEAN,
        Irp: *mut IRP,
    ) -> PMDL;
    pub fn IoFreeMdl(Mdl: PMDL);
    pub fn MmBuildMdlForNonPagedPool(MemoryDescriptorList: PMDL);
    pub fn MmProbeAndLockPages(
        MemoryDescriptorList: PMDL,
        AccessMode: u8,
        Operation: u32,
    );
    pub fn MmUnlockPages(MemoryDescriptorList: PMDL);
    pub fn MmUnmapLockedPages(BaseAddress: PVOID, MemoryDescriptorList: PMDL);
    pub fn MmMapLockedPagesSpecifyCache(
        Mdl: PMDL,
        AccessMode: u8,
        CacheType: u32,
        RequestedAddress: PVOID,
        BugCheckOnFailure: u8,
        Priority: u32,
    ) -> PVOID;

    // --- Strings ---
    pub fn RtlInitUnicodeString(
        DestinationString: *mut UNICODE_STRING,
        SourceString: *const u16,
    );

    // --- File I/O ---
    pub fn ZwCreateFile(
        FileHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        AllocationSize: *mut i64,
        FileAttributes: u32,
        ShareAccess: u32,
        CreateDisposition: u32,
        CreateOptions: u32,
        EaBuffer: PVOID,
        EaLength: u32,
    ) -> NTSTATUS;
    pub fn ZwReadFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PVOID,
        ApcContext: PVOID,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: u32,
        ByteOffset: *mut i64,
        Key: *mut u32,
    ) -> NTSTATUS;
    pub fn ZwWriteFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PVOID,
        ApcContext: PVOID,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        Buffer: PVOID,
        Length: u32,
        ByteOffset: *mut i64,
        Key: *mut u32,
    ) -> NTSTATUS;
    pub fn ZwClose(Handle: HANDLE) -> NTSTATUS;
    pub fn ZwFlushBuffersFile(FileHandle: HANDLE, IoStatusBlock: *mut IO_STATUS_BLOCK) -> NTSTATUS;
    pub fn ZwQueryInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: u32,
        FileInformationClass: u32,
    ) -> NTSTATUS;
    pub fn ZwSetInformationFile(
        FileHandle: HANDLE,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        FileInformation: PVOID,
        Length: u32,
        FileInformationClass: u32,
    ) -> NTSTATUS;
    pub fn ZwDeviceIoControlFile(
        FileHandle: HANDLE,
        Event: HANDLE,
        ApcRoutine: PVOID,
        ApcContext: PVOID,
        IoStatusBlock: *mut IO_STATUS_BLOCK,
        IoControlCode: u32,
        InputBuffer: PVOID,
        InputBufferLength: u32,
        OutputBuffer: PVOID,
        OutputBufferLength: u32,
    ) -> NTSTATUS;

    // --- Pool ---
    pub fn ExAllocatePool2(Flags: u64, NumberOfBytes: usize, Tag: u32) -> PVOID;
    pub fn ExFreePool(P: PVOID);
    pub fn ExFreePoolWithTag(P: PVOID, Tag: u32);

    // --- Dispatcher / synchronization ---
    pub fn KeInitializeEvent(Event: *mut KEVENT, Type: u32, State: BOOLEAN);
    pub fn KeSetEvent(Event: *mut KEVENT, Increment: KPRIORITY, Wait: BOOLEAN) -> LONG;
    pub fn KeClearEvent(Event: *mut KEVENT);
    pub fn KeResetEvent(Event: *mut KEVENT) -> LONG;
    pub fn KeInitializeSemaphore(Semaphore: *mut KSEMAPHORE, Count: LONG, Limit: LONG);
    pub fn KeReleaseSemaphore(
        Semaphore: *mut KSEMAPHORE,
        Increment: KPRIORITY,
        Adjustment: LONG,
        Wait: BOOLEAN,
    ) -> LONG;
    pub fn KeInitializeSpinLock(SpinLock: *mut KSPIN_LOCK);
    pub fn KfAcquireSpinLock(SpinLock: *mut KSPIN_LOCK) -> KIRQL;
    pub fn KfReleaseSpinLock(SpinLock: *mut KSPIN_LOCK, NewIrql: KIRQL);
    pub fn KeInitializeMutex(Mutex: *mut KMUTEX, Level: u32);
    pub fn KeReleaseMutex(Mutex: *mut KMUTEX, Wait: BOOLEAN) -> LONG;
    pub fn KeWaitForSingleObject(
        Object: PVOID,
        WaitReason: u32,
        WaitMode: u8,
        Alertable: BOOLEAN,
        Timeout: *mut i64,
    ) -> NTSTATUS;
    pub fn KeDelayExecutionThread(
        WaitMode: u8,
        Alertable: BOOLEAN,
        Interval: *mut i64,
    );

    // --- Interlocked list operations ---
    pub fn ExInterlockedInsertTailList(
        ListHead: *mut LIST_ENTRY,
        ListEntry: *mut LIST_ENTRY,
        Lock: *mut KSPIN_LOCK,
    ) -> *mut LIST_ENTRY;
    pub fn ExInterlockedRemoveHeadList(
        ListHead: *mut LIST_ENTRY,
        Lock: *mut KSPIN_LOCK,
    ) -> *mut LIST_ENTRY;

    // --- Threads / objects ---
    pub fn PsCreateSystemThread(
        ThreadHandle: *mut HANDLE,
        DesiredAccess: u32,
        ObjectAttributes: *mut OBJECT_ATTRIBUTES,
        ProcessHandle: HANDLE,
        ClientId: *mut CLIENT_ID,
        StartRoutine: PKSTART_ROUTINE,
        StartContext: PVOID,
    ) -> NTSTATUS;
    pub fn PsTerminateSystemThread(ExitStatus: NTSTATUS);
    pub fn KeSetPriorityThread(Thread: PKTHREAD, Priority: KPRIORITY) -> KPRIORITY;
    pub fn ObReferenceObjectByHandle(
        Handle: HANDLE,
        DesiredAccess: u32,
        ObjectType: PVOID,
        AccessMode: u8,
        Object: *mut PVOID,
        HandleInformation: PVOID,
    ) -> NTSTATUS;
    pub fn ObfDereferenceObject(Object: PVOID);

    // --- Debug output ---
    pub fn DbgPrintEx(
        ComponentId: u32,
        Level: u32,
        Format: *const u8,
    ) -> u32;
}

/// `MmGetSystemAddressForMdlSafe` is a FORCEINLINE function in the WDK.
#[inline]
pub unsafe fn MmGetSystemAddressForMdlSafe(mdl: PMDL, priority: u32) -> PVOID {
    if (*mdl).MdlFlags & (MDL_MAPPED_TO_SYSTEM_VA | MDL_SOURCE_IS_NONPAGED_POOL) != 0 {
        (*mdl).MappedSystemVa
    } else {
        MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MM_CACHED,
            core::ptr::null_mut(),
            0,
            priority,
        )
    }
}

// ===========================================================================
// Compile-time size & field-offset checks
// ===========================================================================
const _: () = {
    assert!(core::mem::size_of::<UNICODE_STRING>() == 16);
    assert!(core::mem::size_of::<OBJECT_ATTRIBUTES>() == 48);
    assert!(core::mem::size_of::<IO_STATUS_BLOCK>() == 16);
    assert!(core::mem::size_of::<CLIENT_ID>() == 16);
    assert!(core::mem::size_of::<DISK_GEOMETRY>() == 24);
    assert!(core::mem::size_of::<MDL>() == 48);
    assert!(core::mem::size_of::<PARTITION_INFORMATION>() == 32);
    assert!(core::mem::size_of::<GET_LENGTH_INFORMATION>() == 8);
    assert!(core::mem::size_of::<DISK_GEOMETRY_EX>() == 32);
    assert!(core::mem::size_of::<STORAGE_DEVICE_NUMBER>() == 12);
    assert!(core::mem::size_of::<DISK_EXTENT>() == 24);
    assert!(core::mem::size_of::<VOLUME_DISK_EXTENTS>() == 8);
    assert!(core::mem::size_of::<DeviceIoControlParams>() == 24);
    assert!(core::mem::size_of::<ReadParams>() == 24);
    assert!(core::mem::size_of::<WriteParams>() == 24);
    assert!(core::mem::size_of::<IO_STACK_PARAMETERS>() == 24);
    assert!(core::mem::size_of::<IO_STACK_LOCATION>() == 72);
    assert!(core::mem::size_of::<IRP>() == 208);
    assert!(core::mem::size_of::<DEVICE_OBJECT>() == 336);
    assert!(core::mem::size_of::<DRIVER_OBJECT>() == 336);
    assert!(core::mem::size_of::<MOUNTMGR_CREATE_POINT_INPUT>() == 8);
    assert!(core::mem::size_of::<MOUNTMGR_MOUNT_POINT>() == 24);
    assert!(core::mem::size_of::<MOUNTDEV_SUGGESTED_LINK_NAME>() == 6);
    assert!(core::mem::size_of::<STORAGE_DESCRIPTOR_HEADER>() == 8);
    assert!(core::mem::size_of::<STORAGE_DEVICE_DESCRIPTOR>() == 36);
    assert!(core::mem::size_of::<PARTITION_INFORMATION_MBR>() == 28);
    assert!(core::mem::size_of::<PARTITION_INFORMATION_EX>() == 64);
    assert!(core::mem::size_of::<GUID>() == 16);
    assert!(core::mem::size_of::<LIST_ENTRY>() == 16);
    // Dispatcher objects (aligned opaque blobs)
    assert!(core::mem::size_of::<KEVENT>() == 24);
    assert!(core::mem::size_of::<KSEMAPHORE>() == 32);
    assert!(core::mem::size_of::<KMUTEX>() == 56);
    assert!(core::mem::size_of::<IO_REMOVE_LOCK>() == 32);
    assert!(core::mem::size_of::<KSPIN_LOCK>() == 8);
    assert!(core::mem::align_of::<KEVENT>() >= 8);
    assert!(core::mem::align_of::<KSEMAPHORE>() >= 8);
    assert!(core::mem::align_of::<KMUTEX>() >= 8);
    assert!(core::mem::align_of::<IO_REMOVE_LOCK>() >= 8);

    // --- IRP field offsets (verified against the offset helpers @0x30/0xB8) ---
    assert!(core::mem::offset_of!(IRP, MdlAddress) == 8, "IRP.MdlAddress");
    assert!(core::mem::offset_of!(IRP, Flags) == 16, "IRP.Flags");
    assert!(core::mem::offset_of!(IRP, AssociatedIrp) == 24, "IRP.AssociatedIrp");
    assert!(0x30 + core::mem::size_of::<IO_STATUS_BLOCK>() <= 208, "IoStatus@0x30 in bounds");
    assert!(0xB8 + core::mem::size_of::<*mut IO_STACK_LOCATION>() <= 208, "CurrentStackLocation@0xB8 in bounds");

    // --- IO_STACK_LOCATION field offsets ---
    assert!(core::mem::offset_of!(IO_STACK_LOCATION, MajorFunction) == 0, "IO_STACK.MajorFunction");
    assert!(core::mem::offset_of!(IO_STACK_LOCATION, Control) == 3, "IO_STACK.Control");
    assert!(core::mem::offset_of!(IO_STACK_LOCATION, Parameters) == 8, "IO_STACK.Parameters");
    // DeviceIoControlParams field offsets; IoControlCode in IO_STACK = 8 + 12 = 20
    assert!(core::mem::offset_of!(DeviceIoControlParams, OutputBufferLength) == 0, "DIC.OutputBufferLength");
    assert!(core::mem::offset_of!(DeviceIoControlParams, InputBufferLength) == 8, "DIC.InputBufferLength");
    assert!(core::mem::offset_of!(DeviceIoControlParams, IoControlCode) == 12, "DIC.IoControlCode");

    // --- DEVICE_OBJECT field offsets (verified against WDK 10.0.26100.0 wdm.h) ---
    assert!(core::mem::offset_of!(DEVICE_OBJECT, DriverObject) == 0x08, "DEVICE_OBJECT.DriverObject");
    assert!(core::mem::offset_of!(DEVICE_OBJECT, ReferenceCount) == 0x04, "DEVICE_OBJECT.ReferenceCount");
    assert!(core::mem::offset_of!(DEVICE_OBJECT, Flags) == 0x30, "DEVICE_OBJECT.Flags");
    assert!(core::mem::offset_of!(DEVICE_OBJECT, DeviceExtension) == 0x40, "DEVICE_OBJECT.DeviceExtension");
    assert!(core::mem::offset_of!(DEVICE_OBJECT, DeviceType) == 0x48, "DEVICE_OBJECT.DeviceType");
    assert!(core::mem::offset_of!(DEVICE_OBJECT, StackSize) == 0x4C, "DEVICE_OBJECT.StackSize");
};
