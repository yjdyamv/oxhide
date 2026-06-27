//! Shared device-name builders (`\Device\OxhideVolumeX`, `\DosDevices\X:`).
//!
//! Replaces the three duplicated copies of these helpers that previously lived
//! in `volume.rs`, `volume_ioctl.rs`, and `mount_mgr.rs`.  Corresponds to
//! VeraCrypt `TCGetNTNameFromNumber` / `TCGetDosNameFromNumber`.

/// Length in `u16` units excluding the trailing NUL.
pub fn wcslen(s: &[u16]) -> usize {
    s.iter().position(|&c| c == 0).unwrap_or(s.len())
}

/// Build `\Device\OxhideVolumeX` (NUL-terminated) for drive number 0..25.
pub fn volume_nt_name(drive_no: usize) -> [u16; 32] {
    let base = b"\\Device\\OxhideVolume";
    let mut buf = [0u16; 32];
    for (i, &b) in base.iter().enumerate() {
        buf[i] = b as u16;
    }
    buf[base.len()] = b'A' as u16 + drive_no as u16;
    buf
}

/// Build `\DosDevices\X:` (NUL-terminated) for drive number 0..25.
pub fn volume_dos_name(drive_no: usize) -> [u16; 16] {
    let base = b"\\DosDevices\\";
    let mut buf = [0u16; 16];
    for (i, &b) in base.iter().enumerate() {
        buf[i] = b as u16;
    }
    let off = base.len();
    buf[off] = b'A' as u16 + drive_no as u16;
    buf[off + 1] = b':' as u16;
    buf
}

/// Build `\GLOBAL??\X:` (NUL-terminated) — the global namespace alias used by
/// `IsDriveLetterAvailable` checks.
pub fn volume_global_dos_name(drive_no: usize) -> [u16; 16] {
    let base = b"\\GLOBAL??\\";
    let mut buf = [0u16; 16];
    for (i, &b) in base.iter().enumerate() {
        buf[i] = b as u16;
    }
    let off = base.len();
    buf[off] = b'A' as u16 + drive_no as u16;
    buf[off + 1] = b':' as u16;
    buf
}
