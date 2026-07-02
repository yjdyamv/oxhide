//! Virtual disk geometry computation.
//!
//! Extracted from `vcrypt-driver/src/crypto.rs` to be testable without WDK.

/// Compute the virtual disk geometry following VeraCrypt's convention.
///
/// VeraCrypt uses a trivial geometry:
/// - 1 track per cylinder
/// - 1 sector per track
/// - `NumberOfCylinders = total_sectors` (i.e. `DiskLength / BytesPerSector`)
///
/// All values assume 512-byte sector alignment.
///
/// Returns `(cylinders, tracks_per_cylinder, sectors_per_track)`.
pub fn compute_virtual_geometry(disk_length: u64, bytes_per_sector: u32) -> (u64, u32, u32) {
    let sector_count = disk_length / bytes_per_sector as u64;
    let cylinders = sector_count.max(1);
    (cylinders, 1, 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_standard_volume() {
        // 100 MB = 104,857,600 bytes → 204,800 sectors → 204,800 cylinders
        let (cylinders, tracks, spt) = compute_virtual_geometry(104_857_600, 512);
        assert_eq!(cylinders, 204_800);
        assert_eq!(tracks, 1);
        assert_eq!(spt, 1);
    }

    #[test]
    fn test_min_volume() {
        // Minimum VeraCrypt volume: 256 KB = 262,144 bytes → 512 sectors
        let (cylinders, tracks, spt) = compute_virtual_geometry(262_144, 512);
        assert_eq!(cylinders, 512);
        assert_eq!(tracks, 1);
        assert_eq!(spt, 1);
    }

    #[test]
    fn test_small_volume_clamped() {
        // Volume smaller than one sector → clamped to 1 cylinder
        let (cylinders, tracks, spt) = compute_virtual_geometry(256, 512);
        assert_eq!(cylinders, 1);
        assert_eq!(tracks, 1);
        assert_eq!(spt, 1);
    }

    #[test]
    fn test_large_volume() {
        // 1 TB = 1,099,511,627,776 bytes → 2^31 sectors
        let (cylinders, tracks, spt) = compute_virtual_geometry(1_099_511_627_776, 512);
        assert_eq!(cylinders, 2_147_483_648);
        assert_eq!(tracks, 1);
        assert_eq!(spt, 1);
    }

    #[test]
    fn test_non_512_sector_size() {
        let (cylinders, tracks, spt) = compute_virtual_geometry(4_194_304, 4096);
        assert_eq!(cylinders, 1024);
        assert_eq!(tracks, 1);
        assert_eq!(spt, 1);
    }
}
