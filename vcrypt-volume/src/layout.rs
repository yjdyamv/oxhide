//! Volume header layouts — V2 Normal, V1 Legacy, V2 Hidden

use vcrypt_format::header::VOLUME_HEADER_SIZE;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeType {
    Normal,
    Hidden,
}

#[derive(Debug, Clone, Copy)]
pub struct HeaderLayout {
    pub header_offset: u64,
    pub backup_offset: Option<u64>,
    pub read_size: usize,
    pub name: &'static str,
    pub volume_type: VolumeType,
}

impl HeaderLayout {
    pub fn v2_normal(file_size: u64) -> Self {
        Self {
            header_offset: 0,
            backup_offset: Some(file_size.saturating_sub(2 * VOLUME_HEADER_SIZE as u64)),
            read_size: VOLUME_HEADER_SIZE,
            name: "V2 Normal",
            volume_type: VolumeType::Normal,
        }
    }

    pub fn v1_legacy() -> Self {
        Self {
            header_offset: 0,
            backup_offset: None,
            read_size: 512,
            name: "V1 Legacy",
            volume_type: VolumeType::Normal,
        }
    }

    pub fn v2_hidden(file_size: u64) -> Self {
        Self {
            header_offset: VOLUME_HEADER_SIZE as u64,
            backup_offset: Some(file_size.saturating_sub(VOLUME_HEADER_SIZE as u64)),
            read_size: VOLUME_HEADER_SIZE,
            name: "V2 Hidden",
            volume_type: VolumeType::Hidden,
        }
    }

    pub fn candidates(file_size: u64) -> Vec<Self> {
        vec![
            Self::v2_normal(file_size),
            Self::v1_legacy(),
            Self::v2_hidden(file_size),
        ]
    }
}
