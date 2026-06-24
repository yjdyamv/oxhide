use super::error::{VolResult, VolumeError};
use super::io::SectorCipher;
use vcrypt_core::ciphers::{
    AesCipher, BlockCipher, CamelliaCipher, CascadeMode, CipherType, KuznyechikCipher,
    SerpentCipher, TwofishCipher,
};
use vcrypt_core::xts::XtsMode;

struct SingleSectorXts<C: BlockCipher> {
    xts: XtsMode<C>,
}

impl<C: BlockCipher + 'static> SectorCipher for SingleSectorXts<C> {
    fn encrypt_sector(&self, sector: u64, data: &mut [u8]) -> VolResult<()> {
        self.xts
            .encrypt(sector, data)
            .map_err(|e| VolumeError::CryptoError(format!("XTS encrypt: {}", e)))
    }

    fn decrypt_sector(&self, sector: u64, data: &mut [u8]) -> VolResult<()> {
        self.xts
            .decrypt(sector, data)
            .map_err(|e| VolumeError::CryptoError(format!("XTS decrypt: {}", e)))
    }
}

struct CascadeSectorCipher {
    passes: Vec<Box<dyn SectorCipher>>,
}

impl SectorCipher for CascadeSectorCipher {
    fn encrypt_sector(&self, sector: u64, data: &mut [u8]) -> VolResult<()> {
        for pass in &self.passes {
            pass.encrypt_sector(sector, data)?;
        }
        Ok(())
    }

    fn decrypt_sector(&self, sector: u64, data: &mut [u8]) -> VolResult<()> {
        for pass in self.passes.iter().rev() {
            pass.decrypt_sector(sector, data)?;
        }
        Ok(())
    }
}

pub fn create_sector_cipher(cipher: CipherType, key: &[u8]) -> VolResult<Box<dyn SectorCipher>> {
    match cipher {
        CipherType::Aes => single_xts::<AesCipher>(key, AesCipher::new),
        CipherType::Serpent => single_xts::<SerpentCipher>(key, SerpentCipher::new),
        CipherType::Twofish => single_xts::<TwofishCipher>(key, TwofishCipher::new),
        CipherType::Camellia => single_xts::<CamelliaCipher>(key, CamelliaCipher::new),
        CipherType::Kuznyechik => single_xts::<KuznyechikCipher>(key, KuznyechikCipher::new),
        cipher => {
            let mode = match cipher {
                CipherType::AesTwofish => CascadeMode::AesTwofish,
                CipherType::AesTwofishSerpent => CascadeMode::AesTwofishSerpent,
                CipherType::SerpentAes => CascadeMode::SerpentAes,
                CipherType::SerpentTwofishAes => CascadeMode::SerpentTwofishAes,
                CipherType::TwofishSerpent => CascadeMode::TwofishSerpent,
                _ => return Err(VolumeError::Unsupported(format!("unknown cipher"))),
            };
            let passes = build_cascade_passes(mode, key)?;
            Ok(Box::new(CascadeSectorCipher { passes }))
        }
    }
}

fn single_xts<C: BlockCipher + 'static>(
    key: &[u8],
    ctor: fn(&[u8]) -> vcrypt_core::Result<C>,
) -> VolResult<Box<dyn SectorCipher>> {
    let xts = XtsMode::new(key, ctor)
        .map_err(|e| VolumeError::CryptoError(format!("XTS: {}", e)))?;
    Ok(Box::new(SingleSectorXts { xts }))
}

fn build_cascade_passes(
    mode: CascadeMode,
    key: &[u8],
) -> VolResult<Vec<Box<dyn SectorCipher>>> {
    let single_key_len = mode.key_size();
    if key.len() != single_key_len * 2 {
        return Err(VolumeError::CryptoError(format!(
            "Bad key size for {}: expected {}, got {}",
            mode.name(),
            single_key_len * 2,
            key.len()
        )));
    }

    let data_half = &key[..single_key_len];
    let tweak_half = &key[single_key_len..];
    let order = mode.veracrypt_order();

    let mut passes = Vec::new();
    for (ct, offset) in &order {
        let combined: Vec<u8> = data_half[*offset..*offset + 32]
            .iter()
            .chain(&tweak_half[*offset..*offset + 32])
            .copied()
            .collect();
        let pass = single_pass_xts(*ct, &combined)?;
        passes.push(pass);
    }
    Ok(passes)
}

fn single_pass_xts(ct: CipherType, key: &[u8]) -> VolResult<Box<dyn SectorCipher>> {
    match ct {
        CipherType::Aes => single_xts::<AesCipher>(key, AesCipher::new),
        CipherType::Serpent => single_xts::<SerpentCipher>(key, SerpentCipher::new),
        CipherType::Twofish => single_xts::<TwofishCipher>(key, TwofishCipher::new),
        CipherType::Camellia => single_xts::<CamelliaCipher>(key, CamelliaCipher::new),
        CipherType::Kuznyechik => single_xts::<KuznyechikCipher>(key, KuznyechikCipher::new),
        _ => Err(VolumeError::Unsupported(format!(
            "cascade pass must be single cipher, got {}",
            ct.name()
        ))),
    }
}
