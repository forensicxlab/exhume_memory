use std::collections::HashSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use memflow::mem::phys_mem::PhysicalMemory;
use memflow::prelude::v1::*;
use rayon::prelude::*;
use serde::{Serialize, Serializer, ser::SerializeStruct};

use crate::cli::ConnectorKind;
use crate::connector::{Connector, ConnectorOptions, resolve_physical_end};

const TAGS: &[&[u8]] = &[b"Fve ", b"CNGb", b"dFVE"];
const SIGNATURES: &[&[u8]] = &[&[
    0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x04, 0x80, 0x00, 0x00,
]];

#[derive(Debug, Clone)]
pub struct BitlockerScanRequest {
    pub start: Option<u64>,
    pub end: Option<u64>,
    pub chunk_size: usize,
}

pub type BitlockerProgressCallback =
    Arc<dyn Fn(crate::api::MemoryProgressUpdate) + Send + Sync + 'static>;
pub type BitlockerHitCallback = Arc<dyn Fn(BitlockerHit) + Send + Sync + 'static>;

#[derive(Clone, Default)]
pub struct BitlockerScanCallbacks {
    pub on_progress: Option<BitlockerProgressCallback>,
    pub on_hit: Option<BitlockerHitCallback>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BitlockerScanReport {
    pub scan_start: u64,
    pub scan_end: u64,
    pub chunk_size: usize,
    pub chunk_count: u64,
    pub hits: Vec<BitlockerHit>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BitlockerHit {
    pub address: u64,
    pub tag: String,
    pub material: FveMaterial,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MaterialType {
    AesCbc128,
    AesCbc256,
    AesXts128,
    AesXts256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FveMaterial {
    pub material_type: MaterialType,
    pub fvek: Vec<u8>,
    pub tweak: Option<Vec<u8>>,
}

impl Serialize for FveMaterial {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("FveMaterial", 4)?;
        state.serialize_field("material_type", &self.material_type)?;
        state.serialize_field("fvek", &hex::encode(&self.fvek))?;
        state.serialize_field("tweak", &self.tweak.as_ref().map(hex::encode))?;
        state.serialize_field("full", &self.render_full_key_hex())?;
        state.end()
    }
}

pub fn scan_bitlocker(
    connector_options: &ConnectorOptions,
    request: &BitlockerScanRequest,
) -> Result<BitlockerScanReport> {
    scan_bitlocker_with_callbacks(
        connector_options,
        request,
        &BitlockerScanCallbacks::default(),
    )
}

pub fn scan_bitlocker_with_callbacks(
    connector_options: &ConnectorOptions,
    request: &BitlockerScanRequest,
    callbacks: &BitlockerScanCallbacks,
) -> Result<BitlockerScanReport> {
    if request.chunk_size == 0 {
        anyhow::bail!("chunk_size must be > 0");
    }

    let connector = connector_options.open()?;
    let start = request.start.unwrap_or(0);
    let end = resolve_physical_end(connector.clone(), request.end)?;

    if end <= start {
        anyhow::bail!("invalid scan range: end must be greater than start");
    }

    let chunk_count = (end - start).div_ceil(request.chunk_size as u64);
    log::info!(
        "bitlocker scan starting: range={start:#x}..{end:#x} chunk_size={:#x} chunks={chunk_count}",
        request.chunk_size
    );

    let mut hits = match connector_options.kind {
        ConnectorKind::Pcileech => {
            scan_sequential(connector, start, chunk_count, request.chunk_size, callbacks)
        }
        ConnectorKind::Rawmem => scan_parallel(
            connector_options,
            start,
            chunk_count,
            request.chunk_size,
            callbacks,
        )?,
    };

    hits.sort_by_key(|hit| hit.address);

    Ok(BitlockerScanReport {
        scan_start: start,
        scan_end: end,
        chunk_size: request.chunk_size,
        chunk_count,
        hits,
    })
}

fn scan_sequential(
    mut connector: Connector,
    start: u64,
    chunk_count: u64,
    chunk_size: usize,
    callbacks: &BitlockerScanCallbacks,
) -> Vec<BitlockerHit> {
    let mut hits = Vec::new();

    for i in 0..chunk_count {
        let chunk_base = start + i * chunk_size as u64;
        let mut buf = vec![0u8; chunk_size + 1024];
        if connector
            .phys_view()
            .read_raw_into(Address::from(chunk_base), &mut buf)
            .is_ok()
        {
            let chunk_hits = collect_hits(&buf, chunk_base);
            emit_hits(callbacks, &chunk_hits);
            hits.extend(chunk_hits);
        }

        let scanned = i + 1;
        maybe_emit_progress(callbacks, scanned, chunk_count);
        if scanned == 1 || scanned % 256 == 0 || scanned == chunk_count {
            log::info!("bitlocker scan progress: {scanned}/{chunk_count} chunks");
        }
    }

    hits
}

fn scan_parallel(
    connector_options: &ConnectorOptions,
    start: u64,
    chunk_count: u64,
    chunk_size: usize,
    callbacks: &BitlockerScanCallbacks,
) -> Result<Vec<BitlockerHit>> {
    let progress = AtomicU64::new(0);
    let callbacks = callbacks.clone();
    let per_chunk = (0..chunk_count)
        .into_par_iter()
        .map(|i| {
            let result = scan_chunk(
                connector_options,
                start + i * chunk_size as u64,
                chunk_size,
                &callbacks,
            );
            let scanned = progress.fetch_add(1, Ordering::Relaxed) + 1;
            maybe_emit_progress(&callbacks, scanned, chunk_count);
            if scanned == 1 || scanned % 256 == 0 || scanned == chunk_count {
                log::info!("bitlocker scan progress: {scanned}/{chunk_count} chunks");
            }
            result
        })
        .collect::<Vec<_>>();

    let mut hits = Vec::new();
    for chunk_hits in per_chunk {
        hits.extend(chunk_hits?);
    }

    Ok(hits)
}

fn scan_chunk(
    connector_options: &ConnectorOptions,
    chunk_base: u64,
    chunk_size: usize,
    callbacks: &BitlockerScanCallbacks,
) -> Result<Vec<BitlockerHit>> {
    let mut connector = connector_options.open()?;
    let mut buf = vec![0u8; chunk_size + 1024];

    if connector
        .phys_view()
        .read_raw_into(Address::from(chunk_base), &mut buf)
        .is_ok()
    {
        let hits = collect_hits(&buf, chunk_base);
        emit_hits(callbacks, &hits);
        return Ok(hits);
    }

    Ok(Vec::new())
}

fn collect_hits(buf: &[u8], base_addr: u64) -> Vec<BitlockerHit> {
    let mut hits = Vec::new();
    scan_buffer(buf, base_addr, |address, tag, material| {
        hits.push(BitlockerHit {
            address,
            tag: String::from_utf8_lossy(tag).into_owned(),
            material: material.clone(),
        });
    });
    hits
}

fn emit_hits(callbacks: &BitlockerScanCallbacks, hits: &[BitlockerHit]) {
    if let Some(callback) = &callbacks.on_hit {
        for hit in hits {
            callback(hit.clone());
        }
    }
}

fn maybe_emit_progress(callbacks: &BitlockerScanCallbacks, current: u64, total: u64) {
    if current != 1 && current != total && current % 32 != 0 {
        return;
    }

    if let Some(callback) = &callbacks.on_progress {
        callback(crate::api::MemoryProgressUpdate {
            current,
            total,
            message: format!("scanned {current}/{total} chunks"),
        });
    }
}

fn scan_buffer<F>(buf: &[u8], base_addr: u64, mut on_match: F)
where
    F: FnMut(u64, &[u8], &FveMaterial),
{
    for j in 0..buf.len().saturating_sub(128) {
        for tag in TAGS {
            if buf[j..].starts_with(*tag) {
                if let Some(material) =
                    FveMaterial::parse_from_tag(std::str::from_utf8(tag).unwrap(), &buf[j..])
                {
                    on_match(base_addr + j as u64, tag, &material);
                }
            }
        }

        for sig in SIGNATURES {
            if buf[j..].starts_with(*sig) {
                if let Some(material) = FveMaterial::parse_from_signature(sig, &buf[j..]) {
                    on_match(base_addr + j as u64, b"SIG ", &material);
                }
            }
        }
    }
}

impl FveMaterial {
    pub fn parse_from_tag(tag: &str, data: &[u8]) -> Option<Self> {
        match tag {
            "Fve " | "CNGb" | "dFVE" => Self::from_bytes(data),
            _ => None,
        }
    }

    pub fn parse_from_signature(sig: &[u8], data: &[u8]) -> Option<Self> {
        if sig.starts_with(&[0x2c, 0x00, 0x00, 0x00]) {
            if data.len() < 44 {
                return None;
            }

            let fvek = data[12..44].to_vec();
            if !Self::validate_key(&fvek) {
                return None;
            }

            return Some(Self {
                material_type: MaterialType::AesXts128,
                fvek: fvek[0..16].to_vec(),
                tweak: Some(fvek[16..32].to_vec()),
            });
        }

        if sig == b"MSSK" {
            return None;
        }

        None
    }

    pub fn render_full_key_hex(&self) -> String {
        let fvek_hex = hex::encode(&self.fvek);
        if let Some(tweak) = &self.tweak {
            format!("{fvek_hex}{}", hex::encode(tweak))
        } else {
            fvek_hex
        }
    }

    fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 0x50 {
            return None;
        }

        let version = u32::from_le_bytes(data[8..12].try_into().ok()?);

        let (m_type, fvek_off, tweak_off) = match version {
            0x20000 | 0x20001 => (MaterialType::AesXts256, 0x30, Some(0x50)),
            0x10000 | 0x10001 => (MaterialType::AesXts128, 0x30, Some(0x40)),
            0x1000 => (MaterialType::AesCbc128, 0x24, None),
            0x2000 => (MaterialType::AesCbc256, 0x24, None),
            _ => return None,
        };

        let fvek_len = match m_type {
            MaterialType::AesXts256 | MaterialType::AesCbc256 => 32,
            MaterialType::AesXts128 | MaterialType::AesCbc128 => 16,
        };

        if data.len() < fvek_off + fvek_len {
            return None;
        }

        let fvek = data[fvek_off..fvek_off + fvek_len].to_vec();
        if !Self::validate_key(&fvek) {
            return None;
        }

        let tweak = tweak_off.and_then(|off| {
            if data.len() >= off + fvek_len {
                let candidate = data[off..off + fvek_len].to_vec();
                if Self::validate_key(&candidate) {
                    Some(candidate)
                } else {
                    None
                }
            } else {
                None
            }
        });

        Some(Self {
            material_type: m_type,
            fvek,
            tweak,
        })
    }

    fn validate_key(key: &[u8]) -> bool {
        if key.iter().all(|&b| b == 0) {
            return false;
        }

        let mut repeats = 0;
        for i in 0..key.len().saturating_sub(1) {
            if key[i] == key[i + 1] {
                repeats += 1;
            }
        }
        if repeats > key.len() / 2 {
            return false;
        }

        let unique = key.iter().copied().collect::<HashSet<_>>();
        unique.len() >= 4
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_aes_xts_256() {
        let mut data = vec![0u8; 0x80];
        data[0..4].copy_from_slice(b"Fve ");
        data[8..12].copy_from_slice(&0x20000u32.to_le_bytes());

        let fvek: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(7).wrapping_add(0x11));
        data[0x30..0x50].copy_from_slice(&fvek);

        let tweak: [u8; 32] = std::array::from_fn(|i| (i as u8).wrapping_mul(5).wrapping_add(0x22));
        data[0x50..0x70].copy_from_slice(&tweak);

        let material = FveMaterial::from_bytes(&data).expect("should parse");
        assert_eq!(material.material_type, MaterialType::AesXts256);
        assert_eq!(material.fvek, fvek);
        assert_eq!(material.tweak.unwrap(), tweak);
    }

    #[test]
    fn test_parse_aes_cbc_128() {
        let mut data = vec![0u8; 0x60];
        data[0..4].copy_from_slice(b"Fve ");
        data[8..12].copy_from_slice(&0x1000u32.to_le_bytes());

        let fvek: [u8; 16] = std::array::from_fn(|i| (i as u8).wrapping_mul(9).wrapping_add(0x33));
        data[0x24..0x24 + 16].copy_from_slice(&fvek);

        let material = FveMaterial::from_bytes(&data).expect("should parse");
        assert_eq!(material.material_type, MaterialType::AesCbc128);
        assert_eq!(material.fvek, fvek);
        assert!(material.tweak.is_none());
    }

    #[test]
    fn test_null_key_rejected() {
        let mut data = vec![0u8; 0x80];
        data[0..4].copy_from_slice(b"Fve ");
        data[8..12].copy_from_slice(&0x20000u32.to_le_bytes());

        let material = FveMaterial::from_bytes(&data);
        assert!(material.is_none(), "should reject all-zero keys");
    }
}
