//! Block-backed snapshot store for durable filesystem images.
//!
//! This is intentionally below the executive writable-overlay policy: it persists an opaque snapshot
//! byte string to a fixed block range using two commit slots. Payload sectors are written first and
//! the header sector is written last, so a failed/torn update leaves either the previous slot valid
//! or no new slot visible.

use alloc::vec::Vec;

const STORE_MAGIC: [u8; 8] = *b"USNTSNP\0";
const STORE_VERSION: u16 = 1;
const HEADER_LEN: usize = 48;

/// Errors reported by the snapshot block store.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SnapshotBlockStoreError {
    InvalidGeometry,
    OutOfSpace,
    Io,
    Corrupt,
    OutOfMemory,
}

/// Minimal sector I/O contract required by [`SnapshotBlockStore`].
pub trait SnapshotBlockDevice {
    fn sector_size(&self) -> usize;
    fn sector_count(&self) -> u64;
    fn read_sector(&mut self, lba: u64, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError>;
    fn write_sector(&mut self, lba: u64, data: &[u8]) -> Result<(), SnapshotBlockStoreError>;
}

/// A two-slot commit area over a fixed block range.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SnapshotBlockStore {
    start_lba: u64,
    sector_count: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StoredSnapshot {
    pub generation: u64,
    pub payload: Vec<u8>,
}

#[derive(Copy, Clone)]
struct SlotHeader {
    slot: u32,
    generation: u64,
    payload_len: u64,
    payload_crc: u32,
    payload_sectors: u32,
}

#[derive(Clone)]
struct SlotSnapshot {
    slot: u32,
    generation: u64,
    payload: Vec<u8>,
}

impl SnapshotBlockStore {
    pub fn new(start_lba: u64, sector_count: u64) -> Self {
        Self {
            start_lba,
            sector_count,
        }
    }

    pub fn payload_capacity<D: SnapshotBlockDevice>(
        &self,
        dev: &D,
    ) -> Result<usize, SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let payload_sectors = slot_sectors
            .checked_sub(1)
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        usize::try_from(payload_sectors)
            .ok()
            .and_then(|sectors| sectors.checked_mul(sector_size))
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)
    }

    pub fn read_latest<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<StoredSnapshot>, SnapshotBlockStoreError> {
        let slot0 = self.read_slot(dev, 0);
        let slot1 = self.read_slot(dev, 1);
        match (slot0, slot1) {
            (Ok(Some(a)), Ok(Some(b))) => {
                let latest = if b.generation > a.generation { b } else { a };
                Ok(Some(StoredSnapshot {
                    generation: latest.generation,
                    payload: latest.payload,
                }))
            }
            (Ok(Some(a)), _) => Ok(Some(StoredSnapshot {
                generation: a.generation,
                payload: a.payload,
            })),
            (_, Ok(Some(b))) => Ok(Some(StoredSnapshot {
                generation: b.generation,
                payload: b.payload,
            })),
            (Ok(None), Ok(None)) => Ok(None),
            (Err(err), Ok(None)) | (Ok(None), Err(err)) => Err(err),
            (Err(_), Err(_)) => Err(SnapshotBlockStoreError::Corrupt),
        }
    }

    /// Commit a new payload to the alternate slot and return its generation.
    pub fn commit_next<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        payload: &[u8],
    ) -> Result<u64, SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        if payload.len() > self.payload_capacity(dev)? {
            return Err(SnapshotBlockStoreError::OutOfSpace);
        }
        let latest = match (self.read_slot(dev, 0), self.read_slot(dev, 1)) {
            (Ok(a), Ok(b)) => match (a, b) {
                (Some(a), Some(b)) => Some(if b.generation > a.generation { b } else { a }),
                (Some(a), None) => Some(a),
                (None, Some(b)) => Some(b),
                (None, None) => None,
            },
            (Ok(Some(a)), _) => Some(a),
            (_, Ok(Some(b))) => Some(b),
            (Ok(None), _) | (_, Ok(None)) => None,
            (Err(_), Err(_)) => None,
        };
        let (target_slot, generation) = match latest {
            Some(latest) => (1 - latest.slot, latest.generation.saturating_add(1)),
            None => (0, 1),
        };
        let payload_sectors = payload.len().div_ceil(sector_size);
        let payload_sectors_u32 =
            u32::try_from(payload_sectors).map_err(|_| SnapshotBlockStoreError::OutOfSpace)?;
        if payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::OutOfSpace);
        }

        let slot_base = self.slot_lba(slot_sectors, target_slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(sector_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(sector_size, 0);
        for index in 0..payload_sectors {
            sector.fill(0);
            let start = index * sector_size;
            let end = (start + sector_size).min(payload.len());
            sector[..end - start].copy_from_slice(&payload[start..end]);
            dev.write_sector(slot_base + 1 + index as u64, &sector)?;
        }

        sector.fill(0);
        encode_header(
            &mut sector,
            SlotHeader {
                slot: target_slot,
                generation,
                payload_len: payload.len() as u64,
                payload_crc: crc32c(payload),
                payload_sectors: payload_sectors_u32,
            },
        );
        dev.write_sector(slot_base, &sector)?;
        Ok(generation)
    }

    fn geometry<D: SnapshotBlockDevice>(
        &self,
        dev: &D,
    ) -> Result<(usize, u64), SnapshotBlockStoreError> {
        let sector_size = dev.sector_size();
        if sector_size < HEADER_LEN || self.sector_count < 4 || self.sector_count % 2 != 0 {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        if self
            .start_lba
            .checked_add(self.sector_count)
            .is_none_or(|end| end > dev.sector_count())
        {
            return Err(SnapshotBlockStoreError::InvalidGeometry);
        }
        Ok((sector_size, self.sector_count / 2))
    }

    fn slot_lba(&self, slot_sectors: u64, slot: u32) -> Result<u64, SnapshotBlockStoreError> {
        if slot > 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        self.start_lba
            .checked_add(slot_sectors.saturating_mul(slot as u64))
            .ok_or(SnapshotBlockStoreError::InvalidGeometry)
    }

    fn read_slot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotSnapshot>, SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let slot_base = self.slot_lba(slot_sectors, slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(sector_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(sector_size, 0);
        dev.read_sector(slot_base, &mut sector)?;
        let Some(header) = decode_header(&sector)? else {
            return Ok(None);
        };
        if header.slot != slot || header.payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let payload_len =
            usize::try_from(header.payload_len).map_err(|_| SnapshotBlockStoreError::Corrupt)?;
        let payload_capacity = usize::try_from(header.payload_sectors)
            .ok()
            .and_then(|sectors| sectors.checked_mul(sector_size))
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        if payload_len > payload_capacity {
            return Err(SnapshotBlockStoreError::Corrupt);
        }

        let mut payload = Vec::new();
        payload
            .try_reserve_exact(payload_len)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        let mut remaining = payload_len;
        for index in 0..header.payload_sectors {
            sector.fill(0);
            dev.read_sector(slot_base + 1 + index as u64, &mut sector)?;
            let copy = remaining.min(sector_size);
            payload.extend_from_slice(&sector[..copy]);
            remaining -= copy;
        }
        if crc32c(&payload) != header.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(Some(SlotSnapshot {
            slot,
            generation: header.generation,
            payload,
        }))
    }
}

fn encode_header(out: &mut [u8], header: SlotHeader) {
    out[..HEADER_LEN].fill(0);
    out[0..8].copy_from_slice(&STORE_MAGIC);
    put_u16(&mut out[8..10], HEADER_LEN as u16);
    put_u16(&mut out[10..12], STORE_VERSION);
    put_u32(&mut out[12..16], 0);
    put_u64(&mut out[16..24], header.generation);
    put_u64(&mut out[24..32], header.payload_len);
    put_u32(&mut out[32..36], header.payload_crc);
    put_u32(&mut out[36..40], header.payload_sectors);
    put_u32(&mut out[40..44], header.slot);
    let crc = crc32c(&out[..HEADER_LEN - 4]);
    put_u32(&mut out[44..48], crc);
}

fn decode_header(bytes: &[u8]) -> Result<Option<SlotHeader>, SnapshotBlockStoreError> {
    if bytes.len() < HEADER_LEN {
        return Err(SnapshotBlockStoreError::InvalidGeometry);
    }
    if bytes[..HEADER_LEN].iter().all(|byte| *byte == 0) {
        return Ok(None);
    }
    if bytes[0..8] != STORE_MAGIC {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    let header_len = read_u16(&bytes[8..10]);
    let version = read_u16(&bytes[10..12]);
    if header_len as usize != HEADER_LEN || version != STORE_VERSION {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    let header_crc = read_u32(&bytes[44..48]);
    if crc32c(&bytes[..HEADER_LEN - 4]) != header_crc {
        return Err(SnapshotBlockStoreError::Corrupt);
    }
    Ok(Some(SlotHeader {
        generation: read_u64(&bytes[16..24]),
        payload_len: read_u64(&bytes[24..32]),
        payload_crc: read_u32(&bytes[32..36]),
        payload_sectors: read_u32(&bytes[36..40]),
        slot: read_u32(&bytes[40..44]),
    }))
}

fn put_u16(out: &mut [u8], value: u16) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], value: u32) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn put_u64(out: &mut [u8], value: u64) {
    out.copy_from_slice(&value.to_le_bytes());
}

fn read_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes.try_into().unwrap())
}

fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes(bytes.try_into().unwrap())
}

fn read_u64(bytes: &[u8]) -> u64 {
    u64::from_le_bytes(bytes.try_into().unwrap())
}

fn crc32c(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0x82F6_3B78
            } else {
                crc >> 1
            };
        }
    }
    !crc
}
