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

/// Byte sink used by streaming snapshot encoders.
pub trait SnapshotPayloadSink {
    fn write_all(&mut self, bytes: &[u8]) -> Result<(), SnapshotBlockStoreError>;
}

/// Sequential byte reader used by streaming snapshot decoders.
pub trait SnapshotPayloadReader {
    fn read_exact(&mut self, out: &mut [u8]) -> Result<(), SnapshotBlockStoreError>;
    fn remaining(&self) -> usize;
}

/// Sector-buffered payload writer for [`SnapshotBlockStore::commit_next_streaming`].
pub struct PayloadSectorWriter<'a, D: SnapshotBlockDevice> {
    dev: &'a mut D,
    sector: Vec<u8>,
    sector_size: usize,
    slot_base: u64,
    max_payload_len: usize,
    written: usize,
    sector_index: u64,
    sector_offset: usize,
}

/// Sector-buffered payload reader for [`SnapshotBlockStore::read_latest_streaming`].
pub struct PayloadSectorReader<'a, D: SnapshotBlockDevice> {
    dev: &'a mut D,
    sector: Vec<u8>,
    sector_size: usize,
    slot_base: u64,
    payload_len: usize,
    payload_crc: u32,
    read: usize,
    sector_index: u64,
    sector_offset: usize,
    sector_valid: usize,
    crc: Crc32c,
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
    generation: u64,
    payload: Vec<u8>,
}

#[derive(Copy, Clone)]
struct SlotSummary {
    slot: u32,
    generation: u64,
}

#[derive(Copy, Clone)]
struct SlotReadPlan {
    slot: u32,
    generation: u64,
    payload_len: usize,
    payload_crc: u32,
    payload_sectors: u32,
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

    /// Read the latest valid payload through a sector-buffered reader without allocating it whole.
    pub fn read_latest_streaming<D, F, R>(
        &self,
        dev: &mut D,
        read_payload: F,
    ) -> Result<Option<(u64, usize, R)>, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorReader<'_, D>) -> Result<R, SnapshotBlockStoreError>,
    {
        let Some(plan) = self.latest_valid_slot(dev)? else {
            return Ok(None);
        };
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let slot_base = self.slot_lba(slot_sectors, plan.slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(sector_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(sector_size, 0);
        let generation = plan.generation;
        let payload_len = plan.payload_len;
        let mut reader = PayloadSectorReader::new(dev, sector, sector_size, slot_base, plan);
        let result = read_payload(&mut reader)?;
        reader.finish()?;
        Ok(Some((generation, payload_len, result)))
    }

    /// Commit a new payload to the alternate slot and return its generation.
    pub fn commit_next<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        payload: &[u8],
    ) -> Result<u64, SnapshotBlockStoreError> {
        self.commit_next_streaming(dev, payload.len(), crc32c(payload), |writer| {
            writer.write_all(payload)
        })
    }

    /// Commit a payload produced incrementally by `write_payload`.
    ///
    /// The caller supplies the exact length and CRC of the byte stream. Payload sectors are written
    /// first and the slot header is written last, preserving the same torn-write behavior as
    /// [`Self::commit_next`] without requiring the whole payload in memory.
    pub fn commit_next_streaming<D, F>(
        &self,
        dev: &mut D,
        payload_len: usize,
        payload_crc: u32,
        write_payload: F,
    ) -> Result<u64, SnapshotBlockStoreError>
    where
        D: SnapshotBlockDevice,
        F: FnOnce(&mut PayloadSectorWriter<'_, D>) -> Result<(), SnapshotBlockStoreError>,
    {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        let max_payload_len = usize::try_from(
            slot_sectors
                .checked_sub(1)
                .ok_or(SnapshotBlockStoreError::InvalidGeometry)?,
        )
        .ok()
        .and_then(|sectors| sectors.checked_mul(sector_size))
        .ok_or(SnapshotBlockStoreError::InvalidGeometry)?;
        if payload_len > max_payload_len {
            return Err(SnapshotBlockStoreError::OutOfSpace);
        }
        let latest = self.latest_slot_summary(dev);
        let (target_slot, generation) = match latest {
            Some(latest) => (1 - latest.slot, latest.generation.saturating_add(1)),
            None => (0, 1),
        };
        let payload_sectors = payload_len.div_ceil(sector_size);
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
        let mut writer = PayloadSectorWriter::new(dev, sector, sector_size, slot_base, payload_len);
        write_payload(&mut writer)?;
        let (mut sector, written) = writer.finish()?;
        if written != payload_len {
            return Err(SnapshotBlockStoreError::Corrupt);
        }

        sector.fill(0);
        encode_header(
            &mut sector,
            SlotHeader {
                slot: target_slot,
                generation,
                payload_len: payload_len as u64,
                payload_crc,
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
            generation: header.generation,
            payload,
        }))
    }

    fn read_slot_plan<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
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
        Ok(Some(SlotReadPlan {
            slot,
            generation: header.generation,
            payload_len,
            payload_crc: header.payload_crc,
            payload_sectors: header.payload_sectors,
        }))
    }

    fn read_valid_slot_plan<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
        let Some(plan) = self.read_slot_plan(dev, slot)? else {
            return Ok(None);
        };
        self.validate_slot_payload_crc(dev, plan)?;
        Ok(Some(plan))
    }

    fn validate_slot_payload_crc<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        plan: SlotReadPlan,
    ) -> Result<(), SnapshotBlockStoreError> {
        let (sector_size, slot_sectors) = self.geometry(dev)?;
        if plan.payload_sectors as u64 > slot_sectors - 1 {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        let slot_base = self.slot_lba(slot_sectors, plan.slot)?;
        let mut sector = Vec::new();
        sector
            .try_reserve_exact(sector_size)
            .map_err(|_| SnapshotBlockStoreError::OutOfMemory)?;
        sector.resize(sector_size, 0);
        let mut remaining = plan.payload_len;
        let mut crc = Crc32c::new();
        for index in 0..plan.payload_sectors {
            sector.fill(0);
            dev.read_sector(slot_base + 1 + index as u64, &mut sector)?;
            let copy = remaining.min(sector_size);
            crc.update(&sector[..copy]);
            remaining -= copy;
        }
        if remaining != 0 || crc.finish() != plan.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(())
    }

    fn read_slot_header<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
        slot: u32,
    ) -> Result<Option<SlotSummary>, SnapshotBlockStoreError> {
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
        Ok(Some(SlotSummary {
            slot,
            generation: header.generation,
        }))
    }

    fn latest_slot_summary<D: SnapshotBlockDevice>(&self, dev: &mut D) -> Option<SlotSummary> {
        match (self.read_slot_header(dev, 0), self.read_slot_header(dev, 1)) {
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
        }
    }

    fn latest_valid_slot<D: SnapshotBlockDevice>(
        &self,
        dev: &mut D,
    ) -> Result<Option<SlotReadPlan>, SnapshotBlockStoreError> {
        let slot0 = self.read_valid_slot_plan(dev, 0);
        let slot1 = self.read_valid_slot_plan(dev, 1);
        match (slot0, slot1) {
            (Ok(Some(a)), Ok(Some(b))) => Ok(Some(if b.generation > a.generation { b } else { a })),
            (Ok(Some(a)), _) => Ok(Some(a)),
            (_, Ok(Some(b))) => Ok(Some(b)),
            (Ok(None), Ok(None)) => Ok(None),
            (Err(err), Ok(None)) | (Ok(None), Err(err)) => Err(err),
            (Err(_), Err(_)) => Err(SnapshotBlockStoreError::Corrupt),
        }
    }
}

impl<'a, D: SnapshotBlockDevice> PayloadSectorWriter<'a, D> {
    fn new(
        dev: &'a mut D,
        sector: Vec<u8>,
        sector_size: usize,
        slot_base: u64,
        max_payload_len: usize,
    ) -> Self {
        Self {
            dev,
            sector,
            sector_size,
            slot_base,
            max_payload_len,
            written: 0,
            sector_index: 0,
            sector_offset: 0,
        }
    }

    fn finish(mut self) -> Result<(Vec<u8>, usize), SnapshotBlockStoreError> {
        if self.sector_offset != 0 {
            self.sector[self.sector_offset..].fill(0);
            self.dev
                .write_sector(self.slot_base + 1 + self.sector_index, &self.sector)?;
            self.sector.fill(0);
        }
        Ok((self.sector, self.written))
    }
}

impl<D: SnapshotBlockDevice> SnapshotPayloadSink for PayloadSectorWriter<'_, D> {
    fn write_all(&mut self, mut bytes: &[u8]) -> Result<(), SnapshotBlockStoreError> {
        let remaining = self
            .max_payload_len
            .checked_sub(self.written)
            .ok_or(SnapshotBlockStoreError::Corrupt)?;
        if bytes.len() > remaining {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        while !bytes.is_empty() {
            let copy = bytes.len().min(self.sector_size - self.sector_offset);
            self.sector[self.sector_offset..self.sector_offset + copy]
                .copy_from_slice(&bytes[..copy]);
            self.sector_offset += copy;
            self.written += copy;
            bytes = &bytes[copy..];
            if self.sector_offset == self.sector_size {
                self.dev
                    .write_sector(self.slot_base + 1 + self.sector_index, &self.sector)?;
                self.sector.fill(0);
                self.sector_index += 1;
                self.sector_offset = 0;
            }
        }
        Ok(())
    }
}

impl<'a, D: SnapshotBlockDevice> PayloadSectorReader<'a, D> {
    fn new(
        dev: &'a mut D,
        sector: Vec<u8>,
        sector_size: usize,
        slot_base: u64,
        plan: SlotReadPlan,
    ) -> Self {
        Self {
            dev,
            sector,
            sector_size,
            slot_base,
            payload_len: plan.payload_len,
            payload_crc: plan.payload_crc,
            read: 0,
            sector_index: 0,
            sector_offset: 0,
            sector_valid: 0,
            crc: Crc32c::new(),
        }
    }

    fn fill_sector(&mut self) -> Result<(), SnapshotBlockStoreError> {
        if self.read >= self.payload_len {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        self.sector.fill(0);
        self.dev
            .read_sector(self.slot_base + 1 + self.sector_index, &mut self.sector)?;
        self.sector_index += 1;
        self.sector_offset = 0;
        self.sector_valid = (self.payload_len - self.read).min(self.sector_size);
        Ok(())
    }

    fn finish(self) -> Result<(), SnapshotBlockStoreError> {
        if self.read != self.payload_len || self.crc.finish() != self.payload_crc {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        Ok(())
    }
}

impl<D: SnapshotBlockDevice> SnapshotPayloadReader for PayloadSectorReader<'_, D> {
    fn read_exact(&mut self, mut out: &mut [u8]) -> Result<(), SnapshotBlockStoreError> {
        if out.len() > self.remaining() {
            return Err(SnapshotBlockStoreError::Corrupt);
        }
        while !out.is_empty() {
            if self.sector_offset == self.sector_valid {
                self.fill_sector()?;
            }
            let copy = out.len().min(self.sector_valid - self.sector_offset);
            let bytes = &self.sector[self.sector_offset..self.sector_offset + copy];
            self.crc.update(bytes);
            out[..copy].copy_from_slice(bytes);
            self.sector_offset += copy;
            self.read += copy;
            out = &mut out[copy..];
        }
        Ok(())
    }

    fn remaining(&self) -> usize {
        self.payload_len - self.read
    }
}

struct Crc32c {
    crc: u32,
}

impl Crc32c {
    fn new() -> Self {
        Self { crc: 0xFFFF_FFFF }
    }

    fn update(&mut self, data: &[u8]) {
        for &b in data {
            self.crc ^= b as u32;
            for _ in 0..8 {
                self.crc = if self.crc & 1 != 0 {
                    (self.crc >> 1) ^ 0x82F6_3B78
                } else {
                    self.crc >> 1
                };
            }
        }
    }

    fn finish(self) -> u32 {
        !self.crc
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
    let mut crc = Crc32c::new();
    crc.update(data);
    crc.finish()
}
