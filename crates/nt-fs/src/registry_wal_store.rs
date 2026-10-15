//! A bounded sector WAL whose durable commit marker is separate from its prepared data.
//!
//! The caller owns CM publication. It may call `commit` only after the exact prepared
//! mutation has entered CM COMMIT. Neither `prepare` nor `commit` retries uncertain I/O.
//! The device is retained until the operation is settled; a crash may replay a marked
//! mutation whose caller never received a reply.
//! Live recovery still needs a separately durable high-water anchor: a wholly erased
//! committed suffix otherwise looks like an unused zero-filled tail.

use alloc::vec::Vec;
use nt_config_store::codec::crc32c;

use crate::{OwnedBoundedBlockRange, SnapshotBlockDevice, SnapshotBlockStoreError, WalSnapshotAnchor};

const PREPARE_MAGIC: [u8; 8] = *b"USRWALP1";
const COMMIT_MAGIC: [u8; 8] = *b"USRWALC1";
const HEADER_BYTES: usize = 36;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryWalError {
    InvalidGeometry,
    WrongIncarnation,
    Corrupt,
    OutOfSpace,
    OutOfMemory,
    GenerationExhausted,
    InvalidState,
    Uncertain,
    Storage(SnapshotBlockStoreError),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryWalState {
    Ready,
    RecoveredUncommitted,
    PendingPrepare,
    Prepared,
    Uncertain,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RegistryWalRecord {
    pub serial: u64,
    pub payload: Vec<u8>,
}

/// The exact committed prefix parsed or durably written before its device owner leaves
/// the WAL. Only a settled WAL can issue this proof; callers may move the returned device
/// into the two-header snapshot anchor update without reopening the physical reserve.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegistryWalVerifiedPrefix {
    incarnation: u64,
    serial: u64,
    end_lba: u64,
}

/// Carries a verified committed prefix with the exact device that supplied it. Native
/// recovery and publication pass this owner directly to the snapshot anchor update.
#[must_use = "retain the verified WAL device until its anchor is published or recovery is resolved"]
pub struct RegistryWalVerifiedDevice<D> {
    device: D,
    prefix: RegistryWalVerifiedPrefix,
    record_end_lbas: Vec<u64>,
}

/// Move-only proof of the settled WAL prefix for another use of the same physical reserve.
/// A caller must separately prove the paired snapshot headers still name this anchor.
#[must_use = "bind this continuation to the same reserve and paired snapshot anchor"]
pub struct RegistryWalContinuation {
    prefix: RegistryWalVerifiedPrefix,
    record_end_lbas: Vec<u64>,
}

impl RegistryWalContinuation {
    pub fn anchor(&self) -> WalSnapshotAnchor { self.prefix.anchor() }

    pub(crate) fn from_parts(prefix: RegistryWalVerifiedPrefix, record_end_lbas: Vec<u64>) -> Self {
        Self { prefix, record_end_lbas }
    }

    pub(crate) fn empty(incarnation: u64) -> Self {
        Self {
            prefix: RegistryWalVerifiedPrefix { incarnation, serial: 0, end_lba: 0 },
            record_end_lbas: Vec::new(),
        }
    }

    pub(crate) fn from_verified<D>(verified: RegistryWalVerifiedDevice<D>) -> (D, Self) {
        let (device, prefix, record_end_lbas) = verified.into_parts();
        (device, Self { prefix, record_end_lbas })
    }
}

impl<D> RegistryWalVerifiedDevice<D> {
    pub fn anchor(&self) -> WalSnapshotAnchor { self.prefix.anchor() }
    pub fn into_device(self) -> D { self.device }

    pub(crate) fn device_mut(&mut self) -> &mut D { &mut self.device }

    pub(crate) fn into_parts(self) -> (D, RegistryWalVerifiedPrefix, Vec<u64>) {
        (self.device, self.prefix, self.record_end_lbas)
    }

    pub(crate) fn from_parts(device: D, prefix: RegistryWalVerifiedPrefix, record_end_lbas: Vec<u64>) -> Self {
        Self { device, prefix, record_end_lbas }
    }
}

impl<D: SnapshotBlockDevice> RegistryWalVerifiedDevice<OwnedBoundedBlockRange<D>> {
    /// Move from the bounded WAL view to its full parent without releasing the exact lease.
    pub fn into_full_device(self) -> RegistryWalVerifiedDevice<D> {
        let (device, prefix, record_end_lbas) = self.into_parts();
        RegistryWalVerifiedDevice::from_parts(device.into_device(), prefix, record_end_lbas)
    }
}

impl RegistryWalVerifiedPrefix {
    pub fn anchor(self) -> WalSnapshotAnchor {
        WalSnapshotAnchor {
            incarnation: self.incarnation,
            serial: self.serial,
            end_lba: self.end_lba,
        }
    }
}

struct Pending {
    serial: u64,
    sectors: u64,
    payload: Vec<u8>,
}

/// Owns one exact device lease and an unresolved append until its terminal barrier.
#[must_use = "retain the WAL owner and device lease across uncertain writes"]
pub struct RegistryWal<D: SnapshotBlockDevice> {
    device: Option<D>,
    incarnation: u64,
    cursor: u64,
    next_serial: u64,
    records: Vec<RegistryWalRecord>,
    record_end_lbas: Vec<u64>,
    pending: Option<Pending>,
    recovered_tail_sectors: Option<u64>,
    state: RegistryWalState,
}

impl<D: SnapshotBlockDevice> Drop for RegistryWal<D> {
    fn drop(&mut self) {
        if self.state != RegistryWalState::Ready {
            // A missing explicit terminal result cannot release the physical lease. The
            // leaked owner keeps the reserve closed, and the panic exposes caller misuse.
            if let Some(device) = self.device.take() {
                core::mem::forget(device);
            }
            panic!("dropping unresolved registry WAL storage effect");
        }
    }
}

impl<D: SnapshotBlockDevice> core::fmt::Debug for RegistryWal<D> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RegistryWal")
            .field("incarnation", &self.incarnation)
            .field("cursor", &self.cursor)
            .field("next_serial", &self.next_serial)
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

fn sector_buffer(size: usize) -> Result<Vec<u8>, RegistryWalError> {
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(size)
        .map_err(|_| RegistryWalError::OutOfMemory)?;
    bytes.resize(size, 0);
    Ok(bytes)
}

fn sector_is_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| *byte == 0)
}

fn zero_suffix<D: SnapshotBlockDevice>(
    device: &mut D,
    start: u64,
) -> Result<bool, RegistryWalError> {
    // The caller already read and checked `start`. Range reads preserve full-tail validation
    // while allowing the native AHCI device to amortize commands over several sectors.
    const BATCH_SECTORS: usize = 64;
    let size = device.sector_size();
    let bytes = size.checked_mul(BATCH_SECTORS).ok_or(RegistryWalError::InvalidGeometry)?;
    let mut batch = sector_buffer(bytes)?;
    let mut lba = start + 1;
    while lba < device.sector_count() {
        let sectors = (device.sector_count() - lba).min(BATCH_SECTORS as u64) as usize;
        let span = sectors * size;
        device.read_sectors(lba, &mut batch[..span]).map_err(RegistryWalError::Storage)?;
        if !sector_is_zero(&batch[..span]) {
            return Ok(false);
        }
        lba += sectors as u64;
    }
    Ok(true)
}

fn clear_frame<D: SnapshotBlockDevice>(
    device: &mut D,
    start: u64,
    payload_sectors: u64,
) -> Result<(), RegistryWalError> {
    let blank = sector_buffer(device.sector_size())?;
    let marker = start + 1 + payload_sectors;
    // Keep the valid PREPARE header while clearing its suffix. A power cut before the
    // first barrier leaves an unmarked tail; after it, the header can be cleared safely.
    for lba in start + 1..=marker {
        device
            .write_sector(lba, &blank)
            .map_err(RegistryWalError::Storage)?;
    }
    device.flush().map_err(RegistryWalError::Storage)?;
    device
        .write_sector(start, &blank)
        .map_err(RegistryWalError::Storage)?;
    device.flush().map_err(RegistryWalError::Storage)
}

fn framed_sector(
    size: usize,
    magic: [u8; 8],
    incarnation: u64,
    serial: u64,
    payload_len: u32,
    payload_crc: u32,
) -> Result<Vec<u8>, RegistryWalError> {
    let mut sector = sector_buffer(size)?;
    sector[..8].copy_from_slice(&magic);
    sector[8..16].copy_from_slice(&incarnation.to_le_bytes());
    sector[16..24].copy_from_slice(&serial.to_le_bytes());
    sector[24..28].copy_from_slice(&payload_len.to_le_bytes());
    sector[28..32].copy_from_slice(&payload_crc.to_le_bytes());
    let header_crc = crc32c(&sector[..32]);
    sector[32..HEADER_BYTES].copy_from_slice(&header_crc.to_le_bytes());
    Ok(sector)
}

fn payload_sectors(len: usize, size: usize) -> Result<u64, RegistryWalError> {
    let rounded = len
        .checked_add(size - 1)
        .ok_or(RegistryWalError::OutOfSpace)?;
    u64::try_from(rounded / size).map_err(|_| RegistryWalError::OutOfSpace)
}

impl<D: SnapshotBlockDevice> RegistryWal<D> {
    /// Resume an in-process WAL owner without scanning the zero-filled suffix. The caller
    /// must hold the same exclusive physical reserve that produced the continuation and
    /// must have checked both snapshot headers against `anchored` under that lease.
    /// A reboot must call `recover`, which scans and validates the whole tail again.
    ///
    /// # Safety
    /// `device` must be the exact WAL range of the original reserve, exclusively owned
    /// since the continuation was minted. The paired snapshot headers must durably name
    /// `anchored`; a bare numeric anchor is not physical identity or authority.
    pub unsafe fn resume_from_continuation(
        device: D,
        continuation: RegistryWalContinuation,
        anchored: WalSnapshotAnchor,
    ) -> Result<Self, (RegistryWalError, D, RegistryWalContinuation)> {
        let size = device.sector_size();
        let count = device.sector_count();
        let prefix = continuation.prefix;
        let serial_count = usize::try_from(prefix.serial).ok();
        let mut previous = 0u64;
        let boundaries_valid = continuation.record_end_lbas.iter().all(|&end| {
            let valid = end >= previous.saturating_add(3) && end <= count;
            previous = end;
            valid
        });
        let valid = size >= HEADER_BYTES && count >= 3
            && prefix.incarnation != 0
            && prefix.anchor() == anchored
            && serial_count == Some(continuation.record_end_lbas.len())
            && boundaries_valid
            && previous == prefix.end_lba
            && prefix.serial.checked_add(1).is_some();
        if !valid {
            return Err((RegistryWalError::Corrupt, device, continuation));
        }
        Ok(Self {
            device: Some(device),
            incarnation: prefix.incarnation,
            cursor: prefix.end_lba,
            next_serial: prefix.serial + 1,
            records: Vec::new(),
            record_end_lbas: continuation.record_end_lbas,
            pending: None,
            recovered_tail_sectors: None,
            state: RegistryWalState::Ready,
        })
    }

    /// Recover only the contiguous, checksum-verified committed prefix. A valid prepared
    /// record without a marker is an unacknowledged tail and may be reused after reboot.
    pub fn recover(mut device: D, incarnation: u64) -> Result<Self, RegistryWalError> {
        let size = device.sector_size();
        if incarnation == 0 || size < HEADER_BYTES || device.sector_count() < 3 {
            return Err(RegistryWalError::InvalidGeometry);
        }
        let mut sector = sector_buffer(size)?;
        let mut cursor = 0u64;
        let mut serial = 1u64;
        let mut records = Vec::new();
        let mut record_end_lbas = Vec::new();
        let mut recovered_tail_sectors = None;
        while cursor < device.sector_count() {
            device
                .read_sector(cursor, &mut sector)
                .map_err(RegistryWalError::Storage)?;
            if sector_is_zero(&sector) {
                if !zero_suffix(&mut device, cursor)? {
                    return Err(RegistryWalError::Corrupt);
                }
                break;
            }
            if sector[..8] != PREPARE_MAGIC
                || u32::from_le_bytes(sector[32..HEADER_BYTES].try_into().unwrap())
                    != crc32c(&sector[..32])
                || !sector_is_zero(&sector[HEADER_BYTES..])
            {
                return Err(RegistryWalError::Corrupt);
            }
            let found_incarnation = u64::from_le_bytes(sector[8..16].try_into().unwrap());
            if found_incarnation != incarnation {
                return Err(RegistryWalError::WrongIncarnation);
            }
            let found_serial = u64::from_le_bytes(sector[16..24].try_into().unwrap());
            if found_serial != serial {
                return Err(RegistryWalError::Corrupt);
            }
            let len = u32::from_le_bytes(sector[24..28].try_into().unwrap()) as usize;
            if len == 0 {
                return Err(RegistryWalError::Corrupt);
            }
            let payload_crc = u32::from_le_bytes(sector[28..32].try_into().unwrap());
            let payload_count = payload_sectors(len, size)?;
            let marker_lba = cursor
                .checked_add(1)
                .and_then(|v| v.checked_add(payload_count))
                .ok_or(RegistryWalError::Corrupt)?;
            if marker_lba >= device.sector_count() {
                return Err(RegistryWalError::Corrupt);
            }
            device
                .read_sector(marker_lba, &mut sector)
                .map_err(RegistryWalError::Storage)?;
            if sector_is_zero(&sector) {
                if !zero_suffix(&mut device, marker_lba)? {
                    return Err(RegistryWalError::Corrupt);
                }
                recovered_tail_sectors = Some(payload_count);
                break;
            }
            let expected = framed_sector(
                size,
                COMMIT_MAGIC,
                incarnation,
                serial,
                len as u32,
                payload_crc,
            )?;
            if sector != expected {
                return Err(RegistryWalError::Corrupt);
            }
            let mut payload = Vec::new();
            payload
                .try_reserve_exact(len)
                .map_err(|_| RegistryWalError::OutOfMemory)?;
            for index in 0..payload_count {
                device
                    .read_sector(cursor + 1 + index, &mut sector)
                    .map_err(RegistryWalError::Storage)?;
                let remaining = len - payload.len();
                let take = remaining.min(size);
                payload.extend_from_slice(&sector[..take]);
                if take < size && !sector_is_zero(&sector[take..]) {
                    return Err(RegistryWalError::Corrupt);
                }
            }
            if crc32c(&payload) != payload_crc {
                return Err(RegistryWalError::Corrupt);
            }
            records
                .try_reserve(1)
                .map_err(|_| RegistryWalError::OutOfMemory)?;
            record_end_lbas
                .try_reserve(1)
                .map_err(|_| RegistryWalError::OutOfMemory)?;
            records.push(RegistryWalRecord { serial, payload });
            record_end_lbas.push(marker_lba + 1);
            serial = serial
                .checked_add(1)
                .ok_or(RegistryWalError::GenerationExhausted)?;
            cursor = marker_lba + 1;
        }
        Ok(Self {
            device: Some(device),
            incarnation,
            cursor,
            next_serial: serial,
            records,
            record_end_lbas,
            pending: None,
            recovered_tail_sectors,
            state: if recovered_tail_sectors.is_some() {
                RegistryWalState::RecoveredUncommitted
            } else {
                RegistryWalState::Ready
            },
        })
    }

    /// Recovered payloads, or records appended since an in-process continuation resumed.
    pub fn records(&self) -> &[RegistryWalRecord] {
        &self.records
    }
    pub fn state(&self) -> RegistryWalState {
        self.state
    }

    /// The exact committed endpoint is observable only when no write or recovered tail
    /// still owns an uncertain effect. Native admission compares this with both v2 headers
    /// before reserving another serial.
    pub fn settled_anchor(&self) -> Option<WalSnapshotAnchor> {
        if self.state != RegistryWalState::Ready {
            return None;
        }
        let (incarnation, serial, end_lba) = self.verified_prefix()?;
        Some(WalSnapshotAnchor { incarnation, serial, end_lba })
    }

    /// Only a scanned or settled WAL prefix can satisfy an external durability anchor.
    pub(crate) fn verified_prefix(&self) -> Option<(u64, u64, u64)> {
        if !matches!(
            self.state,
            RegistryWalState::Ready | RegistryWalState::RecoveredUncommitted
        ) {
            return None;
        }
        let serial = self.next_serial.checked_sub(1)?;
        Some((self.incarnation, serial, self.cursor))
    }

    /// Exact end of one parsed committed frame, including its marker sector.
    pub(crate) fn verified_record_end_lba(&self, serial: u64) -> Option<u64> {
        self.verified_prefix()?;
        if serial == 0 {
            return Some(0);
        }
        let index = usize::try_from(serial.checked_sub(1)?).ok()?;
        self.record_end_lbas.get(index).copied()
    }

    /// Discard a verified but unmarked tail after reboot. This may write after recovery,
    /// so its owner and lease are retained if any clearing effect is uncertain.
    pub fn clear_recovered_tail(&mut self) -> Result<(), RegistryWalError> {
        if self.state == RegistryWalState::Uncertain {
            return Err(RegistryWalError::Uncertain);
        }
        if self.state != RegistryWalState::RecoveredUncommitted {
            return Err(RegistryWalError::InvalidState);
        }
        let sectors = self.recovered_tail_sectors.expect("recovered WAL tail");
        let result = clear_frame(
            self.device.as_mut().expect("retained WAL device"),
            self.cursor,
            sectors,
        );
        if let Err(error) = result {
            self.state = RegistryWalState::Uncertain;
            return Err(error);
        }
        self.recovered_tail_sectors = None;
        self.state = RegistryWalState::Ready;
        Ok(())
    }

    /// Reserve the entire frame and its marker before the first native effect.
    pub fn begin(&mut self, payload: Vec<u8>) -> Result<(), RegistryWalError> {
        if self.state == RegistryWalState::Uncertain {
            return Err(RegistryWalError::Uncertain);
        }
        if self.state != RegistryWalState::Ready {
            return Err(RegistryWalError::InvalidState);
        }
        let device = self.device.as_ref().expect("retained WAL device");
        let size = device.sector_size();
        let len = u32::try_from(payload.len()).map_err(|_| RegistryWalError::OutOfSpace)?;
        if len == 0 {
            return Err(RegistryWalError::InvalidGeometry);
        }
        let count = payload_sectors(payload.len(), size)?;
        let end = self
            .cursor
            .checked_add(count)
            .and_then(|v| v.checked_add(2))
            .ok_or(RegistryWalError::OutOfSpace)?;
        if end > device.sector_count() {
            return Err(RegistryWalError::OutOfSpace);
        }
        self.next_serial
            .checked_add(1)
            .ok_or(RegistryWalError::GenerationExhausted)?;
        self.records
            .try_reserve(1)
            .map_err(|_| RegistryWalError::OutOfMemory)?;
        self.record_end_lbas
            .try_reserve(1)
            .map_err(|_| RegistryWalError::OutOfMemory)?;
        self.pending = Some(Pending {
            serial: self.next_serial,
            sectors: count,
            payload,
        });
        self.state = RegistryWalState::PendingPrepare;
        Ok(())
    }

    /// Cancel a reservation before PREPARE starts. No sector has been touched, so this
    /// is the only pending state that can release its device without a clearing barrier.
    pub fn cancel_pending(&mut self) -> Result<(), RegistryWalError> {
        if self.state != RegistryWalState::PendingPrepare {
            return Err(RegistryWalError::InvalidState);
        }
        self.pending = None;
        self.state = RegistryWalState::Ready;
        Ok(())
    }

    /// Write PREPARE plus payload, then issue the first device durability barrier.
    pub fn prepare(&mut self) -> Result<(), RegistryWalError> {
        if self.state == RegistryWalState::Uncertain {
            return Err(RegistryWalError::Uncertain);
        }
        if self.state != RegistryWalState::PendingPrepare {
            return Err(RegistryWalError::InvalidState);
        }
        let pending = self.pending.as_ref().unwrap();
        let size = self
            .device
            .as_ref()
            .expect("retained WAL device")
            .sector_size();
        let result = (|| {
            let header = framed_sector(
                size,
                PREPARE_MAGIC,
                self.incarnation,
                pending.serial,
                pending.payload.len() as u32,
                crc32c(&pending.payload),
            )?;
            self.device
                .as_mut()
                .expect("retained WAL device")
                .write_sector(self.cursor, &header)
                .map_err(RegistryWalError::Storage)?;
            let mut sector = sector_buffer(size)?;
            for (index, chunk) in pending.payload.chunks(size).enumerate() {
                sector.fill(0);
                sector[..chunk.len()].copy_from_slice(chunk);
                self.device
                    .as_mut()
                    .expect("retained WAL device")
                    .write_sector(self.cursor + 1 + index as u64, &sector)
                    .map_err(RegistryWalError::Storage)?;
            }
            self.device
                .as_mut()
                .expect("retained WAL device")
                .flush()
                .map_err(RegistryWalError::Storage)
        })();
        self.state = if result.is_ok() {
            RegistryWalState::Prepared
        } else {
            RegistryWalState::Uncertain
        };
        result
    }

    /// Call only after CM has entered COMMIT for the exact prepared journal. The marker's
    /// barrier is the proof required before CM ACK or any caller success reply.
    pub fn commit(&mut self) -> Result<(), RegistryWalError> {
        if self.state == RegistryWalState::Uncertain {
            return Err(RegistryWalError::Uncertain);
        }
        if self.state != RegistryWalState::Prepared {
            return Err(RegistryWalError::InvalidState);
        }
        let pending = self.pending.as_ref().unwrap();
        let size = self
            .device
            .as_ref()
            .expect("retained WAL device")
            .sector_size();
        let marker_lba = self.cursor + 1 + pending.sectors;
        let result = (|| {
            let marker = framed_sector(
                size,
                COMMIT_MAGIC,
                self.incarnation,
                pending.serial,
                pending.payload.len() as u32,
                crc32c(&pending.payload),
            )?;
            self.device
                .as_mut()
                .expect("retained WAL device")
                .write_sector(marker_lba, &marker)
                .map_err(RegistryWalError::Storage)?;
            self.device
                .as_mut()
                .expect("retained WAL device")
                .flush()
                .map_err(RegistryWalError::Storage)
        })();
        if let Err(error) = result {
            self.state = RegistryWalState::Uncertain;
            return Err(error);
        }
        let pending = self.pending.take().unwrap();
        self.records.push(RegistryWalRecord {
            serial: pending.serial,
            payload: pending.payload,
        });
        self.record_end_lbas.push(marker_lba + 1);
        self.next_serial += 1;
        self.cursor = marker_lba + 1;
        self.state = RegistryWalState::Ready;
        Ok(())
    }

    /// Call only after CM confirms that the matching preparation was aborted before COMMIT.
    /// A failed clearing barrier retains the exact pending record and blocks reuse.
    pub fn abort_prepared(&mut self) -> Result<(), RegistryWalError> {
        if self.state == RegistryWalState::Uncertain {
            return Err(RegistryWalError::Uncertain);
        }
        if self.state != RegistryWalState::Prepared {
            return Err(RegistryWalError::InvalidState);
        }
        let sectors = self.pending.as_ref().unwrap().sectors;
        let result = clear_frame(
            self.device.as_mut().expect("retained WAL device"),
            self.cursor,
            sectors,
        );
        if let Err(error) = result {
            self.state = RegistryWalState::Uncertain;
            return Err(error);
        }
        self.pending = None;
        self.state = RegistryWalState::Ready;
        Ok(())
    }

    /// The lease can leave only after all owned writes have a terminal durable result.
    pub fn into_device(mut self) -> Result<D, Self> {
        if self.state == RegistryWalState::Ready {
            Ok(self.device.take().expect("retained WAL device"))
        } else {
            Err(self)
        }
    }

    /// Atomically transfer the settled device and its exact committed prefix. The same
    /// physical lease can then enter [`crate::WalSnapshotAnchorUpdate::admit_verified_wal`]
    /// without recreating storage authority or guessing the final frame boundary.
    pub fn into_verified_device(mut self) -> Result<RegistryWalVerifiedDevice<D>, Self> {
        if self.state != RegistryWalState::Ready {
            return Err(self);
        }
        let (incarnation, serial, end_lba) = self.verified_prefix().expect("settled WAL prefix");
        let prefix = RegistryWalVerifiedPrefix { incarnation, serial, end_lba };
        Ok(RegistryWalVerifiedDevice::from_parts(
            self.device.take().expect("retained WAL device"),
            prefix,
            core::mem::take(&mut self.record_end_lbas),
        ))
    }

    /// Return a settled in-process prefix after a pre-effect refusal or confirmed abort.
    /// The token cannot authorize another write until paired headers are checked again.
    pub fn into_continuation(self) -> Result<(D, RegistryWalContinuation), Self> {
        let verified = self.into_verified_device()?;
        Ok(RegistryWalContinuation::from_verified(verified))
    }

    #[cfg(test)]
    fn device_mut_for_test(&mut self) -> &mut D {
        self.device.as_mut().expect("retained WAL device")
    }

    #[cfg(test)]
    fn into_device_for_test(mut self) -> D {
        self.state = RegistryWalState::Ready;
        self.device.take().expect("retained WAL device")
    }
}

#[cfg(test)]
#[path = "registry_wal_store/tests.rs"]
mod tests;
