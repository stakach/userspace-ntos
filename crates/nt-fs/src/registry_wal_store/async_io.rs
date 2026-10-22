//! Retained physical steps for live WAL prepare, marker, and confirmed abort.
//! The synchronous and native paths share the same frame encoding and WAL owner.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncWalIoKind { Write, Flush }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AsyncWalIoRequest {
    pub sequence: u64,
    pub kind: AsyncWalIoKind,
    pub lba: u64,
    pub bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AsyncWalRefusal { NoEffect, RetainedEffects }

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Operation { Prepare, Commit, Abort }

pub(super) struct AsyncWalEffect {
    operation: Operation,
    step: u64,
    pending: Option<AsyncWalIoRequest>,
    entered: bool,
    sector: Vec<u8>,
}

impl<D: SnapshotBlockDevice> RegistryWal<D> {
    pub fn async_active(&self) -> bool { self.async_effect.is_some() }

    fn start_async(&mut self, operation: Operation) -> Result<(), RegistryWalError> {
        if self.state == RegistryWalState::Uncertain { return Err(RegistryWalError::Uncertain); }
        if self.async_effect.is_some() { return Err(RegistryWalError::InvalidState); }
        let expected = match operation {
            Operation::Prepare => RegistryWalState::PendingPrepare,
            Operation::Commit | Operation::Abort => RegistryWalState::Prepared,
        };
        if self.state != expected { return Err(RegistryWalError::InvalidState); }
        let sector = sector_buffer(self.device.as_ref().expect("retained WAL device").sector_size())?;
        self.async_effect = Some(AsyncWalEffect { operation, step: 0, pending: None, entered: false, sector });
        Ok(())
    }

    pub fn start_async_prepare(&mut self) -> Result<(), RegistryWalError> {
        self.start_async(Operation::Prepare)
    }

    pub fn start_async_commit(&mut self) -> Result<(), RegistryWalError> {
        self.start_async(Operation::Commit)
    }

    pub fn start_async_abort_prepared(&mut self) -> Result<(), RegistryWalError> {
        self.start_async(Operation::Abort)
    }

    /// Mint one exact command. The owned sector remains stable until its terminal result.
    pub fn enter_next_async(&mut self) -> Result<Option<AsyncWalIoRequest>, RegistryWalError> {
        if self.state == RegistryWalState::Uncertain { return Err(RegistryWalError::Uncertain); }
        let Some(effect) = self.async_effect.as_mut() else { return Ok(None); };
        if effect.pending.is_some() { return Err(RegistryWalError::InvalidState); }
        let pending = self.pending.as_ref().expect("async WAL effect owns a frame");
        let size = effect.sector.len();
        let payload_sectors = pending.sectors;
        let (kind, lba) = match effect.operation {
            Operation::Prepare if effect.step == 0 => {
                encode_framed_sector(&mut effect.sector, PREPARE_MAGIC, self.incarnation,
                    pending.serial, pending.payload.len() as u32, crc32c(&pending.payload));
                (AsyncWalIoKind::Write, self.cursor)
            }
            Operation::Prepare if effect.step <= payload_sectors => {
                let offset = (effect.step as usize - 1) * size;
                let chunk = &pending.payload[offset..pending.payload.len().min(offset + size)];
                effect.sector.fill(0);
                effect.sector[..chunk.len()].copy_from_slice(chunk);
                (AsyncWalIoKind::Write, self.cursor + effect.step)
            }
            Operation::Prepare => (AsyncWalIoKind::Flush, 0),
            Operation::Commit if effect.step == 0 => {
                encode_framed_sector(&mut effect.sector, COMMIT_MAGIC, self.incarnation,
                    pending.serial, pending.payload.len() as u32, crc32c(&pending.payload));
                (AsyncWalIoKind::Write, self.cursor + 1 + payload_sectors)
            }
            Operation::Commit => (AsyncWalIoKind::Flush, 0),
            Operation::Abort if effect.step <= payload_sectors => {
                effect.sector.fill(0);
                (AsyncWalIoKind::Write, self.cursor + 1 + effect.step)
            }
            Operation::Abort if effect.step == payload_sectors + 1 => (AsyncWalIoKind::Flush, 0),
            Operation::Abort if effect.step == payload_sectors + 2 => {
                effect.sector.fill(0);
                (AsyncWalIoKind::Write, self.cursor)
            }
            Operation::Abort => (AsyncWalIoKind::Flush, 0),
        };
        let sequence = self.async_sequence;
        self.async_sequence = sequence.checked_add(1).ok_or(RegistryWalError::GenerationExhausted)?;
        let request = AsyncWalIoRequest { sequence, kind, lba,
            bytes: if kind == AsyncWalIoKind::Write { size } else { 0 } };
        effect.pending = Some(request);
        effect.entered = false;
        Ok(Some(request))
    }

    pub fn async_write_bytes(&self, request: AsyncWalIoRequest) -> Option<&[u8]> {
        let effect = self.async_effect.as_ref()?;
        (effect.pending == Some(request) && request.kind == AsyncWalIoKind::Write)
            .then_some(effect.sector.as_slice())
    }

    /// A request refused before physical entry can be reissued with a fresh sequence.
    pub fn release_unentered_async(&mut self, request: AsyncWalIoRequest) -> Result<(), RegistryWalError> {
        let Some(effect) = self.async_effect.as_mut() else { return Err(RegistryWalError::InvalidState); };
        if effect.pending != Some(request) || effect.entered { return Err(RegistryWalError::InvalidState); }
        effect.pending = None;
        Ok(())
    }

    /// A permanent local refusal is cancellable only before the first PREPARE write. Later
    /// steps retain the exact device because earlier physical effects may be durable.
    pub fn refuse_unentered_async(&mut self, request: AsyncWalIoRequest) -> Result<AsyncWalRefusal, RegistryWalError> {
        let Some(effect) = self.async_effect.as_ref() else { return Err(RegistryWalError::InvalidState); };
        if effect.pending != Some(request) || effect.entered { return Err(RegistryWalError::InvalidState); }
        if effect.operation == Operation::Prepare && effect.step == 0 {
            self.async_effect = None;
            self.cancel_pending()?;
            Ok(AsyncWalRefusal::NoEffect)
        } else {
            self.state = RegistryWalState::Uncertain;
            Ok(AsyncWalRefusal::RetainedEffects)
        }
    }

    pub fn mark_entered_async(&mut self, request: AsyncWalIoRequest) -> Result<(), RegistryWalError> {
        let Some(effect) = self.async_effect.as_mut() else { return Err(RegistryWalError::InvalidState); };
        if effect.pending != Some(request) || effect.entered { return Err(RegistryWalError::InvalidState); }
        effect.entered = true;
        Ok(())
    }

    pub fn complete_async(
        &mut self, request: AsyncWalIoRequest,
        result: Result<(), SnapshotBlockStoreError>,
    ) -> Result<(), RegistryWalError> {
        let Some(effect) = self.async_effect.as_mut() else { return Err(RegistryWalError::InvalidState); };
        if effect.pending != Some(request) || !effect.entered { return Err(RegistryWalError::InvalidState); }
        if let Err(error) = result {
            self.state = RegistryWalState::Uncertain;
            return Err(RegistryWalError::Storage(error));
        }
        effect.pending = None;
        effect.entered = false;
        effect.step += 1;
        let pending = self.pending.as_ref().expect("async WAL effect owns a frame");
        let final_step = match effect.operation {
            Operation::Prepare => pending.sectors + 2,
            Operation::Commit => 2,
            Operation::Abort => pending.sectors + 4,
        };
        if effect.step != final_step { return Ok(()); }
        match effect.operation {
            Operation::Prepare => self.state = RegistryWalState::Prepared,
            Operation::Commit => {
                let pending = self.pending.take().expect("committed WAL frame");
                self.record_end_lbas.push(self.cursor + 2 + pending.sectors);
                self.records.push(RegistryWalRecord { serial: pending.serial, payload: pending.payload });
                self.next_serial += 1;
                self.cursor += 2 + pending.sectors;
                self.state = RegistryWalState::Ready;
            }
            Operation::Abort => {
                self.pending = None;
                self.state = RegistryWalState::Ready;
            }
        }
        self.async_effect = None;
        Ok(())
    }
}
