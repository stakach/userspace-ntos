//! Per-mount ownership of mutable hive writes awaiting durable checkpoint proof.
//!
//! This is a scheduling contract. A native adapter must capture an image at `begin_batch`,
//! persist it, and report `Durable` only after the image and required storage barriers complete.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FlushTarget {
    mount_generation: u64,
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WritebackBatch {
    mount_generation: u64,
    serial: u64,
    generation: u64,
}

impl WritebackBatch {
    pub fn generation(self) -> FlushTarget {
        FlushTarget {
            mount_generation: self.mount_generation,
            generation: self.generation,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BatchResult {
    /// Persistence and its storage barriers completed for the captured image.
    Durable,
    /// The provider proved that no persistent effect began; retry may use a new batch.
    NoEffect,
    /// Persistence may have begun. Retain this batch until its outcome is resolved.
    Uncertain,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WritebackError {
    GenerationExhausted,
    InFlight,
    Uncertain,
    StaleBatch,
    Dirty,
}

/// Tracks mutation publication separately from persistence of a mounted hive image.
pub struct RegistryWritebackOwner {
    mount_generation: u64,
    dirty_generation: u64,
    durable_generation: u64,
    next_serial: u64,
    pending: Option<WritebackBatch>,
    uncertain: bool,
}

impl RegistryWritebackOwner {
    /// `mount_generation` must identify this exact mount lifetime and must not be reused
    /// while tickets from an older mount can still arrive.
    pub const fn new(mount_generation: u64) -> Self {
        Self {
            mount_generation,
            dirty_generation: 0,
            durable_generation: 0,
            next_serial: 1,
            pending: None,
            uncertain: false,
        }
    }

    /// Call only after the mutation is visible in this mount's in-memory hive.
    pub fn record_mutation(&mut self) -> Result<FlushTarget, WritebackError> {
        self.dirty_generation = self
            .dirty_generation
            .checked_add(1)
            .ok_or(WritebackError::GenerationExhausted)?;
        Ok(self.flush_target())
    }

    /// The barrier for an explicit flush captures all mutations visible at this instant.
    pub const fn flush_target(&self) -> FlushTarget {
        FlushTarget {
            mount_generation: self.mount_generation,
            generation: self.dirty_generation,
        }
    }

    pub const fn is_durable(&self, target: FlushTarget) -> bool {
        target.mount_generation == self.mount_generation
            && target.generation <= self.durable_generation
    }

    pub const fn is_dirty(&self) -> bool {
        self.dirty_generation > self.durable_generation
    }

    pub const fn pending_batch(&self) -> Option<WritebackBatch> {
        self.pending
    }

    /// Capture at most one coalesced batch. The caller must retain the exact ticket through I/O.
    pub fn begin_batch(&mut self) -> Result<Option<WritebackBatch>, WritebackError> {
        if self.uncertain {
            return Err(WritebackError::Uncertain);
        }
        if self.pending.is_some() {
            return Err(WritebackError::InFlight);
        }
        if !self.is_dirty() {
            return Ok(None);
        }
        let next = self
            .next_serial
            .checked_add(1)
            .ok_or(WritebackError::GenerationExhausted)?;
        let batch = WritebackBatch {
            mount_generation: self.mount_generation,
            serial: self.next_serial,
            generation: self.dirty_generation,
        };
        self.next_serial = next;
        self.pending = Some(batch);
        Ok(Some(batch))
    }

    pub fn complete(
        &mut self,
        batch: WritebackBatch,
        result: BatchResult,
    ) -> Result<(), WritebackError> {
        if self.pending != Some(batch) {
            return Err(WritebackError::StaleBatch);
        }
        match result {
            BatchResult::Durable => {
                self.durable_generation = batch.generation;
                self.pending = None;
                self.uncertain = false;
            }
            BatchResult::NoEffect => {
                if self.uncertain {
                    // A previous uncertain effect cannot later be called effect-free.
                    return Err(WritebackError::Uncertain);
                }
                self.pending = None;
            }
            BatchResult::Uncertain => self.uncertain = true,
        }
        Ok(())
    }

    /// A mount cannot be discarded while it owns unpublished or uncertain effects.
    pub fn retire(&self) -> Result<(), WritebackError> {
        if self.pending.is_some() {
            return Err(WritebackError::InFlight);
        }
        if self.is_dirty() {
            return Err(WritebackError::Dirty);
        }
        Ok(())
    }
}
