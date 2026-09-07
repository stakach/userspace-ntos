//! One permanently reserved scratch slot, with retry-owned mapping cleanup.

const RESOURCES: u32 = 0xc000_009a;
const INVALID: u32 = 0xc000_000d;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporaryAliasSource {
    pub process: u64,
    pub page: u64,
    pub frame: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporaryAliasSnapshot {
    pub source: TemporaryAliasSource,
    pub slot: u64,
    pub address: u64,
    pub writable: bool,
}

pub trait TemporaryAliasIo {
    /// Reserve an empty slot permanently for this owner. It is never returned to the free list.
    fn reserve_slot(&mut self) -> Result<u64, u32>;
    /// Failure leaves the destination empty. The source remains owned by its original registry.
    fn copy(&mut self, source: u64, slot: u64) -> Result<(), u32>;
    fn map(&mut self, slot: u64, address: u64, writable: bool) -> Result<(), u32>;
    /// Finalize the copied capability and its mapping before acknowledging an empty slot.
    fn delete(&mut self, slot: u64) -> Result<(), u32>;
}

/// Non-cloneable, allocation-free owner. Keep it in durable storage. The caller must exclude
/// source retirement while `pending()` is present and serialize all access, including callbacks.
pub struct TemporaryAlias {
    slot: u64,
    pending: Option<TemporaryAliasSnapshot>,
}

impl TemporaryAlias {
    pub const fn new() -> Self {
        Self {
            slot: 0,
            pending: None,
        }
    }

    pub fn pending(&self) -> Option<TemporaryAliasSnapshot> {
        self.pending
    }

    pub fn memory_available(&self, process: u64, base: u64, size: u64) -> bool {
        let Some(pending) = self.pending else {
            return true;
        };
        if pending.source.process != process || size == 0 {
            return true;
        }
        base.checked_add(size)
            .is_some_and(|end| end <= pending.source.page || base >= pending.source.page + 0x1000)
    }

    pub fn process_available(&self, process: u64) -> bool {
        self.pending
            .is_none_or(|pending| pending.source.process != process)
    }

    /// A copied-cap number does not identify every alias of the same physical backing. Until
    /// canonical backing identity is available here, no frame may be republished during cleanup.
    pub fn backing_release_available(&self) -> bool {
        self.pending.is_none()
    }

    /// Retire only the retained copy. Never touch the source or recycle the dedicated slot.
    pub fn drain(&mut self, io: &mut impl TemporaryAliasIo) -> Result<(), u32> {
        if let Some(pending) = self.pending {
            io.delete(pending.slot)?;
            self.pending = None;
        }
        Ok(())
    }

    /// The caller resolves the source only after draining the preceding request. This keeps stale
    /// source identities from crossing cleanup syscalls, and rejects overwriting a retained alias.
    pub fn with_frame<T>(
        &mut self,
        source: TemporaryAliasSource,
        address: u64,
        writable: bool,
        io: &mut impl TemporaryAliasIo,
        access: impl FnOnce(u64) -> T,
    ) -> Result<T, u32> {
        if self.pending.is_some() {
            return Err(RESOURCES);
        }
        if source.frame == 0
            || source.page & 0xfff != 0
            || source.page.checked_add(0x1000).is_none()
            || address == 0
            || address & 0xfff != 0
            || address.checked_add(0x1000).is_none()
        {
            return Err(INVALID);
        }
        if self.slot == 0 {
            self.slot = io.reserve_slot()?;
            if self.slot == 0 {
                return Err(RESOURCES);
            }
        }
        io.copy(source.frame, self.slot)?;
        self.pending = Some(TemporaryAliasSnapshot {
            source,
            slot: self.slot,
            address,
            writable,
        });
        if let Err(status) = io.map(self.slot, address, writable) {
            let _ = self.drain(io);
            return Err(status);
        }
        let result = access(address);
        self.drain(io)?;
        Ok(result)
    }
}

impl Default for TemporaryAlias {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "temporary_alias_tests.rs"]
mod tests;
