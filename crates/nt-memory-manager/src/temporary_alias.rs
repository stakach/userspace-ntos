//! One permanently reserved scratch slot, with retry-owned mapping cleanup.

const RESOURCES: u32 = 0xc000_009a;
const INVALID: u32 = 0xc000_000d;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporaryAliasScope {
    ClientPage {
        process: u64,
        page: u64,
    },
    /// No proven process/page identity; exclude all address spaces until cleanup completes.
    Frame,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporaryAliasSource {
    pub scope: TemporaryAliasScope,
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
        if size == 0 {
            return true;
        }
        let TemporaryAliasScope::ClientPage {
            process: owner,
            page,
        } = pending.source.scope
        else {
            return false;
        };
        if owner != process {
            return true;
        }
        base.checked_add(size)
            .is_some_and(|end| end <= page || base >= page + 0x1000)
    }

    pub fn process_available(&self, process: u64) -> bool {
        self.pending.is_none_or(|pending| {
            matches!(pending.source.scope,
            TemporaryAliasScope::ClientPage { process: owner, .. } if owner != process)
        })
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
        let invalid_source = match source.scope {
            TemporaryAliasScope::ClientPage { page, .. } => {
                page & 0xfff != 0 || page.checked_add(0x1000).is_none()
            }
            TemporaryAliasScope::Frame => false,
        };
        if source.frame == 0
            || invalid_source
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

    pub fn with_range<T>(
        &mut self,
        source: TemporaryAliasSource,
        address: u64,
        range: core::ops::Range<usize>,
        writable: bool,
        io: &mut impl TemporaryAliasIo,
        access: impl FnOnce(u64) -> T,
    ) -> Result<T, u32> {
        if range.start > range.end || range.end > 0x1000 {
            return Err(INVALID);
        }
        self.with_frame(source, address, writable, io, |address| {
            access(address + range.start as u64)
        })
    }

    /// Retire the read alias before touching the destination. The local buffer is never lent
    /// across backend calls; each closure performs only a synchronous bounded memory transfer.
    #[inline(never)]
    pub fn copy_page(
        &mut self,
        source: u64,
        destination: u64,
        address: u64,
        io: &mut impl TemporaryAliasIo,
        read: impl FnOnce(u64, &mut [u8; 0x1000]),
        write: impl FnOnce(u64, &[u8; 0x1000]),
    ) -> Result<(), u32> {
        if destination == 0 {
            return Err(INVALID);
        }
        let mut bytes = [0u8; 0x1000];
        self.with_frame(
            TemporaryAliasSource {
                scope: TemporaryAliasScope::Frame,
                frame: source,
            },
            address,
            false,
            io,
            |address| read(address, &mut bytes),
        )?;
        self.with_frame(
            TemporaryAliasSource {
                scope: TemporaryAliasScope::Frame,
                frame: destination,
            },
            address,
            true,
            io,
            |address| write(address, &bytes),
        )
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
