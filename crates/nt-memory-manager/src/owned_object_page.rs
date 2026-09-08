//! A canonical unmapped object frame and all of its explicitly owned mapping aliases.

use crate::alias_transition::{AliasTransition, AliasTransitionIo};
use crate::retained_alias::AliasRetirementIo;
use alloc::vec::Vec;

const INVALID: u32 = crate::STATUS_INVALID_HANDLE;
const RESOURCES: u32 = 0xc000_009a;

/// seL4 read and write rights for the executive's initialization mapping.
pub const ROOT_ALIAS_RIGHTS: u64 = 3;

/// Synchronous mechanism boundary. Calls may not reenter this owner or its containing ledger.
/// D and L must carry genuine, retained object and VSpace identities; this core mints neither.
/// Raw integers are identifiers only, never proof of authority without backend validation.
/// All targets describe the same page at their exact mapping address. Preparing page tables
/// must retain their ownership separately, including on failure. No untracked aliases may escape.
pub trait ObjectPageIo<D, L: Copy + Eq> {
    /// Transfer one exclusively owned, zeroed, UNMAPPED frame. Err transfers nothing and must
    /// not hide an acquired frame. The backend retains its own partial acquisition on error.
    fn acquire_zeroed_frame(&mut self, descriptor: &D) -> Result<u64, u32>;
    fn prepare_alias(&mut self, descriptor: &D, target: L) -> Result<(), u32>;
    /// Return every reserved alias slot, including empty slots on failed copy. A successful
    /// nonzero slot owns a copied unmapped cap, never the canonical frame's original cap.
    fn copy(&mut self, frame: u64, target: L) -> (u64, u32);
    /// Failure leaves the alias unmapped. Rights are supplied unchanged, not synthesized.
    fn map(&mut self, slot: u64, target: L, rights: u64) -> Result<(), u32>;
    fn unmap(&mut self, slot: u64, target: L) -> Result<(), u32>;
    fn delete(&mut self, slot: u64, target: L) -> Result<(), u32>;
    /// Publish only an empty, unretyped alias slot. Err preserves allocator ownership exactly.
    fn recycle_alias(&mut self, slot: u64, target: L) -> Result<(), u32>;
    /// Initialize fresh unpublished bytes through the root alias. This may be retried after Err
    /// and must be idempotent until successful. It must not publish objects or enter a provider.
    fn initialize(&mut self, descriptor: &D, root_target: L) -> Result<(), u32>;
    /// Checked transfer of the original backing owner, called only after every alias is empty.
    /// Err retains that exact frame in this owner; no hidden partial transfer is permitted.
    fn release_backing(&mut self, frame: u64) -> Result<(), u32>;
}

struct Alias<L> {
    target: L,
    transition: AliasTransition,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ObjectPageStats {
    pub backing_frames: usize,
    pub alias_rows: usize,
    pub alias_caps: usize,
    pub live_aliases: usize,
    pub pending_aliases: usize,
    pub initialized: bool,
    pub retiring: bool,
    pub released: bool,
}

/// Durable, nonclone ownership. Place it in its containing ledger before calling construct.
/// Dropping does not release mechanisms: retain the owner until `is_released()` is true.
/// The descriptor and target identities must not be mutated through interior mutability.
/// Mapping does not grant a provider permission to acquire a Ps pointer; that admission and
/// provider execution rundown remain the caller's responsibility before retirement starts.
///
/// ```compile_fail
/// use nt_memory_manager::owned_object_page::OwnedObjectPage;
/// let page = OwnedObjectPage::new(7u64, 1u64);
/// let duplicate = page.clone();
/// ```
#[must_use = "retain object backing and alias owners until checked retirement completes"]
pub struct OwnedObjectPage<D, L: Copy + Eq> {
    descriptor: D,
    root_target: L,
    frame: Option<u64>,
    aliases: Vec<Alias<L>>,
    initialized: bool,
    retiring: bool,
}

impl<D, L: Copy + Eq> OwnedObjectPage<D, L> {
    pub const fn new(descriptor: D, root_target: L) -> Self {
        Self {
            descriptor,
            root_target,
            frame: None,
            aliases: Vec::new(),
            initialized: false,
            retiring: false,
        }
    }

    pub const fn descriptor(&self) -> &D {
        &self.descriptor
    }
    pub const fn root_target(&self) -> L {
        self.root_target
    }
    /// Ownership inspection only, not permission to map or transfer the original cap.
    pub const fn frame_cap(&self) -> Option<u64> {
        self.frame
    }
    pub const fn is_initialized(&self) -> bool {
        self.initialized && !self.retiring
    }
    pub fn is_released(&self) -> bool {
        self.retiring
            && self.frame.is_none()
            && self.aliases.iter().all(|row| row.transition.is_empty())
    }

    pub fn owns_cap(&self, cap: u64) -> bool {
        cap != 0
            && (self.frame == Some(cap)
                || self.aliases.iter().any(|row| {
                    row.transition
                        .snapshot()
                        .capabilities()
                        .any(|owned| owned == cap)
                }))
    }

    pub fn live_alias(&self, target: L) -> Option<(u64, u64)> {
        if !self.is_initialized() {
            return None;
        }
        self.aliases
            .iter()
            .find(|row| row.target == target)?
            .transition
            .live()
    }

    pub fn stats(&self) -> ObjectPageStats {
        ObjectPageStats {
            backing_frames: usize::from(self.frame.is_some()),
            alias_rows: self.aliases.len(),
            alias_caps: self
                .aliases
                .iter()
                .map(|row| row.transition.snapshot().capabilities().count())
                .sum(),
            live_aliases: self
                .aliases
                .iter()
                .filter(|row| row.transition.live().is_some())
                .count(),
            pending_aliases: self
                .aliases
                .iter()
                .filter(|row| !row.transition.is_empty() && row.transition.live().is_none())
                .count(),
            initialized: self.initialized,
            retiring: self.retiring,
            released: self.is_released(),
        }
    }

    /// Complete the root alias and initialization, retaining each successful stage on error.
    /// Repeated construction of an initialized owner never touches live object bytes.
    pub fn construct(&mut self, io: &mut impl ObjectPageIo<D, L>) -> Result<(), u32> {
        if self.retiring {
            return Err(INVALID);
        }
        if self.initialized {
            return Ok(());
        }
        if self.frame.is_none() {
            let frame = io.acquire_zeroed_frame(&self.descriptor)?;
            if frame == 0 {
                return Err(RESOURCES);
            }
            self.frame = Some(frame);
        }
        self.ensure_alias(self.root_target, ROOT_ALIAS_RIGHTS, io)?;
        io.initialize(&self.descriptor, self.root_target)?;
        self.initialized = true;
        Ok(())
    }

    /// Publish or change one exact target alias. A failed target does not invalidate other
    /// live targets. Recovery drains its retained failed candidate before another copy/remap.
    pub fn map_alias(
        &mut self,
        target: L,
        rights: u64,
        io: &mut impl ObjectPageIo<D, L>,
    ) -> Result<(), u32> {
        if !self.is_initialized() || (target == self.root_target && rights != ROOT_ALIAS_RIGHTS) {
            return Err(INVALID);
        }
        self.ensure_alias(target, rights, io)
    }

    fn ensure_alias(
        &mut self,
        target: L,
        rights: u64,
        io: &mut impl ObjectPageIo<D, L>,
    ) -> Result<(), u32> {
        let frame = self.frame.ok_or(INVALID)?;
        let index = match self.aliases.iter().position(|row| row.target == target) {
            Some(index) => index,
            None => {
                self.aliases.try_reserve(1).map_err(|_| RESOURCES)?;
                self.aliases.push(Alias {
                    target,
                    transition: AliasTransition::empty(),
                });
                self.aliases.len() - 1
            }
        };
        let transition = &mut self.aliases[index].transition;
        if transition
            .live()
            .is_some_and(|(_, current)| current == rights)
        {
            return Ok(());
        }
        io.prepare_alias(&self.descriptor, target)?;
        let mut adapter = Io {
            backend: io,
            frame,
            target,
            descriptor: core::marker::PhantomData::<D>,
        };
        transition.recover(&mut adapter)?;
        match transition.live() {
            Some((_, current)) if current == rights => Ok(()),
            Some(_) => transition.remap(rights, &mut adapter),
            None => transition.replace(rights, &mut adapter),
        }
    }

    /// Caller first withdraws pointer/execution admission. This permanently withdraws alias
    /// admission and releases all live, failed-copy and failed-map slots before backing transfer.
    /// Nonroot aliases drain first so failed provider cleanup retains the root mapping.
    /// It is valid even if construction never finished; no initialization is performed here.
    pub fn retire(&mut self, io: &mut impl ObjectPageIo<D, L>) -> Result<(), u32> {
        self.retiring = true;
        for root_pass in [false, true] {
            for row in &mut self.aliases {
                if (row.target == self.root_target) != root_pass {
                    continue;
                }
                let mut adapter = Io {
                    backend: io,
                    frame: self.frame.unwrap_or(0),
                    target: row.target,
                    descriptor: core::marker::PhantomData::<D>,
                };
                row.transition.retire(&mut adapter)?;
            }
        }
        if let Some(frame) = self.frame {
            io.release_backing(frame)?;
            self.frame = None;
        }
        Ok(())
    }
}

struct Io<'a, I, D, L> {
    backend: &'a mut I,
    frame: u64,
    target: L,
    descriptor: core::marker::PhantomData<D>,
}

impl<D, L: Copy + Eq, I: ObjectPageIo<D, L>> AliasRetirementIo for Io<'_, I, D, L> {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.backend.unmap(cap, self.target)
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.backend.delete(cap, self.target)
    }
    fn recycle_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.backend.recycle_alias(cap, self.target)
    }
    fn recycle_unretyped_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.backend.recycle_alias(cap, self.target)
    }
}

impl<D, L: Copy + Eq, I: ObjectPageIo<D, L>> AliasTransitionIo for Io<'_, I, D, L> {
    fn copy(&mut self) -> (u64, u32) {
        self.backend.copy(self.frame, self.target)
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.backend.map(cap, self.target, rights)
    }
}

#[cfg(test)]
#[path = "owned_object_page_tests.rs"]
mod tests;
