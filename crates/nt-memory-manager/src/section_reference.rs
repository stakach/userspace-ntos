//! Object-pointer leases, independent of Section handles and mapped views.

use super::{GenericSectionTable, SectionIdentity};
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_AUTHORITY: AtomicU64 = AtomicU64::new(1);

/// An exact, replay-resistant object reference. Copies are not additional references;
/// duplicate through the table before transferring independently owned lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "retain the lease until its object pointer is released"]
pub struct SectionReference {
    authority: u64,
    generation: u64,
    identity: SectionIdentity,
}

impl SectionReference {
    pub const fn identity(self) -> SectionIdentity {
        self.identity
    }
}

impl GenericSectionTable {
    /// The caller supplies an authoritative canonical identity, not a native pointer or handle.
    /// Reserve ownership before returning the pointer; allocation/exhaustion changes no count.
    pub fn retain_section(&mut self, identity: SectionIdentity) -> Option<SectionReference> {
        if self.section_identity(identity.index) != Some(identity) {
            return None;
        }
        let generation = self.reference_generation.checked_add(1)?;
        self.references.try_reserve(1).ok()?;
        let authority = if self.reference_authority == 0 {
            NEXT_AUTHORITY.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |next| {
                next.checked_add(1)
            }).ok()?
        } else {
            self.reference_authority
        };
        let reference = SectionReference { authority, generation, identity };
        self.references.push(reference);
        self.reference_authority = authority;
        self.reference_generation = generation;
        Some(reference)
    }

    /// Duplicate only a still-owned exact lease, including after the opening handle closed.
    pub fn retain_section_reference(&mut self, reference: SectionReference) -> Option<SectionReference> {
        if reference.authority != self.reference_authority || !self.references.contains(&reference) {
            return None;
        }
        self.retain_section(reference.identity)
    }

    /// Bind an opening handle only through a still-owned reference from this exact table.
    pub fn bind_section_reference_handle(
        &mut self,
        reference: SectionReference,
        handle: u64,
    ) -> bool {
        if reference.authority != self.reference_authority
            || !self.references.contains(&reference)
            || self.section_identity(reference.identity.index) != Some(reference.identity)
        {
            return false;
        }
        self.bind_handle(reference.identity.index, handle)
    }

    /// Consume one exact lease. Neither a consumed copy nor another table's lease is authority.
    pub fn release_section_reference(&mut self, reference: SectionReference) -> bool {
        if reference.authority != self.reference_authority
            || self.section_identity(reference.identity.index) != Some(reference.identity)
        {
            return false;
        }
        let Some(index) = self.references.iter().position(|entry| *entry == reference) else {
            return false;
        };
        let _ = self.references.swap_remove(index);
        self.clear_section_if_unreferenced(reference.identity.index);
        true
    }

    pub(super) fn section_has_references(&self, index: usize) -> bool {
        self.references.iter().any(|reference| reference.identity.index == index)
    }
}
