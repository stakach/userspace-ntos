//! Retained, initially empty paging trees for canonical Ps body mappings.
//!
//! This is mechanism preparation only: no body is allocated or published here. Each caller owns
//! one tree for an exact retained VSpace lifetime and later supplies the leaf-mapping owners.

use super::*;
use nt_memory_manager::owned_paging_structure::{
    OwnedPagingStructure, PagingStructureError, PagingStructureIo, PagingStructurePhase,
};

pub(crate) const PS_OBJECT_ARENA_BASE: u64 = 0x0000_4080_0000_0000;
pub(crate) const PS_OBJECT_ARENA_LIMIT: u64 = 0x0000_4100_0000_0000;
const PAGE_BYTES: u64 = 0x1000;
const PML4_BRANCH_BYTES: u64 = 1 << 39;

const _: () = {
    assert!(PS_OBJECT_ARENA_BASE >> 39 == 129);
    assert!(PS_OBJECT_ARENA_BASE & (PML4_BRANCH_BYTES - 1) == 0);
    assert!(PS_OBJECT_ARENA_LIMIT - PS_OBJECT_ARENA_BASE == PML4_BRANCH_BYTES);
    assert!(PS_OBJECT_ARENA_LIMIT <= 0x0000_8000_0000_0000);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Level {
    Pdpt,
    Directory,
    Table,
}

impl Level {
    const fn object_type(self) -> u64 {
        match self {
            Self::Pdpt => OBJ_X86_PDPT,
            Self::Directory => OBJ_X86_PAGE_DIRECTORY,
            Self::Table => OBJ_X86_PAGE_TABLE,
        }
    }

    const fn map_label(self) -> u64 {
        match self {
            Self::Pdpt => LBL_X86_PDPT_MAP,
            Self::Directory => LBL_X86_PAGE_DIRECTORY_MAP,
            Self::Table => LBL_X86_PAGE_TABLE_MAP,
        }
    }

    const fn unmap_label(self) -> u64 {
        match self {
            Self::Pdpt => sel4_rt::LBL_X86_PDPT_UNMAP,
            Self::Directory => sel4_rt::LBL_X86_PAGE_DIRECTORY_UNMAP,
            Self::Table => sel4_rt::LBL_X86_PAGE_TABLE_UNMAP,
        }
    }

    const fn span(self) -> u64 {
        match self {
            Self::Pdpt => 1 << 39,
            Self::Directory => 1 << 30,
            Self::Table => 1 << 21,
        }
    }
}

#[derive(Clone, Copy)]
struct Descriptor<L> {
    lifetime: L,
    pml4: u64,
    level: Level,
    base: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PsObjectPagingError {
    InvalidRoot,
    OutsideArena,
    Retiring,
    InsufficientResources,
    Mechanism(PagingStructureError),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PsObjectPagingStats {
    pub rows: usize,
    pub owned_slots: usize,
    pub mapped_tables: usize,
    pub constructing_tables: usize,
    pub retiring_tables: usize,
    pub released_tables: usize,
    pub retiring: bool,
}

/// No lifetime or handle is minted here. `L` must be the caller's existing exact lifetime value,
/// including its owning catalog/manager incarnation where the underlying identity requires one.
/// The tree is not cloneable, and failed operations leave its ownership available for retry.
#[must_use = "keep this paging tree until every retained capability is released"]
pub(crate) struct PsObjectPaging<L> {
    lifetime: L,
    pml4: u64,
    tables: Vec<OwnedPagingStructure<Descriptor<L>>>,
    retiring: bool,
}

impl<L: Copy + Eq> PsObjectPaging<L> {
    /// # Safety
    /// The caller must own and retain the exact VSpace identified by `(lifetime, pml4)` until this
    /// tree is released, reserve branch 129 exclusively for this tree, and publish this owner in
    /// durable storage before construction. `pml4` is a root-CNode capability, not a provider-local
    /// slot. No other owner may install or adopt paging structures in this branch. A reusable slot
    /// or domain ordinal alone is not an exact lifetime. Initial System's existing image mappings
    /// are separate and must not be adopted into this tree.
    pub(crate) unsafe fn new(lifetime: L, pml4: u64) -> Result<Self, PsObjectPagingError> {
        if pml4 == 0 {
            return Err(PsObjectPagingError::InvalidRoot);
        }
        Ok(Self {
            lifetime,
            pml4,
            tables: Vec::new(),
            retiring: false,
        })
    }

    fn validate_root(&self, lifetime: L, pml4: u64) -> Result<(), PsObjectPagingError> {
        if lifetime != self.lifetime || pml4 != self.pml4 {
            Err(PsObjectPagingError::InvalidRoot)
        } else {
            Ok(())
        }
    }

    /// Construct the exact three-level path for one page, with no leaf frame mapping. All missing
    /// metadata rows are reserved and published before the first capability allocation or syscall.
    /// An existing mapped row is reused only from this ledger; DELETE_FIRST is never adoption.
    ///
    /// # Safety
    /// The constructor's lifetime/exclusivity contract must still hold. Calls are root-executive
    /// serialized mechanism operations; no reentrant component dispatch may borrow this tree.
    pub(crate) unsafe fn ensure_page(
        &mut self,
        lifetime: L,
        pml4: u64,
        page: u64,
    ) -> Result<(), PsObjectPagingError> {
        self.validate_root(lifetime, pml4)?;
        if self.retiring {
            return Err(PsObjectPagingError::Retiring);
        }
        if page & (PAGE_BYTES - 1) != 0
            || !(PS_OBJECT_ARENA_BASE..PS_OBJECT_ARENA_LIMIT).contains(&page)
            || page
                .checked_add(PAGE_BYTES)
                .is_none_or(|end| end > PS_OBJECT_ARENA_LIMIT)
        {
            return Err(PsObjectPagingError::OutsideArena);
        }
        let path = [Level::Pdpt, Level::Directory, Level::Table].map(|level| Descriptor {
            lifetime: self.lifetime,
            pml4: self.pml4,
            level,
            base: page & !(level.span() - 1),
        });
        let mut indices = path.map(|descriptor| {
            self.tables.iter().position(|table| {
                let existing = table.descriptor();
                existing.level == descriptor.level && existing.base == descriptor.base
            })
        });
        let missing = indices.iter().filter(|index| index.is_none()).count();
        if missing != 0 {
            let _durable = allocator::enter_durable();
            self.tables
                .try_reserve(missing)
                .map_err(|_| PsObjectPagingError::InsufficientResources)?;
            for (descriptor, index) in path.into_iter().zip(indices.iter_mut()) {
                if index.is_none() {
                    *index = Some(self.tables.len());
                    self.tables.push(OwnedPagingStructure::new(descriptor));
                }
            }
        }
        let mut io = Io {
            lifetime: self.lifetime,
            pml4: self.pml4,
        };
        for index in indices {
            self.tables[index.expect("all paging-path rows were prepublished")]
                .construct(&mut io)
                .map_err(PsObjectPagingError::Mechanism)?;
        }
        Ok(())
    }

    /// # Safety
    /// Before this call the caller must permanently withdraw leaf admission and drain every leaf
    /// mapping/alias in this branch, including unpublished or failed-construction aliases. The
    /// exact VSpace must remain retained until success. This method then retires owned tables
    /// bottom-up; it never removes a parent while a child table still owns cleanup work.
    pub(crate) unsafe fn retire_descendants_drained(
        &mut self,
        lifetime: L,
        pml4: u64,
    ) -> Result<(), PsObjectPagingError> {
        self.validate_root(lifetime, pml4)?;
        self.retiring = true;
        let mut io = Io {
            lifetime: self.lifetime,
            pml4: self.pml4,
        };
        for level in [Level::Table, Level::Directory, Level::Pdpt] {
            for table in &mut self.tables {
                if table.descriptor().level == level {
                    table
                        .retire(&mut io)
                        .map_err(PsObjectPagingError::Mechanism)?;
                }
            }
        }
        Ok(())
    }

    pub(crate) fn is_released(&self) -> bool {
        self.retiring && self.tables.iter().all(OwnedPagingStructure::is_released)
    }

    /// Includes allocated-empty and delete-acknowledged slots still awaiting recycling.
    pub(crate) fn owns_cap(&self, cap: u64) -> bool {
        self.tables.iter().any(|table| table.owns_cap(cap))
    }

    pub(crate) fn stats(&self) -> PsObjectPagingStats {
        let mut stats = PsObjectPagingStats {
            rows: self.tables.len(),
            retiring: self.retiring,
            ..PsObjectPagingStats::default()
        };
        for table in &self.tables {
            let snapshot = table.snapshot();
            stats.owned_slots += usize::from(snapshot.capability().is_some());
            match snapshot.phase() {
                PagingStructurePhase::Vacant
                | PagingStructurePhase::Reserved
                | PagingStructurePhase::Retyped => stats.constructing_tables += 1,
                PagingStructurePhase::Mapped => stats.mapped_tables += 1,
                PagingStructurePhase::RetiringMapped
                | PagingStructurePhase::RetiringRetyped
                | PagingStructurePhase::RetiringDeleted
                | PagingStructurePhase::RetiringEmpty => stats.retiring_tables += 1,
                PagingStructurePhase::Released => stats.released_tables += 1,
            }
        }
        stats
    }
}

struct Io<L> {
    lifetime: L,
    pml4: u64,
}

fn mechanism_result(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(u32::try_from(error).unwrap_or(nt_address_space::STATUS_INVALID_PARAMETER))
    }
}

impl<L: Copy + Eq> Io<L> {
    fn validate(&self, descriptor: &Descriptor<L>) -> Result<(), u32> {
        if descriptor.lifetime != self.lifetime
            || descriptor.pml4 != self.pml4
            || descriptor.base & (descriptor.level.span() - 1) != 0
            || !(PS_OBJECT_ARENA_BASE..PS_OBJECT_ARENA_LIMIT).contains(&descriptor.base)
        {
            Err(nt_address_space::STATUS_INVALID_PARAMETER)
        } else {
            Ok(())
        }
    }
}

impl<L: Copy + Eq> PagingStructureIo<Descriptor<L>> for Io<L> {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        try_alloc_slot().ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }

    fn retype(&mut self, slot: u64, descriptor: &Descriptor<L>) -> Result<(), u32> {
        self.validate(descriptor)?;
        mechanism_result(unsafe {
            untyped_retype_r(
                CAP_INIT_UNTYPED,
                descriptor.level.object_type(),
                PAGING_BITS,
                1,
                slot,
            )
        })
    }

    fn map(&mut self, slot: u64, descriptor: &Descriptor<L>) -> Result<(), u32> {
        self.validate(descriptor)?;
        mechanism_result(unsafe {
            paging_struct_map_r(
                slot,
                descriptor.level.map_label(),
                descriptor.base,
                descriptor.pml4,
            )
        })
    }

    fn unmap(&mut self, slot: u64, descriptor: &Descriptor<L>) -> Result<(), u32> {
        self.validate(descriptor)?;
        mechanism_result(unsafe { unmap_paging_structure(slot, descriptor.level) })
    }

    fn delete(&mut self, slot: u64) -> Result<(), u32> {
        mechanism_result(unsafe { cnode_delete_r(slot) })
    }

    fn recycle_retyped(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_empty(slot) }
            .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
    }

    fn recycle_unretyped(&mut self, slot: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(slot) }
            .map_err(|_| nt_address_space::STATUS_INVALID_PARAMETER)
    }
}

/// The paging invocation wrapper supplies zero arguments for Unmap and returns its checked label.
unsafe fn unmap_paging_structure(slot: u64, level: Level) -> u64 {
    paging_struct_map_r(slot, level.unmap_label(), 0, 0)
}
