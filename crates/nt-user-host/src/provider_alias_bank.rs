//! Exact ownership of provider leaf aliases moved from root slots into child CNodes.
//!
//! The caller serializes the entire operation, including backend calls. Segment construction is
//! a separate backend owner. Source frames and PML4s are borrowed and must outlive retained rows.
use crate::process_identity::ProcessIdentity;
use crate::thread_rollback::ThreadRollbackId;
#[path = "provider_alias_segment.rs"]
pub mod segment;
#[path = "thread_provider_alias_journal.rs"]
pub mod thread_journal;
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderAliasRequest {
    pub pi: usize,
    pub process: ProcessIdentity,
    pub page: u64,
    pub pml4: u64,
    pub source_frame: u64,
    pub rights: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderAliasHandle {
    index: usize,
    generation: u64,
}

impl ProviderAliasHandle {
    pub fn index(self) -> usize {
        self.index
    }
    pub fn generation(self) -> u64 {
        self.generation
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChildCap {
    pub cnode: u64,
    pub slot: u64,
}

/// Root slot numbers and child-CNode slot numbers belong to different namespaces.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderAliasCapability {
    Root(u64),
    Child(ChildCap),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootAliasSnapshot {
    pub slot: u64,
    pub populated: bool,
    pub mapped: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProviderAliasSnapshot {
    pub handle: ProviderAliasHandle,
    pub request: ProviderAliasRequest,
    pub root: Option<RootAliasSnapshot>,
    pub child: Option<ChildCap>,
    pub releasing: bool,
    pub claim: Option<ThreadRollbackId>,
}

impl ProviderAliasSnapshot {
    /// Leaf ownership only. Source frames, PML4s and segment CNodes are borrowed provenance.
    pub fn owned_capabilities(self) -> impl Iterator<Item = ProviderAliasCapability> {
        [
            self.root
                .map(|root| ProviderAliasCapability::Root(root.slot)),
            self.child.map(ProviderAliasCapability::Child),
        ]
        .into_iter()
        .flatten()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BankError {
    InvalidRequest,
    OwnerChanged,
    RequestConflict,
    Releasing,
    InsufficientResources,
    StaleHandle,
    InvalidBackend,
    Claimed,
    NotClaimed,
    SharedCapability(ProviderAliasCapability),
    Backend(u32),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ProviderAliasStats {
    pub entries: usize,
    pub live: usize,
    pub mapped: usize,
    pub high_water: usize,
    pub moves: u64,
    pub releases: u64,
    pub failures: u64,
}

pub trait ProviderAliasIo {
    /// Transfer a uniquely reserved root slot even when copying fails. A failed copy leaves it
    /// empty. Zero on failure means no slot was acquired; zero on success is invalid.
    fn copy(&mut self, source: u64) -> (u64, u32);
    fn map(&mut self, root: u64, page: u64, rights: u64, pml4: u64) -> Result<(), u32>;
    fn ensure_segment(&mut self, segment: usize) -> Result<u64, u32>;
    /// Success moves the mapped capability and leaves the root slot empty. Failure moves nothing.
    fn move_to_child(&mut self, root: u64, child: ChildCap) -> Result<(), u32>;
    fn recycle_empty_root(&mut self, root: u64) -> Result<(), u32>;
    /// Successful deletion finalizes any mapping; it does not recycle the root slot.
    fn delete_root(&mut self, root: u64) -> Result<(), u32>;
    /// Successful deletion finalizes the mapping. The bank itself owns child slot reuse.
    fn delete_child(&mut self, child: ChildCap) -> Result<(), u32>;
}

struct Row {
    request: ProviderAliasRequest,
    root: Option<RootAliasSnapshot>,
    child: Option<ChildCap>,
    releasing: bool,
    claim: Option<ThreadRollbackId>,
}

impl Row {
    fn retire(&mut self, io: &mut impl ProviderAliasIo) -> Result<(), BankError> {
        if let Some(child) = self.child {
            io.delete_child(child).map_err(BankError::Backend)?;
            self.child = None;
        }
        if let Some(root) = self.root.as_mut() {
            if root.populated {
                io.delete_root(root.slot).map_err(BankError::Backend)?;
                root.populated = false;
                root.mapped = false;
            }
            io.recycle_empty_root(root.slot)
                .map_err(BankError::Backend)?;
            self.root = None;
        }
        Ok(())
    }
}

struct Slot {
    generation: u64,
    row: Option<Row>,
}

struct ProcessRows {
    pi: usize,
    process: ProcessIdentity,
    releasing: bool,
    pages: Vec<(u64, ProviderAliasHandle)>,
}

pub struct ProviderAliasBank {
    slots: Vec<Slot>,
    free: Vec<usize>,
    processes: Vec<ProcessRows>,
    segment_cnodes: Vec<Option<u64>>,
    live: usize,
    segment_slots: u64,
    capacity: usize,
    high_water: usize,
    moves: u64,
    releases: u64,
    failures: u64,
}

impl ProviderAliasBank {
    pub fn new(segment_slots: u64, max_segments: usize) -> Result<Self, BankError> {
        let capacity = usize::try_from(segment_slots)
            .ok()
            .and_then(|slots| slots.checked_mul(max_segments))
            .filter(|capacity| *capacity != 0)
            .ok_or(BankError::InvalidRequest)?;
        let mut segment_cnodes = Vec::new();
        segment_cnodes
            .try_reserve_exact(max_segments)
            .map_err(|_| BankError::InsufficientResources)?;
        segment_cnodes.resize(max_segments, None);
        Ok(Self {
            slots: Vec::new(),
            free: Vec::new(),
            processes: Vec::new(),
            live: 0,
            segment_cnodes,
            segment_slots,
            capacity,
            high_water: 0,
            moves: 0,
            releases: 0,
            failures: 0,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.live == 0
    }
    pub fn entry_count(&self) -> usize {
        self.slots.len()
    }
    pub fn process_is_empty(&self, pi: usize) -> bool {
        !self.processes.iter().any(|process| process.pi == pi)
    }

    pub fn admit_process(&self, pi: usize, process: ProcessIdentity) -> Result<(), BankError> {
        if !process.is_valid() {
            return Err(BankError::InvalidRequest);
        }
        if let Some(current) = self.processes.iter().find(|current| current.pi == pi) {
            if current.process != process {
                return Err(BankError::OwnerChanged);
            }
            if current.releasing {
                return Err(BankError::Releasing);
            }
        }
        Ok(())
    }

    pub fn mapped_prefix(
        &self,
        pi: usize,
        process: ProcessIdentity,
        base: u64,
        count: u64,
        pml4: u64,
        source_base: u64,
        rights: u64,
    ) -> bool {
        if self.admit_process(pi, process).is_err() {
            return false;
        }
        let Some(current) = self.processes.iter().find(|current| current.pi == pi) else {
            return count == 0;
        };
        for offset in 0..count {
            let Some(page) = offset
                .checked_mul(4096)
                .and_then(|bytes| base.checked_add(bytes))
            else {
                return false;
            };
            let Some(source_frame) = source_base.checked_add(offset) else {
                return false;
            };
            let Ok(position) = current.pages.binary_search_by_key(&page, |(page, _)| *page) else {
                return false;
            };
            let handle = current.pages[position].1;
            let slot = &self.slots[handle.index];
            if slot.generation != handle.generation {
                return false;
            }
            let Some(row) = slot.row.as_ref() else {
                return false;
            };
            if row.claim.is_some()
                || row.root.is_some()
                || row.child.is_none()
                || row.request
                    != (ProviderAliasRequest {
                        pi,
                        process,
                        page,
                        pml4,
                        source_frame,
                        rights,
                    })
            {
                return false;
            }
        }
        true
    }

    pub fn snapshots(&self) -> impl Iterator<Item = ProviderAliasSnapshot> + '_ {
        self.slots.iter().enumerate().filter_map(|(index, slot)| {
            let row = slot.row.as_ref()?;
            Some(ProviderAliasSnapshot {
                handle: ProviderAliasHandle {
                    index,
                    generation: slot.generation,
                },
                request: row.request,
                root: row.root,
                child: row.child,
                releasing: row.releasing,
                claim: row.claim,
            })
        })
    }

    pub fn get(&self, handle: ProviderAliasHandle) -> Option<ProviderAliasSnapshot> {
        let slot = self.slots.get(handle.index)?;
        if slot.generation != handle.generation {
            return None;
        }
        let row = slot.row.as_ref()?;
        Some(ProviderAliasSnapshot {
            handle,
            request: row.request,
            root: row.root,
            child: row.child,
            releasing: row.releasing,
            claim: row.claim,
        })
    }

    pub fn owns_root_cap(&self, cap: u64) -> bool {
        self.snapshots()
            .any(|row| row.root.is_some_and(|root| root.slot == cap))
    }

    pub fn owns_child_cap(&self, cap: ChildCap) -> bool {
        self.snapshots().any(|row| row.child == Some(cap))
    }

    pub fn stats(&self) -> ProviderAliasStats {
        let mut stats = ProviderAliasStats {
            entries: self.slots.len(),
            high_water: self.high_water,
            moves: self.moves,
            releases: self.releases,
            failures: self.failures,
            ..ProviderAliasStats::default()
        };
        for row in self.slots.iter().filter_map(|slot| slot.row.as_ref()) {
            stats.live += 1;
            stats.mapped +=
                usize::from(row.child.is_some() || row.root.is_some_and(|root| root.mapped));
        }
        stats
    }

    fn reserve(&mut self, request: ProviderAliasRequest) -> Result<usize, BankError> {
        if !request.process.is_valid()
            || request.pml4 == 0
            || request.source_frame == 0
            || request.page & 4095 != 0
            || request.page.checked_add(4096).is_none()
        {
            return Err(BankError::InvalidRequest);
        }
        self.admit_process(request.pi, request.process)?;
        let process_index = self
            .processes
            .iter()
            .position(|process| process.pi == request.pi);
        let insertion = if let Some(process_index) = process_index {
            match self.processes[process_index]
                .pages
                .binary_search_by_key(&request.page, |(page, _)| *page)
            {
                Ok(position) => {
                    let handle = self.processes[process_index].pages[position].1;
                    let index = handle.index;
                    assert_eq!(self.slots[index].generation, handle.generation);
                    let row = self.slots[index].row.as_ref().expect("live page index");
                    if row.claim.is_some() {
                        return Err(BankError::Claimed);
                    }
                    if row.request != request {
                        return Err(BankError::RequestConflict);
                    }
                    return Ok(index);
                }
                Err(position) => position,
            }
        } else {
            0
        };
        if self.free.is_empty() && self.slots.len() == self.capacity {
            return Err(BankError::InsufficientResources);
        }
        // Reserve both ownership indexing and every eventual free publication before effects.
        let mut new_pages = Vec::new();
        if let Some(index) = process_index {
            self.processes[index]
                .pages
                .try_reserve(1)
                .map_err(|_| BankError::InsufficientResources)?;
        } else {
            self.processes
                .try_reserve(1)
                .map_err(|_| BankError::InsufficientResources)?;
            new_pages
                .try_reserve(1)
                .map_err(|_| BankError::InsufficientResources)?;
        }
        if self.free.is_empty() {
            self.slots
                .try_reserve(1)
                .map_err(|_| BankError::InsufficientResources)?;
            self.free
                .try_reserve(self.slots.len() + 1 - self.free.len())
                .map_err(|_| BankError::InsufficientResources)?;
        }
        let index = match self.free.pop() {
            Some(index) => index,
            None => {
                self.slots.push(Slot {
                    generation: 0,
                    row: None,
                });
                self.slots.len() - 1
            }
        };
        let process_index = process_index.unwrap_or_else(|| {
            self.processes.push(ProcessRows {
                pi: request.pi,
                process: request.process,
                releasing: false,
                pages: new_pages,
            });
            self.processes.len() - 1
        });
        let slot = &mut self.slots[index];
        slot.generation += 1;
        slot.row = Some(Row {
            request,
            root: None,
            child: None,
            releasing: false,
            claim: None,
        });
        self.processes[process_index].pages.insert(
            insertion,
            (
                request.page,
                ProviderAliasHandle {
                    index,
                    generation: slot.generation,
                },
            ),
        );
        self.live += 1;
        self.high_water = self.high_water.max(self.live);
        Ok(index)
    }

    pub fn map(
        &mut self,
        request: ProviderAliasRequest,
        io: &mut impl ProviderAliasIo,
    ) -> Result<ProviderAliasHandle, BankError> {
        let result = self.map_inner(request, io);
        if result.is_err() {
            self.failures = self.failures.saturating_add(1);
        }
        result
    }

    fn map_inner(
        &mut self,
        request: ProviderAliasRequest,
        io: &mut impl ProviderAliasIo,
    ) -> Result<ProviderAliasHandle, BankError> {
        let index = self.reserve(request)?;
        let slot = &mut self.slots[index];
        let row = slot.row.as_mut().expect("reserved alias row");
        // Empty roots are retained after either failed copying or a completed move. Recycling
        // precedes acquiring anything else, and a moved child is never copied or mapped again.
        if let Some(root) = row.root.filter(|root| !root.populated) {
            io.recycle_empty_root(root.slot)
                .map_err(BankError::Backend)?;
            row.root = None;
        }
        if row.child.is_none() {
            if row.root.is_none() {
                let (cap, status) = io.copy(request.source_frame);
                if cap != 0 {
                    row.root = Some(RootAliasSnapshot {
                        slot: cap,
                        populated: status == 0,
                        mapped: false,
                    });
                }
                if status != 0 {
                    return Err(BankError::Backend(status));
                }
                if cap == 0 {
                    return Err(BankError::InvalidBackend);
                }
            }
            let root = row.root.as_mut().expect("copy retained its root");
            if !root.mapped {
                io.map(root.slot, request.page, request.rights, request.pml4)
                    .map_err(BankError::Backend)?;
                root.mapped = true;
            }
            let segment = (index as u64 / self.segment_slots) as usize;
            let cnode = io.ensure_segment(segment).map_err(BankError::Backend)?;
            if cnode == 0 {
                return Err(BankError::InvalidBackend);
            }
            if self.segment_cnodes[segment].is_some_and(|known| known != cnode)
                || self
                    .segment_cnodes
                    .iter()
                    .enumerate()
                    .any(|(index, known)| index != segment && *known == Some(cnode))
            {
                return Err(BankError::InvalidBackend);
            }
            self.segment_cnodes[segment] = Some(cnode);
            let child = ChildCap {
                cnode,
                slot: index as u64 % self.segment_slots,
            };
            io.move_to_child(root.slot, child)
                .map_err(BankError::Backend)?;
            root.populated = false;
            root.mapped = false;
            row.child = Some(child);
            self.moves = self.moves.saturating_add(1);
            io.recycle_empty_root(root.slot)
                .map_err(BankError::Backend)?;
            row.root = None;
        }
        Ok(ProviderAliasHandle {
            index,
            generation: slot.generation,
        })
    }

    pub fn release_process(
        &mut self,
        pi: usize,
        process: ProcessIdentity,
        io: &mut impl ProviderAliasIo,
    ) -> Result<(), BankError> {
        let result = self.release_inner(pi, process, io);
        if result.is_err() {
            self.failures = self.failures.saturating_add(1);
        }
        result
    }

    fn release_inner(
        &mut self,
        pi: usize,
        process: ProcessIdentity,
        io: &mut impl ProviderAliasIo,
    ) -> Result<(), BankError> {
        if !process.is_valid() {
            return Err(BankError::InvalidRequest);
        }
        let Some(process_index) = self.processes.iter().position(|current| current.pi == pi) else {
            return Ok(());
        };
        let current = &mut self.processes[process_index];
        if current.process != process {
            return Err(BankError::OwnerChanged);
        }
        for &(_, handle) in &current.pages {
            let slot = &self.slots[handle.index];
            if slot.generation == handle.generation
                && slot.row.as_ref().is_some_and(|row| row.claim.is_some())
            {
                return Err(BankError::Claimed);
            }
        }
        current.releasing = true;
        // Fence every row before the first backend call. Partial release cannot reopen admission.
        for &(_, handle) in &current.pages {
            let slot = &mut self.slots[handle.index];
            if slot.generation != handle.generation {
                continue;
            }
            if let Some(row) = slot.row.as_mut() {
                row.releasing = true;
            }
        }
        for &(_, handle) in &current.pages {
            let index = handle.index;
            let slot = &mut self.slots[index];
            if slot.generation != handle.generation {
                continue;
            }
            let Some(row) = slot.row.as_mut() else {
                continue;
            };
            row.retire(io)?;
            slot.row = None;
            if slot.generation != u64::MAX {
                self.free.push(index);
            }
            self.live -= 1;
            self.releases = self.releases.saturating_add(1);
        }
        self.processes.swap_remove(process_index);
        Ok(())
    }

    /// Private journal driver. The complete disjoint-journal and quiescence checks belong to the
    /// caller; this method validates every index before effects and acknowledges removal in place.
    fn retire_claimed(
        &mut self,
        handle: ProviderAliasHandle,
        id: ThreadRollbackId,
        io: &mut impl ProviderAliasIo,
    ) -> Result<(), BankError> {
        let snapshot = self.get(handle).ok_or(BankError::StaleHandle)?;
        if snapshot.claim != Some(id) {
            return Err(BankError::OwnerChanged);
        }
        let identity = id.identity();
        let process = ProcessIdentity {
            pid: identity.pid,
            generation: identity.process_generation,
        };
        if snapshot.request.pi != identity.pi || snapshot.request.process != process {
            return Err(BankError::OwnerChanged);
        }
        self.admit_process(identity.pi, process)?;
        let process_index = self
            .processes
            .iter()
            .position(|row| row.pi == identity.pi)
            .ok_or(BankError::OwnerChanged)?;
        let position = self.processes[process_index]
            .pages
            .binary_search_by_key(&snapshot.request.page, |(page, _)| *page)
            .map_err(|_| BankError::StaleHandle)?;
        if self.processes[process_index].pages[position].1 != handle {
            return Err(BankError::StaleHandle);
        }
        let slot = &mut self.slots[handle.index];
        slot.row
            .as_mut()
            .expect("validated claimed row")
            .retire(io)?;
        slot.row = None;
        self.processes[process_index].pages.remove(position);
        if self.processes[process_index].pages.is_empty() {
            self.processes.swap_remove(process_index);
        }
        if slot.generation != u64::MAX {
            self.free.push(handle.index);
        }
        self.live -= 1;
        self.releases = self.releases.saturating_add(1);
        Ok(())
    }
}

#[cfg(test)]
#[path = "provider_alias_bank_tests.rs"]
mod tests;
