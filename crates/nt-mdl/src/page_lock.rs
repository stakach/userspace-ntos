//! Exact ownership of process pages locked on behalf of hosted MDLs.
//!
//! The ledger records intent before native pinning and retains that intent across uncertain
//! effects. It does not itself fault pages in, validate protection, or pin physical frames.

use alloc::vec::Vec;

use crate::MdlKey;

const PAGE_SIZE: u64 = 4096;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessOwner {
    pub slot: u64,
    pub generation: u64,
}

impl ProcessOwner {
    pub const fn new(slot: u64, generation: u64) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self { slot, generation })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MdlOwner {
    pub key: MdlKey,
    pub generation: u32,
}

impl MdlOwner {
    pub const fn new(key: MdlKey, generation: u32) -> Option<Self> {
        if generation == 0 {
            return None;
        }
        Some(Self { key, generation })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LockOperation {
    Read,
    Write,
    Modify,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageRange {
    first: u64,
    end: u64,
}

impl PageRange {
    pub fn for_bytes(address: u64, length: u64) -> Option<Self> {
        let last = address.checked_add(length.checked_sub(1)?)?;
        let first = address & !(PAGE_SIZE - 1);
        let end = (last & !(PAGE_SIZE - 1)).checked_add(PAGE_SIZE)?;
        Some(Self { first, end })
    }

    pub const fn first_page(self) -> u64 {
        self.first
    }

    pub const fn end_exclusive(self) -> u64 {
        self.end
    }

    pub const fn contains_page(self, page: u64) -> bool {
        page & (PAGE_SIZE - 1) == 0 && page >= self.first && page < self.end
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageLockTicket(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLockState {
    Preparing,
    Locked,
    Releasing,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageLockError {
    InvalidOwner,
    AlreadyOwned,
    UnknownTicket,
    WrongState,
    InsufficientResources,
    TicketIdsExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageLockRecord {
    pub ticket: PageLockTicket,
    pub process: ProcessOwner,
    pub mdl: MdlOwner,
    pub range: PageRange,
    pub operation: LockOperation,
    pub state: PageLockState,
}

pub struct MdlPageLockLedger {
    records: Vec<PageLockRecord>,
    next_ticket: u64,
}

impl Default for MdlPageLockLedger {
    fn default() -> Self {
        Self::new()
    }
}

impl MdlPageLockLedger {
    pub const fn new() -> Self {
        Self {
            records: Vec::new(),
            next_ticket: 1,
        }
    }

    /// Record ownership before the first native residency or pin effect.
    pub fn prepare(
        &mut self,
        process: ProcessOwner,
        mdl: MdlOwner,
        range: PageRange,
        operation: LockOperation,
    ) -> Result<PageLockTicket, PageLockError> {
        if process.generation == 0 || mdl.generation == 0
            || mdl.key.domain_id == 0 || mdl.key.domain_cookie == 0 || mdl.key.component_va == 0
        {
            return Err(PageLockError::InvalidOwner);
        }
        if self.records.iter().any(|record| record.mdl.key == mdl.key) {
            return Err(PageLockError::AlreadyOwned);
        }
        self.records
            .try_reserve(1)
            .map_err(|_| PageLockError::InsufficientResources)?;
        let next = self
            .next_ticket
            .checked_add(1)
            .ok_or(PageLockError::TicketIdsExhausted)?;
        let ticket = PageLockTicket(self.next_ticket);
        self.next_ticket = next;
        self.records.push(PageLockRecord {
            ticket,
            process,
            mdl,
            range,
            operation,
            state: PageLockState::Preparing,
        });
        Ok(ticket)
    }

    pub fn get(&self, ticket: PageLockTicket) -> Option<PageLockRecord> {
        self.records.iter().find(|record| record.ticket == ticket).copied()
    }

    /// Call only after every page has been validated and pinned for this exact process.
    pub fn commit_pinned(&mut self, ticket: PageLockTicket) -> Result<(), PageLockError> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.ticket == ticket)
            .ok_or(PageLockError::UnknownTicket)?;
        if record.state != PageLockState::Preparing {
            return Err(PageLockError::WrongState);
        }
        record.state = PageLockState::Locked;
        Ok(())
    }

    /// Remove an uncommitted intent only after proving no native pin remains.
    pub fn abort_unpinned(&mut self, ticket: PageLockTicket) -> Result<(), PageLockError> {
        self.remove_in_state(ticket, PageLockState::Preparing)
    }

    /// Retain the owner while native unpin/alias cleanup is in progress or uncertain.
    pub fn begin_release(&mut self, ticket: PageLockTicket) -> Result<(), PageLockError> {
        let record = self
            .records
            .iter_mut()
            .find(|record| record.ticket == ticket)
            .ok_or(PageLockError::UnknownTicket)?;
        if record.state != PageLockState::Locked {
            return Err(PageLockError::WrongState);
        }
        record.state = PageLockState::Releasing;
        Ok(())
    }

    /// Remove ownership only after native cleanup has been independently confirmed.
    pub fn confirm_released(&mut self, ticket: PageLockTicket) -> Result<(), PageLockError> {
        self.remove_in_state(ticket, PageLockState::Releasing)
    }

    fn remove_in_state(
        &mut self,
        ticket: PageLockTicket,
        expected: PageLockState,
    ) -> Result<(), PageLockError> {
        let index = self
            .records
            .iter()
            .position(|record| record.ticket == ticket)
            .ok_or(PageLockError::UnknownTicket)?;
        if self.records[index].state != expected {
            return Err(PageLockError::WrongState);
        }
        self.records.swap_remove(index);
        Ok(())
    }

    /// All nonterminal states count: a pending native effect forbids process-page retirement.
    pub fn page_owner_count(&self, process: ProcessOwner, page: u64) -> usize {
        self.records
            .iter()
            .filter(|record| record.process == process && record.range.contains_page(page))
            .count()
    }

    pub fn process_has_locks(&self, process: ProcessOwner) -> bool {
        self.records.iter().any(|record| record.process == process)
    }

    pub fn mdl_has_lock(&self, mdl: MdlOwner) -> bool {
        self.records.iter().any(|record| record.mdl == mdl)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owners(n: u64) -> (ProcessOwner, MdlOwner) {
        (
            ProcessOwner::new(1, 2).unwrap(),
            MdlOwner::new(MdlKey::new(3, 4, n).unwrap(), 5).unwrap(),
        )
    }

    #[test]
    fn overlapping_mdls_retain_independent_page_owners() {
        let mut ledger = MdlPageLockLedger::new();
        let (process, first) = owners(0x1000);
        let (_, second) = owners(0x2000);
        let range = PageRange::for_bytes(0x1fff, 2).unwrap();
        let a = ledger.prepare(process, first, range, LockOperation::Read).unwrap();
        let b = ledger.prepare(process, second, range, LockOperation::Write).unwrap();
        ledger.commit_pinned(a).unwrap();
        ledger.commit_pinned(b).unwrap();
        assert_eq!(ledger.page_owner_count(process, 0x1000), 2);
        assert_eq!(ledger.page_owner_count(process, 0x2000), 2);
        ledger.begin_release(a).unwrap();
        assert_eq!(ledger.page_owner_count(process, 0x1000), 2);
        ledger.confirm_released(a).unwrap();
        assert_eq!(ledger.page_owner_count(process, 0x1000), 1);
        assert!(ledger.mdl_has_lock(second));
        assert!(ledger.process_has_locks(process));
    }

    #[test]
    fn uncertain_pin_and_release_remain_owned() {
        let mut ledger = MdlPageLockLedger::new();
        let (process, mdl) = owners(0x1000);
        let range = PageRange::for_bytes(0x2123, 100).unwrap();
        let ticket = ledger.prepare(process, mdl, range, LockOperation::Modify).unwrap();
        assert_eq!(ledger.page_owner_count(process, 0x2000), 1);
        assert_eq!(ledger.prepare(process, mdl, range, LockOperation::Read), Err(PageLockError::AlreadyOwned));
        assert_eq!(ledger.begin_release(ticket), Err(PageLockError::WrongState));
        ledger.commit_pinned(ticket).unwrap();
        assert_eq!(ledger.abort_unpinned(ticket), Err(PageLockError::WrongState));
        ledger.begin_release(ticket).unwrap();
        assert_eq!(ledger.begin_release(ticket), Err(PageLockError::WrongState));
        assert_eq!(ledger.page_owner_count(process, 0x2000), 1);
        ledger.confirm_released(ticket).unwrap();
        assert!(!ledger.process_has_locks(process));
    }

    #[test]
    fn process_generation_and_range_are_exact() {
        let mut ledger = MdlPageLockLedger::new();
        let (process, mdl) = owners(0x1000);
        assert!(ProcessOwner::new(0, 2).is_some());
        assert!(PageRange::for_bytes(0, 0).is_none());
        assert!(PageRange::for_bytes(u64::MAX, 1).is_none());
        let range = PageRange::for_bytes(0x2fff, 2).unwrap();
        let ticket = ledger.prepare(process, mdl, range, LockOperation::Read).unwrap();
        assert_eq!(range.first_page(), 0x2000);
        assert_eq!(range.end_exclusive(), 0x4000);
        assert_eq!(ledger.page_owner_count(ProcessOwner::new(1, 3).unwrap(), 0x2000), 0);
        assert_eq!(ledger.page_owner_count(process, 0x2001), 0);
        let reused = MdlOwner::new(mdl.key, mdl.generation + 1).unwrap();
        assert_eq!(ledger.prepare(process, reused, range, LockOperation::Read), Err(PageLockError::AlreadyOwned));
        ledger.abort_unpinned(ticket).unwrap();
        assert_eq!(ledger.abort_unpinned(ticket), Err(PageLockError::UnknownTicket));
    }
}
