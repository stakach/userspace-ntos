//! Reserve-only session views: the `SEC_RESERVE` Sections win32k maps with
//! `MmMapViewInSessionSpace` for the global USER heap and every desktop heap.
//!
//! NT reserves such a view at its full size, but a page is backed only once it is committed:
//! `MEM_COMMIT` inside a view of the Section (`IntUserHeapCommitRoutine`, or the heap's own
//! growth) commits the Section's page for every view, and touching a page that was never committed
//! is an access violation (`MiResolveDemandZeroFault` is never reached for a zero prototype PTE).
//! Section pages cannot be decommitted or freed through a view (`STATUS_UNABLE_TO_DELETE_SECTION`);
//! they are released together when the Section itself is deleted.
//!
//! This ledger owns one virtual band of such views. It is pure state: the executive performs the
//! native frame, mapping and alias effects and reports each one back, so an uncertain effect stays
//! quarantined against reuse. Physical frames are recorded only for committed pages, which is the
//! band's entire physical cost. A committed page is backed when it is committed rather than on
//! first touch, because the executive itself reads USER structures through the same addresses and
//! must never fault on a committed page.
//!
//! Clients are hosted GUI processes that project the band read-only. Each committed page records
//! which admitted clients already hold its alias, so a commit can be pushed to every client and a
//! newly connected client can catch up on every page committed before it.

use alloc::vec::Vec;

pub const PAGE_SIZE: u64 = 0x1000;
/// `MM_ALLOCATION_GRANULARITY`: view bases are 64 KiB aligned, as NT places mapped views.
pub const VIEW_ALIGNMENT: u64 = 0x1_0000;
/// Client process indices are bits of a `u64`.
pub const MAX_CLIENTS: usize = 64;

pub const STATUS_NO_MEMORY: u32 = 0xC000_0017;
pub const STATUS_CONFLICTING_ADDRESSES: u32 = 0xC000_0018;
pub const STATUS_UNABLE_TO_DELETE_SECTION: u32 = 0xC000_001B;
pub const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
pub const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;
pub const STATUS_INVALID_HANDLE: u32 = 0xC000_0008;
pub const STATUS_DEVICE_BUSY: u32 = 0x8000_0011;

/// The provider's requests to the band owner. Each is one four-word message; every reply is
/// `(status, first, second, 0)`.
pub mod wire {
    /// `(bytes)` reserves a view: replies `(base, generation)`.
    pub const OP_RESERVE: u64 = 1;
    /// `(address, bytes)` commits the page-rounded range inside one view: replies `(base, bytes)`.
    pub const OP_COMMIT: u64 = 2;
    /// `(base, generation)` deletes the view's Section pages and frees its addresses.
    pub const OP_RELEASE: u64 = 3;
}

/// One reserved view. The generation distinguishes a later reservation at a reused base.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ViewReservation {
    pub base: u64,
    pub bytes: u64,
    pub generation: u64,
}

impl ViewReservation {
    pub const fn end(self) -> u64 {
        self.base + self.bytes
    }

    pub const fn contains(self, address: u64) -> bool {
        address >= self.base && address < self.end()
    }
}

/// A page-rounded commit request that lies inside one reservation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommitRange {
    pub reservation: ViewReservation,
    pub base: u64,
    pub bytes: u64,
}

/// The native owners of one committed page: the frame, the provider's copy of it, and the
/// clients (bit per process index) holding a read-only alias.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CommittedPage {
    pub address: u64,
    pub frame: u64,
    pub provider: u64,
    pub clients: u64,
}

/// What an access to an address in the band may observe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageAccess {
    /// No view reserves the address.
    Unreserved,
    /// Reserved but never committed: an access is an access violation.
    Uncommitted,
    /// Committed and backed.
    Committed,
    /// A native effect on the page is in flight or was uncertain.
    Unavailable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BandError {
    InvalidSize,
    OutOfSpace,
    NoMemory,
    NotReserved,
    ConflictingAddresses,
    StaleReservation,
    Releasing,
    EffectInProgress,
    NotCommitted,
    InvalidClient,
    Quarantined,
    PagesRemain,
    SectionPages,
}

impl BandError {
    /// The NTSTATUS a caller of the Mm service observes.
    pub const fn status(self) -> u32 {
        match self {
            Self::InvalidSize | Self::InvalidClient => STATUS_INVALID_PARAMETER,
            Self::OutOfSpace => STATUS_NO_MEMORY,
            Self::NoMemory => STATUS_INSUFFICIENT_RESOURCES,
            Self::NotReserved | Self::ConflictingAddresses | Self::NotCommitted => {
                STATUS_CONFLICTING_ADDRESSES
            }
            Self::StaleReservation | Self::Releasing => STATUS_INVALID_HANDLE,
            Self::EffectInProgress | Self::Quarantined | Self::PagesRemain => STATUS_DEVICE_BUSY,
            Self::SectionPages => STATUS_UNABLE_TO_DELETE_SECTION,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Page {
    Reserved,
    Committing,
    Committed(CommittedPage),
    Retiring(CommittedPage),
    Quarantined,
}

struct Row {
    reservation: ViewReservation,
    releasing: bool,
    pages: Vec<Page>,
}

impl Row {
    fn page_index(&self, address: u64) -> Option<usize> {
        self.reservation.contains(address)
            .then(|| ((address - self.reservation.base) / PAGE_SIZE) as usize)
    }
}

pub struct SessionViewBand {
    base: u64,
    bytes: u64,
    rows: Vec<Row>,
    next_generation: u64,
    committed_pages: u64,
    clients: u64,
}

impl SessionViewBand {
    /// An empty band over `[base, base + bytes)`. Both must be view aligned.
    pub const fn new(base: u64, bytes: u64) -> Self {
        assert!(base % VIEW_ALIGNMENT == 0 && bytes % VIEW_ALIGNMENT == 0 && bytes != 0);
        assert!(base.checked_add(bytes).is_some());
        Self { base, bytes, rows: Vec::new(), next_generation: 1, committed_pages: 0, clients: 0 }
    }

    pub const fn base(&self) -> u64 {
        self.base
    }

    pub const fn bytes(&self) -> u64 {
        self.bytes
    }

    pub const fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.bytes
    }

    /// Pages with a frame recorded: the band's physical cost.
    pub const fn committed_pages(&self) -> u64 {
        self.committed_pages
    }

    /// Virtual bytes held by live reservations.
    pub fn reserved_bytes(&self) -> u64 {
        self.rows.iter().map(|row| row.reservation.bytes).sum()
    }

    pub fn reservation_count(&self) -> usize {
        self.rows.len()
    }

    /// Reserve a view of `bytes` (rounded up to a page). Only virtual addresses are consumed.
    pub fn reserve(&mut self, bytes: u64) -> Result<ViewReservation, BandError> {
        let bytes = bytes.checked_add(PAGE_SIZE - 1).ok_or(BandError::InvalidSize)? & !(PAGE_SIZE - 1);
        if bytes == 0 {
            return Err(BandError::InvalidSize);
        }
        if bytes > self.bytes {
            return Err(BandError::OutOfSpace);
        }
        let mut candidate = self.base;
        loop {
            let end = candidate.checked_add(bytes).ok_or(BandError::OutOfSpace)?;
            if end > self.base + self.bytes {
                return Err(BandError::OutOfSpace);
            }
            let overlap = self.rows.iter()
                .filter(|row| row.reservation.base < end && candidate < row.reservation.end())
                .map(|row| row.reservation.end())
                .max();
            match overlap {
                Some(next) => {
                    candidate = next.checked_add(VIEW_ALIGNMENT - 1).ok_or(BandError::OutOfSpace)?
                        & !(VIEW_ALIGNMENT - 1);
                }
                None => break,
            }
        }
        let generation = self.next_generation;
        let next_generation = generation.checked_add(1).ok_or(BandError::NoMemory)?;
        let page_count = (bytes / PAGE_SIZE) as usize;
        let mut pages = Vec::new();
        pages.try_reserve_exact(page_count).map_err(|_| BandError::NoMemory)?;
        pages.resize(page_count, Page::Reserved);
        self.rows.try_reserve(1).map_err(|_| BandError::NoMemory)?;
        let reservation = ViewReservation { base: candidate, bytes, generation };
        self.rows.push(Row { reservation, releasing: false, pages });
        self.next_generation = next_generation;
        Ok(reservation)
    }

    /// The live reservation containing `address`.
    pub fn reservation_at(&self, address: u64) -> Option<ViewReservation> {
        self.rows.iter().find(|row| row.reservation.contains(address)).map(|row| row.reservation)
    }

    fn row(&self, reservation: ViewReservation) -> Result<&Row, BandError> {
        let row = self.rows.iter().find(|row| row.reservation.base == reservation.base)
            .ok_or(BandError::NotReserved)?;
        if row.reservation != reservation {
            return Err(BandError::StaleReservation);
        }
        Ok(row)
    }

    fn row_mut(&mut self, reservation: ViewReservation) -> Result<&mut Row, BandError> {
        let row = self.rows.iter_mut().find(|row| row.reservation.base == reservation.base)
            .ok_or(BandError::NotReserved)?;
        if row.reservation != reservation {
            return Err(BandError::StaleReservation);
        }
        Ok(row)
    }

    /// `MEM_COMMIT` rounding and placement: the start rounds down and the end rounds up to a
    /// page, and the whole range must fit the one view that contains its start.
    pub fn commit_range(&self, address: u64, bytes: u64) -> Result<CommitRange, BandError> {
        if bytes == 0 {
            return Err(BandError::InvalidSize);
        }
        let base = address & !(PAGE_SIZE - 1);
        let end = address.checked_add(bytes - 1).ok_or(BandError::InvalidSize)? | (PAGE_SIZE - 1);
        let end = end.checked_add(1).ok_or(BandError::InvalidSize)?;
        let row = self.rows.iter().find(|row| row.reservation.contains(base))
            .ok_or(BandError::NotReserved)?;
        if end > row.reservation.end() {
            return Err(BandError::ConflictingAddresses);
        }
        if row.releasing {
            return Err(BandError::Releasing);
        }
        Ok(CommitRange { reservation: row.reservation, base, bytes: end - base })
    }

    /// The first page of `range` that is not yet committed. Already committed pages are kept
    /// as they are; an in-flight or quarantined page fails the commit.
    pub fn next_uncommitted(&self, range: CommitRange) -> Result<Option<u64>, BandError> {
        let row = self.row(range.reservation)?;
        if row.releasing {
            return Err(BandError::Releasing);
        }
        let mut page = range.base;
        while page < range.base + range.bytes {
            let index = row.page_index(page).ok_or(BandError::ConflictingAddresses)?;
            match row.pages[index] {
                Page::Reserved => return Ok(Some(page)),
                Page::Committed(_) => {}
                Page::Committing | Page::Retiring(_) => return Err(BandError::EffectInProgress),
                Page::Quarantined => return Err(BandError::Quarantined),
            }
            page += PAGE_SIZE;
        }
        Ok(None)
    }

    /// Record that the native backing of `page` is about to be created.
    pub fn begin_commit(&mut self, reservation: ViewReservation, page: u64) -> Result<(), BandError> {
        let row = self.row_mut(reservation)?;
        if row.releasing {
            return Err(BandError::Releasing);
        }
        let index = row.page_index(page).filter(|_| page % PAGE_SIZE == 0)
            .ok_or(BandError::ConflictingAddresses)?;
        match row.pages[index] {
            Page::Reserved => {
                row.pages[index] = Page::Committing;
                Ok(())
            }
            Page::Committed(_) => Err(BandError::EffectInProgress),
            Page::Committing | Page::Retiring(_) => Err(BandError::EffectInProgress),
            Page::Quarantined => Err(BandError::Quarantined),
        }
    }

    /// Publish the frame and provider copy now mapped at `page`.
    pub fn complete_commit(
        &mut self,
        reservation: ViewReservation,
        page: u64,
        frame: u64,
        provider: u64,
    ) -> Result<CommittedPage, BandError> {
        let row = self.row_mut(reservation)?;
        let index = row.page_index(page).ok_or(BandError::ConflictingAddresses)?;
        if row.pages[index] != Page::Committing || frame == 0 || provider == 0 {
            return Err(BandError::EffectInProgress);
        }
        let committed = CommittedPage { address: page, frame, provider, clients: 0 };
        row.pages[index] = Page::Committed(committed);
        self.committed_pages += 1;
        Ok(committed)
    }

    /// The backing of `page` could not be obtained and no native effect happened: the page is
    /// reserved again.
    pub fn abort_commit(&mut self, reservation: ViewReservation, page: u64) -> Result<(), BandError> {
        let row = self.row_mut(reservation)?;
        let index = row.page_index(page).ok_or(BandError::ConflictingAddresses)?;
        if row.pages[index] != Page::Committing {
            return Err(BandError::EffectInProgress);
        }
        row.pages[index] = Page::Reserved;
        Ok(())
    }

    /// A native effect on `page` failed or is uncertain. The page, and therefore its view,
    /// can never be reused; its frame, if any, stays recorded for diagnosis.
    pub fn quarantine(&mut self, page: u64) {
        if let Some(row) = self.rows.iter_mut().find(|row| row.reservation.contains(page)) {
            let index = ((page - row.reservation.base) / PAGE_SIZE) as usize;
            if matches!(row.pages[index], Page::Committed(_) | Page::Retiring(_)) {
                self.committed_pages -= 1;
            }
            row.pages[index] = Page::Quarantined;
        }
    }

    pub fn access(&self, address: u64) -> PageAccess {
        let Some(row) = self.rows.iter().find(|row| row.reservation.contains(address)) else {
            return PageAccess::Unreserved;
        };
        match row.pages[((address - row.reservation.base) / PAGE_SIZE) as usize] {
            Page::Reserved => PageAccess::Uncommitted,
            Page::Committed(_) => PageAccess::Committed,
            Page::Committing | Page::Retiring(_) | Page::Quarantined => PageAccess::Unavailable,
        }
    }

    pub fn committed(&self, address: u64) -> Option<CommittedPage> {
        let row = self.rows.iter().find(|row| row.reservation.contains(address))?;
        match row.pages[((address - row.reservation.base) / PAGE_SIZE) as usize] {
            Page::Committed(page) => Some(page),
            _ => None,
        }
    }

    /// Section pages are not decommitted through a view: NT refuses `MEM_DECOMMIT` and
    /// `MEM_RELEASE` on a mapped Section. Only Section deletion releases them.
    pub fn decommit(&self, address: u64, _bytes: u64) -> Result<(), BandError> {
        if self.reservation_at(address).is_some() {
            Err(BandError::SectionPages)
        } else {
            Err(BandError::NotReserved)
        }
    }

    // --- clients -----------------------------------------------------------------------------

    pub const fn clients(&self) -> u64 {
        self.clients
    }

    /// Admit a client process; later commits are pushed to it.
    pub fn admit_client(&mut self, pi: usize) -> Result<(), BandError> {
        if pi >= MAX_CLIENTS {
            return Err(BandError::InvalidClient);
        }
        self.clients |= 1 << pi;
        Ok(())
    }

    /// Admitted clients that do not yet alias the committed `page`.
    pub fn clients_missing(&self, page: u64) -> u64 {
        self.committed(page).map_or(0, |committed| self.clients & !committed.clients)
    }

    /// The first committed page at or after `from` that admitted client `pi` does not alias.
    pub fn next_unmapped_for_client(&self, pi: usize, from: u64) -> Option<CommittedPage> {
        if pi >= MAX_CLIENTS || self.clients & (1 << pi) == 0 {
            return None;
        }
        let bit = 1u64 << pi;
        self.rows.iter()
            .flat_map(|row| row.pages.iter())
            .filter_map(|page| match page {
                Page::Committed(committed) if committed.address >= from
                    && committed.clients & bit == 0 => Some(*committed),
                _ => None,
            })
            .min_by_key(|committed| committed.address)
    }

    fn committed_mut(&mut self, address: u64) -> Option<&mut CommittedPage> {
        let row = self.rows.iter_mut().find(|row| row.reservation.contains(address))?;
        match &mut row.pages[((address - row.reservation.base) / PAGE_SIZE) as usize] {
            Page::Committed(page) | Page::Retiring(page) => Some(page),
            _ => None,
        }
    }

    /// Client `pi` now holds an alias of the committed `page`.
    pub fn record_client_mapping(&mut self, page: u64, pi: usize) -> Result<(), BandError> {
        if pi >= MAX_CLIENTS || self.clients & (1 << pi) == 0 {
            return Err(BandError::InvalidClient);
        }
        let Some(row) = self.rows.iter_mut().find(|row| row.reservation.contains(page)) else {
            return Err(BandError::NotReserved);
        };
        match &mut row.pages[((page - row.reservation.base) / PAGE_SIZE) as usize] {
            Page::Committed(committed) => {
                committed.clients |= 1 << pi;
                Ok(())
            }
            _ => Err(BandError::NotCommitted),
        }
    }

    /// Client `pi`'s alias of `page` was removed while its page retires.
    pub fn clear_client_mapping(&mut self, page: u64, pi: usize) -> Result<(), BandError> {
        if pi >= MAX_CLIENTS {
            return Err(BandError::InvalidClient);
        }
        let committed = self.committed_mut(page).ok_or(BandError::NotCommitted)?;
        committed.clients &= !(1 << pi);
        Ok(())
    }

    /// Client `pi` is gone and its aliases were removed with its address space.
    pub fn forget_client(&mut self, pi: usize) {
        if pi >= MAX_CLIENTS {
            return;
        }
        let bit = 1u64 << pi;
        self.clients &= !bit;
        for row in &mut self.rows {
            for page in &mut row.pages {
                if let Page::Committed(committed) | Page::Retiring(committed) = page {
                    committed.clients &= !bit;
                }
            }
        }
    }

    // --- release -----------------------------------------------------------------------------

    /// The Section is deleted: refuse further commits and start releasing its pages.
    pub fn begin_release(&mut self, reservation: ViewReservation) -> Result<(), BandError> {
        let row = self.row_mut(reservation)?;
        if row.pages.iter().any(|page| matches!(page, Page::Committing)) {
            return Err(BandError::EffectInProgress);
        }
        row.releasing = true;
        Ok(())
    }

    /// Move the next committed page of a releasing view into retirement and return its owners.
    pub fn next_retirement(
        &mut self,
        reservation: ViewReservation,
    ) -> Result<Option<CommittedPage>, BandError> {
        let row = self.row_mut(reservation)?;
        if !row.releasing {
            return Err(BandError::EffectInProgress);
        }
        if let Some(page) = row.pages.iter().find_map(|page| match page {
            Page::Retiring(committed) => Some(*committed),
            _ => None,
        }) {
            return Ok(Some(page));
        }
        for page in &mut row.pages {
            if let Page::Committed(committed) = *page {
                *page = Page::Retiring(committed);
                return Ok(Some(committed));
            }
        }
        Ok(None)
    }

    /// The retiring page's client aliases, provider copy and frame are all gone.
    pub fn complete_page_retirement(
        &mut self,
        reservation: ViewReservation,
        page: u64,
    ) -> Result<(), BandError> {
        let row = self.row_mut(reservation)?;
        let index = row.page_index(page).ok_or(BandError::ConflictingAddresses)?;
        match row.pages[index] {
            Page::Retiring(committed) if committed.clients == 0 => {
                row.pages[index] = Page::Reserved;
                self.committed_pages -= 1;
                Ok(())
            }
            Page::Retiring(_) => Err(BandError::PagesRemain),
            _ => Err(BandError::NotCommitted),
        }
    }

    /// Free the view's addresses once every page is released. A quarantined page keeps them.
    pub fn complete_release(&mut self, reservation: ViewReservation) -> Result<(), BandError> {
        let row = self.row(reservation)?;
        if !row.releasing {
            return Err(BandError::EffectInProgress);
        }
        if row.pages.iter().any(|page| matches!(page, Page::Quarantined)) {
            return Err(BandError::Quarantined);
        }
        if row.pages.iter().any(|page| *page != Page::Reserved) {
            return Err(BandError::PagesRemain);
        }
        self.rows.retain(|row| row.reservation != reservation);
        Ok(())
    }
}

#[cfg(test)]
#[path = "session_view_band_tests.rs"]
mod tests;
