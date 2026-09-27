//! Exact process-lifetime ownership of win32k's fixed client alias window.
use crate::client_alias_window::{ClientAliasWindow, WindowError, WindowOwner, WindowState};
use crate::thread_alias_journal::ThreadAliasMapping;
use alloc::vec::Vec;
use nt_memory_manager::alias_transition::AliasTransitionIo;
use nt_memory_manager::retained_alias::AliasRetirementIo;

/// Copy into one previously reserved destination slot. `Err` proves that slot is empty; an
/// uncertain copy result must be resolved or retained by the caller, never reported as `Err`.
/// The registry checks the destination against every retained alias before invoking this trait.
pub trait ReservedAliasTransitionIo: AliasRetirementIo {
    fn copy_into(&mut self, destination_cap: u64) -> Result<(), u32>;
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32>;
}

struct ReservedBackend<'a, I> {
    io: &'a mut I,
    destination_cap: u64,
}

impl<I: ReservedAliasTransitionIo> AliasRetirementIo for ReservedBackend<'_, I> {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.io.unmap(cap)
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.io.delete(cap)
    }
    fn recycle_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.io.recycle_slot(slot)
    }
    fn recycle_unretyped_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.io.recycle_unretyped_slot(slot)
    }
}

impl<I: ReservedAliasTransitionIo> AliasTransitionIo for ReservedBackend<'_, I> {
    fn copy(&mut self) -> (u64, u32) {
        let status = match self.io.copy_into(self.destination_cap) {
            Ok(()) => 0,
            Err(0) => nt_memory_manager::STATUS_INVALID_HANDLE,
            Err(status) => status,
        };
        (self.destination_cap, status)
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.io.map(cap, rights)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegistryError {
    InvalidOwner,
    MissingOwner,
    StaleOwner(WindowOwner),
    OwnerExists,
    ActiveOwner(WindowOwner),
    BlockedOwner(WindowOwner),
    Busy,
    MissingPage(u64),
    DuplicatePage(u64),
    SharedCapability(u64),
    Claimed,
    StaleMappings,
    InsufficientResources,
    Backend { page: u64, status: u32 },
}

impl From<WindowError> for RegistryError {
    fn from(error: WindowError) -> Self {
        match error {
            WindowError::InvalidOwner => Self::InvalidOwner,
            WindowError::OwnerChanged => Self::StaleMappings,
            WindowError::Busy => Self::Busy,
            WindowError::Claimed => Self::Claimed,
            WindowError::StaleMappings => Self::StaleMappings,
            WindowError::DuplicatePage(page) => Self::DuplicatePage(page),
            WindowError::SharedCapability(cap) => Self::SharedCapability(cap),
            WindowError::InsufficientResources => Self::InsufficientResources,
            WindowError::Backend { page, status } => Self::Backend { page, status },
        }
    }
}

struct OwnerRows {
    window: ClientAliasWindow,
    rows: Vec<ThreadAliasMapping>,
    retiring: bool,
}

/// Retains every alias row, including caps hidden behind suspended or blocked owners. The
/// caller must serialize access with all physical alias effects and authenticate WindowOwner.
/// Neither a PI nor a numeric cap alone establishes process-lifetime authority.
#[must_use = "retained alias rows must outlive every suspended or blocked switch"]
pub struct ClientAliasRegistry {
    owners: Vec<OwnerRows>,
}

impl ClientAliasRegistry {
    pub const fn new() -> Self {
        Self { owners: Vec::new() }
    }

    fn index(&self, owner: WindowOwner) -> Result<usize, RegistryError> {
        if !owner.is_valid() {
            return Err(RegistryError::InvalidOwner);
        }
        if let Some(index) = self
            .owners
            .iter()
            .position(|entry| entry.window.owner() == owner)
        {
            return Ok(index);
        }
        if let Some(entry) = self
            .owners
            .iter()
            .find(|entry| entry.window.owner().pi == owner.pi)
        {
            return Err(RegistryError::StaleOwner(entry.window.owner()));
        }
        Err(RegistryError::MissingOwner)
    }

    pub fn state(&self, owner: WindowOwner) -> Result<WindowState, RegistryError> {
        Ok(self.owners[self.index(owner)?].window.state())
    }

    pub fn is_retiring(&self, owner: WindowOwner) -> Result<bool, RegistryError> {
        Ok(self.owners[self.index(owner)?].retiring)
    }

    pub fn active_owner(&self) -> Option<WindowOwner> {
        self.owners
            .iter()
            .find(|entry| entry.window.state() == WindowState::Active)
            .map(|entry| entry.window.owner())
    }

    pub fn blocked_owner(&self) -> Option<WindowOwner> {
        self.owners
            .iter()
            .find(|entry| entry.window.state() == WindowState::Blocked)
            .map(|entry| entry.window.owner())
    }

    /// Includes candidate and retiring caps as well as unmapped suspended caps.
    pub fn owns_cap(&self, cap: u64) -> bool {
        cap != 0
            && self
                .owners
                .iter()
                .flat_map(|entry| &entry.rows)
                .flat_map(|row| row.snapshot().capabilities())
                .any(|held| held == cap)
    }

    /// Immutable exact-owner lookup for retirement preflight. Mutation goes through methods
    /// below so a suspended/blocked owner cannot be retired or replaced accidentally.
    pub fn page(
        &self,
        owner: WindowOwner,
        page: u64,
    ) -> Result<&ThreadAliasMapping, RegistryError> {
        self.owners[self.index(owner)?]
            .rows
            .iter()
            .find(|row| row.page() == page)
            .ok_or(RegistryError::MissingPage(page))
    }

    /// Replacement preflight only; this does not grant mutable access or validate a future
    /// copied cap. The native caller must retain exclusion and prove fresh-cap ownership.
    pub fn replacement_target(
        &self,
        owner: WindowOwner,
        page: u64,
    ) -> Result<&ThreadAliasMapping, RegistryError> {
        let index = self.index(owner)?;
        if self.owners[index].retiring || self.owners[index].window.state() != WindowState::Active {
            return Err(RegistryError::Busy);
        }
        let row = self.page(owner, page)?;
        if row.is_claimed() {
            return Err(RegistryError::Claimed);
        }
        if row.live().is_none() {
            return Err(RegistryError::StaleMappings);
        }
        Ok(row)
    }

    fn check_candidate(&self, candidate_cap: u64) -> Result<(), RegistryError> {
        if candidate_cap == 0 {
            return Err(RegistryError::StaleMappings);
        }
        if self.owns_cap(candidate_cap) {
            return Err(RegistryError::SharedCapability(candidate_cap));
        }
        Ok(())
    }

    /// Replace one active page after the caller has reserved an exclusive destination slot.
    /// The backend can only copy into that slot, rather than choosing a cap after preflight.
    /// On backend error the row retains every slot whose cleanup is still unacknowledged.
    pub fn replace_active_page(
        &mut self,
        owner: WindowOwner,
        page: u64,
        candidate_cap: u64,
        rights: u64,
        backend: &mut impl ReservedAliasTransitionIo,
    ) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        if self.owners[index].retiring || self.owners[index].window.state() != WindowState::Active {
            return Err(RegistryError::Busy);
        }
        let row_index = self.owners[index]
            .rows
            .iter()
            .position(|row| row.page() == page)
            .ok_or(RegistryError::MissingPage(page))?;
        if self.owners[index].rows[row_index].is_claimed() {
            return Err(RegistryError::Claimed);
        }
        if self.owners[index].rows[row_index].live().is_none() {
            return Err(RegistryError::StaleMappings);
        }
        self.check_candidate(candidate_cap)?;
        self.owners[index].rows[row_index]
            .replace(
                rights,
                &mut ReservedBackend {
                    io: backend,
                    destination_cap: candidate_cap,
                },
            )
            .map_err(|status| RegistryError::Backend { page, status })
    }

    /// Admit a new active page. Reserve the row before copying or mapping a cap so failure
    /// cannot lose a partially constructed alias. Retry cleanup with `recover_page`.
    pub fn admit_active_page(
        &mut self,
        owner: WindowOwner,
        page: u64,
        candidate_cap: u64,
        rights: u64,
        backend: &mut impl ReservedAliasTransitionIo,
    ) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        if self.owners[index].retiring || self.owners[index].window.state() != WindowState::Active {
            return Err(RegistryError::Busy);
        }
        if self.owners[index].rows.iter().any(|row| row.page() == page) {
            return Err(RegistryError::DuplicatePage(page));
        }
        self.check_candidate(candidate_cap)?;
        let row = ThreadAliasMapping::new(page).ok_or(RegistryError::StaleMappings)?;
        let rows = &mut self.owners[index].rows;
        rows.try_reserve(1)
            .map_err(|_| RegistryError::InsufficientResources)?;
        rows.push(row);
        let result = rows.last_mut().expect("reserved row").replace(
            rights,
            &mut ReservedBackend {
                io: backend,
                destination_cap: candidate_cap,
            },
        );
        if rows.last().expect("reserved row").is_empty() {
            rows.pop();
        }
        result.map_err(|status| RegistryError::Backend { page, status })
    }

    /// Retry an interrupted replacement or admission without making another copy. Empty
    /// admitted rows are removed only after cleanup is acknowledged.
    pub fn recover_page(
        &mut self,
        owner: WindowOwner,
        page: u64,
        backend: &mut impl AliasTransitionIo,
    ) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        let entry = &mut self.owners[index];
        if entry.retiring || entry.window.state() != WindowState::Active {
            return Err(RegistryError::Busy);
        }
        let row_index = entry
            .rows
            .iter()
            .position(|row| row.page() == page)
            .ok_or(RegistryError::MissingPage(page))?;
        if entry.rows[row_index].is_claimed() {
            return Err(RegistryError::Claimed);
        }
        entry.rows[row_index]
            .recover(backend)
            .map_err(|status| RegistryError::Backend { page, status })?;
        if entry.rows[row_index].is_empty() {
            entry.rows.swap_remove(row_index);
        }
        Ok(())
    }

    fn check_rows(&self, rows: &[ThreadAliasMapping]) -> Result<(), RegistryError> {
        for (index, row) in rows.iter().enumerate() {
            if row.is_claimed() {
                return Err(RegistryError::Claimed);
            }
            if row.live().is_none() || row.snapshot().capabilities().count() != 1 {
                return Err(RegistryError::StaleMappings);
            }
            if rows[..index].iter().any(|prior| prior.page() == row.page()) {
                return Err(RegistryError::DuplicatePage(row.page()));
            }
            for cap in row.snapshot().capabilities() {
                if self.owns_cap(cap)
                    || rows[..index]
                        .iter()
                        .any(|prior| prior.snapshot().capabilities().any(|held| held == cap))
                {
                    return Err(RegistryError::SharedCapability(cap));
                }
            }
        }
        Ok(())
    }

    /// Admit already-created live rows only when the physical fixed-VA window has no owner.
    /// The caller proves those mappings are in the given process VSpace before admission.
    pub fn insert_active(
        &mut self,
        owner: WindowOwner,
        rows: &mut Vec<ThreadAliasMapping>,
    ) -> Result<(), RegistryError> {
        if !owner.is_valid() {
            return Err(RegistryError::InvalidOwner);
        }
        if self.index(owner).is_ok() {
            return Err(RegistryError::OwnerExists);
        }
        if let Some(existing) = self
            .owners
            .iter()
            .find(|entry| entry.window.owner().pi == owner.pi)
        {
            return Err(RegistryError::StaleOwner(existing.window.owner()));
        }
        if let Some(blocked) = self.blocked_owner() {
            return Err(RegistryError::BlockedOwner(blocked));
        }
        if let Some(active) = self.active_owner() {
            return Err(RegistryError::ActiveOwner(active));
        }
        self.check_rows(rows)?;
        self.owners
            .try_reserve(1)
            .map_err(|_| RegistryError::InsufficientResources)?;
        let window = ClientAliasWindow::new(owner)?;
        self.owners.push(OwnerRows {
            window,
            rows: core::mem::take(rows),
            retiring: false,
        });
        Ok(())
    }

    /// Failure may leave the old owner Active (rollback succeeded) or Blocked (retry needed).
    /// It never makes another owner Active.
    pub fn suspend_active<I: AliasTransitionIo>(
        &mut self,
        owner: WindowOwner,
        backend: impl FnMut(u64) -> I,
    ) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        if self.owners[index].retiring || self.owners[index].window.state() != WindowState::Active {
            return Err(RegistryError::Busy);
        }
        let entry = &mut self.owners[index];
        entry
            .window
            .suspend_all(owner, &mut entry.rows, backend)
            .map_err(Into::into)
    }

    /// A partially restored target becomes Blocked, not Active. No other target can publish
    /// while any owner is blocked, even if some of its rows have already been remapped.
    pub fn restore_owner<I: AliasTransitionIo>(
        &mut self,
        owner: WindowOwner,
        backend: impl FnMut(u64) -> I,
    ) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        if let Some(active) = self.active_owner() {
            return Err(RegistryError::ActiveOwner(active));
        }
        if let Some(blocked) = self.blocked_owner() {
            if blocked != owner {
                return Err(RegistryError::BlockedOwner(blocked));
            }
        }
        let entry = &mut self.owners[index];
        if entry.retiring {
            return Err(RegistryError::Busy);
        }
        entry
            .window
            .restore_all(owner, &mut entry.rows, backend)
            .map_err(Into::into)
    }

    /// After the caller proves execution quiescence and excludes new admission, begin terminal
    /// process cleanup. Suspended rows can then be deleted without remapping their fixed VAs.
    pub fn begin_retirement(&mut self, owner: WindowOwner) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        self.owners[index].retiring = true;
        Ok(())
    }

    /// Ordinary retirement requires an active owner. Terminal process cleanup may retire
    /// suspended or blocked rows after `begin_retirement`; failure retains the exact row/cap.
    pub fn retire_page(
        &mut self,
        owner: WindowOwner,
        page: u64,
        backend: &mut impl AliasRetirementIo,
    ) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        let entry = &mut self.owners[index];
        if !entry.retiring && entry.window.state() != WindowState::Active {
            return Err(RegistryError::Busy);
        }
        let row_index = entry
            .rows
            .iter()
            .position(|row| row.page() == page)
            .ok_or(RegistryError::MissingPage(page))?;
        entry.rows[row_index]
            .retire(backend)
            .map_err(|status| RegistryError::Backend { page, status })?;
        if entry.rows[row_index].is_empty() {
            entry.rows.swap_remove(row_index);
        }
        Ok(())
    }

    /// Remove metadata only after every row has been retired. Never discards retained caps.
    pub fn remove_empty_owner(&mut self, owner: WindowOwner) -> Result<(), RegistryError> {
        let index = self.index(owner)?;
        let entry = &self.owners[index];
        if (!entry.retiring && entry.window.state() != WindowState::Active)
            || !entry.rows.is_empty()
        {
            return Err(RegistryError::Busy);
        }
        self.owners.swap_remove(index);
        Ok(())
    }
}

impl Default for ClientAliasRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[path = "client_alias_registry_tests.rs"]
mod tests;
