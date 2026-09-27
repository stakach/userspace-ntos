//! Failure-atomic suspension of the aliases occupying one client window.
use crate::process_identity::ProcessIdentity;
use crate::thread_alias_journal::ThreadAliasMapping;
use alloc::vec::Vec;
use nt_memory_manager::alias_transition::AliasTransitionIo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WindowOwner {
    pub pi: usize,
    pub process: ProcessIdentity,
    pub vspace: u64,
}

impl WindowOwner {
    pub const fn is_valid(self) -> bool {
        self.process.is_valid() && self.vspace != 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowState {
    Active,
    Suspended,
    Blocked,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    InvalidOwner,
    OwnerChanged,
    Busy,
    Claimed,
    StaleMappings,
    DuplicatePage(u64),
    SharedCapability(u64),
    InsufficientResources,
    Backend { page: u64, status: u32 },
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    page: u64,
    cap: u64,
    rights: u64,
}

/// Owns the transaction metadata, not the caps. The caller retains and excludes the mapping
/// table, its process-generation authority, and the destination VSpace across every backend call.
/// Backend calls must not reenter or mutate the table. Dropping a blocked or suspended window
/// does not release the retained aliases or authorize another owner to use their fixed VAs.
#[must_use = "retain this coordinator while any client alias is suspended or blocked"]
pub struct ClientAliasWindow {
    owner: WindowOwner,
    state: WindowState,
    entries: Vec<Entry>,
}

impl ClientAliasWindow {
    pub fn new(owner: WindowOwner) -> Result<Self, WindowError> {
        if !owner.is_valid() {
            return Err(WindowError::InvalidOwner);
        }
        Ok(Self {
            owner,
            state: WindowState::Active,
            entries: Vec::new(),
        })
    }

    pub fn owner(&self) -> WindowOwner {
        self.owner
    }

    pub fn state(&self) -> WindowState {
        self.state
    }

    pub fn is_complete(&self) -> bool {
        self.state == WindowState::Suspended
    }

    fn check_owner(&self, current: WindowOwner) -> Result<(), WindowError> {
        if current != self.owner {
            Err(WindowError::OwnerChanged)
        } else {
            Ok(())
        }
    }

    fn capture(&mut self, rows: &[ThreadAliasMapping]) -> Result<(), WindowError> {
        let mut entries = Vec::new();
        entries
            .try_reserve(rows.len())
            .map_err(|_| WindowError::InsufficientResources)?;
        for row in rows {
            if row.is_claimed() {
                return Err(WindowError::Claimed);
            }
            let (cap, rights) = row.live().ok_or(WindowError::StaleMappings)?;
            if cap == 0 || row.snapshot().capabilities().count() != 1 {
                return Err(WindowError::StaleMappings);
            }
            if entries.iter().any(|entry: &Entry| entry.page == row.page()) {
                return Err(WindowError::DuplicatePage(row.page()));
            }
            if entries.iter().any(|entry| entry.cap == cap) {
                return Err(WindowError::SharedCapability(cap));
            }
            entries.push(Entry {
                page: row.page(),
                cap,
                rights,
            });
        }
        self.entries = entries;
        Ok(())
    }

    /// Rejects changed coverage, claims, in-flight replacements and changed cap/rights before
    /// performing another physical effect. The caller must exclude new admission throughout.
    pub fn revalidate(
        &self,
        current: WindowOwner,
        rows: &[ThreadAliasMapping],
    ) -> Result<(), WindowError> {
        self.check_owner(current)?;
        if self.entries.len() != rows.len() {
            return Err(WindowError::StaleMappings);
        }
        for entry in &self.entries {
            let mut found = rows.iter().filter(|row| row.page() == entry.page);
            let row = found.next().ok_or(WindowError::StaleMappings)?;
            if found.next().is_some() {
                return Err(WindowError::DuplicatePage(entry.page));
            }
            if row.is_claimed() {
                return Err(WindowError::Claimed);
            }
            let retained = row.live().or_else(|| row.suspended());
            if retained != Some((entry.cap, entry.rights))
                || row.snapshot().capabilities().count() != 1
                || (self.state == WindowState::Suspended && row.suspended().is_none())
            {
                return Err(WindowError::StaleMappings);
            }
        }
        Ok(())
    }

    /// Suspend every page without deleting its cap. A failed unmap restores prior pages in
    /// reverse order. If restoration also fails, `Blocked` retains the exact retry work.
    pub fn suspend_all<I: AliasTransitionIo>(
        &mut self,
        current: WindowOwner,
        rows: &mut [ThreadAliasMapping],
        mut backend: impl FnMut(u64) -> I,
    ) -> Result<(), WindowError> {
        self.check_owner(current)?;
        if self.state != WindowState::Active {
            return Err(WindowError::Busy);
        }
        self.capture(rows)?;
        for entry in &self.entries {
            let row = rows
                .iter_mut()
                .find(|row| row.page() == entry.page)
                .expect("captured page");
            if let Err(status) = row.suspend(&mut backend(entry.page)) {
                let error = WindowError::Backend {
                    page: entry.page,
                    status,
                };
                self.state = WindowState::Blocked;
                let _ = self.restore_inner(rows, &mut backend);
                return Err(error);
            }
        }
        self.state = WindowState::Suspended;
        Ok(())
    }

    fn restore_inner<I: AliasTransitionIo>(
        &mut self,
        rows: &mut [ThreadAliasMapping],
        backend: &mut impl FnMut(u64) -> I,
    ) -> Result<(), WindowError> {
        // A failed map stays suspended. Continue restoring other pages so each is attempted once.
        let mut first_error = None;
        for entry in self.entries.iter().rev() {
            let row = rows
                .iter_mut()
                .find(|row| row.page() == entry.page)
                .expect("validated page");
            if row.suspended().is_some() {
                if let Err(status) = row.resume(&mut backend(entry.page)) {
                    first_error.get_or_insert(WindowError::Backend {
                        page: entry.page,
                        status,
                    });
                }
            }
        }
        if let Some(error) = first_error {
            self.state = WindowState::Blocked;
            Err(error)
        } else {
            self.state = WindowState::Active;
            self.entries.clear();
            Ok(())
        }
    }

    /// Restore the exact caps and rights after a completed suspension, or retry a blocked
    /// rollback. A blocked coordinator cannot begin another transition until this succeeds.
    pub fn restore_all<I: AliasTransitionIo>(
        &mut self,
        current: WindowOwner,
        rows: &mut [ThreadAliasMapping],
        mut backend: impl FnMut(u64) -> I,
    ) -> Result<(), WindowError> {
        self.check_owner(current)?;
        if self.state == WindowState::Active {
            return Err(WindowError::Busy);
        }
        self.revalidate(current, rows)?;
        self.restore_inner(rows, &mut backend)
    }

    pub fn recover<I: AliasTransitionIo>(
        &mut self,
        current: WindowOwner,
        rows: &mut [ThreadAliasMapping],
        backend: impl FnMut(u64) -> I,
    ) -> Result<(), WindowError> {
        if self.state != WindowState::Blocked {
            return Err(WindowError::Busy);
        }
        self.restore_all(current, rows, backend)
    }
}

#[cfg(test)]
#[path = "client_alias_window_tests.rs"]
mod tests;
