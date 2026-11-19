//! Root-side ownership of the provider references held by process-owned USER handles.
//!
//! The win32k provider keeps USER object bodies and their counts; ProcessManager keeps the
//! handles. Handles the provider creates are counted by the provider before it asks the root to
//! publish them. Handles the root creates or removes on its own (inheritance, duplication,
//! `NtClose`, process teardown) change the provider's counts later, through this ledger: the root
//! records each change before or as it changes the table, and the provider drains the changes,
//! applies them to its bodies and acknowledges them. A recorded change stays owned here until
//! that acknowledgement, so a body is never released while a handle still names it.
//!
//! Acquisitions are always delivered before releases for the same target, so the provider's
//! counts never fall below the handles that exist.

use alloc::vec::Vec;
use nt_process::user_object_handle::UserObjectTarget;
use nt_process::{STATUS_INSUFFICIENT_RESOURCES, STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER};

/// Largest count delivered in one provider change.
pub const MAX_DELTA: u32 = 0xFFFF;

/// One batch of count changes for one target, oldest kind first.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandleDelta {
    Acquired { target: UserObjectTarget, count: u32 },
    Released { target: UserObjectTarget, count: u32 },
}

impl HandleDelta {
    pub const fn target(self) -> UserObjectTarget {
        match self {
            Self::Acquired { target, .. } | Self::Released { target, .. } => target,
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct Row {
    target: UserObjectTarget,
    /// ProcessManager handles naming this target.
    live: u32,
    /// Copies the provider has not yet counted.
    acquired: u32,
    /// Removals the provider has not yet counted.
    released: u32,
}

impl Row {
    fn settled(&self) -> bool {
        self.live == 0 && self.acquired == 0 && self.released == 0
    }
}

#[derive(Default)]
pub struct UserObjectHandleLedger {
    rows: Vec<Row>,
}

impl UserObjectHandleLedger {
    pub const fn new() -> Self {
        Self { rows: Vec::new() }
    }

    fn row(&mut self, target: UserObjectTarget) -> Option<&mut Row> {
        self.rows.iter_mut().find(|row| row.target == target)
    }

    fn retire_if_settled(&mut self, target: UserObjectTarget) {
        self.rows.retain(|row| row.target != target || !row.settled());
    }

    /// Make room to record a provider-created handle before it is published.
    pub fn prepare_publication(&mut self, target: UserObjectTarget) -> Result<(), u32> {
        if target.body == 0 || target.object_type == 0 || target.generation == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.row(target).is_some() {
            return Ok(());
        }
        // One live body has one generation: a different generation for the same body means the
        // provider reused a body that still has handles here.
        if self.rows.iter().any(|row| {
            row.target.domain == target.domain && row.target.body == target.body
        }) {
            return Err(STATUS_INVALID_HANDLE);
        }
        self.rows.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
        self.rows.push(Row { target, live: 0, acquired: 0, released: 0 });
        Ok(())
    }

    /// A handle the provider already counted is now visible in a process table.
    pub fn record_published(&mut self, target: UserObjectTarget) -> Result<(), u32> {
        let row = self.row(target).ok_or(STATUS_INVALID_HANDLE)?;
        row.live = row.live.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(())
    }

    /// Undo [`prepare_publication`](Self::prepare_publication) after a refused publish.
    pub fn discard_unpublished(&mut self, target: UserObjectTarget) {
        self.retire_if_settled(target);
    }

    /// ProcessManager is about to copy an existing handle to `target`.
    pub fn acquire(&mut self, target: UserObjectTarget) -> Result<(), u32> {
        let row = self.row(target).ok_or(STATUS_INVALID_HANDLE)?;
        if row.live == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        let live = row.live.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        let acquired = row.acquired.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        row.live = live;
        row.acquired = acquired;
        Ok(())
    }

    /// The copy prepared by [`acquire`](Self::acquire) was not installed. An acquisition the
    /// provider already counted becomes a release instead.
    pub fn cancel_acquire(&mut self, target: UserObjectTarget) -> Result<(), u32> {
        let row = self.row(target).ok_or(STATUS_INVALID_HANDLE)?;
        if row.live == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        if row.acquired != 0 {
            row.acquired -= 1;
        } else {
            row.released = row.released.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        }
        row.live -= 1;
        self.retire_if_settled(target);
        Ok(())
    }

    /// A ProcessManager handle to `target` has been removed (close, duplicate-close or teardown).
    pub fn release(&mut self, target: UserObjectTarget) -> Result<(), u32> {
        let row = self.row(target).ok_or(STATUS_INVALID_HANDLE)?;
        if row.live == 0 {
            return Err(STATUS_INVALID_HANDLE);
        }
        row.released = row.released.checked_add(1).ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        row.live -= 1;
        Ok(())
    }

    /// The next change the provider of `domain` has not counted.
    pub fn next_delta(&self, domain: u64) -> Option<HandleDelta> {
        let row = self
            .rows
            .iter()
            .find(|row| row.target.domain == domain && (row.acquired != 0 || row.released != 0))?;
        Some(if row.acquired != 0 {
            HandleDelta::Acquired { target: row.target, count: row.acquired.min(MAX_DELTA) }
        } else {
            HandleDelta::Released { target: row.target, count: row.released.min(MAX_DELTA) }
        })
    }

    /// The provider of `domain` has applied `delta` to its body.
    pub fn acknowledge(&mut self, domain: u64, delta: HandleDelta) -> Result<(), u32> {
        let target = delta.target();
        if target.domain != domain {
            return Err(STATUS_INVALID_PARAMETER);
        }
        let row = self.row(target).ok_or(STATUS_INVALID_HANDLE)?;
        match delta {
            HandleDelta::Acquired { count, .. } if count != 0 && count <= row.acquired => {
                row.acquired -= count;
            }
            // A copy recorded after this release was delivered came from a still-live handle,
            // so the provider's count stays above zero until that copy is delivered too.
            HandleDelta::Released { count, .. } if count != 0 && count <= row.released => {
                row.released -= count;
            }
            _ => return Err(STATUS_INVALID_PARAMETER),
        }
        self.retire_if_settled(target);
        Ok(())
    }

    /// ProcessManager handles naming `target`.
    pub fn live_handles(&self, target: UserObjectTarget) -> u32 {
        self.rows.iter().find(|row| row.target == target).map_or(0, |row| row.live)
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

#[cfg(test)]
mod tests;
