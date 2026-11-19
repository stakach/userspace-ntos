//! Retained ownership of a driver launch whose rollback could not finish (#361).
//!
//! A failed load has already entered native effects. When `clear_instance` refuses its cleanup
//! (an owner still retains the instance, its domain, or a capability), the instance is neither
//! live nor free. It is recorded here with its service identity, the original load status, the
//! cleanup refusal and its hosted domain; it is never dispatched to, never reported ready, and its
//! service cannot be loaded again until a later retirement finishes the physical cleanup.

use alloc::vec::Vec;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FailedLaunch {
    pub(crate) instance: usize,
    pub(crate) service: Vec<u8>,
    pub(crate) load_status: i32,
    pub(crate) cleanup_status: i32,
    pub(crate) domain_id: u64,
    pub(crate) domain_cookie: u64,
}

pub(crate) struct FailedLaunchQuarantine {
    records: Vec<FailedLaunch>,
}

impl FailedLaunchQuarantine {
    pub(crate) const fn new() -> Self {
        Self { records: Vec::new() }
    }

    /// Retain `launch`. One record per instance; a later refusal updates its cleanup status.
    /// `Err` returns the record when no memory is available; the caller must still treat the
    /// instance as retained (never free, never live).
    pub(crate) fn quarantine(&mut self, launch: FailedLaunch) -> Result<(), FailedLaunch> {
        if let Some(existing) = self.records.iter_mut().find(|row| row.instance == launch.instance) {
            existing.cleanup_status = launch.cleanup_status;
            return Ok(());
        }
        if self.records.try_reserve(1).is_err() {
            return Err(launch);
        }
        self.records.push(launch);
        Ok(())
    }

    pub(crate) fn retains_instance(&self, instance: usize) -> bool {
        self.records.iter().any(|row| row.instance == instance)
    }

    /// A same-name load must wait for the retained instance's retirement.
    pub(crate) fn blocks_reload(&self, service: &[u8]) -> bool {
        self.records.iter().any(|row| row.service.eq_ignore_ascii_case(service))
    }

    /// Try each retained cleanup once. A finished cleanup removes its record; a refusal keeps
    /// it with the latest status. Returns the instances retired.
    pub(crate) fn retire(&mut self, mut cleanup: impl FnMut(usize) -> Result<(), i32>) -> Vec<usize> {
        let mut retired = Vec::new();
        let mut index = 0;
        while index < self.records.len() {
            match cleanup(self.records[index].instance) {
                Ok(()) => {
                    let row = self.records.swap_remove(index);
                    let _ = retired.try_reserve(1);
                    retired.push(row.instance);
                }
                Err(status) => {
                    self.records[index].cleanup_status = status;
                    index += 1;
                }
            }
        }
        retired
    }

    pub(crate) fn len(&self) -> usize {
        self.records.len()
    }
}
