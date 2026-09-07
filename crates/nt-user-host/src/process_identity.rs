//! Process lifetime provenance for retained native thread runtimes.
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

static NEXT_TEMPORARY_GENERATION: AtomicU64 = AtomicU64::new(1);

/// The two authorities have independent counters; equal numeric values are not equal lifetimes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessGeneration {
    Hosted(u64),
    Temporary(u64),
}

impl ProcessGeneration {
    pub const fn is_valid(self) -> bool {
        match self {
            Self::Hosted(value) | Self::Temporary(value) => value != 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub generation: ProcessGeneration,
}

impl ProcessIdentity {
    pub const fn empty() -> Self {
        Self {
            pid: 0,
            generation: ProcessGeneration::Hosted(0),
        }
    }

    pub const fn is_valid(self) -> bool {
        self.pid != 0 && self.generation.is_valid()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TemporaryProcessClaim {
    pi: usize,
    pid: u32,
    generation: u64,
}

impl TemporaryProcessClaim {
    pub fn pi(self) -> usize {
        self.pi
    }
    pub fn pid(self) -> u32 {
        self.pid
    }
    pub fn identity(self) -> ProcessIdentity {
        ProcessIdentity {
            pid: self.pid,
            generation: ProcessGeneration::Temporary(self.generation),
        }
    }
}

/// Resolve exactly one process authority and verify the ETHREAD's owning PID. A temporary claim
/// is not a missing-hosted-generation fallback; simultaneous or mismatched authorities are refused.
pub fn resolve_thread_process_identity(
    pi: usize,
    thread_pid: u32,
    hosted: Option<crate::ProcessMechanism>,
    temporary: Option<TemporaryProcessClaim>,
) -> Option<ProcessIdentity> {
    let process = match (hosted, temporary) {
        (Some(hosted), None) if hosted.pi == pi => ProcessIdentity {
            pid: hosted.pid,
            generation: ProcessGeneration::Hosted(hosted.generation),
        },
        (None, Some(temporary)) if temporary.pi == pi => temporary.identity(),
        _ => return None,
    };
    (process.is_valid() && process.pid == thread_pid).then_some(process)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TemporaryProcessError {
    OutOfRange,
    InvalidPid,
    Occupied,
    DuplicatePid,
    InsufficientResources,
    StaleClaim,
}

/// Allocate slots once, before admission. Claims and exact release allocate no memory.
/// Native callers must exclude live runtimes, VSpaces and other owners before releasing a claim.
pub struct TemporaryProcessSlots {
    slots: Vec<Option<TemporaryProcessClaim>>,
}

impl TemporaryProcessSlots {
    pub fn try_new(count: usize) -> Result<Self, TemporaryProcessError> {
        let mut slots = Vec::new();
        slots
            .try_reserve_exact(count)
            .map_err(|_| TemporaryProcessError::InsufficientResources)?;
        slots.resize(count, None);
        Ok(Self { slots })
    }

    pub fn get(&self, pi: usize) -> Option<TemporaryProcessClaim> {
        self.slots.get(pi).copied().flatten()
    }

    pub fn pi_for_pid(&self, pid: u32) -> Option<usize> {
        self.slots
            .iter()
            .flatten()
            .find(|claim| claim.pid == pid)
            .map(|claim| claim.pi)
    }

    pub fn claim(
        &mut self,
        pi: usize,
        pid: u32,
    ) -> Result<TemporaryProcessClaim, TemporaryProcessError> {
        self.claim_with_counter(pi, pid, &NEXT_TEMPORARY_GENERATION)
    }

    fn claim_with_counter(
        &mut self,
        pi: usize,
        pid: u32,
        counter: &AtomicU64,
    ) -> Result<TemporaryProcessClaim, TemporaryProcessError> {
        let slot = self
            .slots
            .get(pi)
            .ok_or(TemporaryProcessError::OutOfRange)?;
        if pid == 0 {
            return Err(TemporaryProcessError::InvalidPid);
        }
        if slot.is_some() {
            return Err(TemporaryProcessError::Occupied);
        }
        if self.pi_for_pid(pid).is_some() {
            return Err(TemporaryProcessError::DuplicatePid);
        }
        let generation = counter
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                if value == 0 {
                    None
                } else {
                    value.checked_add(1)
                }
            })
            .map_err(|_| TemporaryProcessError::InsufficientResources)?;
        let claim = TemporaryProcessClaim {
            pi,
            pid,
            generation,
        };
        self.slots[pi] = Some(claim);
        Ok(claim)
    }

    pub fn release_exact(
        &mut self,
        claim: TemporaryProcessClaim,
    ) -> Result<(), TemporaryProcessError> {
        let slot = self
            .slots
            .get_mut(claim.pi)
            .ok_or(TemporaryProcessError::OutOfRange)?;
        if *slot != Some(claim) {
            return Err(TemporaryProcessError::StaleClaim);
        }
        *slot = None;
        Ok(())
    }
}

#[cfg(test)]
#[path = "process_identity_tests.rs"]
mod tests;
