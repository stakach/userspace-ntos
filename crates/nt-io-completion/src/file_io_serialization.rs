//! Allocation-free FILE_OBJECT Busy transitions, independent of routes and reference storage.

use crate::{
    FileIoAcquireResult, FileIoMode, FileIoRelease, STATUS_INSUFFICIENT_RESOURCES,
    STATUS_INVALID_HANDLE, STATUS_INVALID_PARAMETER,
};

/// One FILE_OBJECT's serialization state. The embedding owner supplies its captured mode and
/// cleanup-reference state, retains every queued/acquired operation, and selects FIFO waiters.
/// This state does not own File events, references, reply capabilities, or cleanup dispatch.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct FileIoSerialization {
    owner_tid: u64,
    grant_tid: u64,
    waiters: u32,
    cleanup_waiting: bool,
}

impl FileIoSerialization {
    const CLEANUP_LOCK_OWNER: u64 = u64::MAX;

    pub const fn new() -> Self {
        Self {
            owner_tid: 0,
            grant_tid: 0,
            waiters: 0,
            cleanup_waiting: false,
        }
    }

    /// A promoted grant is consumed once; genuine same-thread reentry still contends.
    pub fn begin_io(
        &mut self,
        mode: FileIoMode,
        tid: u64,
        cleanup_reference_held: bool,
    ) -> Result<FileIoAcquireResult, u32> {
        if tid == 0 || tid == Self::CLEANUP_LOCK_OWNER {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !mode.is_synchronous() {
            if cleanup_reference_held {
                return Err(STATUS_INVALID_HANDLE);
            }
            return Ok(FileIoAcquireResult::Bypassed);
        }
        if cleanup_reference_held && !(self.owner_tid == tid && self.grant_tid == tid) {
            return Err(STATUS_INVALID_HANDLE);
        }
        // Releasing Busy does not let a new arrival overtake a counted FIFO waiter.
        if self.owner_tid == 0 && self.waiters == 0 && !self.cleanup_waiting {
            self.owner_tid = tid;
            return Ok(FileIoAcquireResult::Acquired);
        }
        if self.owner_tid == tid && self.grant_tid == tid {
            self.grant_tid = 0;
            return Ok(FileIoAcquireResult::Acquired);
        }
        self.waiters = self
            .waiters
            .checked_add(1)
            .ok_or(STATUS_INSUFFICIENT_RESOURCES)?;
        Ok(FileIoAcquireResult::Contended {
            alertable: mode.is_alertable(),
        })
    }

    /// The embedding owner must first validate its final-handle cleanup reference.
    pub fn begin_cleanup(&mut self, mode: FileIoMode) -> Result<FileIoAcquireResult, u32> {
        if self.cleanup_waiting || self.is_cleanup_owner() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if !mode.is_synchronous() {
            return Ok(FileIoAcquireResult::Bypassed);
        }
        if self.owner_tid == 0 && self.waiters == 0 {
            self.owner_tid = Self::CLEANUP_LOCK_OWNER;
            return Ok(FileIoAcquireResult::Acquired);
        }
        self.cleanup_waiting = true;
        Ok(FileIoAcquireResult::Contended { alertable: false })
    }

    pub fn cancel_io_waiter(&mut self) -> Result<u32, u32> {
        if self.waiters == 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.waiters -= 1;
        Ok(self.waiters)
    }

    /// Reserve Busy for the exact FIFO thread before making its continuation runnable.
    pub fn promote_io_waiter(&mut self, mode: FileIoMode, tid: u64) -> Result<u32, u32> {
        if tid == 0
            || tid == Self::CLEANUP_LOCK_OWNER
            || !mode.is_synchronous()
            || self.owner_tid != 0
            || self.grant_tid != 0
            || self.waiters == 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.waiters -= 1;
        self.owner_tid = tid;
        self.grant_tid = tid;
        Ok(self.waiters)
    }

    pub fn promote_cleanup_if_ready(
        &mut self,
        mode: FileIoMode,
        cleanup_reference_held: bool,
    ) -> Result<bool, u32> {
        if !self.cleanup_waiting {
            return Ok(false);
        }
        if !cleanup_reference_held || !mode.is_synchronous() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if self.has_live_io() {
            return Ok(false);
        }
        self.cleanup_waiting = false;
        self.owner_tid = Self::CLEANUP_LOCK_OWNER;
        Ok(true)
    }

    pub fn release_io(&mut self, mode: FileIoMode, tid: u64) -> Result<FileIoRelease, u32> {
        if tid == 0
            || tid == Self::CLEANUP_LOCK_OWNER
            || !mode.is_synchronous()
            || self.owner_tid != tid
            || self.grant_tid != 0
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.owner_tid = 0;
        Ok(FileIoRelease {
            waiters: self.waiters,
        })
    }

    pub fn release_cleanup_io(&mut self) -> Result<FileIoRelease, u32> {
        if !self.is_cleanup_owner() || self.grant_tid != 0 {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.owner_tid = 0;
        Ok(FileIoRelease {
            waiters: self.waiters,
        })
    }

    pub fn cancel_promoted_io(&mut self, tid: u64) -> Result<FileIoRelease, u32> {
        if tid == 0
            || tid == Self::CLEANUP_LOCK_OWNER
            || self.owner_tid != tid
            || self.grant_tid != tid
        {
            return Err(STATUS_INVALID_PARAMETER);
        }
        self.owner_tid = 0;
        self.grant_tid = 0;
        Ok(FileIoRelease {
            waiters: self.waiters,
        })
    }

    /// Matches the existing hosted observer, including its internal cleanup-owner sentinel.
    pub const fn io_lock_owner(&self) -> Option<u64> {
        if self.owner_tid == 0 {
            None
        } else {
            Some(self.owner_tid)
        }
    }

    pub const fn io_waiter_count(&self) -> u32 {
        self.waiters
    }

    pub const fn cleanup_waiting(&self) -> bool {
        self.cleanup_waiting
    }

    pub const fn is_cleanup_owner(&self) -> bool {
        self.owner_tid == Self::CLEANUP_LOCK_OWNER
    }

    /// Whether acquired, promoted, or counted ordinary I/O still requires its retained reference.
    pub const fn has_live_io(&self) -> bool {
        self.owner_tid != 0 || self.grant_tid != 0 || self.waiters != 0
    }
}

#[cfg(test)]
mod tests;
