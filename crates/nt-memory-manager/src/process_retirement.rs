//! Ordered final VM retirement for an already exiting process.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use = "pending retirement must retain the process deletion owner"]
pub enum ProcessVmRetirement {
    NotQuiescent,
    LeavesPending,
    PageTablesPending,
    VspacePending,
    Complete,
}

/// The existing process-deletion owner supplies generation fencing and serializes each attempt.
/// All cleanup methods are retryable: acknowledge only resources actually released and retain
/// the exact remaining ownership on failure. No callback may admit new access to the dying VM.
pub trait ProcessVmRetirementIo {
    /// Check the exact process generation, stopped execution and outstanding user continuations
    /// before any destructive action, including on retries. This check must have no side effects.
    fn is_quiescent(&self) -> bool;
    /// Finish mapped-data writeback and revoke every alias/leaf, including bootstrap leaves.
    /// Keep image/VAD/working-set metadata and transition backing through failure.
    fn retire_leaves(&mut self) -> bool;
    fn retire_page_tables(&mut self) -> bool;
    /// Release remaining paging/root capabilities, retaining the published root identity on error.
    fn retire_vspace(&mut self) -> bool;
    /// Commit logical retirement only after all physical access is gone. This must not fail;
    /// reserve any needed cleanup metadata in an earlier stage. The outer owner advances its
    /// deletion phase exactly once after this returns, and never retries a completed retirement.
    fn commit_metadata(&mut self);
}

/// No second pending table is needed: the existing process-deletion record owns retries, while
/// each backend resource record retains its own partial cleanup. Earlier empty stages are no-ops.
pub fn retire_process_vm(io: &mut impl ProcessVmRetirementIo) -> ProcessVmRetirement {
    if !io.is_quiescent() {
        return ProcessVmRetirement::NotQuiescent;
    }
    if !io.retire_leaves() {
        return ProcessVmRetirement::LeavesPending;
    }
    if !io.retire_page_tables() {
        return ProcessVmRetirement::PageTablesPending;
    }
    if !io.retire_vspace() {
        return ProcessVmRetirement::VspacePending;
    }
    io.commit_metadata();
    ProcessVmRetirement::Complete
}

#[cfg(test)]
#[path = "process_retirement_tests.rs"]
mod tests;
