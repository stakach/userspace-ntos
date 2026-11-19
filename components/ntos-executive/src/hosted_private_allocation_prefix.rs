//! The retained native prefix of one `NtAllocateVirtualMemory` and its checked rollback.
//!
//! Pages mapped or reprotected before the VAD and commit charge publish are recorded here before
//! the next page effect. When a later page fails, rollback reverses that exact prefix. A refused
//! reversal retains the remainder: the VAD and commit charge stay as they were before the request,
//! and the remaining native pages belong only to this owner. Further VM changes to that process and
//! its retirement are fenced until the rollback settles; it is retried at the event boundary.

use super::*;
use nt_memory_manager::private_allocation_prefix::{
    PrefixEffect, PrefixRollbackOutcome, PrivateAllocationPrefix, PrivateAllocationPrefixIo,
};
use nt_memory_manager::private_page_installation::InstallationEffect;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Target {
    pub(super) pi: usize,
    pub(super) process: nt_memory_manager::ProcessIdentity,
    pub(super) pml4: u64,
}

static mut OWNER: PrivateAllocationPrefix<Target> = PrivateAllocationPrefix::new();
static BORROWED: AtomicBool = AtomicBool::new(false);

struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, u32> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

fn owner() -> &'static mut PrivateAllocationPrefix<Target> {
    unsafe { &mut *core::ptr::addr_of_mut!(OWNER) }
}

/// Both reversals act through owners that retain their exact partial state on error (the client
/// frame registry row, pagefile retirement, or the unchanged resident mapping), so an error is an
/// authoritative refusal and a retry continues that exact state rather than replaying an effect.
fn refused(result: Result<(), u32>) -> InstallationEffect {
    match result {
        Ok(()) => InstallationEffect::Acknowledged,
        Err(status) => InstallationEffect::Refused(status),
    }
}

struct Io<'a> {
    handler: &'a ExecNtHandler,
}

impl Io<'_> {
    fn current(&self, target: &Target) -> bool {
        self.handler.capture_process_identity(target.pi) == Some(target.process)
            && self
                .handler
                .loop_ctx
                .and_then(|ctx| unsafe { ctx.for_process(target.pi) })
                .is_some_and(|ctx| unsafe {
                    (&*ctx.procs)
                        .get(target.pi)
                        .is_some_and(|process| target.pml4 != 0 && process.pml4 == target.pml4)
                })
    }
}

impl PrivateAllocationPrefixIo<Target> for Io<'_> {
    fn unmap(&mut self, target: &Target, page: u64) -> InstallationEffect {
        if !self.current(target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        refused(unsafe { vm_unmap_private_page(target.pi, target.process, page, self.handler) })
    }
    fn reprotect(
        &mut self,
        target: &Target,
        page: u64,
        current: u32,
        restore: u32,
    ) -> InstallationEffect {
        if !self.current(target) {
            return InstallationEffect::Refused(nt_process::STATUS_INVALID_HANDLE);
        }
        refused(unsafe {
            vm_reprotect_private_page(target.pi, target.process, page, current, restore, target.pml4)
        })
    }
}

static RETAINED: AtomicU64 = AtomicU64::new(0);
fn note(outcome: PrefixRollbackOutcome) {
    let (status, rollback_status, quarantined) = match outcome {
        PrefixRollbackOutcome::RolledBack(_) => return,
        PrefixRollbackOutcome::CleanupPending { status, rollback_status } => {
            (status, rollback_status, false)
        }
        PrefixRollbackOutcome::Quarantined { status, rollback_status } => {
            (status, rollback_status, true)
        }
    };
    let count = RETAINED.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if count > 16 && !count.is_power_of_two() {
        return;
    }
    print_str(b"[vm-alloc-prefix] retained #");
    print_u64(count);
    print_str(b" pages=");
    print_u64(owner().retained_pages());
    print_str(b" quarantined=");
    print_u64(quarantined as u64);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" rollback=0x");
    print_hex(rollback_status);
    print_str(b"\n");
}

/// Retry a retained rollback. A new allocation may begin only once the owner is idle.
pub(super) unsafe fn admit_allocation(handler: &ExecNtHandler) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let owner = owner();
    if !owner.is_idle() {
        let outcome = owner.advance(&mut Io { handler });
        note(outcome);
    }
    if owner.is_idle() {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}

/// Fence another VM change to a process whose allocation prefix is still being reversed.
pub(super) unsafe fn admit_process_change(handler: &ExecNtHandler, pi: usize) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let owner = owner();
    if owner.descriptor().is_some_and(|target| target.pi == pi) {
        let outcome = owner.advance(&mut Io { handler });
        note(outcome);
        if !owner.is_idle() {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    Ok(())
}

pub(super) unsafe fn begin(target: Target) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    owner().begin(target)
}

/// Invoke one page effect; it is recorded before any further effect can run.
pub(super) unsafe fn apply(
    page: u64,
    kind: PrefixEffect,
    effect: impl FnOnce() -> Result<(), u32>,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    owner().apply(page, kind, effect)
}

/// The VAD and commit charge publication now own every accepted page.
pub(super) unsafe fn commit() {
    let _borrow = Borrow::acquire().expect("allocation prefix publication is not reentrant");
    owner()
        .commit()
        .expect("the serialized allocation owns its recording prefix through publication");
}

/// Reverse the prefix after `status`. Only a `RolledBack` outcome settles the allocation.
pub(super) unsafe fn fail(handler: &ExecNtHandler, status: u32) -> PrefixRollbackOutcome {
    let Ok(_borrow) = Borrow::acquire() else {
        return PrefixRollbackOutcome::Quarantined {
            status,
            rollback_status: nt_address_space::STATUS_INSUFFICIENT_RESOURCES,
        };
    };
    let outcome = owner().fail(&mut Io { handler }, status);
    note(outcome);
    outcome
}

pub(super) unsafe fn retry_pending(handler: &ExecNtHandler) {
    let Ok(_borrow) = Borrow::acquire() else {
        return;
    };
    let owner = owner();
    if !owner.is_idle() && !owner.is_quarantined() {
        let outcome = owner.advance(&mut Io { handler });
        note(outcome);
    }
}

pub(super) fn process_available(pi: u64) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    owner()
        .descriptor()
        .is_none_or(|target| target.pi as u64 != pi)
}

/// Process retirement cannot pass a prefix it would orphan.
pub(super) unsafe fn drain_for_process(
    handler: &ExecNtHandler,
    process: nt_memory_manager::ProcessIdentity,
) -> Result<(), u32> {
    let _borrow = Borrow::acquire()?;
    let owner = owner();
    if owner
        .descriptor()
        .is_some_and(|target| target.process == process)
    {
        let outcome = owner.advance(&mut Io { handler });
        note(outcome);
        if !owner.is_idle() {
            return Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        }
    }
    Ok(())
}
