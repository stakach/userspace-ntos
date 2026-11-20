//! Hosted mechanism teardown for processes a kernel driver terminated with `ZwTerminateProcess`.
//!
//! ProcessManager termination, handle rundown and exit notification are already complete when
//! a row is recorded. A syscall's NtTerminateProcess tears the mechanisms down in its own turn;
//! a driver service has no turn, so the service loop's maintenance pass drains these rows. The
//! exact process identity guards against a recycled process index.

use nt_user_host::process_identity::ProcessIdentity;

static mut PENDING: alloc::vec::Vec<(u8, ProcessIdentity)> = alloc::vec::Vec::new();

fn pending() -> &'static mut alloc::vec::Vec<(u8, ProcessIdentity)> {
    // Root-thread only: the driver service and the maintenance drain both run on the root.
    unsafe { &mut *core::ptr::addr_of_mut!(PENDING) }
}

/// Reserve the row before the termination effect so recording it afterwards cannot fail.
pub(crate) fn reserve() -> Result<(), u32> {
    pending().try_reserve(1).map_err(|_| nt_process::STATUS_INSUFFICIENT_RESOURCES)
}

/// Record a terminated process's mechanisms after a successful `reserve`.
pub(crate) fn record(process_index: u8, identity: ProcessIdentity) {
    let rows = pending();
    assert!(rows.len() < rows.capacity(), "termination row recorded without reservation");
    rows.push((process_index, identity));
}

/// Take every recorded row. The caller tears down each row whose index still names the same
/// process identity; a row whose index was reclaimed meanwhile is dropped.
pub(crate) fn take() -> alloc::vec::Vec<(u8, ProcessIdentity)> {
    core::mem::take(pending())
}
