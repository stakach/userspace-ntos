//! Coalesced runtime wake demand for bounded hosted DPC dispatch passes.

use super::*;
use nt_component_suspension::ResumeWake;

static mut WAKE: ResumeWake = match ResumeWake::new(10_000, 160_000) {
    Ok(wake) => wake,
    Err(_) => panic!("invalid hosted DPC pacing"),
};

/// Reconcile only canonical queued demand. A busy physical lane does not cancel its work.
pub(crate) unsafe fn next_deadline(now: u64) -> Option<u64> {
    let pending = hosted_driver_dpc_activation_pending();
    let wake = &mut *core::ptr::addr_of_mut!(WAKE);
    wake.reconcile(pending, now);
    wake.next_deadline()
}

/// Timer delivery observes demand without claiming a pass or executing a driver.
pub(crate) unsafe fn wake_due(now: u64) -> u64 {
    u64::from(next_deadline(now).is_some_and(|deadline| deadline <= now))
}

pub(super) unsafe fn run() -> u64 {
    let now = crate::monotonic_time_100ns();
    next_deadline(now);
    let Some(mut pass) = (&mut *core::ptr::addr_of_mut!(WAKE))
        .begin_pass(now)
        .expect("hosted DPC wake identity exhausted")
    else {
        return 0;
    };
    // No wake/table borrow survives native execution. Nested scans cannot claim this pass.
    let delivered = drain_hosted_driver_dpc_snapshot();
    let pending = hosted_driver_dpc_activation_pending();
    (&mut *core::ptr::addr_of_mut!(WAKE))
        .finish_pass(
            &mut pass,
            crate::monotonic_time_100ns(),
            pending,
            delivered != 0,
        )
        .expect("hosted DPC wake completion lost its exact pass");
    // A retained component may receive again without visiting the outer runtime barrier.
    // Programming does not acknowledge demand; bootstrap has no registered runtime owner.
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    crate::service_sec_image::rearm_registered_active_delay_timer();
    delivered
}
