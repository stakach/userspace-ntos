//! Callback-suspended wait admissions that did not return `Accepted` (#336).
//!
//! A user callback completed and left its dispatch suspended in a wait. The wait's admission
//! is attempted with the Reply bound to that callback. A no-effect refusal keeps the wait and
//! its Reply for a later attempt; an indeterminate outcome quarantines both. Neither is ever
//! answered or restarted without an `Accepted` admission.

use super::*;
use crate::retained_admissions::{Disposition, RetainedAdmissions};

#[derive(Clone, Copy)]
pub(super) enum CallbackWait {
    Provider(win32k_glue::PendingProviderWaitDispatch),
    Lpc(win32k_glue::PendingLpcWaitDispatch),
    Receive(win32k_glue::PendingReceiveDispatch),
    Service(win32k_glue::PendingServiceWaitDispatch),
}

#[derive(Clone, Copy)]
pub(super) struct RetainedCallbackWait {
    pub(super) wait: CallbackWait,
    pub(super) reply_cap: u64,
    pub(super) transfer: ComponentCallbackTransfer,
    pub(super) destination: HostedContinuationDestination,
}

impl RetainedCallbackWait {
    unsafe fn admit(&self, handler: &mut ExecNtHandler) -> RetainedWaitAdmission {
        let transfer = NestedWaitTransfer::from_completed(Some(self.transfer));
        match self.wait {
            CallbackWait::Provider(pending) => provider_wait_admit_with_transfer(
                handler, pending, self.reply_cap, transfer, self.destination,
            ),
            CallbackWait::Lpc(pending) => lpc_wait_admit_with_transfer(
                handler, pending, self.reply_cap, transfer, self.destination,
            ),
            CallbackWait::Receive(pending) => receive_admit_with_transfer(
                pending, self.reply_cap, transfer, self.destination,
            ),
            CallbackWait::Service(pending) => service_wait_admit_with_transfer(
                pending, self.reply_cap, transfer, self.destination,
            ),
        }
    }
}

static mut RETAINED: RetainedAdmissions<RetainedCallbackWait> = RetainedAdmissions::new();

unsafe fn trace(stage: &[u8], reply_cap: u64) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    if TRACED.fetch_add(1, Ordering::Relaxed) < 32 {
        let retained = &*core::ptr::addr_of!(RETAINED);
        print_str(b"[callback-wait-admission] ");
        print_str(stage);
        print_str(b" reply=");
        print_u64(reply_cap);
        print_str(b" retrying/quarantined=");
        print_u64(retained.retrying() as u64);
        print_str(b"/");
        print_u64(retained.quarantined() as u64);
        print_str(b"\n");
    }
}

/// Admit `wait` with the Reply it is bound to. Whatever the outcome, that Reply now belongs
/// to the admitted continuation or to this owner; the caller must not answer or restart it.
pub(super) unsafe fn admit_callback_wait(
    handler: &mut ExecNtHandler,
    wait: RetainedCallbackWait,
) -> Disposition {
    let outcome = wait.admit(handler);
    match (&mut *core::ptr::addr_of_mut!(RETAINED)).retain(wait, outcome) {
        Ok(Disposition::Admitted) => Disposition::Admitted,
        Ok(Disposition::RetryLater) => {
            trace(b"refused-no-effect retained-for-retry", wait.reply_cap);
            Disposition::RetryLater
        }
        Ok(Disposition::Quarantined) => {
            trace(b"indeterminate quarantined", wait.reply_cap);
            Disposition::Quarantined
        }
        Err(unrecorded) => {
            // No record could be allocated. The Reply still stays unanswered.
            trace(b"retained-without-record", unrecorded.reply_cap);
            Disposition::Quarantined
        }
    }
}

/// Retry every no-effect refusal once. Returns the number newly admitted.
pub(super) unsafe fn retry_callback_waits(handler: &mut ExecNtHandler) -> usize {
    let retained = &mut *core::ptr::addr_of_mut!(RETAINED);
    if retained.retrying() == 0 {
        return 0;
    }
    let admitted = retained.retry(|wait| wait.admit(&mut *handler));
    if admitted != 0 {
        trace(b"retry admitted", 0);
        let _ = component_resume::drain_hosted_ready(core::ptr::from_mut(handler));
    }
    admitted
}
