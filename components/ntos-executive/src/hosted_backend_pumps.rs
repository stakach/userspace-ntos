//! Borrowed backend dispatches whose pump stopped unfinished (#420).
//!
//! A backend caller (a video ACK, a lifecycle ACK or `execute`) borrows its output and has no
//! File row. When its pump stops with no lane to keep it, where the root cannot wait for it,
//! the native continuation and an owned copy of the output stay here instead of becoming an
//! uncertain result. The root boundary resumes each kept pump; the caller keeps the ticket in
//! its own row and collects the true result on a later turn, exactly once
//! (`nt_hosted_runtime::KeptBackendPumps`).

use super::*;
use nt_hosted_runtime::{BackendCollect, BackendTicket, KeptBackendPumps};

struct KeptBackend {
    continuation: FileIrpPumpContinuation,
    output: Vec<u8>,
}

type Returned = (HostedIrpTransportResult, Vec<u8>);

static mut KEPT: KeptBackendPumps<KeptBackend, Returned> = KeptBackendPumps::new();

fn kept() -> &'static mut KeptBackendPumps<KeptBackend, Returned> {
    unsafe { &mut *core::ptr::addr_of_mut!(KEPT) }
}

/// What a backend dispatch gave its caller.
#[must_use = "a pending backend dispatch must be kept and collected"]
pub(super) enum BackendDispatch {
    /// Returned in place; the output is already in the caller's buffer.
    Returned(HostedIrpTransportResult),
    /// Still running; keep the ticket and collect it on a later turn.
    Pending(BackendTicket),
}

/// What the caller's turn found for its ticket.
pub(super) enum BackendCollected {
    /// Still running: the ticket is handed back and this turn has no other effect.
    Pending(BackendTicket),
    /// The true result and the output the dispatch wrote, exactly once.
    Collected(HostedIrpTransportResult, Vec<u8>),
}

/// Dispatch `major` to `inst` exactly as `dispatch_irp_for_instance_exact`, except that an
/// unfinished pump with no lane to keep it is kept here for the caller (#420). The row and the
/// owned output are reserved before the provider can enter; a refused reservation is a
/// certainly unentered `INSUFFICIENT_RESOURCES`. `None` is the exact dispatch's own "the
/// instance is not available".
pub(super) unsafe fn dispatch_exact(
    inst: usize,
    major: u64,
    minor: u64,
    device_object: u64,
    canonical_irp_id: u64,
    canonical_file_id: u64,
    fsctl: u64,
    file_id: u64,
    requestor_tid: u64,
    in_data: &[u8],
    out: &mut [u8],
    caller: nt_process::native_handle::NativeHandleCaller,
) -> Option<BackendDispatch> {
    let mut output = Vec::new();
    if kept().reserve().is_err() || output.try_reserve_exact(out.len()).is_err() {
        return Some(BackendDispatch::Returned(HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        }));
    }
    match dispatch_irp_for_instance_exact_retaining(
        inst, major, minor, device_object, canonical_irp_id, canonical_file_id, fsctl, file_id,
        requestor_tid, None, in_data, out, caller,
    ) {
        HostedIrpDispatchProgress::Returned(result) => result.map(BackendDispatch::Returned),
        HostedIrpDispatchProgress::ChildWorkYield(continuation) => {
            // The native output is copied only when the pump returns; size it exactly as the
            // caller's buffer.
            output.resize(out.len(), 0);
            let ticket = kept().keep(KeptBackend { continuation, output });
            trace(b"kept", ticket.id());
            Some(BackendDispatch::Pending(ticket))
        }
    }
}

/// Run first in the caller's turn, before any other effect.
pub(super) fn collect(ticket: BackendTicket) -> BackendCollected {
    match kept().collect(ticket).expect("a move-only backend ticket names its kept row") {
        BackendCollect::Pending(ticket) => BackendCollected::Pending(ticket),
        BackendCollect::Collected((result, output)) => BackendCollected::Collected(result, output),
    }
}

/// Root boundary only: resume each kept backend pump once. A return is held for its caller; a
/// pump that stops again, or refuses with no effect, stays kept and is never replayed.
pub(super) unsafe fn redrive() -> usize {
    if kept().is_empty() { return 0; }
    // No kept pump runs inside another dispatch's scoped SCSI authority.
    let unscoped: Option<ActivePendingScsiProofAuthority> = None;
    match nt_hosted_runtime::scoped_resume(pending_scsi_proof_slot(), unscoped) {
        nt_hosted_runtime::ScopedResume::Resume => {}
        _ => return 0,
    }
    let mut ids = Vec::new();
    let ready = |kept: &KeptBackend| kept.continuation.retry_without_new_child();
    let count = kept().resumable(ready).count();
    if count == 0 || ids.try_reserve(count).is_err() { return 0; }
    ids.extend(kept().resumable(ready));
    let mut progressed = 0;
    for id in ids {
        // A resume may keep or collect another row: hold no borrow across it.
        let Some(KeptBackend { continuation, mut output }) = kept().take_pump(id) else { continue };
        match continuation.resume_after_child(&mut output) {
            Ok(FileIrpResumeProgress::Completed(result)) => {
                if kept().returned(id, (result, output)).is_err() {
                    trace(b"unowned-return", id);
                    continue;
                }
                trace(b"returned", id);
                progressed += 1;
            }
            Ok(FileIrpResumeProgress::ChildWorkYield(continuation)) | Err(continuation) => {
                if kept().unfinished(id, KeptBackend { continuation, output }).is_err() {
                    trace(b"unowned-pump", id);
                }
            }
        }
    }
    progressed
}

fn trace(stage: &[u8], id: u64) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 32 && !n.is_power_of_two() { return; }
    print_str(b"[backend-pump] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" id=");
    print_u64(id);
    print_str(b"\n");
}
