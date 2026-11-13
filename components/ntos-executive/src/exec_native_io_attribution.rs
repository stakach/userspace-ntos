//! Sampled, process-generation-scoped native I/O dispatch evidence.
//!
//! These ticks cover only the synchronous executive dispatch. A STATUS_PENDING reply carries a
//! retained asynchronous owner or a parked caller; its later wait is never charged to this call.

use super::*;
use nt_user_host::native_io_attribution::{sample_slow_ordinal, NativeIoCall, NativeIoKind, NativeIoOutcome};

static CALLS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static TICKS: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static PENDING_ASYNC: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
static PENDING_PARK: [AtomicU64; 3] = [const { AtomicU64::new(0) }; 3];
// Candidate File routes are captured before dispatch. A synchronous retry may consume its
// retained route during the call, so a lookup at return could name a reused handle instead.
const ROUTE_BUCKETS: usize = 2;
static ROUTE_CALLS: [AtomicU64; 3 * ROUTE_BUCKETS] =
    [const { AtomicU64::new(0) }; 3 * ROUTE_BUCKETS];
static ROUTE_TICKS: [AtomicU64; 3 * ROUTE_BUCKETS] =
    [const { AtomicU64::new(0) }; 3 * ROUTE_BUCKETS];

fn route_bucket(kind: NativeIoKind, route: Option<HostedFileRoute>) -> usize {
    kind.index() * ROUTE_BUCKETS + usize::from(route.is_some())
}

#[derive(Clone, Copy)]
struct OwnerSample {
    generation: u64,
    first: [u8; 3],
    slow_seen: [u32; 3],
}

impl OwnerSample {
    const fn empty() -> Self {
        Self { generation: 0, first: [0; 3], slow_seen: [0; 3] }
    }
}

// Only the executive broker dispatches these syscalls. The PI slot resets on a new process
// generation, so late installers get their own finite samples without preserving stale owners.
static mut OWNER_SAMPLES: [OwnerSample; MAX_PI] = [OwnerSample::empty(); MAX_PI];

fn should_trace(pi: usize, generation: Option<u64>, kind: NativeIoKind, ticks: u64, ordinal: u64) -> bool {
    let Some(generation) = generation.filter(|value| *value != 0 && pi < MAX_PI) else {
        return ordinal < 16;
    };
    let owner = unsafe { &mut (&mut *core::ptr::addr_of_mut!(OWNER_SAMPLES))[pi] };
    if owner.generation != generation {
        *owner = OwnerSample { generation, ..OwnerSample::empty() };
    }
    let index = kind.index();
    let first = owner.first[index] < 8;
    if first { owner.first[index] += 1; }
    let slow = if ticks >= 50_000_000 {
        let seen = owner.slow_seen[index].saturating_add(1);
        owner.slow_seen[index] = seen;
        sample_slow_ordinal(seen)
    } else {
        false
    };
    first || slow
}

fn label(kind: NativeIoKind) -> &'static [u8] {
    match kind {
        NativeIoKind::Read => b"read",
        NativeIoKind::Write => b"write",
        NativeIoKind::RemoveCompletion => b"remove-completion",
    }
}

/// Called after the actual syscall arm returns, including its early error returns. The optional
/// IOSB read is diagnostic only and runs only for a sampled, successful call with the same live
/// process generation. A failed read remains unknown rather than being reported as zero bytes.
pub(super) fn record(
    handler: &ExecNtHandler,
    call: NativeIoCall,
    pi: usize,
    generation: Option<u64>,
    route: Option<HostedFileRoute>,
    status: u32,
    ticks: u64,
) {
    let index = call.kind.index();
    let ordinal = CALLS[index].fetch_add(1, Ordering::Relaxed);
    TICKS[index].fetch_add(ticks, Ordering::Relaxed);
    let route_index = route_bucket(call.kind, route);
    ROUTE_CALLS[route_index].fetch_add(1, Ordering::Relaxed);
    ROUTE_TICKS[route_index].fetch_add(ticks, Ordering::Relaxed);
    let parked = status == nt_io_completion::STATUS_PENDING && match call.kind {
        NativeIoKind::RemoveCompletion => handler.io_completion_park_port >= 0,
        NativeIoKind::Read | NativeIoKind::Write => handler.pending_file_io_wait,
    };
    if status == nt_io_completion::STATUS_PENDING {
        if parked { &PENDING_PARK[index] } else { &PENDING_ASYNC[index] }
            .fetch_add(1, Ordering::Relaxed);
    }
    // Eight initial and geometrically spaced slow samples per operation and exact PI generation.
    if !should_trace(pi, generation, call.kind, ticks, ordinal) { return; }

    let information = if status == 0 && call.iosb_address != 0
        && handler.pi == pi
        && generation.is_some_and(|owned| handler.hosted_process_generation(pi) == Some(owned))
    {
        call.iosb_address.checked_add(8).and_then(|address| {
            let mut bytes = [0u8; 8];
            unsafe { handler.xas_read(address, &mut bytes) }
                .then_some(u64::from_le_bytes(bytes))
        })
    } else {
        None
    };
    let outcome = call.classify(status, information, parked);
    print_str(b"[native-io-dispatch] kind=");
    print_str(label(call.kind));
    print_str(b" ordinal="); print_u64(ordinal);
    print_str(b" pi="); print_u64(pi as u64);
    print_str(b" generation=");
    match generation { Some(value) => print_u64(value), None => print_str(b"unknown") }
    print_str(b" handle=0x"); print_hex_u64(call.handle);
    if let Some(route) = route {
        print_str(b" route-file=0x"); print_hex_u64(route.file_id);
        print_str(b" route-device=0x"); print_hex_u64(route.device_id);
    } else if call.kind != NativeIoKind::RemoveCompletion {
        print_str(b" route=local-or-unknown");
    }
    if let Some(requested) = call.requested_bytes {
        print_str(b" requested-bytes="); print_u64(requested);
    }
    print_str(b" status=0x"); print_hex(status);
    print_str(b" dispatch-Mtick="); print_u64(ticks / 1_000_000);
    match outcome {
        NativeIoOutcome::Completed(Some(value)) => {
            print_str(if call.kind == NativeIoKind::RemoveCompletion {
                b" packet-information="
            } else {
                b" completed-bytes="
            });
            print_u64(value);
        }
        NativeIoOutcome::Completed(None) => print_str(b" information=unknown"),
        NativeIoOutcome::PendingAsync => print_str(b" outcome=async-pending"),
        NativeIoOutcome::PendingPark => print_str(b" outcome=caller-park"),
        NativeIoOutcome::TimedOut => print_str(b" outcome=timeout-no-packet"),
        NativeIoOutcome::Failed => print_str(b" outcome=failed"),
    }
    print_str(b"\n");
}

pub(crate) fn print_summary() {
    for kind in [NativeIoKind::Read, NativeIoKind::Write, NativeIoKind::RemoveCompletion] {
        let index = kind.index();
        print_str(b"[native-io-summary] kind="); print_str(label(kind));
        print_str(b" calls="); print_u64(CALLS[index].load(Ordering::Relaxed));
        print_str(b" dispatch-Mtick="); print_u64(TICKS[index].load(Ordering::Relaxed) / 1_000_000);
        print_str(b" async-pending="); print_u64(PENDING_ASYNC[index].load(Ordering::Relaxed));
        print_str(b" caller-park="); print_u64(PENDING_PARK[index].load(Ordering::Relaxed));
        print_str(b"\n");
        let other = route_bucket(kind, None);
        let hosted = other + 1;
        print_str(b"[native-io-route-summary] kind="); print_str(label(kind));
        print_str(b" other-or-unknown-calls="); print_u64(ROUTE_CALLS[other].load(Ordering::Relaxed));
        print_str(b" other-or-unknown-Mtick="); print_u64(ROUTE_TICKS[other].load(Ordering::Relaxed) / 1_000_000);
        print_str(b" hosted-calls="); print_u64(ROUTE_CALLS[hosted].load(Ordering::Relaxed));
        print_str(b" hosted-Mtick="); print_u64(ROUTE_TICKS[hosted].load(Ordering::Relaxed) / 1_000_000);
        print_str(b"\n");
    }
}
