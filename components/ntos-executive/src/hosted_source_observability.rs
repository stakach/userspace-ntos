//! Successful native source milestones, separate from transport acknowledgements.
//!
//! Terminal counts exact pending receipts and successful inline results. Error inline results
//! collapse provider failure and admission rejection in ExternalDispatchResult, so are excluded.
//! Canonical commit means the canonical IRP has been freed (inline API return or successful strict
//! completion ACK), not Event visibility. Origin commit means the exact origin CommitRequested
//! packet returned Committed. Retirement means both retained semantic Reply and source admission
//! were removed on the normal terminal path; stopped-owner discard is not successful coverage.

use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Clone, Copy)]
pub(super) enum Kind {
    Ioctl,
    Pnp,
    Read,
    Write,
}

struct Counters {
    terminal: AtomicU64,
    origin: AtomicU64,
    canonical: AtomicU64,
    retired: AtomicU64,
}

impl Counters {
    const fn new() -> Self {
        Self {
            terminal: AtomicU64::new(0),
            origin: AtomicU64::new(0),
            canonical: AtomicU64::new(0),
            retired: AtomicU64::new(0),
        }
    }
}

static COUNTS: [Counters; 4] = [const { Counters::new() }; 4];
static IOCTL_METHODS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];

pub(super) fn terminal(kind: Kind, code: u32) {
    COUNTS[kind as usize]
        .terminal
        .fetch_add(1, Ordering::Relaxed);
    if matches!(kind, Kind::Ioctl) {
        IOCTL_METHODS[(code & 3) as usize].fetch_add(1, Ordering::Relaxed);
    }
}
pub(super) fn origin(kind: Kind) {
    COUNTS[kind as usize].origin.fetch_add(1, Ordering::Relaxed);
}
pub(super) fn canonical(kind: Kind) {
    COUNTS[kind as usize]
        .canonical
        .fetch_add(1, Ordering::Relaxed);
}
pub(super) fn retired(kind: Kind) {
    COUNTS[kind as usize]
        .retired
        .fetch_add(1, Ordering::Relaxed);
}

/// The validation profile runs its isolated probe before starting NT user images.
#[cfg(feature = "source-irp-integration")]
pub(crate) fn probe_snapshot() -> nt_compat_exports::source_probe_metrics::Snapshot {
    fn read(kind: Kind) -> [u64; 4] {
        let counters = &COUNTS[kind as usize];
        [
            counters.terminal.load(Ordering::Relaxed),
            counters.origin.load(Ordering::Relaxed),
            counters.canonical.load(Ordering::Relaxed),
            counters.retired.load(Ordering::Relaxed),
        ]
    }
    nt_compat_exports::source_probe_metrics::Snapshot {
        ioctl: read(Kind::Ioctl),
        read: read(Kind::Read),
        write: read(Kind::Write),
        methods: core::array::from_fn(|index| IOCTL_METHODS[index].load(Ordering::Relaxed)),
    }
}

/// Returns a verdict only when each source kind reached a real native terminal.
/// This proves milestone coverage, not that every request has drained at this snapshot.
pub(crate) fn report() -> Option<bool> {
    use crate::{print_str, print_u64};
    print_str(b"[source-native] terminal/origin-commit/canonical-commit/retired");
    let mut all_exercised = true;
    let mut all_committed = true;
    for (index, name) in [b" ioctl=".as_slice(), b" pnp=", b" read=", b" write="]
        .iter()
        .enumerate()
    {
        let counters = &COUNTS[index];
        let values = [
            counters.terminal.load(Ordering::Relaxed),
            counters.origin.load(Ordering::Relaxed),
            counters.canonical.load(Ordering::Relaxed),
            counters.retired.load(Ordering::Relaxed),
        ];
        print_str(name);
        for (field, value) in values.into_iter().enumerate() {
            if field != 0 {
                print_str(b"/");
            }
            print_u64(value);
        }
        all_exercised &= values[0] != 0;
        all_committed &= values.iter().all(|value| *value != 0);
    }
    print_str(b" ioctl-method-terminals(buffered/in/out/neither)=");
    for (index, count) in IOCTL_METHODS.iter().enumerate() {
        if index != 0 {
            print_str(b"/");
        }
        print_u64(count.load(Ordering::Relaxed));
    }
    if !all_exercised {
        print_str(b" coverage=partial");
    }
    print_str(b"\n");
    all_exercised.then_some(all_committed)
}
