//! Root-side latency of one hot file/registry call, from the root receiving its message to the
//! same thread's next message.
//!
//! Phases, all TSC ticks: `ingress` (message received → dispatch start), `handler` (the table
//! dispatch), `tail` (dispatch end → Reply sent, including the pre-reply receive preparation),
//! and `return` (Reply sent → the same badge's next message). `return` is split into the time
//! Root spent blocked idle in its receive and everything else: guest execution of the caller,
//! scheduling, and Root serving other work while the caller's next Call waited. Observation
//! only; a phase whose boundary was not observed (a parked or redirected reply) is not counted.

use core::fmt::Write;
use nt_syscall::NativeService;

const SERVICES: [(NativeService, &str); 6] = [
    (NativeService::NtReadFile, "read"),
    (NativeService::NtWriteFile, "write"),
    (NativeService::NtOpenKey, "open-key"),
    (NativeService::NtOpenKeyEx, "open-key-ex"),
    (NativeService::NtQueryValueKey, "query-value"),
    (NativeService::NtCreateKey, "create-key"),
];
pub(crate) const BADGE_SLOTS: usize = 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Latency {
    pub(crate) calls: u64,
    pub(crate) ingress: u64,
    pub(crate) handler: u64,
    pub(crate) tail: u64,
    pub(crate) returns: u64,
    pub(crate) return_idle: u64,
    pub(crate) return_other: u64,
}

impl Latency {
    const EMPTY: Self = Self { calls: 0, ingress: 0, handler: 0, tail: 0, returns: 0,
        return_idle: 0, return_other: 0 };
}

#[derive(Clone, Copy)]
struct Current {
    badge: u64,
    service: usize,
    ingress_at: u64,
    started: u64,
    finished: Option<u64>,
}

#[derive(Clone, Copy)]
struct Returning {
    badge: u64,
    service: usize,
    replied_at: u64,
    idle_at_reply: u64,
}

pub(crate) struct LatencyCensus {
    rows: [Latency; SERVICES.len()],
    last_ingress: Option<(u64, u64)>,
    current: Option<Current>,
    returning: [Option<Returning>; BADGE_SLOTS],
}

impl LatencyCensus {
    pub(crate) const fn new() -> Self {
        Self { rows: [Latency::EMPTY; SERVICES.len()], last_ingress: None, current: None,
            returning: [None; BADGE_SLOTS] }
    }

    /// Root materialized a message from `badge`; closes that badge's pending return phase.
    pub(crate) fn ingress(&mut self, badge: u64, now: u64, idle_ticks: u64) {
        self.last_ingress = Some((badge, now));
        let Some(slot) = Self::slot(badge) else { return; };
        let Some(returning) = self.returning[slot].take().filter(|row| row.badge == badge)
            else { return; };
        let row = &mut self.rows[returning.service];
        let total = now.saturating_sub(returning.replied_at);
        let idle = idle_ticks.saturating_sub(returning.idle_at_reply).min(total);
        row.returns = row.returns.saturating_add(1);
        row.return_idle = row.return_idle.saturating_add(idle);
        row.return_other = row.return_other.saturating_add(total - idle);
    }

    pub(crate) fn dispatch_started(&mut self, badge: u64, service: Option<NativeService>,
        now: u64) {
        self.current = service
            .and_then(|service| SERVICES.iter().position(|(hot, _)| *hot == service))
            .and_then(|service| {
                let (ingress_badge, ingress_at) = self.last_ingress?;
                (ingress_badge == badge).then_some(Current {
                    badge, service, ingress_at, started: now, finished: None })
            });
    }

    pub(crate) fn dispatch_finished(&mut self, now: u64) {
        if let Some(current) = self.current.as_mut() { current.finished.get_or_insert(now); }
    }

    /// Root is about to send the Reply of the call it last dispatched for `badge`.
    pub(crate) fn replying(&mut self, badge: u64, now: u64, idle_ticks: u64) {
        let Some(current) = self.current.take() else { return; };
        let Some(finished) = current.finished.filter(|_| current.badge == badge) else { return; };
        let row = &mut self.rows[current.service];
        row.calls = row.calls.saturating_add(1);
        row.ingress = row.ingress.saturating_add(current.started.saturating_sub(current.ingress_at));
        row.handler = row.handler.saturating_add(finished.saturating_sub(current.started));
        row.tail = row.tail.saturating_add(now.saturating_sub(finished));
        if let Some(slot) = Self::slot(badge) {
            self.returning[slot] = Some(Returning {
                badge, service: current.service, replied_at: now, idle_at_reply: idle_ticks });
        }
    }

    pub(crate) fn latency(&self, service: NativeService) -> Option<Latency> {
        SERVICES.iter().position(|(hot, _)| *hot == service).map(|index| self.rows[index])
    }

    /// `name=calls/ingress/handler/tail/returns/return-idle/return-other` in Mtick.
    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] hot-service-latency calls/ingress/handler/tail/returns/return-idle/return-other-Mtick:")?;
        for ((_, name), row) in SERVICES.iter().zip(&self.rows) {
            write!(out, " {name}={}/{}/{}/{}/{}/{}/{}", row.calls, row.ingress / 1_000_000,
                row.handler / 1_000_000, row.tail / 1_000_000, row.returns,
                row.return_idle / 1_000_000, row.return_other / 1_000_000)?;
        }
        writeln!(out)
    }

    fn slot(badge: u64) -> Option<usize> {
        usize::try_from(badge).ok().filter(|slot| *slot < BADGE_SLOTS)
    }
}

/// Root-only: the shared root receive, table dispatch and plain Reply tail all run on the
/// single root executor. Other executors never touch this table.
static mut ROOT: LatencyCensus = LatencyCensus::new();

fn root() -> Option<&'static mut LatencyCensus> {
    // SAFETY: only the single root executor passes the check and mutates the table.
    crate::serial_records::is_root_executor()
        .then(|| unsafe { &mut *core::ptr::addr_of_mut!(ROOT) })
}

pub(crate) fn ingress(badge: u64) {
    if let Some(census) = root() {
        census.ingress(badge, crate::disk_census_ticks(), crate::root_idle_receive_ticks());
    }
}

pub(crate) fn dispatch_started(badge: u64, service: Option<NativeService>) {
    if let Some(census) = root() { census.dispatch_started(badge, service, crate::disk_census_ticks()); }
}

pub(crate) fn dispatch_finished() {
    if let Some(census) = root() { census.dispatch_finished(crate::disk_census_ticks()); }
}

pub(crate) fn replying(badge: u64) {
    if let Some(census) = root() {
        census.replying(badge, crate::disk_census_ticks(), crate::root_idle_receive_ticks());
    }
}

pub(crate) fn print_census() {
    let Some(census) = root() else { return; };
    let mut record = nt_printf::record::RecordBuffer::<1024>::new();
    let _ = census.write_census(&mut record);
    crate::print_str(record.bytes());
}
