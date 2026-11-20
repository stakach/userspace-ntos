//! Root-side latency of one hot file/registry call, from the root receiving its message to the
//! same thread's next message.
//!
//! Phases, all TSC ticks: `ingress` (message received → dispatch start), `handler` (the table
//! dispatch), `tail` (dispatch end → Reply sent, including the pre-reply receive preparation),
//! and `return` (Reply sent → the same badge's next message). `return` is split into the time
//! Root spent blocked idle in its receive and everything else: guest execution of the caller,
//! scheduling, and Root serving other work while the caller's next Call waited. Observation
//! only; a phase whose boundary was not observed (a parked or redirected reply) is not counted.
//! When the reply goes through the shared reply-receive, `tail` is also split into `body`
//! (dispatch end → reply-receive entry), `reconcile` (→ timer/owner reconciliation done) and
//! `prepare` (→ Reply sent: receive-boundary observations and the queued-work poll rearm).
//! `body` is further attributed: `pre-tail` (dispatch end → syscall tail entry), and the time
//! the tail spent in service-loop finalization, split into global redrive work, the mounted
//! volume checkpoint and the remaining finalization (reconcile, rearm).

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
    pub(crate) split: u64,
    pub(crate) body: u64,
    pub(crate) reconcile: u64,
    pub(crate) prepare: u64,
    pub(crate) pre_tail: u64,
    pub(crate) global_work: u64,
    pub(crate) checkpoint: u64,
    pub(crate) finalize_other: u64,
}

impl Latency {
    const EMPTY: Self = Self { calls: 0, ingress: 0, handler: 0, tail: 0, returns: 0,
        return_idle: 0, return_other: 0, split: 0, body: 0, reconcile: 0, prepare: 0,
        pre_tail: 0, global_work: 0, checkpoint: 0, finalize_other: 0 };
}

#[derive(Clone, Copy)]
struct Current {
    badge: u64,
    service: usize,
    ingress_at: u64,
    started: u64,
    finished: Option<u64>,
    preparing: Option<u64>,
    reconciled: Option<u64>,
    tail_entered: Option<u64>,
    finalize: [u64; 3],
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
        if self.returning[slot].is_none_or(|row| row.badge != badge) { return; }
        let Some(returning) = self.returning[slot].take() else { return; };
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
                    badge, service, ingress_at, started: now, finished: None,
                    preparing: None, reconciled: None, tail_entered: None, finalize: [0; 3] })
            });
    }

    pub(crate) fn dispatch_finished(&mut self, now: u64) {
        if let Some(current) = self.current.as_mut() { current.finished.get_or_insert(now); }
    }

    /// The syscall tail began for the current call.
    pub(crate) fn tail_entered(&mut self, now: u64) {
        if let Some(current) = self.current.as_mut().filter(|current| current.finished.is_some()) {
            current.tail_entered.get_or_insert(now);
        }
    }

    /// One service-loop finalization in the current call's tail: its work (global redrive and
    /// any volume checkpoint) and the remaining finalization, in ticks.
    pub(crate) fn finalized(&mut self, work: u64, other: u64) {
        if let Some(current) = self.tail_current() {
            current.finalize[0] = current.finalize[0].saturating_add(work);
            current.finalize[2] = current.finalize[2].saturating_add(other);
        }
    }

    /// The volume checkpoint inside the current tail's finalization work, in ticks.
    pub(crate) fn checkpointed(&mut self, ticks: u64) {
        if let Some(current) = self.tail_current() {
            current.finalize[1] = current.finalize[1].saturating_add(ticks);
        }
    }

    fn tail_current(&mut self) -> Option<&mut Current> {
        self.current.as_mut()
            .filter(|current| current.finished.is_some() && current.preparing.is_none())
    }

    /// The shared reply-receive was entered for the current call.
    pub(crate) fn reply_preparing(&mut self, now: u64) {
        if let Some(current) = self.current.as_mut().filter(|current| current.finished.is_some()) {
            current.preparing.get_or_insert(now);
        }
    }

    /// Receive preparation finished reconciling timer owners (the last pass counts).
    pub(crate) fn reconciled(&mut self, now: u64) {
        if let Some(current) = self.current.as_mut().filter(|current| current.preparing.is_some()) {
            current.reconciled = Some(now);
        }
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
        if let (Some(preparing), Some(reconciled)) = (current.preparing, current.reconciled) {
            row.split = row.split.saturating_add(1);
            row.body = row.body.saturating_add(preparing.saturating_sub(finished));
            row.reconcile = row.reconcile.saturating_add(reconciled.saturating_sub(preparing));
            row.prepare = row.prepare.saturating_add(now.saturating_sub(reconciled));
            if let Some(entered) = current.tail_entered {
                row.pre_tail = row.pre_tail.saturating_add(entered.saturating_sub(finished));
            }
            row.global_work = row.global_work
                .saturating_add(current.finalize[0].saturating_sub(current.finalize[1]));
            row.checkpoint = row.checkpoint.saturating_add(current.finalize[1]);
            row.finalize_other = row.finalize_other.saturating_add(current.finalize[2]);
        }
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
        write!(out, "[census] hot-service-latency calls/ingress/handler/tail/returns/return-idle/return-other/split/body/reconcile/prepare/pre-tail/global-work/checkpoint/finalize-other-Mtick:")?;
        for ((_, name), row) in SERVICES.iter().zip(&self.rows) {
            write!(out, " {name}={}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}/{}", row.calls,
                row.ingress / 1_000_000, row.handler / 1_000_000, row.tail / 1_000_000,
                row.returns, row.return_idle / 1_000_000, row.return_other / 1_000_000,
                row.split, row.body / 1_000_000, row.reconcile / 1_000_000,
                row.prepare / 1_000_000, row.pre_tail / 1_000_000,
                row.global_work / 1_000_000, row.checkpoint / 1_000_000,
                row.finalize_other / 1_000_000)?;
        }
        writeln!(out)
    }

    /// Badges are sparse (Explorer's GUI thread was 1242); the stored badge disambiguates a
    /// shared slot, and a colliding reply replaces the older pending return sample.
    fn slot(badge: u64) -> Option<usize> {
        Some((badge % BADGE_SLOTS as u64) as usize)
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

pub(crate) fn tail_entered() {
    if let Some(census) = root() { census.tail_entered(crate::disk_census_ticks()); }
}

pub(crate) fn finalized(work: u64, other: u64) {
    if let Some(census) = root() { census.finalized(work, other); }
}

pub(crate) fn checkpointed(ticks: u64) {
    if let Some(census) = root() { census.checkpointed(ticks); }
}

pub(crate) fn reply_preparing() {
    if let Some(census) = root() { census.reply_preparing(crate::disk_census_ticks()); }
}

pub(crate) fn reconciled() {
    if let Some(census) = root() { census.reconciled(crate::disk_census_ticks()); }
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
