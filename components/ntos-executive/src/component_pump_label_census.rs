//! Root cost per provider request label in the component pump.
//!
//! One cycle is one provider message: from its receipt, through the root servicing it, to the
//! provider's next message. `blocked` is the root's dispatch-receive time inside the cycle
//! (the provider running or waiting); `cycle - blocked` is the root's own handling of that
//! request label. Labels at or above `OTHER_LABEL` share one bucket. Observation only.

use core::fmt::Write;

const OTHER_LABEL: usize = 0x900;
const BUCKETS: usize = OTHER_LABEL + 1;
const TOP_LABELS: usize = 8;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct LabelCost {
    pub(crate) cycles: u64,
    pub(crate) ticks: u64,
    pub(crate) blocked: u64,
}

impl LabelCost {
    const EMPTY: Self = Self { cycles: 0, ticks: 0, blocked: 0 };
    fn handling(&self) -> u64 { self.ticks.saturating_sub(self.blocked) }
}

pub(crate) struct LabelCensus { rows: [LabelCost; BUCKETS] }

fn bucket(label: u64) -> usize {
    if label < OTHER_LABEL as u64 { label as usize } else { OTHER_LABEL }
}

impl LabelCensus {
    pub(crate) const fn new() -> Self { Self { rows: [LabelCost::EMPTY; BUCKETS] } }

    pub(crate) fn record(&mut self, label: u64, ticks: u64, blocked: u64) {
        let row = &mut self.rows[bucket(label)];
        row.cycles = row.cycles.saturating_add(1);
        row.ticks = row.ticks.saturating_add(ticks);
        row.blocked = row.blocked.saturating_add(blocked.min(ticks));
    }

    pub(crate) fn cost(&self, label: u64) -> LabelCost { self.rows[bucket(label)] }

    /// The labels with the most root handling time, `label/cycles/handling/blocked` in Mtick.
    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] component-pump-label top label/cycles/handling-Mtick/blocked-Mtick:")?;
        let mut chosen = [usize::MAX; TOP_LABELS];
        for rank in 0..TOP_LABELS {
            let best = (0..BUCKETS)
                .filter(|bucket| !chosen[..rank].contains(bucket) && self.rows[*bucket].cycles != 0)
                .max_by_key(|bucket| self.rows[*bucket].handling());
            let Some(best) = best else { break; };
            chosen[rank] = best;
            let row = self.rows[best];
            if best == OTHER_LABEL { write!(out, " other")?; } else { write!(out, " {best:#x}")?; }
            write!(out, "/{}/{}/{}", row.cycles, row.handling() / 1_000_000,
                row.blocked / 1_000_000)?;
        }
        writeln!(out)
    }
}

static mut ROOT: LabelCensus = LabelCensus::new();

fn root() -> Option<&'static mut LabelCensus> {
    // SAFETY: only the single root executor passes the check and mutates the table.
    crate::serial_records::is_root_executor()
        .then(|| unsafe { &mut *core::ptr::addr_of_mut!(ROOT) })
}

/// One pump message cycle; recorded when the loop iteration ends.
pub(crate) struct LabelCycle { label: u64, started: u64, blocked_before: u64 }

impl LabelCycle {
    pub(crate) fn enter(label: u64) -> Self {
        Self { label, started: crate::disk_census_ticks(),
            blocked_before: crate::root_dispatch_receive_ticks() }
    }
}

impl Drop for LabelCycle {
    fn drop(&mut self) {
        let ticks = crate::disk_census_ticks().wrapping_sub(self.started);
        let blocked = crate::root_dispatch_receive_ticks().saturating_sub(self.blocked_before);
        if let Some(census) = root() { census.record(self.label, ticks, blocked); }
    }
}

pub(crate) fn print_census() {
    let Some(census) = root() else { return; };
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    let _ = census.write_census(&mut record);
    crate::print_str(record.bytes());
}
