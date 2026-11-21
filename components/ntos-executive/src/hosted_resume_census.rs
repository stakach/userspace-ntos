//! Where a resumed hosted component continuation spends its time.
//!
//! `run_hosted` claims a suspended continuation, pumps its provider until the provider returns
//! or parks again, then settles the outcome. Per continuation kind this records `claim` (entry
//! until the pump starts), `pump` (the provider pump), `blocked` (the part of the pump the root
//! spent blocked in its dispatch receive, i.e. while the provider ran or waited), and `settle`
//! (after the pump until `run_hosted` returns). `pump - blocked` is the root's own work inside
//! the pump: servicing the provider's requests, faults and nested work. Observation only.

use core::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(usize)]
pub(crate) enum Kind { Provider, Lpc, ServiceWait, Other }

const NAMES: [&str; 4] = ["provider", "lpc", "service-wait", "other"];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ResumeCost {
    pub(crate) resumes: u64,
    pub(crate) claim: u64,
    pub(crate) pump: u64,
    pub(crate) blocked: u64,
    pub(crate) settle: u64,
}

impl ResumeCost {
    const EMPTY: Self = Self { resumes: 0, claim: 0, pump: 0, blocked: 0, settle: 0 };
}

/// One resume's TSC marks. `blocked_*` sample the root's cumulative dispatch-receive time.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Marks {
    pub(crate) entered: u64,
    pub(crate) pump: Option<(Kind, u64, u64)>,
    pub(crate) pumped: Option<(u64, u64)>,
}

pub(crate) struct ResumeCensus { rows: [ResumeCost; NAMES.len()] }

impl ResumeCensus {
    pub(crate) const fn new() -> Self { Self { rows: [ResumeCost::EMPTY; NAMES.len()] } }

    /// Record one finished `run_hosted`. A resume refused before its pump is not counted.
    pub(crate) fn record(&mut self, marks: Marks, returned: u64) {
        let (Some((kind, pump_started, blocked_before)), Some((pumped, blocked_after))) =
            (marks.pump, marks.pumped) else { return; };
        let row = &mut self.rows[kind as usize];
        let pump = pumped.saturating_sub(pump_started);
        row.resumes = row.resumes.saturating_add(1);
        row.claim = row.claim.saturating_add(pump_started.saturating_sub(marks.entered));
        row.pump = row.pump.saturating_add(pump);
        row.blocked = row.blocked.saturating_add(blocked_after.saturating_sub(blocked_before)
            .min(pump));
        row.settle = row.settle.saturating_add(returned.saturating_sub(pumped));
    }

    pub(crate) fn cost(&self, kind: Kind) -> ResumeCost { self.rows[kind as usize] }

    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] hosted-resume resumes/claim/pump/blocked/settle-Mtick:")?;
        for (name, row) in NAMES.iter().zip(&self.rows) {
            if row.resumes == 0 { continue; }
            write!(out, " {name}={}/{}/{}/{}/{}", row.resumes, row.claim / 1_000_000,
                row.pump / 1_000_000, row.blocked / 1_000_000, row.settle / 1_000_000)?;
        }
        writeln!(out)
    }
}

static mut ROOT: ResumeCensus = ResumeCensus::new();

fn root() -> Option<&'static mut ResumeCensus> {
    // SAFETY: only the single root executor passes the check and mutates the table.
    crate::serial_records::is_root_executor()
        .then(|| unsafe { &mut *core::ptr::addr_of_mut!(ROOT) })
}

/// Measures one `run_hosted` call; dropped on every return path.
pub(crate) struct ResumeClock { marks: Marks }

impl ResumeClock {
    pub(crate) fn start() -> Self {
        Self { marks: Marks { entered: crate::disk_census_ticks(), pump: None, pumped: None } }
    }
    pub(crate) fn pump_started(&mut self, kind: Kind) {
        self.marks.pump = Some((kind, crate::disk_census_ticks(),
            crate::root_dispatch_receive_ticks()));
    }
    pub(crate) fn pump_finished(&mut self) {
        self.marks.pumped = Some((crate::disk_census_ticks(),
            crate::root_dispatch_receive_ticks()));
    }
}

impl Drop for ResumeClock {
    fn drop(&mut self) {
        if let Some(census) = root() { census.record(self.marks, crate::disk_census_ticks()); }
    }
}

pub(crate) fn print_census() {
    let Some(census) = root() else { return; };
    let mut record = nt_printf::record::RecordBuffer::<256>::new();
    let _ = census.write_census(&mut record);
    crate::print_str(record.bytes());
}
