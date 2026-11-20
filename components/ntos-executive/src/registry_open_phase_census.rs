//! Per-phase TSC cost of native NtOpenKey/NtOpenKeyEx admission, split by NT error status.
//!
//! Phases: capture (OBJECT_ATTRIBUTES, name, subject and handle reservation), target (local or
//! CM key resolution and binding), grant (access check), publish (handle publication) and
//! epilogue (miss bookkeeping, diagnostics and rollback). A failed phase owns the time up to the
//! failure; later phases record zero. Observation only.
use core::fmt::Write;
use core::sync::atomic::{AtomicU64, Ordering};

pub(crate) const PHASES: usize = 5;
const NAMES: &str = "capture/target/grant/publish/epilogue";

/// TSC marks at the end of each admission phase. Unreached marks take the failure time.
pub(crate) struct OpenPhaseClock {
    started: u64,
    captured: Option<u64>,
    marks: [Option<u64>; 3],
    failed_at: Option<u64>,
}

impl OpenPhaseClock {
    pub(crate) fn start(now: u64) -> Self {
        Self { started: now, captured: None, marks: [None; 3], failed_at: None }
    }
    pub(crate) fn captured(&mut self, now: u64) { self.captured = Some(now); }
    pub(crate) fn target_bound(&mut self, now: u64) { self.marks[0] = Some(now); }
    pub(crate) fn granted(&mut self, now: u64) { self.marks[1] = Some(now); }
    pub(crate) fn published(&mut self, now: u64) { self.marks[2] = Some(now); }
    /// The admission result is known; everything after it is epilogue.
    pub(crate) fn settled(&mut self, now: u64) { self.failed_at.get_or_insert(now); }

    fn phases(&self, finished: u64) -> [u64; PHASES] {
        let settled = self.failed_at.unwrap_or(finished);
        let mut boundaries = [settled; PHASES + 1];
        boundaries[0] = self.started;
        boundaries[1] = self.captured.unwrap_or(settled);
        for (index, mark) in self.marks.iter().enumerate() {
            boundaries[index + 2] = if self.captured.is_some() { mark.unwrap_or(settled) }
                else { settled };
        }
        boundaries[PHASES] = finished;
        let mut phases = [0; PHASES];
        for index in 0..PHASES {
            phases[index] = boundaries[index + 1].saturating_sub(boundaries[index]);
        }
        phases
    }
}

struct Outcome {
    calls: AtomicU64,
    ticks: [AtomicU64; PHASES],
}

impl Outcome {
    const fn new() -> Self {
        Self { calls: AtomicU64::new(0), ticks: [const { AtomicU64::new(0) }; PHASES] }
    }
    fn add(&self, phases: [u64; PHASES]) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        for (cell, ticks) in self.ticks.iter().zip(phases) {
            cell.fetch_add(ticks, Ordering::Relaxed);
        }
    }
    fn write(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "{}", self.calls.load(Ordering::Relaxed))?;
        for cell in &self.ticks {
            write!(out, "/{}", cell.load(Ordering::Relaxed) / 1_000_000)?;
        }
        Ok(())
    }
    #[cfg(test)]
    fn snapshot(&self) -> (u64, [u64; PHASES]) {
        (self.calls.load(Ordering::Relaxed),
            core::array::from_fn(|index| self.ticks[index].load(Ordering::Relaxed)))
    }
}

pub(crate) struct OpenPhaseCensus {
    completed: Outcome,
    failed: Outcome,
}

impl OpenPhaseCensus {
    pub(crate) const fn new() -> Self { Self { completed: Outcome::new(), failed: Outcome::new() } }

    pub(crate) fn record(&self, clock: &OpenPhaseClock, status: u32, finished: u64) {
        let phases = clock.phases(finished);
        if status >> 30 == 3 { &self.failed } else { &self.completed }.add(phases);
    }

    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] registry-open-phase ok/err=calls/{NAMES}-Mtick: ok=")?;
        self.completed.write(out)?;
        write!(out, " err=")?;
        self.failed.write(out)?;
        writeln!(out)
    }
}

static OPENS: OpenPhaseCensus = OpenPhaseCensus::new();

/// Sub-phases of a successful registry capture (opens and creates).
pub(crate) const CAPTURE_STEPS: usize = 6;
const CAPTURE_NAMES: &str = "attributes/caller/name/subject/reserve/canon";

/// TSC marks at the end of each capture step; recorded only when every step completed.
pub(crate) struct CaptureClock {
    marks: [u64; CAPTURE_STEPS + 1],
}

impl CaptureClock {
    pub(crate) fn start(now: u64) -> Self { Self { marks: [now; CAPTURE_STEPS + 1] } }
    /// Mark the end of step `step` (0-based, in `CAPTURE_NAMES` order).
    pub(crate) fn mark(&mut self, step: usize, now: u64) {
        if step < CAPTURE_STEPS { self.marks[step + 1] = now; }
    }
    fn steps(&self) -> [u64; CAPTURE_STEPS] {
        core::array::from_fn(|step| self.marks[step + 1].saturating_sub(self.marks[step]))
    }
}

pub(crate) struct CaptureCensus {
    calls: AtomicU64,
    ticks: [AtomicU64; CAPTURE_STEPS],
}

impl CaptureCensus {
    pub(crate) const fn new() -> Self {
        Self { calls: AtomicU64::new(0), ticks: [const { AtomicU64::new(0) }; CAPTURE_STEPS] }
    }
    pub(crate) fn record(&self, clock: &CaptureClock) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        for (cell, ticks) in self.ticks.iter().zip(clock.steps()) {
            cell.fetch_add(ticks, Ordering::Relaxed);
        }
    }
    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] registry-capture-phase calls/{CAPTURE_NAMES}-Mtick={}",
            self.calls.load(Ordering::Relaxed))?;
        for cell in &self.ticks {
            write!(out, "/{}", cell.load(Ordering::Relaxed) / 1_000_000)?;
        }
        writeln!(out)
    }
}

static CAPTURES: CaptureCensus = CaptureCensus::new();

pub(crate) fn record_capture(clock: &CaptureClock) { CAPTURES.record(clock); }

pub(crate) fn record_open(clock: &OpenPhaseClock, status: u32) {
    OPENS.record(clock, status, crate::disk_census_ticks());
}

pub(crate) fn print_census() {
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    let _ = OPENS.write_census(&mut record);
    let _ = CAPTURES.write_census(&mut record);
    crate::print_str(record.bytes());
}
