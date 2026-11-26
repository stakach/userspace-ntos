//! Per-step TSC cost of the global redrive work the root runs at every service boundary: the
//! post-syscall redrive before the Reply tail and the service-loop finalization.
//!
//! Each step records its calls, how many of them reported progress, and its ticks, with the
//! ticks of calls that reported no progress kept separately. That idle share is what a
//! readiness gate on the step could save. A step without a progress result reports only calls
//! and ticks. Steps can nest (a file redrive inside an I/O pump), so an outer step's ticks
//! include its inner steps'. Observation only.

use core::fmt::Write;

macro_rules! steps {
    ($($step:ident => $name:literal,)*) => {
        #[derive(Clone, Copy, Debug, PartialEq, Eq)]
        #[repr(usize)]
        pub(crate) enum Step { $($step,)* }
        const NAMES: &[&str] = &[$($name,)*];
    };
}

steps! {
    // redrive_global_post_syscall_work and its hosted I/O pump.
    LifecyclePump => "lifecycle-pump",
    Dpcs => "dpcs",
    FileRetirements => "file-retire",
    VideoRetirements => "video-retire",
    Backends => "backends",
    NativeBlocks => "native-blocks",
    IoCompletions => "io-completions",
    DriverStarts => "driver-starts",
    CriticalChildren => "critical-children",
    PnpOperations => "pnp-ops",
    ReinitCallbacks => "reinit-callbacks",
    ProgressFileRedrive => "progress-file-redrive",
    PipeFileRedrive => "pipe-file-redrive",
    IrpDrain => "irp-drain",
    LpcEndpoint => "lpc-endpoint",
    LpcConnect => "lpc-connect",
    // pump_hosted_io_completions' sub-drains.
    IoManager => "io-manager",
    IoOwnerDrains => "io-owner-drains",
    IoPnpDrains => "io-pnp-drains",
    // Post-dispatch syscall work outside the redrive.
    ThreadAlert => "thread-alert",
    IoCompletionDeliver => "iocp-deliver",
    // redrive_service_loop_global_work.
    DirectoryWork => "directory-work",
    SecuritySweeps => "security-sweeps",
    DeferredDrains => "deferred-drains",
    RuntimeWaits => "runtime-waits",
    WaitApcRedrive => "wait-apc-redrive",
    RetryFileRedrive => "retry-file-redrive",
    ProcessDeletion => "process-deletion",
    SectionRollbacks => "section-rollbacks",
    ProcessImages => "process-images",
    SectionRetirement => "section-retirement",
    FileCleanup => "file-cleanup",
    // The syscall tail's own pass, and its parts.
    HostedReady => "hosted-ready",
    HostedReadySelect => "hosted-ready-select",
    HostedReadyTerminals => "hosted-ready-terminals",
    HostedReadyMaintenance => "hosted-ready-maintenance",
    HostedReadySearch => "hosted-ready-search",
    HostedReadyRun => "hosted-ready-run",
}

pub(crate) const STEPS: usize = NAMES.len();

/// What a step reported: `Some(true)` progress, `Some(false)` none, `None` not reported.
pub(crate) trait StepProgress {
    fn progressed(&self) -> Option<bool>;
}

impl StepProgress for () { fn progressed(&self) -> Option<bool> { None } }
impl StepProgress for bool { fn progressed(&self) -> Option<bool> { Some(*self) } }
impl StepProgress for u64 { fn progressed(&self) -> Option<bool> { Some(*self != 0) } }
impl StepProgress for usize { fn progressed(&self) -> Option<bool> { Some(*self != 0) } }

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct StepCost {
    pub(crate) calls: u64,
    pub(crate) progressed: u64,
    pub(crate) ticks: u64,
    pub(crate) idle_ticks: u64,
}

impl StepCost {
    const EMPTY: Self = Self { calls: 0, progressed: 0, ticks: 0, idle_ticks: 0 };
}

pub(crate) struct StepCensus {
    rows: [StepCost; STEPS],
}

impl StepCensus {
    pub(crate) const fn new() -> Self { Self { rows: [StepCost::EMPTY; STEPS] } }

    pub(crate) fn record(&mut self, step: Step, ticks: u64, progressed: Option<bool>) {
        let row = &mut self.rows[step as usize];
        row.calls = row.calls.saturating_add(1);
        row.ticks = row.ticks.saturating_add(ticks);
        match progressed {
            Some(true) => row.progressed = row.progressed.saturating_add(1),
            Some(false) => row.idle_ticks = row.idle_ticks.saturating_add(ticks),
            None => {}
        }
    }

    #[allow(dead_code)] // Read by the host census test.
    pub(crate) fn cost(&self, step: Step) -> StepCost { self.rows[step as usize] }

    /// `name=calls/progressed/Mtick/idle-Mtick` for every step that ran.
    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] reply-tail-step calls/progressed/Mtick/idle-Mtick:")?;
        for (name, row) in NAMES.iter().zip(&self.rows) {
            if row.calls == 0 { continue; }
            write!(out, " {name}={}/{}/{}/{}", row.calls, row.progressed,
                row.ticks / 1_000_000, row.idle_ticks / 1_000_000)?;
        }
        writeln!(out)
    }
}

/// Root-only: the post-syscall redrive and service-loop finalization run on the single root
/// executor. An isolated service maps this image read-only and never writes the table.
static mut ROOT: StepCensus = StepCensus::new();

fn root() -> Option<&'static mut StepCensus> {
    // SAFETY: only the single root executor passes the check and mutates the table.
    crate::serial_records::is_root_executor()
        .then(|| unsafe { &mut *core::ptr::addr_of_mut!(ROOT) })
}

/// TSC at the start of a step; pass it to [`end`] with the step's result.
pub(crate) fn begin() -> u64 { crate::disk_census_ticks() }

/// Record one step that began at `started`, and hand its result back.
pub(crate) fn end<T: StepProgress>(step: Step, started: u64, result: T) -> T {
    if let Some(census) = root() {
        census.record(step, crate::disk_census_ticks().wrapping_sub(started), result.progressed());
    }
    result
}

pub(crate) fn print_census() {
    let Some(census) = root() else { return; };
    let mut record = nt_printf::record::RecordBuffer::<2048>::new();
    let _ = census.write_census(&mut record);
    crate::print_str(record.bytes());
}

/// Root-only value snapshot for a bounded exact installer gap.
pub(crate) fn snapshot() -> Option<([u64; STEPS], [u64; STEPS])> {
    let rows = &root()?.rows;
    let mut ticks = [0; STEPS];
    let mut calls = [0; STEPS];
    for (index, row) in rows.iter().enumerate() {
        ticks[index] = row.ticks;
        calls[index] = row.calls;
    }
    Some((ticks, calls))
}

pub(crate) fn label(index: usize) -> Option<&'static str> { NAMES.get(index).copied() }
