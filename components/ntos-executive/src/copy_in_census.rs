//! Cost of hosted-process copy-in (#348): copies, the availability checks they run and their
//! time. Observation only. Root and its workers record atomically; isolated services map these
//! statics read-only and never touch them.
use core::sync::atomic::{AtomicU64, Ordering};

static COPIES: AtomicU64 = AtomicU64::new(0);
static COPY_TICKS: AtomicU64 = AtomicU64::new(0);
static CHECKS: AtomicU64 = AtomicU64::new(0);
static CHECK_TICKS: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_copy(ticks: u64) {
    if !crate::allocator::is_root_heap() { return; }
    COPIES.fetch_add(1, Ordering::Relaxed);
    COPY_TICKS.fetch_add(ticks, Ordering::Relaxed);
}

/// Times one availability check, including its refusal paths.
pub(crate) struct CheckScope(u64);

impl CheckScope {
    pub(crate) fn enter() -> Self { Self(crate::disk_census_ticks()) }
}

impl Drop for CheckScope {
    fn drop(&mut self) {
        if !crate::allocator::is_root_heap() { return; }
        CHECKS.fetch_add(1, Ordering::Relaxed);
        CHECK_TICKS.fetch_add(crate::disk_census_ticks().wrapping_sub(self.0), Ordering::Relaxed);
    }
}

pub(crate) fn print_census(reclaiming_records: usize, records: usize) {
    use core::fmt::Write;
    let mut record = nt_printf::record::RecordBuffer::<256>::new();
    let _ = writeln!(record,
        "[census] copy-in copies/Mtick={}/{} availability-checks/Mtick={}/{} frame-records/reclaiming={}/{}",
        COPIES.load(Ordering::Relaxed), COPY_TICKS.load(Ordering::Relaxed) / 1_000_000,
        CHECKS.load(Ordering::Relaxed), CHECK_TICKS.load(Ordering::Relaxed) / 1_000_000,
        records, reclaiming_records);
    crate::print_str(record.bytes());
}
