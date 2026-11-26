//! Per-call cost of the hot file and registry services, split by NT success and error status.
//!
//! Each row also carries the serial diagnostic bytes the root executor emitted inside the same
//! table-dispatch bracket, so a census can separate service work from synchronous serial output
//! (the kernel's `[debug-output-cost]` record path costs tens of thousands of TSC ticks per
//! byte under KVM). Observation only: the bracket is the one `native_process_time_census` uses,
//! nested dispatches are inclusive, and nothing here affects status, ownership or scheduling.

use core::fmt::Write;
use nt_syscall::NativeService;

/// The measured hot set (#348). `NtOpenKeyEx` has no slot in the SSN histogram, so the
/// service identity, not the SSN bucket, keys these rows.
const SERVICES: [(NativeService, &str); 8] = [
    (NativeService::NtReadFile, "read"),
    (NativeService::NtWriteFile, "write"),
    (NativeService::NtOpenKey, "open-key"),
    (NativeService::NtOpenKeyEx, "open-key-ex"),
    (NativeService::NtQueryValueKey, "query-value"),
    (NativeService::NtCreateKey, "create-key"),
    (NativeService::NtRemoveIoCompletion, "remove-completion"),
    (NativeService::NtClose, "close"),
];
pub(crate) const HOT_SERVICES: usize = SERVICES.len();

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OutcomeCost {
    pub(crate) calls: u64,
    pub(crate) ticks: u64,
    pub(crate) serial_bytes: u64,
}

impl OutcomeCost {
    const EMPTY: Self = Self { calls: 0, ticks: 0, serial_bytes: 0 };

    fn add(&mut self, ticks: u64, serial_bytes: u64) {
        self.calls = self.calls.saturating_add(1);
        self.ticks = self.ticks.saturating_add(ticks);
        self.serial_bytes = self.serial_bytes.saturating_add(serial_bytes);
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ServiceCost {
    /// Success, informational, warning and STATUS_PENDING returns.
    pub(crate) completed: OutcomeCost,
    /// `NT_ERROR` returns, e.g. a registry miss (STATUS_OBJECT_NAME_NOT_FOUND).
    pub(crate) failed: OutcomeCost,
}

pub(crate) struct HotServiceCost {
    rows: [ServiceCost; SERVICES.len()],
}

impl HotServiceCost {
    pub(crate) const fn new() -> Self {
        Self { rows: [ServiceCost { completed: OutcomeCost::EMPTY, failed: OutcomeCost::EMPTY };
            SERVICES.len()] }
    }

    /// Fold one completed table dispatch. Services outside the hot set are ignored.
    pub(crate) fn record(&mut self, service: Option<NativeService>, status: u32, ticks: u64,
        serial_bytes: u64) {
        let Some(index) = service.and_then(|service|
            SERVICES.iter().position(|(hot, _)| *hot == service)) else { return; };
        let row = &mut self.rows[index];
        if status >> 30 == 3 { &mut row.failed } else { &mut row.completed }
            .add(ticks, serial_bytes);
    }

    pub(crate) fn cost(&self, service: NativeService) -> Option<ServiceCost> {
        SERVICES.iter().position(|(hot, _)| *hot == service).map(|index| self.rows[index])
    }

    /// One bounded record: `name=calls/Mtick/serial-bytes:failed-calls/Mtick/serial-bytes`.
    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] hot-service-cost ok/err=calls/Mtick/serial-bytes:")?;
        for ((_, name), row) in SERVICES.iter().zip(&self.rows) {
            let (ok, err) = (row.completed, row.failed);
            write!(out, " {name}={}/{}/{}:{}/{}/{}", ok.calls, ok.ticks / 1_000_000,
                ok.serial_bytes, err.calls, err.ticks / 1_000_000, err.serial_bytes)?;
        }
        writeln!(out)
    }
}

/// Root-only, like the `native_process_time_census` rows the same bracket feeds.
static mut ROOT: HotServiceCost = HotServiceCost::new();

/// `serial_bytes` is the root executor's serial byte delta across the dispatch bracket.
pub(crate) fn record_dispatch(service: Option<NativeService>, status: u32, ticks: u64,
    serial_bytes: u64) {
    // SAFETY: only the single root dispatch executor records or prints this census.
    unsafe { (*core::ptr::addr_of_mut!(ROOT)).record(service, status, ticks, serial_bytes) }
}

pub(crate) fn print_census() {
    let mut record = nt_printf::record::RecordBuffer::<1024>::new();
    // SAFETY: see `record_dispatch`.
    let _ = unsafe { (*core::ptr::addr_of!(ROOT)).write_census(&mut record) };
    crate::print_str(record.bytes());
}

/// Cumulative values for an exact installer gap. The caller must be the root executor,
/// as with `record_dispatch`; these inclusive TSC values are not exclusive SC runtime.
pub(crate) fn snapshot() -> Option<([u64; HOT_SERVICES], [u64; HOT_SERVICES])> {
    // SAFETY: only the root executive calls this snapshot; see the caller's guard.
    let rows = &unsafe { &*core::ptr::addr_of!(ROOT) }.rows;
    let mut ticks = [0; HOT_SERVICES];
    let mut calls = [0; HOT_SERVICES];
    for (index, row) in rows.iter().enumerate() {
        ticks[index] = row.completed.ticks.saturating_add(row.failed.ticks);
        calls[index] = row.completed.calls.saturating_add(row.failed.calls);
    }
    Some((ticks, calls))
}

pub(crate) fn label(index: usize) -> Option<&'static str> {
    SERVICES.get(index).map(|(_, label)| *label)
}

/// Exact statuses returned by NtWaitForMultipleObjects dispatches (a parked wait's dispatch
/// status is recorded when it parks). Eight space-saving slots, most frequent first in output.
pub(crate) struct WaitStatusCensus {
    calls: u64,
    slots: [(u32, u64); 8],
    used: usize,
}

impl WaitStatusCensus {
    pub(crate) const fn new() -> Self {
        Self { calls: 0, slots: [(0, 0); 8], used: 0 }
    }

    pub(crate) fn record(&mut self, service: Option<NativeService>, status: u32) {
        if service == Some(NativeService::NtWaitForMultipleObjects) {
            self.record_status(status);
        }
    }

    pub(crate) fn record_status(&mut self, status: u32) {
        self.calls = self.calls.saturating_add(1);
        if let Some(slot) = self.slots[..self.used].iter_mut().find(|slot| slot.0 == status) {
            slot.1 = slot.1.saturating_add(1);
            return;
        }
        if self.used < self.slots.len() {
            self.slots[self.used] = (status, 1);
            self.used += 1;
            return;
        }
        let smallest = (0..self.slots.len()).min_by_key(|&index| self.slots[index].1).unwrap();
        self.slots[smallest] = (status, self.slots[smallest].1.saturating_add(1));
    }

    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        self.write_census_named(out, "wait-multiple-status")
    }

    pub(crate) fn write_census_named(&self, out: &mut impl Write, name: &str)
        -> core::fmt::Result
    {
        let mut order = [0usize; 8];
        for (slot, index) in order.iter_mut().zip(0..) {
            *slot = index;
        }
        order[..self.used].sort_by(|&a, &b| self.slots[b].1.cmp(&self.slots[a].1));
        write!(out, "[census] {name} calls={}", self.calls)?;
        for &index in &order[..self.used] {
            write!(out, " 0x{:08x}={}", self.slots[index].0, self.slots[index].1)?;
        }
        writeln!(out)
    }
}

static mut WAIT_STATUS: WaitStatusCensus = WaitStatusCensus::new();

pub(crate) fn record_wait_status(service: Option<NativeService>, status: u32) {
    // SAFETY: only the single root dispatch executor records or prints this census.
    unsafe { (*core::ptr::addr_of_mut!(WAIT_STATUS)).record(service, status) }
}

pub(crate) fn print_wait_status_census() {
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    // SAFETY: see `record_wait_status`.
    let _ = unsafe { (*core::ptr::addr_of!(WAIT_STATUS)).write_census(&mut record) };
    crate::print_str(record.bytes());
}

/// The timeout supplied to each parking NtWaitForMultipleObjects, by class. Relative intervals
/// are negative 100 ns counts; positive values are absolute system times.
pub(crate) struct WaitTimeoutCensus {
    counts: [u64; 8],
}

impl WaitTimeoutCensus {
    pub(crate) const fn new() -> Self {
        Self { counts: [0; 8] }
    }

    pub(crate) fn record(&mut self, timeout: Option<i64>) {
        let class = match timeout {
            None => 0,
            Some(0) => 1,
            Some(value) if value > 0 => 7,
            Some(value) => match value.unsigned_abs() {
                0..=10_000 => 2,
                10_001..=160_000 => 3,
                160_001..=1_000_000 => 4,
                1_000_001..=10_000_000 => 5,
                _ => 6,
            },
        };
        self.counts[class] = self.counts[class].saturating_add(1);
    }

    pub(crate) fn write_census(&self, out: &mut impl Write) -> core::fmt::Result {
        write!(out, "[census] wait-timeout infinite/zero/le1ms/le16ms/le100ms/le1s/gt1s/absolute=")?;
        for (index, count) in self.counts.iter().enumerate() {
            if index != 0 {
                write!(out, "/")?;
            }
            write!(out, "{count}")?;
        }
        writeln!(out)
    }
}

static mut WAIT_TIMEOUTS: WaitTimeoutCensus = WaitTimeoutCensus::new();
static mut OBJECT_WAIT_FINAL: WaitStatusCensus = WaitStatusCensus::new();

pub(crate) fn record_wait_timeout(timeout: Option<i64>) {
    // SAFETY: only the single root dispatch executor records or prints this census.
    unsafe { (*core::ptr::addr_of_mut!(WAIT_TIMEOUTS)).record(timeout) }
}

pub(crate) fn record_object_wait_final(status: u32) {
    // SAFETY: see `record_wait_timeout`.
    unsafe { (*core::ptr::addr_of_mut!(OBJECT_WAIT_FINAL)).record_status(status) }
}

pub(crate) fn print_wait_outcome_census() {
    let mut record = nt_printf::record::RecordBuffer::<512>::new();
    // SAFETY: see `record_wait_timeout`.
    let _ = unsafe { (*core::ptr::addr_of!(WAIT_TIMEOUTS)).write_census(&mut record) };
    let _ = unsafe {
        (*core::ptr::addr_of!(OBJECT_WAIT_FINAL)).write_census_named(&mut record, "object-wait-final")
    };
    crate::print_str(record.bytes());
}
