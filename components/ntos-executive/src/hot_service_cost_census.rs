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
