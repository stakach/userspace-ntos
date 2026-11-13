//! Sparse, generation-fenced table-dispatch and scheduler-runtime observation.
//!
//! Counts are diagnostic only. Scheduler contexts are read without publishing process times,
//! evaluating job limits, changing a wait, or retaining a thread owner.

use super::*;
use nt_syscall::NativeService;

const FAMILY_COUNT: usize = 5;
const MAX_SC_READS_PER_CENSUS: usize = 128;

#[derive(Clone, Copy)]
enum Family { File = 0, Registry = 1, Image = 2, Wait = 3, Other = 4 }

impl Family {
    fn of(service: Option<NativeService>) -> Self {
        match service {
            Some(NativeService::NtCreateFile | NativeService::NtOpenFile
                | NativeService::NtCancelIoFile | NativeService::NtLockFile
                | NativeService::NtUnlockFile | NativeService::NtReadFile
                | NativeService::NtWriteFile | NativeService::NtDeviceIoControlFile
                | NativeService::NtCreateNamedPipeFile | NativeService::NtFsControlFile
                | NativeService::NtQueryDirectoryFile | NativeService::NtNotifyChangeDirectoryFile
                | NativeService::NtQueryEaFile | NativeService::NtQueryInformationFile
                | NativeService::NtSetInformationFile | NativeService::NtSetEaFile
                | NativeService::NtQueryQuotaInformationFile
                | NativeService::NtSetQuotaInformationFile
                | NativeService::NtSetVolumeInformationFile
                | NativeService::NtFlushBuffersFile) => Self::File,
            Some(NativeService::NtOpenKey | NativeService::NtOpenKeyEx
                | NativeService::NtCreateKey | NativeService::NtQueryValueKey
                | NativeService::NtSetValueKey | NativeService::NtEnumerateKey
                | NativeService::NtEnumerateValueKey | NativeService::NtQueryKey
                | NativeService::NtDeleteValueKey | NativeService::NtFlushKey
                | NativeService::NtSaveKey | NativeService::NtSaveKeyEx
                | NativeService::NtLoadKey | NativeService::NtLoadKey2
                | NativeService::NtLoadKeyEx | NativeService::NtUnloadKey
                | NativeService::NtUnloadKey2 | NativeService::NtUnloadKeyEx) => Self::Registry,
            Some(NativeService::NtAllocateVirtualMemory | NativeService::NtFreeVirtualMemory
                | NativeService::NtReadVirtualMemory | NativeService::NtWriteVirtualMemory
                | NativeService::NtCreateSection | NativeService::NtOpenSection
                | NativeService::NtMapViewOfSection | NativeService::NtUnmapViewOfSection
                | NativeService::NtQuerySection | NativeService::NtFlushVirtualMemory
                | NativeService::NtLockVirtualMemory | NativeService::NtUnlockVirtualMemory) => Self::Image,
            Some(NativeService::NtWaitForSingleObject | NativeService::NtWaitForMultipleObjects
                | NativeService::NtDelayExecution | NativeService::NtRemoveIoCompletion
                | NativeService::NtReplyWaitReceivePort | NativeService::NtWaitForKeyedEvent
                | NativeService::NtWaitForAlertByThreadId | NativeService::NtWaitForDebugEvent) => Self::Wait,
            _ => Self::Other,
        }
    }
}

#[derive(Clone, Copy)]
struct FamilyTotal { calls: u64, failed: u64, ticks: u64, max_ticks: u64 }

impl FamilyTotal { const EMPTY: Self = Self { calls: 0, failed: 0, ticks: 0, max_ticks: 0 }; }

#[derive(Clone, Copy)]
struct ScBaseline { signature: u64, count: u64, bound_us: u64, donated_us: u64, at_100ns: u64 }

#[derive(Clone, Copy)]
struct Row {
    generation: u64,
    families: [FamilyTotal; FAMILY_COUNT],
    reported_calls: u64,
    baseline: Option<ScBaseline>,
    guest_us: u64,
    server_us: u64,
    wall_us: u64,
    sc_gaps: u64,
    sc_failures: u64,
    live_threads: u64,
    parked_threads: u64,
}

impl Row {
    const EMPTY: Self = Self {
        generation: 0, families: [FamilyTotal::EMPTY; FAMILY_COUNT], reported_calls: 0,
        baseline: None, guest_us: 0, server_us: 0, wall_us: 0, sc_gaps: 0,
        sc_failures: 0, live_threads: 0, parked_threads: 0,
    };

    fn calls(&self) -> u64 {
        self.families.iter().fold(0u64, |sum, family| sum.saturating_add(family.calls))
    }
}

#[derive(Clone, Copy)]
struct ScScan {
    signature: u64,
    count: u64,
    bound_us: u64,
    donated_us: u64,
    parked: u64,
    failures: u64,
}

impl ScScan {
    const EMPTY: Self = Self { signature: 0, count: 0, bound_us: 0,
        donated_us: 0, parked: 0, failures: 0 };
}

static mut ROWS: [Row; MAX_PI] = [Row::EMPTY; MAX_PI];
static mut INVALID_OWNER: u64 = 0;
static mut SC_OVERFLOW: u64 = 0;
static mut LAST_CENSUS: u64 = 0;
static mut REPORTED_INVALID_OWNER: u64 = 0;
static mut REPORTED_SC_OVERFLOW: u64 = 0;
static mut REPLACED_GENERATIONS: u64 = 0;

/// Only the registered table-dispatch bracket is counted; native fast paths that bypass it
/// remain outside these family totals. SC time is sampled independently of that coverage.
pub(crate) fn record_dispatch(pi: usize, generation: Option<u64>,
    service: Option<NativeService>, status: u32, ticks: u64) {
    let Some(generation) = generation.filter(|generation| *generation != 0) else {
        unsafe { INVALID_OWNER = INVALID_OWNER.saturating_add(1); }
        return;
    };
    if pi >= MAX_PI {
        unsafe { INVALID_OWNER = INVALID_OWNER.saturating_add(1); }
        return;
    }
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(ROWS) };
    let row = &mut rows[pi];
    if row.generation != generation {
        if row.generation != 0 {
            unsafe { REPLACED_GENERATIONS = REPLACED_GENERATIONS.saturating_add(1); }
        }
        *row = Row { generation, ..Row::EMPTY };
    }
    let total = &mut row.families[Family::of(service) as usize];
    total.calls = total.calls.saturating_add(1);
    total.failed = total.failed.saturating_add(u64::from(status & 0xc000_0000 == 0xc000_0000));
    total.ticks = total.ticks.saturating_add(ticks);
    total.max_ticks = total.max_ticks.max(ticks);
}

/// Called after a periodic census, including one started inside a nested pump. An exact live
/// binding and its current process generation gate every read-only scheduler-context request.
pub(crate) fn sample_after_census(handler: &ExecNtHandler) {
    let census = CENSUS_PERIODIC_DUMPS.load(Ordering::Acquire);
    if census == 0 || census == unsafe { LAST_CENSUS } { return; }
    unsafe { LAST_CENSUS = census; }
    let now_100ns = crate::monotonic_time_100ns();
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(ROWS) };
    let mut scans = [ScScan::EMPTY; MAX_PI];
    let mut cursor = 0;
    let mut sc_reads = 0;
    while let Some((next, binding, lifetime)) = handler.next_hosted_thread_quiesce_snapshot(cursor) {
        cursor = next;
        let pi = binding.pi;
        if pi >= MAX_PI { continue; }
        let nt_user_host::process_identity::ProcessGeneration::Hosted(generation) =
            binding.process.generation else { continue; };
        if rows[pi].generation != generation { continue; }
        let scan = &mut scans[pi];
        scan.count = scan.count.saturating_add(1);
        scan.parked = scan.parked.saturating_add(u64::from(
            thread_wait_state_badge_parked(binding.badge)));
        if lifetime.is_none() {
            scan.failures = scan.failures.saturating_add(1);
            continue;
        }
        if sc_reads == MAX_SC_READS_PER_CENSUS {
            scan.failures = scan.failures.saturating_add(1);
            unsafe { SC_OVERFLOW = SC_OVERFLOW.saturating_add(1); }
            continue;
        }
        sc_reads += 1;
        let Some(sc) = handler.observed_sched_context_for_binding(binding) else {
            scan.failures = scan.failures.saturating_add(1);
            continue;
        };
        // A changed live-thread set invalidates this interval's delta; do not infer zero CPU.
        scan.signature ^= binding.tid.wrapping_mul(0x9e37_79b9_7f4a_7c15)
            ^ sc.rotate_left(17) ^ binding.badge.rotate_left(31);
        match sel4_rt::sched_context_read_runtime(sc) {
            Ok(runtime) => {
                scan.bound_us = scan.bound_us.saturating_add(runtime.bound_time_us);
                scan.donated_us = scan.donated_us.saturating_add(runtime.donated_time_us);
            }
            Err(_) => scan.failures = scan.failures.saturating_add(1),
        }
    }
    for (pi, scan) in scans.into_iter().enumerate() {
        let row = &mut rows[pi];
        if row.generation == 0 { continue; }
        row.live_threads = scan.count;
        row.parked_threads = scan.parked;
        row.sc_failures = row.sc_failures.saturating_add(scan.failures);
        if scan.failures == 0 && scan.count != 0 {
            if let Some(previous) = row.baseline {
                if previous.signature == scan.signature && previous.count == scan.count
                    && scan.bound_us >= previous.bound_us
                    && scan.donated_us >= previous.donated_us {
                    row.guest_us = row.guest_us.saturating_add(scan.bound_us - previous.bound_us);
                    row.server_us = row.server_us.saturating_add(scan.donated_us - previous.donated_us);
                    row.wall_us = row.wall_us.saturating_add(
                        now_100ns.saturating_sub(previous.at_100ns) / 10);
                } else {
                    row.sc_gaps = row.sc_gaps.saturating_add(1);
                }
            }
            row.baseline = Some(ScBaseline { signature: scan.signature, count: scan.count,
                bound_us: scan.bound_us, donated_us: scan.donated_us, at_100ns: now_100ns });
        } else {
            row.baseline = None;
        }
        let calls = row.calls();
        if calls != 0 && (row.reported_calls == 0
            || calls >= row.reported_calls.saturating_mul(2)
            || census.is_power_of_two()) {
            row.reported_calls = calls;
            print_row(pi, row);
        }
    }
    let invalid = unsafe { INVALID_OWNER };
    if invalid != unsafe { REPORTED_INVALID_OWNER }
        && (invalid <= 4 || invalid >= unsafe { REPORTED_INVALID_OWNER }.saturating_mul(2)) {
        unsafe { REPORTED_INVALID_OWNER = invalid; }
        print_str(b"[native-process-time] invalid-owner="); print_u64(invalid); print_str(b"\n");
    }
    let overflow = unsafe { SC_OVERFLOW };
    if overflow != unsafe { REPORTED_SC_OVERFLOW } && census.is_power_of_two() {
        unsafe { REPORTED_SC_OVERFLOW = overflow; }
        print_str(b"[native-process-time] sc-read-overflow=");
        print_u64(overflow); print_str(b"\n");
    }
    if census.is_power_of_two() && unsafe { REPLACED_GENERATIONS } != 0 {
        print_str(b"[native-process-time] replaced-generations=");
        print_u64(unsafe { REPLACED_GENERATIONS }); print_str(b"\n");
    }
}

fn print_row(pi: usize, row: &Row) {
    print_str(b"[native-process-time] pi/gen/table-calls/bound-us/donated-us/wall-us/live/parked/gaps/sc-errors=");
    print_u64(pi as u64); print_str(b"/"); print_u64(row.generation);
    print_str(b"/"); print_u64(row.calls());
    print_str(b"/"); print_u64(row.guest_us); print_str(b"/"); print_u64(row.server_us);
    print_str(b"/"); print_u64(row.wall_us); print_str(b"/"); print_u64(row.live_threads);
    print_str(b"/"); print_u64(row.parked_threads); print_str(b"/"); print_u64(row.sc_gaps);
    print_str(b"/"); print_u64(row.sc_failures);
    print_str(b" family F/R/I/W/O=count,total-Mtick,max-Mtick,failed:");
    for (index, family) in row.families.iter().enumerate() {
        if index != 0 { print_str(b";"); }
        print_u64(family.calls); print_str(b","); print_u64(family.ticks / 1_000_000);
        print_str(b","); print_u64(family.max_ticks / 1_000_000);
        print_str(b","); print_u64(family.failed);
    }
    print_str(b"\n");
}
