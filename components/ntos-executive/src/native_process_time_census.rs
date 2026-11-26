//! Sparse, generation-fenced table-dispatch and scheduler-runtime observation.
//!
//! Counts are diagnostic only. Scheduler contexts are read without publishing process times,
//! evaluating job limits, changing a wait, or retaining a thread owner.

use super::*;
use nt_hosted_runtime::{HotIoCost, HotProcessCost, OwnerTableCost,
    SetupOwnerCensusGate, SetupOwnerIdentity, SetupOwnerPairValidity, SetupOwnerReceipt,
    SetupOwnerSample, SetupWaitedApplication, select_unique_waited_application,
    top_owner_table_delta};
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
    hot_file: [HotIoCost; 2],
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
        hot_file: [HotIoCost::EMPTY; 2],
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
static mut SETUP_OWNER_GATE: SetupOwnerCensusGate = SetupOwnerCensusGate::new();
static mut SETUP_ROOT_BASELINE: [OwnerTableCost; MAX_PI] =
    [OwnerTableCost::EMPTY; MAX_PI];

fn owner_table_costs(rows: &[Row; MAX_PI]) -> [OwnerTableCost; MAX_PI] {
    let mut costs = [OwnerTableCost::EMPTY; MAX_PI];
    for (pi, row) in rows.iter().enumerate() {
        if row.generation != 0 {
            costs[pi] = OwnerTableCost { generation: row.generation,
                calls: row.calls(), ticks: row.families.iter()
                    .fold(0u64, |total, family| total.saturating_add(family.ticks)) };
        }
    }
    costs
}

/// Observe the live application process that the registered interactive-logon process waits on.
/// Ordinary children need not have a committed execution-role creator entry. The retained wait
/// object, exact caller, live process identity and catalog generation scope this read-only probe.
fn observed_logon_child_pi(handler: &ExecNtHandler, rows: &[Row; MAX_PI]) -> Option<usize> {
    let (logon_target, logon) = handler.unique_live_execution_target(
        nt_exe_image::HostedProcessRole::InteractiveLogon)?;
    let nt_user_host::process_identity::ProcessGeneration::Hosted(logon_generation) =
        logon.generation else { return None; };
    let logon = SetupOwnerIdentity { process_index: logon_target.pi, pid: logon.pid,
        generation: logon_generation };
    let mut slot = 0;
    let mut object_index = 0;
    let waits = core::iter::from_fn(|| loop {
        if slot == crate::object_waiter_len() { return None; }
        let Some((identity, record)) = crate::object_waiter_record(slot) else {
            slot += 1; object_index = 0; continue;
        };
        if crate::object_waiter_is_claimed(identity) || object_index >= record.count as usize {
            slot += 1; object_index = 0; continue;
        }
        let object = record.objects[object_index];
        object_index += 1;
        if object.kind() != WaitObject::KIND_PROCESS { continue; }
        let caller = record.caller.process();
        let nt_user_host::process_identity::ProcessGeneration::Hosted(caller_generation) =
            caller.generation else { continue; };
        let child_pid = object.id() as nt_process::ProcessId;
        let Some(child_pi) = handler.pi_for_pid(child_pid) else { continue; };
        if child_pi >= MAX_PI { continue; }
        let Some(image) = handler.hosted_process_image(child_pi) else { continue; };
        let Some(child) = handler.capture_process_identity(child_pi) else { continue; };
        let nt_user_host::process_identity::ProcessGeneration::Hosted(child_generation) =
            child.generation else { continue; };
        if child.pid != child_pid || child_generation != image.generation
            || rows[child_pi].generation != child_generation { continue; }
        let target = nt_exe_image::SpawnTarget::from_image(image);
        return Some(SetupWaitedApplication {
            caller: SetupOwnerIdentity { process_index: record.caller.pi(),
                pid: caller.pid, generation: caller_generation },
            child: SetupOwnerIdentity { process_index: child_pi,
                pid: child.pid, generation: child_generation },
            live_application: target.role == nt_exe_image::HostedProcessRole::Application
                && handler.is_live_execution_process(target, child),
            direct_parent: handler.pm.process(child.pid)
                .is_some_and(|process| process.parent == Some(logon.pid)),
        });
    });
    select_unique_waited_application(logon, waits).map(|child| child.process_index)
}

/// Only the registered table-dispatch bracket is counted; native fast paths that bypass it
/// remain outside these family totals. SC time is sampled independently of that coverage.
pub(crate) fn record_dispatch(pi: usize, generation: Option<u64>,
    service: Option<NativeService>, status: u32, ticks: u64, serial_bytes: u64,
    requested_bytes: Option<u64>) {
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
    let hot_index = match service {
        Some(NativeService::NtReadFile) => Some(0),
        Some(NativeService::NtWriteFile) => Some(1),
        _ => None,
    };
    if let Some(index) = hot_index {
        let hot = &mut row.hot_file[index];
        hot.calls = hot.calls.saturating_add(1);
        hot.ticks = hot.ticks.saturating_add(ticks);
        hot.serial_bytes = hot.serial_bytes.saturating_add(serial_bytes);
        if let Some(requested_bytes) = requested_bytes {
            hot.requested_bytes = hot.requested_bytes.saturating_add(requested_bytes);
            hot.known_request_calls = hot.known_request_calls.saturating_add(1);
        }
    }
}

/// Root-only value snapshot for exact installer-gap baselines. A reused PI carries a new
/// generation, so the pure ranker refuses to assign its old counters to the new process.
pub(crate) fn snapshot_hot_file() -> [HotProcessCost; MAX_PI] {
    let rows = unsafe { &*core::ptr::addr_of!(ROWS) };
    let mut snapshot = [HotProcessCost::EMPTY; MAX_PI];
    for (pi, value) in snapshot.iter_mut().enumerate() {
        let row = &rows[pi];
        if row.generation != 0 {
            *value = HotProcessCost { generation: row.generation,
                read: row.hot_file[0], write: row.hot_file[1] };
        }
    }
    snapshot
}

/// Called only by the outer root maintenance turn after a periodic census, including one whose
/// clock was advanced inside a nested pump. The nested pump never reads these root-owned tables.
/// An exact live binding and generation gate every read-only scheduler-context request.
pub(crate) fn sample_after_census(handler: &ExecNtHandler) {
    let census = CENSUS_PERIODIC_DUMPS.load(Ordering::Acquire);
    if census == 0 || census == unsafe { LAST_CENSUS } { return; }
    unsafe { LAST_CENSUS = census; }
    let now_100ns = crate::monotonic_time_100ns();
    let rows = unsafe { &mut *core::ptr::addr_of_mut!(ROWS) };
    let setup_pi = crate::serial_records::is_root_executor()
        .then(|| observed_logon_child_pi(handler, rows)).flatten();
    let mut setup_sample = None;
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
        if setup_pi == Some(pi) {
            if let Some(process) = handler.capture_process_identity(pi) {
                setup_sample = Some(SetupOwnerSample { process_index: pi, pid: process.pid,
                    process_generation: row.generation, thread_signature: scan.signature,
                    live_threads: scan.count, parked_threads: scan.parked,
                    sc_errors: scan.failures, bound_us: scan.bound_us,
                    donated_us: scan.donated_us, table_calls: calls });
            }
        }
        if calls != 0 && (row.reported_calls == 0
            || calls >= row.reported_calls.saturating_mul(2)
            || census.is_power_of_two()) {
            row.reported_calls = calls;
            print_row(pi, row);
        }
    }
    if crate::serial_records::is_root_executor() {
        let (terminals, active_children) = handler.install_pipe_census_position();
        let receipt = unsafe { (&mut *core::ptr::addr_of_mut!(SETUP_OWNER_GATE)) }
            .observe(terminals, active_children, setup_sample);
        if let Some(receipt) = receipt {
            print_setup_owner_receipt(handler, rows, now_100ns, receipt);
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

fn print_setup_owner_receipt(handler: &ExecNtHandler, rows: &[Row; MAX_PI], now_100ns: u64,
    receipt: SetupOwnerReceipt) {
    print_str(b"[setup-owner-census] ordinal/terminal-count/at-100ns/validity=");
    print_u64(u64::from(receipt.ordinal)); print_str(b"/");
    print_u64(receipt.terminal_count); print_str(b"/");
    print_u64(now_100ns); print_str(b"/");
    let validity: &[u8] = match receipt.validity {
        SetupOwnerPairValidity::Baseline => b"baseline",
        SetupOwnerPairValidity::Valid => b"valid",
        SetupOwnerPairValidity::MissingOwner => b"missing-owner",
        SetupOwnerPairValidity::ChangedOwner => b"changed-owner",
        SetupOwnerPairValidity::InterruptedByChild => b"interrupted-by-child",
        SetupOwnerPairValidity::ChangedThreadSet => b"changed-thread-set",
        SetupOwnerPairValidity::FailedRuntimeRead => b"failed-runtime-read",
        SetupOwnerPairValidity::CounterRegression => b"counter-regression",
    };
    print_str(validity);
    if let Some(sample) = receipt.sample {
        print_str(b" pi/pid/gen/sc-signature/live/parked/sc-errors/bound-us/donated-us/table-calls=");
        for (index, value) in [sample.process_index as u64, u64::from(sample.pid), sample.process_generation,
            sample.thread_signature, sample.live_threads, sample.parked_threads,
            sample.sc_errors, sample.bound_us, sample.donated_us, sample.table_calls]
            .into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        if let Some(image) = handler.hosted_process_image(sample.process_index) {
            print_str(b" image=\"");
            crate::exec_handler::print_sanitized_ascii(image.leaf, 48);
            print_str(b"\"");
        }
    }
    print_str(b"\n");
    let costs = owner_table_costs(rows);
    if receipt.ordinal == 1 {
        unsafe { *core::ptr::addr_of_mut!(SETUP_ROOT_BASELINE) = costs; }
    } else if receipt.validity == SetupOwnerPairValidity::Valid {
        if let Some((pi, generation, calls, ticks)) = top_owner_table_delta(
        unsafe { &*core::ptr::addr_of!(SETUP_ROOT_BASELINE) }, &costs) {
            print_str(b"[setup-owner-root] top-table-pi/gen/calls/ticks=");
            for (index, value) in [pi as u64, generation, calls, ticks].into_iter().enumerate() {
                if index != 0 { print_str(b"/"); }
                print_u64(value);
            }
            print_str(b" coverage=native-table-dispatch\n");
        }
    }
    let Some(sample) = receipt.sample else { return; };
    print_row(sample.process_index, &rows[sample.process_index]);
    let Some(process) = handler.capture_process_identity(sample.process_index) else { return; };
    let mut matching = 0u64;
    for slot in 0..crate::object_waiter_len() {
        let Some((wait_identity, record)) = crate::object_waiter_record(slot) else { continue; };
        if record.pi != sample.process_index || record.caller.process() != process { continue; }
        matching += 1;
        if matching > 2 { continue; }
        print_str(b"[setup-owner-wait] ordinal/pi/gen/tid/tgen/seq/claimed/reply-cap/reply-sent/count/age-ms/first-object=");
        for (index, value) in [u64::from(receipt.ordinal), sample.process_index as u64,
            sample.process_generation, record.tid, record.caller.thread().generation(),
            record.sequence, u64::from(crate::object_waiter_is_claimed(wait_identity)),
            record.reply_cap, u64::from(record.reply_sent), u64::from(record.count),
            record.latency.parked_age_100ns(now_100ns).unwrap_or(0) / 10_000,
            record.objects.first().map_or(0, |object| object.raw())]
            .into_iter().enumerate() {
            if index != 0 { print_str(b"/"); }
            print_u64(value);
        }
        print_str(b"\n");
    }
    print_str(b"[setup-owner-wait] ordinal/matching/shown=");
    print_u64(u64::from(receipt.ordinal)); print_str(b"/");
    print_u64(matching); print_str(b"/");
    print_u64(matching.min(2)); print_str(b"\n");
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
