//! Bounded timing of runtime DLL loads. This observes the existing loader transaction only.

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

static CALLS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_CALLS: AtomicU32 = AtomicU32::new(0);
static SNAP_DESCRIPTORS: AtomicU64 = AtomicU64::new(0);
static SAMPLED_DESCRIPTORS: AtomicU32 = AtomicU32::new(0);
static TRACE_OUTPUT_TICKS: AtomicU64 = AtomicU64::new(0);
static EXPORT_TOUCH_TICKS: AtomicU64 = AtomicU64::new(0);
static EXPORT_SEARCH_TICKS: AtomicU64 = AtomicU64::new(0);
static FORWARDERS: AtomicU64 = AtomicU64::new(0);
const FIRST_CALLS: u64 = 16;
const FIRST_SNAP_DESCRIPTORS: u64 = 128;
const TICKS_PER_MS: u64 = 10_000; // NtQueryPerformanceCounter now uses 100 ns units.

pub(super) fn reset() {
    CALLS.store(0, Ordering::Release);
    ACTIVE_CALLS.store(0, Ordering::Release);
    SNAP_DESCRIPTORS.store(0, Ordering::Release);
    SAMPLED_DESCRIPTORS.store(0, Ordering::Release);
    TRACE_OUTPUT_TICKS.store(0, Ordering::Release);
    EXPORT_TOUCH_TICKS.store(0, Ordering::Release);
    EXPORT_SEARCH_TICKS.store(0, Ordering::Release);
    FORWARDERS.store(0, Ordering::Release);
}

fn counter() -> Option<u64> {
    let mut value = 0i64;
    let status = unsafe {
        nt_ntdll::trap_stubs::nt_query_performance_counter(core::ptr::addr_of_mut!(value) as u64, 0)
            as u32
    };
    (status == 0).then_some(value as u64)
}

pub(super) fn counter_sample() -> Option<u64> {
    counter()
}

fn process_id() -> u64 {
    let process_id: u64;
    // SAFETY: the on-target loader runs with a mapped TEB; ClientId.UniqueProcess is at gs:0x40.
    unsafe {
        core::arch::asm!(
            "mov {}, gs:[0x40]",
            out(reg) process_id,
            options(nostack, preserves_flags, readonly)
        );
    }
    process_id
}

fn append(buffer: &mut [u8], mut at: usize, bytes: &[u8]) -> usize {
    for &byte in bytes {
        if at == buffer.len() {
            break;
        }
        buffer[at] = byte;
        at += 1;
    }
    at
}

fn elapsed_ms(first: Option<u64>, last: Option<u64>) -> Option<u32> {
    first
        .zip(last)
        .and_then(|(first, last)| last.checked_sub(first))
        .map(|ticks| (ticks / TICKS_PER_MS).min(u32::MAX as u64) as u32)
}

fn measured_ms(first: Option<u64>, last: Option<u64>, output_before: u64) -> Option<u32> {
    let wall = last?.checked_sub(first?)?;
    let output = TRACE_OUTPUT_TICKS
        .load(Ordering::Acquire)
        .saturating_sub(output_before);
    Some((wall.saturating_sub(output) / TICKS_PER_MS).min(u32::MAX as u64) as u32)
}

fn emit(message: &[u8]) {
    let before = counter();
    unsafe { crate::dbg_print_bytes(message.as_ptr(), message.len()) };
    if let Some(ticks) = before.zip(counter()).and_then(|(a, b)| b.checked_sub(a)) {
        TRACE_OUTPUT_TICKS.fetch_add(ticks, Ordering::AcqRel);
    }
}

/// Aggregate export-directory paging and lookup cost without logging on the thunk hot path.
pub(super) struct ExportLookupTimer {
    touch_start: Option<u64>,
    search_start: Option<u64>,
}

impl ExportLookupTimer {
    pub(super) fn begin() -> Self {
        let touch_start = (SAMPLED_DESCRIPTORS.load(Ordering::Acquire) != 0)
            .then(counter)
            .flatten();
        Self {
            touch_start,
            search_start: None,
        }
    }

    pub(super) fn touched(&mut self) {
        let Some(start) = self.touch_start else {
            return;
        };
        if let Some(end) = counter() {
            EXPORT_TOUCH_TICKS.fetch_add(end.saturating_sub(start), Ordering::Relaxed);
            self.search_start = counter();
        }
    }
}

impl Drop for ExportLookupTimer {
    fn drop(&mut self) {
        if let Some(start) = self.search_start {
            if let Some(end) = counter() {
                EXPORT_SEARCH_TICKS.fetch_add(end.saturating_sub(start), Ordering::Relaxed);
            }
        }
    }
}

pub(super) fn forwarder() {
    if SAMPLED_DESCRIPTORS.load(Ordering::Acquire) != 0 {
        FORWARDERS.fetch_add(1, Ordering::Relaxed);
    }
}

fn append_optional_ms<const N: usize>(buffer: &mut [u8; N], at: usize, ms: Option<u32>) -> usize {
    match ms {
        Some(ms) => crate::write_u32_dec(buffer, at, ms),
        None => append(buffer, at, b"-"),
    }
}

pub(super) struct RuntimeLoadTrace {
    ordinal: u64,
    pid: u64,
    work_start: Option<u64>,
    phase_start: Option<u64>,
    phase_output_before: u64,
    map_ms: Option<u32>,
    snap_ms: Option<u32>,
    bookkeeping_ms: Option<u32>,
    attach_ms: Option<u32>,
}

impl RuntimeLoadTrace {
    pub(super) fn begin(name: &[u8]) -> Self {
        ACTIVE_CALLS.fetch_add(1, Ordering::AcqRel);
        let ordinal = CALLS.fetch_add(1, Ordering::Relaxed) + 1;
        let sampled = ordinal <= FIRST_CALLS || ordinal.is_power_of_two();
        let entered = sampled.then(counter).flatten();
        let pid = if sampled { process_id() } else { 0 };
        if let Some(tick) = entered {
            let mut message = [0u8; 256];
            let mut at = append(&mut message, 0, b"[ldr-runtime] begin n=");
            at = crate::write_u32_dec(&mut message, at, ordinal.min(u32::MAX as u64) as u32);
            at = append(&mut message, at, b" pid=0x");
            at = crate::write_u64_hex(&mut message, at, pid);
            at = append(&mut message, at, b" qpc=0x");
            at = crate::write_u64_hex(&mut message, at, tick);
            at = append(&mut message, at, b" name=\"");
            at = append(&mut message, at, &name[..name.len().min(96)]);
            at = append(&mut message, at, b"\"\n");
            emit(&message[..at]);
        }
        let work_start = entered.and_then(|_| counter());
        Self {
            ordinal,
            pid,
            work_start,
            phase_start: work_start,
            phase_output_before: TRACE_OUTPUT_TICKS.load(Ordering::Acquire),
            map_ms: None,
            snap_ms: None,
            bookkeeping_ms: None,
            attach_ms: None,
        }
    }

    fn phase_done(&mut self, phase: &[u8]) -> Option<u32> {
        let end = self.phase_start.and_then(|_| counter());
        let duration = measured_ms(self.phase_start, end, self.phase_output_before);
        if let Some(tick) = end {
            let mut message = [0u8; 128];
            let mut at = append(&mut message, 0, b"[ldr-runtime] phase n=");
            at = crate::write_u32_dec(&mut message, at, self.ordinal.min(u32::MAX as u64) as u32);
            at = append(&mut message, at, b" pid=0x");
            at = crate::write_u64_hex(&mut message, at, self.pid);
            at = append(&mut message, at, b" qpc=0x");
            at = crate::write_u64_hex(&mut message, at, tick);
            at = append(&mut message, at, b" stage=");
            at = append(&mut message, at, phase);
            at = append(&mut message, at, b" phase-ms=");
            at = append_optional_ms(&mut message, at, duration);
            at = append(&mut message, at, b"\n");
            emit(&message[..at]);
        }
        // The next phase starts after serial output, so no phase duration charges debug I/O.
        self.phase_start = end.and_then(|_| counter());
        self.phase_output_before = TRACE_OUTPUT_TICKS.load(Ordering::Acquire);
        duration
    }

    pub(super) fn map_done(&mut self) {
        self.map_ms = self.phase_done(b"map");
    }
    pub(super) fn snap_done(&mut self) {
        self.snap_ms = self.phase_done(b"snap");
    }
    pub(super) fn bookkeeping_done(&mut self) {
        self.bookkeeping_ms = self.phase_done(b"book");
    }
    pub(super) fn attach_done(&mut self) {
        self.attach_ms = self.phase_done(b"attach");
    }

    pub(super) fn finish(self, status: u32) {
        ACTIVE_CALLS.fetch_sub(1, Ordering::AcqRel);
        let Some(start) = self.work_start else {
            return;
        };
        let finished = counter();
        let mut message = [0u8; 256];
        let mut at = append(&mut message, 0, b"[ldr-runtime] end n=");
        at = crate::write_u32_dec(&mut message, at, self.ordinal.min(u32::MAX as u64) as u32);
        at = append(&mut message, at, b" pid=0x");
        at = crate::write_u64_hex(&mut message, at, self.pid);
        at = append(&mut message, at, b" qpc=0x");
        at = crate::write_u64_hex(&mut message, at, finished.unwrap_or(0));
        at = append(&mut message, at, b" status=0x");
        at = crate::write_u64_hex(&mut message, at, status as u64);
        at = append(&mut message, at, b" map/snap/book/attach/elapsed-ms=");
        for (index, ms) in [
            self.map_ms,
            self.snap_ms,
            self.bookkeeping_ms,
            self.attach_ms,
            elapsed_ms(Some(start), finished),
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                at = append(&mut message, at, b"/");
            }
            at = append_optional_ms(&mut message, at, ms);
        }
        at = append(&mut message, at, b"\n");
        emit(&message[..at]);
    }
}

/// Observe one import descriptor while a runtime LdrLoadDll transaction is active. The
/// preparation interval includes recursive dependency mapping and snapping; resolve covers only
/// this descriptor's thunk walk after its dependency is ready.
pub(super) struct SnapDescriptorTrace {
    ordinal: u64,
    pid: u64,
    resolved_before: Option<u32>,
    start: Option<u64>,
    start_output_before: u64,
    ready: Option<u64>,
    resolve_start: Option<u64>,
    resolve_output_before: u64,
    export_touch_before: u64,
    export_search_before: u64,
    forwarders_before: u64,
    thunks: u32,
    slow_thunks: u32,
    max_thunk_ticks: u64,
    max_name: [u8; 48],
    max_name_len: usize,
    max_ordinal: u32,
    max_by_ordinal: bool,
    pre_ticks: u64,
    resolve_ticks: u64,
    post_ticks: u64,
}

pub(super) fn begin_snap_descriptor(
    image_base: u64,
    depth: u32,
    dependency: &[u8],
) -> Option<SnapDescriptorTrace> {
    if ACTIVE_CALLS.load(Ordering::Acquire) == 0 {
        return None;
    }
    let ordinal = SNAP_DESCRIPTORS.fetch_add(1, Ordering::Relaxed) + 1;
    if ordinal > FIRST_SNAP_DESCRIPTORS && !ordinal.is_power_of_two() {
        return None;
    }
    let tick = counter()?;
    SAMPLED_DESCRIPTORS.fetch_add(1, Ordering::AcqRel);
    let pid = process_id();
    let mut message = [0u8; 192];
    let mut at = append(&mut message, 0, b"[ldr-snap] begin n=");
    at = crate::write_u32_dec(&mut message, at, ordinal.min(u32::MAX as u64) as u32);
    at = append(&mut message, at, b" pid=0x");
    at = crate::write_u64_hex(&mut message, at, pid);
    at = append(&mut message, at, b" qpc=0x");
    at = crate::write_u64_hex(&mut message, at, tick);
    at = append(&mut message, at, b" module=0x");
    at = crate::write_u64_hex(&mut message, at, image_base);
    at = append(&mut message, at, b" depth=");
    at = crate::write_u32_dec(&mut message, at, depth);
    at = append(&mut message, at, b" dep=");
    at = append(&mut message, at, &dependency[..dependency.len().min(32)]);
    at = append(&mut message, at, b"\n");
    emit(&message[..at]);
    Some(SnapDescriptorTrace {
        ordinal,
        pid,
        resolved_before: None,
        start: counter(),
        start_output_before: TRACE_OUTPUT_TICKS.load(Ordering::Acquire),
        ready: None,
        resolve_start: None,
        resolve_output_before: 0,
        export_touch_before: 0,
        export_search_before: 0,
        forwarders_before: 0,
        thunks: 0,
        slow_thunks: 0,
        max_thunk_ticks: 0,
        max_name: [0; 48],
        max_name_len: 0,
        max_ordinal: 0,
        max_by_ordinal: false,
        pre_ticks: 0,
        resolve_ticks: 0,
        post_ticks: 0,
    })
}

impl SnapDescriptorTrace {
    pub(super) fn dependency_ready(&mut self, base: u64, resolved_before: u32) {
        self.resolved_before = Some(resolved_before);
        self.ready = self.start.and_then(|_| counter());
        let Some(tick) = self.ready else { return };
        let mut message = [0u8; 160];
        let mut at = append(&mut message, 0, b"[ldr-snap] ready n=");
        at = crate::write_u32_dec(&mut message, at, self.ordinal.min(u32::MAX as u64) as u32);
        at = append(&mut message, at, b" pid=0x");
        at = crate::write_u64_hex(&mut message, at, self.pid);
        at = append(&mut message, at, b" qpc=0x");
        at = crate::write_u64_hex(&mut message, at, tick);
        at = append(&mut message, at, b" base=0x");
        at = crate::write_u64_hex(&mut message, at, base);
        at = append(&mut message, at, b" prepare-ms=");
        at = append_optional_ms(
            &mut message,
            at,
            measured_ms(self.start, self.ready, self.start_output_before),
        );
        at = append(&mut message, at, b"\n");
        emit(&message[..at]);
        self.resolve_start = counter();
        self.resolve_output_before = TRACE_OUTPUT_TICKS.load(Ordering::Acquire);
        self.export_touch_before = EXPORT_TOUCH_TICKS.load(Ordering::Acquire);
        self.export_search_before = EXPORT_SEARCH_TICKS.load(Ordering::Acquire);
        self.forwarders_before = FORWARDERS.load(Ordering::Acquire);
    }

    pub(super) fn record_thunk(
        &mut self,
        started: Option<u64>,
        resolve_started: Option<u64>,
        resolve_done: Option<u64>,
        done: Option<u64>,
        name: &[u8],
        ordinal: u32,
        by_ordinal: bool,
    ) {
        let (Some(started), Some(resolve_started), Some(resolve_done), Some(done)) =
            (started, resolve_started, resolve_done, done)
        else {
            return;
        };
        let Some(pre) = resolve_started.checked_sub(started) else {
            return;
        };
        let Some(resolve) = resolve_done.checked_sub(resolve_started) else {
            return;
        };
        let Some(post) = done.checked_sub(resolve_done) else {
            return;
        };
        let Some(total) = done.checked_sub(started) else {
            return;
        };
        self.thunks = self.thunks.saturating_add(1);
        self.pre_ticks = self.pre_ticks.saturating_add(pre);
        self.resolve_ticks = self.resolve_ticks.saturating_add(resolve);
        self.post_ticks = self.post_ticks.saturating_add(post);
        if total >= 100 * TICKS_PER_MS {
            self.slow_thunks = self.slow_thunks.saturating_add(1);
        }
        if total > self.max_thunk_ticks {
            self.max_thunk_ticks = total;
            self.max_by_ordinal = by_ordinal;
            self.max_ordinal = ordinal;
            self.max_name_len = name.len().min(self.max_name.len());
            self.max_name[..self.max_name_len].copy_from_slice(&name[..self.max_name_len]);
        }
    }

    pub(super) fn finish(self, resolved: u32, status: u32) {
        SAMPLED_DESCRIPTORS.fetch_sub(1, Ordering::AcqRel);
        let end = counter();
        let mut message = [0u8; 160];
        let mut at = append(&mut message, 0, b"[ldr-snap] end n=");
        at = crate::write_u32_dec(&mut message, at, self.ordinal.min(u32::MAX as u64) as u32);
        at = append(&mut message, at, b" pid=0x");
        at = crate::write_u64_hex(&mut message, at, self.pid);
        at = append(&mut message, at, b" qpc=0x");
        at = crate::write_u64_hex(&mut message, at, end.unwrap_or(0));
        at = append(&mut message, at, b" resolved=");
        at = match self.resolved_before {
            Some(before) => crate::write_u32_dec(&mut message, at, resolved.saturating_sub(before)),
            None => append(&mut message, at, b"-"),
        };
        at = append(&mut message, at, b" status=0x");
        at = crate::write_u64_hex(&mut message, at, status as u64);
        at = append(&mut message, at, b" resolve-ms=");
        at = append_optional_ms(
            &mut message,
            at,
            measured_ms(self.resolve_start, end, self.resolve_output_before),
        );
        at = append(&mut message, at, b"\n");
        emit(&message[..at]);
        if self.resolve_start.is_some() {
            let mut summary = [0u8; 320];
            let mut at = append(&mut summary, 0, b"[ldr-thunks] n=");
            at = crate::write_u32_dec(&mut summary, at, self.ordinal.min(u32::MAX as u64) as u32);
            at = append(&mut summary, at, b" pid=0x");
            at = crate::write_u64_hex(&mut summary, at, self.pid);
            at = append(&mut summary, at, b" count/slow/max-ms=");
            at = crate::write_u32_dec(&mut summary, at, self.thunks);
            at = append(&mut summary, at, b"/");
            at = crate::write_u32_dec(&mut summary, at, self.slow_thunks);
            at = append(&mut summary, at, b"/");
            at = crate::write_u32_dec(
                &mut summary,
                at,
                (self.max_thunk_ticks / TICKS_PER_MS) as u32,
            );
            at = append(&mut summary, at, b" max=");
            if self.max_by_ordinal {
                at = append(&mut summary, at, b"#");
                at = crate::write_u32_dec(&mut summary, at, self.max_ordinal);
            } else {
                at = append(&mut summary, at, &self.max_name[..self.max_name_len]);
            }
            at = append(
                &mut summary,
                at,
                b" pre/resolve/post/export-touch/export-search-ms=",
            );
            for (index, ticks) in [
                self.pre_ticks,
                self.resolve_ticks,
                self.post_ticks,
                EXPORT_TOUCH_TICKS
                    .load(Ordering::Acquire)
                    .saturating_sub(self.export_touch_before),
                EXPORT_SEARCH_TICKS
                    .load(Ordering::Acquire)
                    .saturating_sub(self.export_search_before),
            ]
            .into_iter()
            .enumerate()
            {
                if index != 0 {
                    at = append(&mut summary, at, b"/");
                }
                at = crate::write_u32_dec(
                    &mut summary,
                    at,
                    (ticks / TICKS_PER_MS).min(u32::MAX as u64) as u32,
                );
            }
            at = append(&mut summary, at, b" forwarders=");
            at = crate::write_u32_dec(
                &mut summary,
                at,
                FORWARDERS
                    .load(Ordering::Acquire)
                    .saturating_sub(self.forwarders_before)
                    .min(u32::MAX as u64) as u32,
            );
            at = append(&mut summary, at, b"\n");
            emit(&summary[..at]);
        }
    }
}
