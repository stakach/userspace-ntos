//! Bounded timing of runtime DLL loads. This observes the existing loader transaction only.

use core::sync::atomic::{AtomicU64, Ordering};

static CALLS: AtomicU64 = AtomicU64::new(0);
static TRACE_OUTPUT_TICKS: AtomicU64 = AtomicU64::new(0);
const FIRST_CALLS: u64 = 16;
const TICKS_PER_MS: u64 = 10_000; // NtQueryPerformanceCounter now uses 100 ns units.

pub(super) fn reset() {
    CALLS.store(0, Ordering::Release);
    TRACE_OUTPUT_TICKS.store(0, Ordering::Release);
}

fn counter() -> Option<u64> {
    let mut value = 0i64;
    let status = unsafe {
        nt_ntdll::trap_stubs::nt_query_performance_counter(core::ptr::addr_of_mut!(value) as u64, 0)
            as u32
    };
    (status == 0).then_some(value as u64)
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
