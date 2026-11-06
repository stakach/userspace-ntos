//! Bounded timing of runtime DLL loads. This observes the existing loader transaction only.

use core::sync::atomic::{AtomicU64, Ordering};

static CALLS: AtomicU64 = AtomicU64::new(0);
const FIRST_CALLS: u64 = 128;
const TICKS_PER_MS: u64 = 10_000; // NtQueryPerformanceCounter now uses 100 ns units.

pub(super) fn reset() {
    CALLS.store(0, Ordering::Release);
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

fn append_ms<const N: usize>(
    buffer: &mut [u8; N],
    at: usize,
    first: Option<u64>,
    last: Option<u64>,
) -> usize {
    match first
        .zip(last)
        .and_then(|(first, last)| last.checked_sub(first))
    {
        Some(ticks) => crate::write_u32_dec(
            buffer,
            at,
            (ticks / TICKS_PER_MS).min(u32::MAX as u64) as u32,
        ),
        None => append(buffer, at, b"-"),
    }
}

pub(super) struct RuntimeLoadTrace {
    ordinal: u64,
    pid: u64,
    work_start: Option<u64>,
    map_done: Option<u64>,
    snap_done: Option<u64>,
    bookkeeping_done: Option<u64>,
    attach_done: Option<u64>,
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
            unsafe { crate::dbg_print_bytes(message.as_ptr(), at) };
        }
        Self {
            ordinal,
            pid,
            work_start: entered.and_then(|_| counter()),
            map_done: None,
            snap_done: None,
            bookkeeping_done: None,
            attach_done: None,
        }
    }

    pub(super) fn map_done(&mut self) {
        self.map_done = self.work_start.and_then(|_| counter());
    }
    pub(super) fn snap_done(&mut self) {
        self.snap_done = self.work_start.and_then(|_| counter());
    }
    pub(super) fn bookkeeping_done(&mut self) {
        self.bookkeeping_done = self.work_start.and_then(|_| counter());
    }
    pub(super) fn attach_done(&mut self) {
        self.attach_done = self.work_start.and_then(|_| counter());
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
        at = append(&mut message, at, b" map/snap/book/attach/total-ms=");
        for (index, (first, last)) in [
            (Some(start), self.map_done),
            (self.map_done, self.snap_done),
            (
                self.snap_done.or(self.map_done).or(Some(start)),
                self.bookkeeping_done,
            ),
            (self.bookkeeping_done, self.attach_done),
            (Some(start), finished),
        ]
        .into_iter()
        .enumerate()
        {
            if index != 0 {
                at = append(&mut message, at, b"/");
            }
            at = append_ms(&mut message, at, first, last);
        }
        at = append(&mut message, at, b"\n");
        unsafe { crate::dbg_print_bytes(message.as_ptr(), at) };
    }
}
