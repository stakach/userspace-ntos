//! Bounded timing evidence for synchronous hosted named-pipe reads.
//!
//! This sidecar observes the exact pending File owner. It never grants ownership or changes
//! completion decisions. Live reads occupy bounded slots; the first eight and later power-of-two
//! ordinals per process generation are printed, as are unusually slow completions. A census
//! reports the oldest retained read and overflow, including reads that never complete.

use super::*;

const TRACE_CAPACITY: usize = 64;

#[derive(Clone, Copy)]
struct ProcessSample {
    generation: u64,
    reads: u32,
}

impl ProcessSample {
    const fn empty() -> Self { Self { generation: 0, reads: 0 } }
}

#[derive(Clone, Copy)]
struct ReadSample {
    identity: nt_io_manager::PendingFileIoIdentity,
    irp_id: u64,
    trace_id: u64,
    pi: u32,
    generation: u64,
    file_id: u64,
    ordinal: u32,
    print_normal: bool,
    started_100ns: Option<u64>,
    terminal_seen: bool,
    terminal_100ns: Option<u64>,
}

static mut PROCESS_SAMPLES: [ProcessSample; MAX_PI] = [ProcessSample::empty(); MAX_PI];
static mut READ_SAMPLES: [Option<ReadSample>; TRACE_CAPACITY] = [None; TRACE_CAPACITY];
static mut NEXT_TRACE_ID: u64 = 0;
static mut TRACE_OVERFLOW: u64 = 0;
const SLOW_100NS: u64 = 5 * 10_000_000;

fn elapsed_ms(start: Option<u64>, end: Option<u64>) -> Option<u64> {
    start.zip(end).map(|(start, end)| end.saturating_sub(start) / 10_000)
}

fn print_elapsed(label: &[u8], start: Option<u64>, end: Option<u64>) {
    print_str(label);
    if let Some(ms) = elapsed_ms(start, end) { print_u64(ms); }
    else { print_str(b"unknown"); }
}

fn print_owner(sample: ReadSample) {
    print_str(b" id="); print_u64(sample.trace_id);
    print_str(b" irp=0x"); print_hex_u64(sample.irp_id);
    print_str(b" pi="); print_u64(sample.pi as u64);
    print_str(b" generation="); print_u64(sample.generation);
    print_str(b" file=0x"); print_hex_u64(sample.file_id);
}

fn sample_slot(
    identity: nt_io_manager::PendingFileIoIdentity,
    irp_id: u64,
) -> Option<&'static mut ReadSample> {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(READ_SAMPLES)).iter_mut()
            .flatten().find(|sample| sample.identity == identity && sample.irp_id == irp_id)
    }
}

fn reap_stale(samples: &mut [Option<ReadSample>; TRACE_CAPACITY]) {
    for slot in samples.iter_mut() {
        if slot.is_some_and(|sample| {
            (unsafe { &*core::ptr::addr_of!(PENDING_FILE_IO) })
                .get_exact(sample.identity)
                .is_none_or(|live| live.irp_id != sample.irp_id)
        }) {
            *slot = None;
        }
    }
}

pub(super) fn parked(
    handler: &ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity,
    pending: nt_io_manager::PendingFileIo,
    wait_for_completion: bool,
) {
    // The input is the pre-publication snapshot; the live row owns the transferred Reply.
    let Some(pending) = (unsafe { &*core::ptr::addr_of!(PENDING_FILE_IO) })
        .get_exact(identity).filter(|live| live.irp_id == pending.irp_id)
    else { return; };
    let Some(file_id) = pending.route.hosted_file_id() else { return; };
    if !wait_for_completion || !pending.reply_required
        || pending.major != nt_io_abi::major::IRP_MJ_READ
        || !handler.hosted_file_is_named_pipe(file_id)
    { return; }
    let pi = pending.pi as usize;
    let Some(generation) = handler.hosted_process_generation(pi).filter(|value| *value != 0)
        .filter(|_| pi < MAX_PI)
    else { return; };
    let process = unsafe { &mut (&mut *core::ptr::addr_of_mut!(PROCESS_SAMPLES))[pi] };
    if process.generation != generation {
        *process = ProcessSample { generation, reads: 0 };
    }
    process.reads = process.reads.saturating_add(1);
    let ordinal = process.reads;
    let print_normal = ordinal <= 8 || (ordinal >= 16 && ordinal.is_power_of_two());
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(READ_SAMPLES) };
    // An abandoned caller may retire through a different cleanup path. Reuse a diagnostic slot
    // only after the exact owner is gone; a numeric File/IRP alone cannot establish liveness.
    reap_stale(samples);
    let Some(slot) = samples.iter_mut().find(|sample| sample.is_none()) else {
        unsafe {
            let overflow = &mut *core::ptr::addr_of_mut!(TRACE_OVERFLOW);
            *overflow = overflow.saturating_add(1);
        }
        return;
    };
    let trace_id = unsafe {
        let next = &mut *core::ptr::addr_of_mut!(NEXT_TRACE_ID);
        *next = next.saturating_add(1);
        *next
    };
    let sample = ReadSample {
        identity, irp_id: pending.irp_id, trace_id,
        pi: pending.pi, generation, file_id, ordinal, print_normal,
        started_100ns: diagnostic_time_100ns(),
        terminal_seen: false, terminal_100ns: None,
    };
    *slot = Some(sample);
    if !print_normal { return; }
    print_str(b"[pipe-read-lifetime] stage=park"); print_owner(sample);
    print_str(b" tid="); print_u64(pending.tid);
    print_str(b" ordinal="); print_u64(ordinal as u64);
    print_str(b"\n");
}

/// The executive's first validated terminal observation may follow provider completion.
pub(super) fn terminal_observed(
    identity: nt_io_manager::PendingFileIoIdentity,
    irp_id: u64,
    status: u32,
) {
    let Some(sample) = sample_slot(identity, irp_id) else { return; };
    if sample.terminal_seen { return; }
    let now = diagnostic_time_100ns();
    sample.terminal_seen = true;
    sample.terminal_100ns = now;
    let slow = sample.started_100ns.zip(now)
        .is_some_and(|(start, end)| end.saturating_sub(start) >= SLOW_100NS);
    if !sample.print_normal && !slow { return; }
    print_str(b"[pipe-read-lifetime] stage=terminal-observed"); print_owner(*sample);
    print_str(b" status=0x"); print_hex(status);
    print_elapsed(b" park-to-terminal-ms=", sample.started_100ns, now);
    print_str(b"\n");
}

/// A successful Reply publication unblocks the caller; it does not prove user execution.
pub(super) fn reply_delivered(
    identity: nt_io_manager::PendingFileIoIdentity,
    irp_id: u64,
) {
    let Some(sample) = sample_slot(identity, irp_id) else { return; };
    let now = diagnostic_time_100ns();
    let slow = sample.started_100ns.zip(now)
        .is_some_and(|(start, end)| end.saturating_sub(start) >= SLOW_100NS);
    if !sample.print_normal && !slow { return; }
    print_str(b"[pipe-read-lifetime] stage=reply-delivered"); print_owner(*sample);
    print_elapsed(b" park-to-reply-ms=", sample.started_100ns, now);
    print_elapsed(b" terminal-to-reply-ms=", sample.terminal_100ns, now);
    print_str(b"\n");
}

pub(super) fn retired(identity: nt_io_manager::PendingFileIoIdentity, irp_id: u64) {
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(READ_SAMPLES) };
    if let Some(slot) = samples.iter_mut().find(|slot| slot.is_some_and(|sample| {
        sample.identity == identity && sample.irp_id == irp_id
    })) {
        *slot = None;
    }
}

pub(crate) fn print_summary() {
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(READ_SAMPLES) };
    reap_stale(samples);
    let now = diagnostic_time_100ns();
    let mut live = 0u64;
    let mut awaiting_terminal = 0u64;
    let mut oldest: Option<ReadSample> = None;
    for slot in samples.iter_mut() {
        let Some(sample) = slot else { continue; };
        live += 1;
        if !sample.terminal_seen { awaiting_terminal += 1; }
        if oldest.is_none_or(|other| {
            (!sample.terminal_seen && other.terminal_seen)
                || (sample.terminal_seen == other.terminal_seen
                    && sample.trace_id < other.trace_id)
        }) {
            oldest = Some(*sample);
        }
    }
    print_str(b"[pipe-read-lifetime] stage=census live="); print_u64(live);
    print_str(b" awaiting-terminal="); print_u64(awaiting_terminal);
    print_str(b" overflow-total="); print_u64(unsafe { *core::ptr::addr_of!(TRACE_OVERFLOW) });
    if let Some(oldest) = oldest {
        print_str(b" oldest"); print_owner(oldest);
        print_str(b" ordinal="); print_u64(oldest.ordinal as u64);
        print_elapsed(b" age-ms=", oldest.started_100ns, now);
        print_str(b" terminal-observed="); print_u64(oldest.terminal_seen as u64);
    }
    print_str(b"\n");
}
