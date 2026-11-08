//! Bounded, observation-only timing for reads of the installed mounted volume.
//!
//! The canonical File and IRP identify a dispatch. A pending sample gains its exact
//! File owner only after publication; terminal, Reply, and backend ACK stay distinct.

use super::*;

const CAPACITY: usize = 128;
const SLOW_100NS: u64 = 2 * 10_000_000;

#[derive(Clone, Copy)]
struct Sample {
    owner: Option<nt_io_manager::PendingFileIoIdentity>,
    irp: u64,
    file: u64,
    mount: u64,
    route: u8,
    pi: u32,
    generation: u64,
    ordinal: u64,
    requested: u32,
    started: Option<u64>,
    dispatched: Option<u64>,
    terminal: Option<u64>,
    print_normal: bool,
}

static mut SAMPLES: [Option<Sample>; CAPACITY] = [None; CAPACITY];
static mut PROCESS_GENERATIONS: [u64; MAX_PI] = [0; MAX_PI];
static mut PROCESS_READS: [u64; MAX_PI] = [0; MAX_PI];
static mut OVERFLOW: u64 = 0;
static mut SLOW_TERMINALS: u64 = 0;

fn elapsed_ms(start: Option<u64>, end: Option<u64>) {
    match start
        .zip(end)
        .and_then(|(start, end)| end.checked_sub(start))
    {
        Some(ticks) => print_u64(ticks / 10_000),
        None => print_str(b"?"),
    }
}

fn print_key(sample: Sample) {
    print_str(b" pi/gen/ordinal/file/mount/route/irp/bytes=");
    print_u64(sample.pi as u64);
    print_str(b"/");
    print_u64(sample.generation);
    print_str(b"/");
    print_u64(sample.ordinal);
    print_str(b"/0x");
    print_hex_u64(sample.file);
    print_str(b"/");
    print_u64(sample.mount);
    print_str(b"/");
    print_u64(sample.route as u64);
    print_str(b"/0x");
    print_hex_u64(sample.irp);
    print_str(b"/");
    print_u64(sample.requested as u64);
}

fn matching_sample(
    identity: nt_io_manager::PendingFileIoIdentity,
    irp: u64,
) -> Option<&'static mut Sample> {
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SAMPLES))
            .iter_mut()
            .flatten()
            .find(|sample| sample.owner == Some(identity) && sample.irp == irp)
    }
}

fn reap_stale() {
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    for slot in samples.iter_mut() {
        if slot.is_some_and(|sample| {
            sample.owner.is_some_and(|identity| {
                (unsafe { &*core::ptr::addr_of!(PENDING_FILE_IO) })
                    .get_exact(identity)
                    .is_none_or(|pending| pending.irp_id != sample.irp)
            })
        }) {
            *slot = None;
        }
    }
}

/// Called after the native dispatch returns. `started` was sampled immediately before it.
pub(crate) fn dispatched(
    device: u64,
    file: u64,
    pi: usize,
    generation: u64,
    requested: u32,
    started: Option<u64>,
    result: Result<(i32, u64, u64), u32>,
) {
    if pi >= MAX_PI
        || generation == 0
        || crate::mounted_volume::exec_volume_device() != Some(device)
    {
        return;
    }
    let Some(mount) = crate::mounted_volume::mount_id_for_live_device(device) else {
        return;
    };
    let route = unsafe { crate::fs_loader::exec_fs_mount_identity() }
        .and_then(crate::fs_loader::exec_block_route_kind)
        .map_or(0, |kind| match kind {
            nt_fs::BlockSourceKind::Boot => 1,
            nt_fs::BlockSourceKind::Draining => 2,
            nt_fs::BlockSourceKind::Native => 3,
        });
    let now = diagnostic_time_100ns();
    let generations = unsafe { &mut *core::ptr::addr_of_mut!(PROCESS_GENERATIONS) };
    let reads = unsafe { &mut *core::ptr::addr_of_mut!(PROCESS_READS) };
    if generations[pi] != generation {
        generations[pi] = generation;
        reads[pi] = 0;
    }
    reads[pi] = reads[pi].saturating_add(1);
    let ordinal = reads[pi];
    let print_normal = ordinal <= 8 || ordinal.is_power_of_two();
    let (status, transferred, irp) = match result {
        Ok((status, transferred, irp)) => (status as u32, transferred, irp),
        Err(status) => (status, 0, 0),
    };
    let sample = Sample {
        owner: None,
        irp,
        file,
        mount: mount.value(),
        route,
        pi: pi as u32,
        generation,
        ordinal,
        requested,
        started,
        dispatched: now,
        terminal: None,
        print_normal,
    };
    if status == nt_status::NtStatus::PENDING.raw() as u32 && irp != 0 {
        reap_stale();
        let samples = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
        if let Some(slot) = samples.iter_mut().find(|slot| slot.is_none()) {
            *slot = Some(sample);
        } else {
            unsafe {
                let overflow = &mut *core::ptr::addr_of_mut!(OVERFLOW);
                *overflow = overflow.saturating_add(1);
            }
        }
    }
    if !print_normal {
        return;
    }
    print_str(b"[mounted-read-lifetime] stage=dispatch");
    print_key(sample);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" transferred=");
    print_u64(transferred);
    print_str(b" dispatch-ms=");
    elapsed_ms(started, now);
    print_str(b"\n");
}

/// Bind a pending dispatch to the generation-exact File owner after publication.
pub(super) fn parked(
    handler: &ExecNtHandler,
    identity: nt_io_manager::PendingFileIoIdentity,
    pending: nt_io_manager::PendingFileIo,
) {
    if pending.major != nt_io_abi::major::IRP_MJ_READ {
        return;
    }
    let Some(file) = pending.route.hosted_file_id() else {
        return;
    };
    let pi = pending.pi as usize;
    let Some(generation) = handler.hosted_process_generation(pi) else {
        return;
    };
    let Some(sample) = (unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) })
        .iter_mut()
        .flatten()
        .find(|sample| {
            sample.owner.is_none()
                && sample.irp == pending.irp_id
                && sample.file == file
                && sample.pi == pending.pi
                && sample.generation == generation
        })
    else {
        return;
    };
    if !(unsafe { &*core::ptr::addr_of!(PENDING_FILE_IO) })
        .get_exact(identity)
        .is_some_and(|live| live.irp_id == sample.irp && live.route.hosted_file_id() == Some(file))
    {
        return;
    }
    sample.owner = Some(identity);
}

pub(super) fn terminal_observed(
    identity: nt_io_manager::PendingFileIoIdentity,
    irp: u64,
    status: u32,
    transferred: u64,
) {
    let Some(sample) = matching_sample(identity, irp) else {
        return;
    };
    if sample.terminal.is_some() {
        return;
    }
    let now = diagnostic_time_100ns();
    sample.terminal = now;
    if !sample.print_normal {
        if !sample
            .started
            .zip(now)
            .is_some_and(|(start, end)| end.saturating_sub(start) >= SLOW_100NS)
        {
            return;
        }
        let count = unsafe { &mut *core::ptr::addr_of_mut!(SLOW_TERMINALS) };
        *count = count.saturating_add(1);
        if *count > 64 && !count.is_power_of_two() {
            return;
        }
    }
    print_str(b"[mounted-read-lifetime] stage=terminal");
    print_key(*sample);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b" transferred=");
    print_u64(transferred);
    let abandoned = unsafe { &*core::ptr::addr_of!(PENDING_FILE_IO) }
        .get_exact(identity)
        .is_some_and(|pending| pending.consumer_abandoned);
    print_str(b" caller-abandoned=");
    print_u64(u64::from(abandoned));
    print_str(b" submit-to-terminal-ms=");
    elapsed_ms(sample.started, now);
    print_str(b" dispatch-to-terminal-ms=");
    elapsed_ms(sample.dispatched, now);
    print_str(b"\n");
}

pub(super) fn reply_delivered(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) {
    let Some(sample) = matching_sample(identity, irp) else {
        return;
    };
    if !sample.print_normal {
        return;
    }
    print_str(b"[mounted-read-lifetime] stage=reply");
    print_key(*sample);
    print_str(b" terminal-to-reply-ms=");
    elapsed_ms(sample.terminal, diagnostic_time_100ns());
    print_str(b"\n");
}

pub(super) fn backend_acked(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) {
    let Some(sample) = matching_sample(identity, irp) else {
        return;
    };
    if !sample.print_normal {
        return;
    }
    print_str(b"[mounted-read-lifetime] stage=ack");
    print_key(*sample);
    print_str(b" terminal-to-ack-ms=");
    elapsed_ms(sample.terminal, diagnostic_time_100ns());
    print_str(b"\n");
}

pub(super) fn retired(identity: nt_io_manager::PendingFileIoIdentity, irp: u64) {
    let samples = unsafe { &mut *core::ptr::addr_of_mut!(SAMPLES) };
    if let Some(slot) = samples
        .iter_mut()
        .find(|slot| slot.is_some_and(|sample| sample.owner == Some(identity) && sample.irp == irp))
    {
        *slot = None;
    }
}

pub(crate) fn print_summary() {
    reap_stale();
    let samples = unsafe { &*core::ptr::addr_of!(SAMPLES) };
    let mut live = 0u64;
    let mut unbound = 0u64;
    let mut waiting = 0u64;
    let mut oldest: Option<Sample> = None;
    for sample in samples.iter().flatten() {
        live += 1;
        unbound += u64::from(sample.owner.is_none());
        waiting += u64::from(sample.terminal.is_none());
        if oldest.is_none_or(|other| sample.started < other.started) {
            oldest = Some(*sample);
        }
    }
    print_str(
        b"[mounted-read-lifetime] stage=census live/unbound/waiting/overflow/slow-terminals=",
    );
    print_u64(live);
    print_str(b"/");
    print_u64(unbound);
    print_str(b"/");
    print_u64(waiting);
    print_str(b"/");
    print_u64(unsafe { *core::ptr::addr_of!(OVERFLOW) });
    print_str(b"/");
    print_u64(unsafe { *core::ptr::addr_of!(SLOW_TERMINALS) });
    if let Some(sample) = oldest {
        print_str(b" oldest");
        print_key(sample);
        print_str(b" age-ms=");
        elapsed_ms(sample.started, diagnostic_time_100ns());
    }
    print_str(b"\n");
}
