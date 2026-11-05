//! Observation-only bridge from an exact parked File CREATE to an atomic census sample.

use super::*;
use crate::mounted_create_owner_snapshot::{Observation, OwnerKey, OwnerSnapshot, Phase};

static LAST: OwnerSnapshot = OwnerSnapshot::new();
// The ordinary latest-owner sample is overwritten by SCM CREATEs before Winlogon reaches
// GINA. Keep one observation-only, exact owner for its first msgina.dll open.
static MSGINA: OwnerSnapshot = OwnerSnapshot::new();
static MSGINA_PID: AtomicU64 = AtomicU64::new(0);
static MSGINA_PROCESS_GENERATION: AtomicU64 = AtomicU64::new(0);
static MSGINA_CENSUS_SAMPLES: AtomicU64 = AtomicU64::new(0);
static PARK_SAMPLES: AtomicU64 = AtomicU64::new(0);
static ACK_TIMING_SAMPLES: AtomicU64 = AtomicU64::new(0);
static LOOKUP_PROGRESS_SAMPLES: AtomicU64 = AtomicU64::new(0);
const ACK_TIMING_SAMPLE_LIMIT: u64 = 64;

/// Join one exact lookup's settled work to the already published File CREATE owner.
/// Bounded samples reveal a slow lookup while it is still pending; they do not retain
/// any provider command, reply, or second owner ledger.
pub(crate) fn lookup_progress(
    irp: u64, physical_mount: u64,
    attribution: crate::mounted_volume_backend::mounted_create_lookup::CreateLookupAttribution,
) {
    let owner = LAST.read().filter(|owner| {
        owner.key.irp == irp && owner.key.physical == physical_mount
    });
    let ordinal = LOOKUP_PROGRESS_SAMPLES.fetch_add(1, Ordering::Relaxed) + 1;
    if ordinal > ACK_TIMING_SAMPLE_LIMIT && !ordinal.is_power_of_two() { return; }
    let now = crate::monotonic_time_100ns();
    crate::print_str(b"[mounted-create-lookup] irp/mount/cache-copies/physical-settlements/park-elapsed-ms/owner-phase/t_ms=");
    crate::print_hex_u64(irp);
    crate::print_str(b"/");
    crate::print_u64(physical_mount);
    crate::print_str(b"/");
    crate::print_u64(attribution.copied_cache_completions);
    crate::print_str(b"/");
    crate::print_u64(attribution.physical_settlements);
    crate::print_str(b"/");
    print_elapsed_ms(owner.map(|owner| owner.parked_100ns), Some(now));
    crate::print_str(b"/");
    if let Some(owner) = owner {
        crate::print_u64(owner.phase as u64);
    } else {
        crate::print_str(b"-");
    }
    crate::print_str(b"/");
    crate::print_u64(now / 10_000);
    crate::print_str(b"\n");
}

fn print_elapsed_ms(start: Option<u64>, end: Option<u64>) {
    match start.zip(end).and_then(|(start, end)| end.checked_sub(start)) {
        Some(elapsed) => crate::print_u64(elapsed / 10_000),
        None => crate::print_str(b"-"),
    }
}

fn name_fingerprint(units: &[u16]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for &unit in units {
        hash = (hash ^ u64::from(unit)).wrapping_mul(0x100_0000_01b3);
    }
    hash
}

fn is_msgina_name(units: &[u16]) -> bool {
    const LEAF: &[u8] = b"msgina.dll";
    units.len() >= LEAF.len()
        && units[units.len() - LEAF.len()..].iter().zip(LEAF).all(|(&unit, &byte)| {
            unit <= 0x7f && (unit as u8).eq_ignore_ascii_case(&byte)
        })
        && (units.len() == LEAF.len()
            || matches!(units[units.len() - LEAF.len() - 1], 0x5c | 0x2f))
}

fn print_msgina_stage(stage: &[u8], sample: Observation) {
    crate::print_str(b"[winlogon-msgina-create] stage=");
    crate::print_str(stage);
    crate::print_str(b" pid/gen/pi/tid/badge=");
    crate::print_u64(MSGINA_PID.load(Ordering::Relaxed));
    crate::print_str(b"/");
    crate::print_u64(MSGINA_PROCESS_GENERATION.load(Ordering::Relaxed));
    crate::print_str(b"/");
    crate::print_u64(sample.pi);
    crate::print_str(b"/");
    crate::print_u64(sample.tid);
    crate::print_str(b"/");
    crate::print_u64(sample.badge);
    crate::print_str(b" owner/table/slot/gen=");
    crate::print_u64(sample.key.table);
    crate::print_str(b"/");
    crate::print_u64(sample.key.slot);
    crate::print_str(b"/");
    crate::print_u64(sample.key.generation);
    crate::print_str(b" irp/file=");
    crate::print_hex_u64(sample.key.irp);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.key.file);
    crate::print_str(b" phase/status/delivery=");
    crate::print_u64(sample.phase as u64);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.status);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.delivery);
    crate::print_str(b" t_ms=");
    crate::print_u64(crate::monotonic_time_100ns() / 10_000);
    crate::print_str(b"\n");
}

unsafe fn exact_pending(
    identity: nt_io_manager::PendingFileIoIdentity, irp: u64, file: u64,
) -> Option<nt_io_manager::PendingFileIo> {
    let pending = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity)?;
    (pending.irp_id == irp && pending.route.hosted_file_id() == Some(file)
        && pending.major == nt_io_abi::major::IRP_MJ_CREATE
        && pending.reply_required && !pending.consumer_abandoned)
        .then_some(pending)
}

pub(super) unsafe fn park_exact(
    handler: &ExecNtHandler, identity: nt_io_manager::PendingFileIoIdentity, irp: u64,
) {
    let Some(pending) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity) else { return; };
    let Some(file_id) = pending.route.hosted_file_id() else { return; };
    if exact_pending(identity, irp, file_id).is_none() || pending.reply_cap == 0 { return; }
    let (device, hash, name_len, msgina_name) = {
        let manager = driver_launch::io_manager_mut();
        let Some(canonical_irp) = manager.irp(nt_io_manager::IrpId(irp)) else { return; };
        if canonical_irp.id.raw() != irp || canonical_irp.file_id.map(nt_io_manager::FileId::raw) != Some(file_id)
            || canonical_irp.origin_major != nt_io_abi::major::IRP_MJ_CREATE
            || canonical_irp.requestor_tid != pending.tid { return; }
        let Some(file) = manager.file(nt_io_manager::FileId(file_id)) else { return; };
        if file.device_id != canonical_irp.origin_device_id { return; }
        (file.device_id.raw(), name_fingerprint(file.file_name.as_units()),
            file.file_name.as_units().len() as u64,
            is_msgina_name(file.file_name.as_units()))
    };
    let Some(physical) = fs_loader::exec_fs_mount_identity() else { return; };
    if mounted_volume::exec_volume_device() != Some(device) { return; }
    let Some(logical) = mounted_volume::mount_id_for_live_device(device) else { return; };
    let Some(route) = fs_loader::exec_block_route_kind(physical) else { return; };
    let route = match route {
        nt_fs::BlockSourceKind::Boot => 1,
        nt_fs::BlockSourceKind::Draining => 2,
        nt_fs::BlockSourceKind::Native => 3,
    };
    let key = OwnerKey {
        table: identity.table(), slot: identity.slot() as u64,
        generation: identity.generation(), irp, file: file_id, device,
        physical: physical.value(), logical: logical.value(),
    };
    let parked_100ns = crate::monotonic_time_100ns();
    if msgina_name && MSGINA.read().is_none()
        && handler.hosted_process_role(pending.pi as usize)
            == Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
    {
        if let Some(process) = handler.capture_process_identity(pending.pi as usize) {
            if let nt_types::ProcessGeneration::Hosted(generation) = process.generation {
                if MSGINA.park(key, pending.pi as u64, pending.tid, pending.badge,
                    hash, name_len, route, parked_100ns)
                {
                    MSGINA_PID.store(process.pid as u64, Ordering::Relaxed);
                    MSGINA_PROCESS_GENERATION.store(generation, Ordering::Relaxed);
                    if let Some(sample) = MSGINA.read() {
                        print_msgina_stage(b"park", sample);
                    }
                }
            }
        }
    }
    if !LAST.park(key, pending.pi as u64, pending.tid, pending.badge,
        hash, name_len, route, parked_100ns) { return; }
    let n = PARK_SAMPLES.fetch_add(1, Ordering::Relaxed) + 1;
    if n <= ACK_TIMING_SAMPLE_LIMIT || n.is_power_of_two() {
        crate::print_str(b"[mounted-create-owner] parked irp/file/device/mount/owner=");
        crate::print_hex_u64(irp);
        crate::print_str(b"/");
        crate::print_hex_u64(file_id);
        crate::print_str(b"/");
        crate::print_hex_u64(device);
        crate::print_str(b"/");
        crate::print_u64(physical.value());
        crate::print_str(b"/");
        crate::print_u64(identity.slot() as u64);
        crate::print_str(b":");
        crate::print_u64(identity.generation());
        crate::print_str(b" route=");
        crate::print_u64(route);
        crate::print_str(b" lookup-phase=");
        crate::print_str(mounted_volume::mounted_create_phase(irp, physical.value())
            .unwrap_or(b"unavailable"));
        crate::print_str(b" t_ms=");
        crate::print_u64(parked_100ns / 10_000);
        crate::print_str(b" name-hash=");
        crate::print_hex_u64(hash);
        crate::print_str(b" name=\"");
        let manager = driver_launch::io_manager_mut();
        if let Some(file) = manager.file(nt_io_manager::FileId(file_id)) {
            let units = file.file_name.as_units();
            for &unit in units.iter().take(48) {
                let byte = if (0x20..=0x7e).contains(&unit) { unit as u8 } else { b'?' };
                crate::print_str(&[byte]);
            }
            if units.len() > 48 { crate::print_str(b"..."); }
        }
        crate::print_str(b"\"\n");
    }
}

unsafe fn advance_exact(
    identity: nt_io_manager::PendingFileIoIdentity, irp: u64, file: u64,
    phase: Phase, status: u32,
) {
    let Some(pending) = exact_pending(identity, irp, file) else { return; };
    if let Some(sample) = MSGINA.read() {
        if sample.key.table == identity.table()
            && sample.key.slot == identity.slot() as u64
            && sample.key.generation == identity.generation()
            && sample.key.irp == irp && sample.key.file == file
            && sample.pi == pending.pi as u64
            && sample.tid == pending.tid && sample.badge == pending.badge
            && (phase as u64) > sample.phase as u64
            && MSGINA.advance(sample.key, phase, u64::from(status),
                u64::from(pending.delivery_state), crate::monotonic_time_100ns())
        {
            if let Some(updated) = MSGINA.read() {
                let stage: &[u8] = match phase {
                    Phase::Parked => b"park",
                    Phase::Terminal => b"terminal",
                    Phase::ReplyPublished => b"reply",
                    Phase::BackendAcked => b"ack",
                };
                print_msgina_stage(stage, updated);
            }
        }
    }
    let Some(observation) = LAST.read() else { return; };
    let key = observation.key;
    if key.table != identity.table() || key.slot != identity.slot() as u64
        || key.generation != identity.generation() || key.irp != irp || key.file != file { return; }
    let now_100ns = crate::monotonic_time_100ns();
    if !LAST.advance(key, phase, u64::from(status), u64::from(pending.delivery_state), now_100ns)
        || phase != Phase::BackendAcked
        || observation.phase == Phase::BackendAcked
    { return; }
    let Some(sample) = LAST.read() else { return; };
    if sample.key != key || sample.phase != Phase::BackendAcked { return; }
    if ACK_TIMING_SAMPLES.fetch_add(1, Ordering::Relaxed) >= ACK_TIMING_SAMPLE_LIMIT { return; }
    crate::print_str(b"[mounted-create-timing] irp/file/tid/status/park-terminal-ms/terminal-reply-ms/reply-ack-ms/total-ms/t_ms=");
    crate::print_hex_u64(sample.key.irp);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.key.file);
    crate::print_str(b"/");
    crate::print_u64(sample.tid);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.status);
    crate::print_str(b"/");
    print_elapsed_ms(Some(sample.parked_100ns), sample.terminal_100ns);
    crate::print_str(b"/");
    print_elapsed_ms(sample.terminal_100ns, sample.reply_100ns);
    crate::print_str(b"/");
    print_elapsed_ms(sample.reply_100ns, sample.ack_100ns);
    crate::print_str(b"/");
    print_elapsed_ms(Some(sample.parked_100ns), sample.ack_100ns);
    crate::print_str(b"/");
    crate::print_u64(now_100ns / 10_000);
    crate::print_str(b"\n");
}

pub(super) unsafe fn terminal_exact(
    identity: nt_io_manager::PendingFileIoIdentity, irp: u64, file: u64, status: u32,
) { advance_exact(identity, irp, file, Phase::Terminal, status); }

pub(super) unsafe fn reply_exact(
    identity: nt_io_manager::PendingFileIoIdentity, irp: u64, file: u64, status: u32,
) { advance_exact(identity, irp, file, Phase::ReplyPublished, status); }

pub(super) unsafe fn ack_exact(
    identity: nt_io_manager::PendingFileIoIdentity, irp: u64, file: u64, status: u32,
) { advance_exact(identity, irp, file, Phase::BackendAcked, status); }

/// The periodic caller can run in a nested pump. Read only the published atomic sample.
pub(crate) fn print_snapshot() {
    let Some(sample) = LAST.read() else { return; };
    crate::print_str(b"[mounted-create-owner] last irp/file/device/physical/logical=");
    crate::print_hex_u64(sample.key.irp);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.key.file);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.key.device);
    crate::print_str(b"/");
    crate::print_u64(sample.key.physical);
    crate::print_str(b"/");
    crate::print_u64(sample.key.logical);
    crate::print_str(b" owner/table/slot/generation=");
    crate::print_u64(sample.key.table);
    crate::print_str(b"/");
    crate::print_u64(sample.key.slot);
    crate::print_str(b"/");
    crate::print_u64(sample.key.generation);
    crate::print_str(b" pi/tid/badge=");
    crate::print_u64(sample.pi);
    crate::print_str(b"/");
    crate::print_u64(sample.tid);
    crate::print_str(b"/");
    crate::print_u64(sample.badge);
    crate::print_str(b" route/phase/status/delivery/name-hash/name-len=");
    crate::print_u64(sample.route);
    crate::print_str(b"/");
    crate::print_u64(sample.phase as u64);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.status);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.delivery);
    crate::print_str(b"/");
    crate::print_hex_u64(sample.name_hash);
    crate::print_str(b"/");
    crate::print_u64(sample.name_len);
    crate::print_str(b"\n");

    let Some(gina) = MSGINA.read() else { return; };
    let n = MSGINA_CENSUS_SAMPLES.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 8 && !n.is_power_of_two() { return; }
    let pending = unsafe {
        let table = &*core::ptr::addr_of!(PENDING_FILE_IO);
        usize::try_from(gina.key.slot).ok()
            .and_then(|slot| table.identity(slot))
            .filter(|identity| identity.table() == gina.key.table
                && identity.generation() == gina.key.generation)
            .and_then(|identity| table.get_exact(identity))
            .filter(|pending| pending.irp_id == gina.key.irp
                && pending.route.hosted_file_id() == Some(gina.key.file)
                && pending.pi as u64 == gina.pi
                && pending.tid == gina.tid && pending.badge == gina.badge)
    };
    crate::print_str(b"[winlogon-msgina-owner] phase/status/pending/parked/reply/abandoned=");
    crate::print_u64(gina.phase as u64);
    crate::print_str(b"/");
    crate::print_hex_u64(gina.status);
    crate::print_str(b"/");
    crate::print_u64(pending.is_some() as u64);
    crate::print_str(b"/");
    crate::print_u64(crate::thread_wait_state_badge_parked(gina.badge) as u64);
    crate::print_str(b"/");
    crate::print_u64(pending.is_some_and(|row| row.reply_required && row.reply_cap != 0) as u64);
    crate::print_str(b"/");
    crate::print_u64(pending.is_some_and(|row| row.consumer_abandoned) as u64);
    crate::print_str(b" deadline=none file-retry-global=");
    match driver_launch::hosted_file_retry_deadline(crate::monotonic_time_100ns()) {
        Some(deadline) => crate::print_u64(deadline),
        None => crate::print_str(b"none"),
    }
    crate::print_str(b" sas/msgloop/wait/dialogs=");
    crate::print_u64(crate::WINLOGON_SAS_MILESTONE.load(Ordering::Relaxed));
    crate::print_str(b"/");
    crate::print_u64(crate::WINLOGON_MSGLOOP_MILESTONE.load(Ordering::Relaxed));
    crate::print_str(b"/");
    crate::print_u64(crate::WINLOGON_MAIN_EVENT_WAIT_PARKED.load(Ordering::Relaxed));
    crate::print_str(b"/");
    crate::print_u64(crate::WINLOGON_DIALOG_WINDOWS.load(Ordering::Relaxed));
    crate::print_str(b"\n");
}
