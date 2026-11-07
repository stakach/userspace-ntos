//! Observation-only bridge from an exact parked File CREATE to an atomic census sample.

use super::*;
use crate::mounted_create_owner_snapshot::{OwnerKey, OwnerSnapshot, Phase};

static LAST: OwnerSnapshot = OwnerSnapshot::new();
static PARK_SAMPLES: AtomicU64 = AtomicU64::new(0);
static ACK_TIMING_SAMPLES: AtomicU64 = AtomicU64::new(0);
static LOOKUP_PROGRESS_SAMPLES: AtomicU64 = AtomicU64::new(0);
static RECEIVE_OWNER_IRP: AtomicU64 = AtomicU64::new(0);
static RECEIVE_OWNER_SAMPLES: AtomicU64 = AtomicU64::new(0);
const ACK_TIMING_SAMPLE_LIMIT: u64 = 64;

/// Bounded observation after the timer receive barrier has reconciled. The parked File CREATE
/// identity is only a filter; all physical and timer facts come from their existing owners.
pub(crate) fn receive_boundary_snapshot() {
    let Some(owner) = LAST.read().filter(|owner| owner.phase == Phase::Parked && owner.route == 3)
        else { return; };
    if RECEIVE_OWNER_IRP.swap(owner.key.irp, Ordering::AcqRel) != owner.key.irp {
        RECEIVE_OWNER_SAMPLES.store(0, Ordering::Release);
    }
    let sample = RECEIVE_OWNER_SAMPLES.fetch_add(1, Ordering::AcqRel) + 1;
    if sample > 32 && !sample.is_power_of_two() { return; }
    let claimable = crate::mounted_volume::mounted_sector_claimable();
    let now = crate::monotonic_time_100ns();
    let retry = crate::driver_launch::mounted_native_block_next_deadline(now);
    crate::print_str(b"[mounted-receive] irp/sample/physical/claimable/retry-ms/rearm-requested/pit-armed/pit-source/pit-deadline-ms/tick-pending=");
    crate::print_hex_u64(owner.key.irp);
    crate::print_str(b"/"); crate::print_u64(sample);
    crate::print_str(b"/"); crate::print_hex_u64(crate::driver_launch::mounted_native_physical_irp_id());
    crate::print_str(b"/");
    match claimable { Some(value) => crate::print_u64(u64::from(value)), None => crate::print_str(b"?") }
    crate::print_str(b"/");
    match retry { Some(deadline) => crate::print_u64(deadline / 10_000), None => crate::print_str(b"-") }
    crate::print_str(b"/");
    crate::print_u64(u64::from(super::MOUNTED_NATIVE_TIMER_REARM_DEMAND.is_pending()));
    crate::print_str(b"/"); crate::print_u64(u64::from(crate::LAST_REARM_AUTHORITY.is_armed()));
    crate::print_str(b"/"); crate::print_u64(crate::LAST_REARM_SOURCE.load(Ordering::Relaxed));
    crate::print_str(b"/"); crate::print_u64(crate::LAST_REARM_DEADLINE.load(Ordering::Relaxed) / 10_000);
    crate::print_str(b"/"); crate::print_u64(crate::DELAY_TIMER_TICKS_PENDING.load(Ordering::Relaxed));
    crate::print_str(b"\n");
}

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
    identity: nt_io_manager::PendingFileIoIdentity, irp: u64,
) {
    let Some(pending) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity) else { return; };
    let Some(file_id) = pending.route.hosted_file_id() else { return; };
    if exact_pending(identity, irp, file_id).is_none() || pending.reply_cap == 0 { return; }
    let (device, hash, name_len) = {
        let manager = driver_launch::io_manager_mut();
        let Some(canonical_irp) = manager.irp(nt_io_manager::IrpId(irp)) else { return; };
        if canonical_irp.id.raw() != irp || canonical_irp.file_id.map(nt_io_manager::FileId::raw) != Some(file_id)
            || canonical_irp.origin_major != nt_io_abi::major::IRP_MJ_CREATE
            || canonical_irp.requestor_tid != pending.tid { return; }
        let Some(file) = manager.file(nt_io_manager::FileId(file_id)) else { return; };
        if file.device_id != canonical_irp.origin_device_id { return; }
        (file.device_id.raw(), name_fingerprint(file.file_name.as_units()),
            file.file_name.as_units().len() as u64)
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
}
