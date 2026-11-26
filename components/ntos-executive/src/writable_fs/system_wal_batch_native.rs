//! One retained native SYSTEM WAL batch, independent of the row that published CM.
//!
//! A monotonic epoch and exact mount/request identity bind each native command to the
//! physical owner. A refused or uncertain command never permits a replacement owner.

use super::*;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};
use nt_config_client::{
    PreparedSystemHiveMutation, SystemHiveMount, SystemHiveMutationCommitReceipt,
};
use nt_fs::{AsyncWalIoRequest, AsyncWalRefusal, SystemWalBatchError};
use nt_memory_manager::SectionMountId;
use registry_wal::{BatchOwner, BatchReservation};

struct Claimed {
    request: AsyncWalIoRequest,
    entered: bool,
}

#[derive(Clone, Copy)]
enum State {
    Collecting,
    Draining,
    /// Native authority has been released, but the target has not been published as durable.
    Finished {
        target: u64,
    },
    /// The first PREPARE had no physical effect. Keep the exact payload until an explicit retry.
    NoEffectRefused {
        status: u32,
        retry_after_100ns: u64,
    },
    /// An uncertain effect or local contradiction retains the owner without replay.
    Blocked {
        status: u32,
    },
    /// Physical release completed, but publishing the durable high-water contradicted CM.
    PublicationBlocked {
        status: u32,
    },
}

struct Active {
    epoch: u64,
    mount: SectionMountId,
    cm_mount: SystemHiveMount,
    durable_floor: u64,
    owner: BatchOwner,
    claim: Option<Claimed>,
    reservation_outstanding: bool,
    no_effect_retries: u8,
    last_publish_100ns: u64,
    state: State,
}

static NEXT_EPOCH: AtomicU64 = AtomicU64::new(1);
static mut ACTIVE: Option<Active> = None;
const NO_EFFECT_RETRY_DELAY_100NS: u64 = 5 * 10_000_000;
const MAX_NO_EFFECT_RETRIES: u8 = 3;
const IDLE_DRAIN_DELAY_100NS: u64 = 1_000_000;

pub(crate) fn batch_error_status(error: SystemWalBatchError) -> u32 {
    match error {
        SystemWalBatchError::OutOfSpace | SystemWalBatchError::OutOfMemory => {
            nt_fs::STATUS_INSUFFICIENT_RESOURCES
        }
        SystemWalBatchError::Busy => snapshot_storage::BUSY,
        SystemWalBatchError::InvalidGeometry
        | SystemWalBatchError::InvalidJournal
        | SystemWalBatchError::SequenceGap => nt_fs::STATUS_DATA_ERROR,
        SystemWalBatchError::InvalidGeneration
        | SystemWalBatchError::GenerationGap
        | SystemWalBatchError::ReservationMismatch => nt_fs::STATUS_INVALID_DEVICE_REQUEST,
    }
}

fn block(active: &mut Active, status: u32) {
    active.state = State::Blocked { status };
    WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
}

fn exact(active: &Active, epoch: u64, mount: SectionMountId, request: AsyncWalIoRequest) -> bool {
    active.epoch == epoch
        && active.mount == mount
        && active
            .claim
            .as_ref()
            .is_some_and(|claim| claim.request == request)
}

fn idle_drain_due(active: &Active) -> bool {
    matches!(active.state, State::Collecting)
        && !active.reservation_outstanding
        && crate::monotonic_time_100ns().saturating_sub(active.last_publish_100ns)
            >= IDLE_DRAIN_DELAY_100NS
}

/// Install a fully admitted batch. Failure returns the untouched move-only owner to its caller.
///
/// # Safety
/// The executive is single-threaded. The caller must not install another physical reserve
/// owner while this singleton is occupied, including in a blocked or refused state.
pub(crate) unsafe fn install(owner: BatchOwner) -> Result<u64, (u32, BatchOwner)> {
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) };
    if slot.is_some() {
        return Err((snapshot_storage::BUSY, owner));
    }
    let epoch = match NEXT_EPOCH.fetch_update(Ordering::AcqRel, Ordering::Acquire, |next| {
        next.checked_add(1)
    }) {
        Ok(epoch) => epoch,
        Err(_) => return Err((nt_fs::STATUS_INSUFFICIENT_RESOURCES, owner)),
    };
    let mount = owner.mount();
    let cm_mount = owner.cm_mount();
    let durable_floor = owner.published_generation();
    *slot = Some(Active {
        epoch,
        mount,
        cm_mount,
        durable_floor,
        owner,
        claim: None,
        reservation_outstanding: false,
        no_effect_retries: 0,
        last_publish_100ns: crate::monotonic_time_100ns(),
        state: State::Collecting,
    });
    Ok(epoch)
}

/// Observe only a collecting batch at this exact CM mount and preceding generation.
pub(crate) unsafe fn active_epoch_for(prepared: &PreparedSystemHiveMutation) -> Option<u64> {
    let active = unsafe { (&*core::ptr::addr_of!(ACTIVE)).as_ref() }?;
    (matches!(active.state, State::Collecting)
        && active.cm_mount == prepared.mount()
        && active.owner.published_generation() == prepared.expected_generation())
    .then_some(active.epoch)
}

/// True only when draining existing WAL bytes could create a new frame opportunity.
pub(crate) unsafe fn has_collected_entries(epoch: u64) -> bool {
    unsafe { (&*core::ptr::addr_of!(ACTIVE)).as_ref() }.is_some_and(|active| {
        active.epoch == epoch
            && matches!(active.state, State::Collecting)
            && active.owner.has_collected_payload()
    })
}

/// Exact CM mount and both generation horizons while the batch remains retained.
pub(crate) unsafe fn active_generations() -> Option<(SystemHiveMount, u64, u64)> {
    let active = unsafe { (&*core::ptr::addr_of!(ACTIVE)).as_ref() }?;
    Some((
        active.cm_mount,
        active.owner.published_generation(),
        crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire),
    ))
}

/// Bounded, read-only terminal census of the one retained batch.
pub(crate) unsafe fn print_quiesce_owner() {
    let active = unsafe { (&*core::ptr::addr_of!(ACTIVE)).as_ref() };
    print_str(b"[quiesce-system-wal-batch] phase=");
    let Some(active) = active else {
        print_str(b"absent\n");
        return;
    };
    print_str(match active.state {
        State::Collecting => b"collecting",
        State::Draining => b"draining",
        State::Finished { .. } => b"finished",
        State::NoEffectRefused { .. } => b"no-effect-refused",
        State::Blocked { .. } => b"blocked",
        State::PublicationBlocked { .. } => b"publication-blocked",
    });
    print_str(b" epoch=");
    print_u64(active.epoch);
    print_str(b" physical-mount=");
    print_u64(active.mount.value());
    print_str(b" cm-mount=");
    print_u64(active.cm_mount.identity_token());
    print_str(b" published=");
    print_u64(active.owner.published_generation());
    print_str(b" durable=");
    print_u64(crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION.load(Ordering::Acquire));
    print_str(b" claim-entered=");
    print_u64(u64::from(
        active.claim.as_ref().is_some_and(|claim| claim.entered),
    ));
    print_str(b" refusal=0x");
    let refusal = match active.state {
        State::NoEffectRefused { status, .. }
        | State::Blocked { status }
        | State::PublicationBlocked { status } => status,
        _ => 0,
    };
    print_hex(refusal);
    print_str(b"\n");
}

pub(crate) unsafe fn active_mount() -> Option<SystemHiveMount> {
    unsafe { active_generations() }.map(|(mount, _, _)| mount)
}

pub(crate) unsafe fn published_generation() -> Option<u64> {
    unsafe { active_generations() }.map(|(_, published, _)| published)
}

pub(crate) unsafe fn durable_generation() -> Option<u64> {
    unsafe { active_generations() }.map(|(_, _, durable)| durable)
}

pub(crate) unsafe fn reserve(
    epoch: u64,
    prepared: &PreparedSystemHiveMutation,
    bytes: Vec<u8>,
) -> Result<BatchReservation, (SystemWalBatchError, Vec<u8>)> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err((SystemWalBatchError::ReservationMismatch, bytes));
    };
    if active.epoch != epoch || !matches!(active.state, State::Collecting) {
        return Err((SystemWalBatchError::ReservationMismatch, bytes));
    }
    let reservation = active.owner.reserve(prepared, bytes)?;
    active.reservation_outstanding = true;
    Ok(reservation)
}

pub(crate) unsafe fn append_committed(
    epoch: u64,
    reservation: BatchReservation,
    receipt: SystemHiveMutationCommitReceipt,
) -> Result<(), (SystemWalBatchError, BatchReservation)> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err((SystemWalBatchError::ReservationMismatch, reservation));
    };
    if active.epoch != epoch || !matches!(active.state, State::Collecting) {
        return Err((SystemWalBatchError::ReservationMismatch, reservation));
    }
    active.owner.append_committed(reservation, receipt)?;
    active.reservation_outstanding = false;
    active.last_publish_100ns = crate::monotonic_time_100ns();
    Ok(())
}

/// The caller must retain exact pre-COMMIT no-effect evidence or a matching CM abort ACK.
pub(crate) unsafe fn cancel(
    epoch: u64,
    reservation: BatchReservation,
) -> Result<Vec<u8>, (SystemWalBatchError, BatchReservation)> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err((SystemWalBatchError::ReservationMismatch, reservation));
    };
    if active.epoch != epoch || !matches!(active.state, State::Collecting) {
        return Err((SystemWalBatchError::ReservationMismatch, reservation));
    }
    let bytes = active.owner.cancel(reservation)?;
    active.reservation_outstanding = false;
    Ok(bytes)
}

/// Seal after the sole CM slot has settled. The owner remains installed on every refusal.
pub(crate) unsafe fn request_drain(epoch: u64) -> Result<(), u32> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if active.epoch != epoch {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    match active.state {
        State::Collecting => {
            active.owner.request_drain().map_err(batch_error_status)?;
            active.state = State::Draining;
            Ok(())
        }
        State::Draining | State::Finished { .. } => Ok(()),
        State::NoEffectRefused { status, .. }
        | State::Blocked { status }
        | State::PublicationBlocked { status } => Err(status),
    }
}

/// Flush, fold, and checkpoint fences can request the active batch without a copied epoch.
pub(crate) unsafe fn request_drain_if_active() -> Result<(), u32> {
    let Some(epoch) =
        (unsafe { (&*core::ptr::addr_of!(ACTIVE)).as_ref() }).map(|active| active.epoch)
    else {
        return Ok(());
    };
    unsafe { request_drain(epoch) }
}

fn advance(active: &mut Active) -> Result<Option<u64>, u32> {
    if active.claim.is_some() {
        return Err(snapshot_storage::BUSY);
    }
    match active.state {
        State::Collecting => Ok(None),
        State::Finished { target } => Ok(Some(target)),
        State::NoEffectRefused { status, .. }
        | State::Blocked { status }
        | State::PublicationBlocked { status } => Err(status),
        State::Draining => match active.owner.advance_drain() {
            Ok(target) => {
                active.state = State::Finished { target };
                Ok(Some(target))
            }
            Err(status)
                if status == snapshot_storage::BUSY
                    || status == nt_fs::STATUS_INSUFFICIENT_RESOURCES =>
            {
                Err(status)
            }
            Err(status) => Err(block_and_return(active, status)),
        },
    }
}

fn block_and_return(active: &mut Active, status: u32) -> u32 {
    block(active, status);
    status
}

/// Drive retained PREPARE, marker, both anchors, and physical release. Some(target) remains
/// held until `finish_durable` atomically publishes the durable generation.
pub(crate) unsafe fn drive(epoch: u64) -> Result<Option<u64>, u32> {
    let progressed = {
        let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        };
        if active.epoch != epoch {
            return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
        }
        advance(active)?
    };
    match progressed {
        Some(target) => {
            unsafe { finish_durable(epoch, target) }?;
            Ok(Some(target))
        }
        None => Ok(None),
    }
}

/// Publish the generation only after the physical owner has finished both anchors. This
/// terminal acknowledgement is the sole path that removes the singleton batch slot.
pub(crate) unsafe fn finish_durable(epoch: u64, target: u64) -> Result<(), u32> {
    let slot = unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) };
    let Some(active) = slot.as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if active.epoch != epoch || !matches!(active.state, State::Finished { .. }) {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    if active.claim.is_some()
        || !matches!(active.state, State::Finished { target: finished } if finished == target)
        || crate::LIVE_CONFIG_MANAGER_SYSTEM_MOUNT != Some(active.cm_mount)
        || crate::LIVE_CONFIG_MANAGER_SYSTEM_PUBLISHED_GENERATION.load(Ordering::Acquire) != target
    {
        let status = nt_fs::STATUS_DATA_ERROR;
        active.state = State::PublicationBlocked { status };
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        print_str(b"[system-wal-batch] durable-publication-contradiction status=0x");
        print_hex(status);
        print_str(b"\n");
        return Err(status);
    }
    let previous = active.durable_floor;
    if crate::LIVE_CONFIG_MANAGER_SYSTEM_GENERATION
        .compare_exchange(previous, target, Ordering::AcqRel, Ordering::Acquire)
        .is_err()
    {
        let status = 0xC000_0059u32;
        active.state = State::PublicationBlocked { status };
        WRITABLE_FS_SNAPSHOT_MOUNT_BLOCKED.store(true, Ordering::Release);
        print_str(b"[system-wal-batch] durable-generation-changed status=0x");
        print_hex(status);
        print_str(b"\n");
        return Err(status);
    }
    if target > previous {
        crate::boot_progress::note_boot_progress(
            crate::boot_progress::BootProgress::DurableRegistryPublication,
        );
    }
    let _finished = slot.take();
    Ok(())
}

/// Only a proven no-effect first PREPARE can be explicitly retried after its refusal cause
/// has been corrected. Entered or uncertain requests have no retry path.
pub(crate) unsafe fn retry_no_effect(epoch: u64) -> Result<(), u32> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if active.epoch != epoch
        || active.claim.is_some()
        || !matches!(active.state, State::NoEffectRefused { .. })
    {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.state = State::Draining;
    Ok(())
}

pub(crate) unsafe fn holds_reserve() -> bool {
    // Even after physical release, Finished must exclude a new SYSTEM mutation until
    // its target generation is published as durable and the singleton is removed.
    unsafe { (&*core::ptr::addr_of!(ACTIVE)).is_some() }
}

pub(crate) unsafe fn outer_io_queued() -> bool {
    let Some(active) = (unsafe { (&*core::ptr::addr_of!(ACTIVE)).as_ref() }) else {
        return false;
    };
    if active.claim.is_some() {
        return false;
    }
    match active.state {
        State::Collecting => idle_drain_due(active),
        State::Draining | State::Finished { .. } => true,
        State::NoEffectRefused {
            retry_after_100ns, ..
        } => crate::monotonic_time_100ns() >= retry_after_100ns,
        _ => false,
    }
}

/// Advance a draining batch before claiming its next physical command. The claim is retained
/// here until exact release, refusal, or provider terminal plus ACK.
pub(crate) unsafe fn claim_next() -> Option<native_snapshot_io::SnapshotClaim> {
    let _durable = crate::allocator::enter_durable();
    let completed = {
        let active = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut()?;
        if active.claim.is_some() {
            return None;
        }
        if idle_drain_due(active) {
            match active.owner.request_drain() {
                Ok(()) => active.state = State::Draining,
                Err(SystemWalBatchError::Busy) => return None,
                Err(error) => {
                    block(active, batch_error_status(error));
                    return None;
                }
            }
        }
        if let State::NoEffectRefused {
            retry_after_100ns, ..
        } = active.state
        {
            if crate::monotonic_time_100ns() >= retry_after_100ns {
                active.state = State::Draining;
            }
        }
        if !matches!(active.state, State::Draining | State::Finished { .. }) {
            return None;
        }
        match advance(active) {
            Ok(Some(target)) => Some((active.epoch, target)),
            _ => None,
        }
    };
    if let Some((epoch, target)) = completed {
        // Both anchors have settled and no more native request will wake the pump.
        let _ = unsafe { finish_durable(epoch, target) };
        return None;
    }
    let active = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut()?;
    if !matches!(active.state, State::Draining) || !active.owner.native_io_active() {
        return None;
    }
    match active.owner.claim_native_io() {
        Ok(Some((request, operation, input))) => {
            active.claim = Some(Claimed {
                request,
                entered: false,
            });
            Some(native_snapshot_io::SnapshotClaim::from_system_batch(
                active.mount,
                operation,
                input,
                active.epoch,
                request,
            ))
        }
        Ok(None) => None,
        Err(status)
            if status == snapshot_storage::BUSY
                || status == nt_fs::STATUS_INSUFFICIENT_RESOURCES =>
        {
            None
        }
        Err(status) => {
            block(active, status);
            None
        }
    }
}

pub(crate) unsafe fn mark_entered(
    epoch: u64,
    mount: SectionMountId,
    request: AsyncWalIoRequest,
) -> Result<(), u32> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if !exact(active, epoch, mount, request)
        || !matches!(active.state, State::Draining)
        || active.claim.as_ref().is_some_and(|claim| claim.entered)
    {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.owner.mark_native_io_entered(request)?;
    if let Some(claim) = active.claim.as_mut() {
        claim.entered = true;
    }
    Ok(())
}

pub(crate) unsafe fn release_unentered(
    epoch: u64,
    mount: SectionMountId,
    request: AsyncWalIoRequest,
) -> Result<(), u32> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if !exact(active, epoch, mount, request)
        || active.claim.as_ref().is_some_and(|claim| claim.entered)
    {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    active.owner.release_unentered_native_io(request)?;
    active.claim = None;
    Ok(())
}

pub(crate) unsafe fn refuse_unentered(
    epoch: u64,
    mount: SectionMountId,
    request: AsyncWalIoRequest,
    status: nt_status::NtStatus,
) -> Result<(), u32> {
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if !exact(active, epoch, mount, request)
        || active.claim.as_ref().is_some_and(|claim| claim.entered)
    {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    match active.owner.refuse_unentered_native_io(request) {
        Ok(AsyncWalRefusal::NoEffect) => {
            active.claim = None;
            active.no_effect_retries = active.no_effect_retries.saturating_add(1);
            if active.no_effect_retries > MAX_NO_EFFECT_RETRIES {
                block(active, status.0 as u32);
            } else {
                active.state = State::NoEffectRefused {
                    status: status.0 as u32,
                    retry_after_100ns: crate::monotonic_time_100ns()
                        .saturating_add(NO_EFFECT_RETRY_DELAY_100NS),
                };
            }
        }
        Ok(AsyncWalRefusal::RetainedEffects) | Err(_) => {
            block(active, status.0 as u32);
        }
    }
    Ok(())
}

/// Invalid or stale tokens fail without touching the current owner. A failed exact terminal
/// blocks this owner's physical lease and preserves its claim for diagnosis.
pub(crate) unsafe fn complete(
    epoch: u64,
    mount: SectionMountId,
    request: AsyncWalIoRequest,
    result: Result<&[u8], nt_status::NtStatus>,
) -> Result<native_snapshot_io::SnapshotCompletion, u32> {
    use native_snapshot_io::SnapshotCompletion;
    let Some(active) = (unsafe { &mut *core::ptr::addr_of_mut!(ACTIVE) }).as_mut() else {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    };
    if !exact(active, epoch, mount, request)
        || !matches!(active.state, State::Draining)
        || !active.claim.as_ref().is_some_and(|claim| claim.entered)
    {
        return Err(nt_fs::STATUS_INVALID_DEVICE_REQUEST);
    }
    match active.owner.complete_native_io(request, result) {
        Ok(SnapshotCompletion::Settled) => {
            active.claim = None;
            Ok(SnapshotCompletion::Settled)
        }
        Ok(SnapshotCompletion::Failed(status)) | Err(status) => {
            block(active, status);
            Ok(SnapshotCompletion::Failed(status))
        }
    }
}
