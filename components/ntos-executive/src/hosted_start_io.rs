//! Root-owned StartIo packet, queue, callback and source lifetime transport.

use super::*;
use nt_io_manager::device_queue::{
    DeviceQueueEdits, DeviceQueueEntrySnapshot, DeviceQueueSnapshot, DeviceQueueWrite,
    LockedDeviceQueueMemory,
};
use nt_io_manager::start_io::{self, CurrentPacketRelation, Device, LockedStartIoMemory, Packet};
use nt_io_manager::start_io_current::{CompletionObservation, CurrentPhase, CurrentReceipt, LivePacket};
use nt_io_manager::start_io_native_owner::{PendingStartIoNodeIdentity, StartIoSourcePin};
use nt_io_manager::source_irp_ledger::SourceIrpForwardIdentity;
use nt_io_manager::start_io_native_transaction::{StartIoCallbackFence, StartIoTransactionId};
use nt_io_manager::start_io_queued::QueuedStartIo;

#[path = "hosted_start_io_packet.rs"]
mod packet;

/// Exact pre-effect owners for an op6-projected first packet. This does not enqueue or invoke
/// StartIo. The eventual native callback transaction must consume these owners under the queue
/// lock and retain them across its uncertain Reply and terminal completion.
#[must_use = "retain the exact packet and device owners until native callback integration"]
struct PreparedFirstProjectedPacket {
    instance_index: usize,
    instance: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    node: PendingStartIoNodeIdentity,
    current: CurrentReceipt<nt_io_manager::HostedDeviceProjectionReference, StartIoSourcePin>,
    incoming: LivePacket<StartIoSourcePin>,
}

impl PreparedFirstProjectedPacket {
    fn source_identity(&self) -> SourceIrpForwardIdentity { self.incoming.identity() }
}

#[must_use = "retain a refused no-effect owner until checked local release"]
enum FirstPacketReleaseRefusal {
    NotEmpty(PreparedFirstProjectedPacket),
    Owners {
        registration: nt_io_manager::HostedDevicePointerRegistration,
        identity: SourceIrpForwardIdentity,
        device: nt_io_manager::HostedDeviceProjectionReference,
        source: StartIoSourcePin,
    },
}

/// Only a proven no-effect refusal may enter this release path. An uncertain queue write or
/// foreign Reply must stay in the committed transaction instead.
fn release_prepared_first_packet(
    prepared: PreparedFirstProjectedPacket,
) -> Result<(), FirstPacketReleaseRefusal> {
    let PreparedFirstProjectedPacket {
        instance_index, instance, registration, node, current, incoming,
    } = prepared;
    let device = match current.into_empty_owner() {
        Ok(device) => device,
        Err(current) => return Err(FirstPacketReleaseRefusal::NotEmpty(
            PreparedFirstProjectedPacket { instance_index, instance, registration, node, current, incoming },
        )),
    };
    let identity = incoming.identity();
    let source = incoming.into_owner();
    let mut refused = FirstPacketReleaseRefusal::Owners {
        registration, identity, device, source,
    };
    if retry_first_packet_release(&mut refused).is_err() { return Err(refused); }
    Ok(())
}

fn retry_first_packet_release(refused: &mut FirstPacketReleaseRefusal) -> Result<(), i32> {
    let FirstPacketReleaseRefusal::Owners {
        registration, identity, device, source,
    } = refused else { return Err(STATUS_INVALID_HANDLE); };
    hosted_source_irp_ledger::release_projected_start_io_packet(
        *registration, *identity, device, source,
    )
}

type FirstPacketOwner = StartIoCallbackFence<
    StartIoSourcePin, nt_io_manager::HostedDeviceProjectionReference,
>;

struct FirstPacketCurrentSlot {
    registration: nt_io_manager::HostedDevicePointerRegistration,
    node: PendingStartIoNodeIdentity,
    current: CurrentReceipt<nt_io_manager::HostedDeviceProjectionReference, StartIoSourcePin>,
}

struct FirstPacketTransaction {
    id: StartIoTransactionId,
    node: PendingStartIoNodeIdentity,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    callback_target: u64,
    source: SourceIrpForwardIdentity,
    owner: FirstPacketOwnerState,
    terminal_pin: Option<StartIoSourcePin>,
    next_performed: bool,
}

/// A WDM insertion owns the exact physical source and projection independently of CurrentIrp.
/// The intrusive queue, never this receipt vector's order, chooses a later packet.
struct QueuedPacketOwner {
    instance_index: usize,
    instance: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    node: PendingStartIoNodeIdentity,
    device: nt_io_manager::HostedDeviceProjectionReference,
    source: StartIoSourcePin,
    callback: nt_io_manager::HostedDeviceProjectionReference,
}

struct QueuedPacketTransaction {
    source: SourceIrpForwardIdentity,
    owner: QueuedPacketState,
    source_released: bool,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    node: PendingStartIoNodeIdentity,
}

enum QueuedPacketState {
    Linked(QueuedStartIo<QueuedPacketOwner>),
    Unlinked(QueuedPacketOwner),
    Vacant,
}

enum FirstPacketOwnerState {
    Committed(FirstPacketOwner),
    Completed {
        callback: nt_io_manager::HostedDeviceProjectionReference,
    },
    Vacant,
}

static FIRST_PACKET_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static FIRST_PACKET_LOCK: AtomicU64 = AtomicU64::new(0);
static mut FIRST_PACKET_TRANSACTIONS: Option<Vec<FirstPacketTransaction>> = None;
static mut FIRST_PACKET_CURRENT: Option<Vec<FirstPacketCurrentSlot>> = None;
static mut FIRST_PACKET_QUEUED: Option<Vec<QueuedPacketTransaction>> = None;
static FIRST_PACKET_CLEANUP_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static mut FIRST_PACKET_CLEANUP: Option<Vec<FirstPacketCleanupRow>> = None;

struct FirstPacketCleanupRow {
    id: u64,
    refused: Option<FirstPacketCommitReleaseRefusal>,
}

pub(super) struct FirstPacketGuard;
impl Drop for FirstPacketGuard {
    fn drop(&mut self) { FIRST_PACKET_LOCK.store(0, Ordering::Release); }
}

pub(super) fn lock_first_packets() -> FirstPacketGuard {
    while FIRST_PACKET_LOCK.compare_exchange_weak(
        0, 1, Ordering::Acquire, Ordering::Relaxed,
    ).is_err() { crate::yield_now(); }
    FirstPacketGuard
}

fn first_packet_transactions() -> &'static mut Vec<FirstPacketTransaction> {
    // Every caller holds FIRST_PACKET_LOCK; no reference crosses a callback or foreign Reply.
    unsafe { (&mut *core::ptr::addr_of_mut!(FIRST_PACKET_TRANSACTIONS)).get_or_insert_with(Vec::new) }
}

fn first_packet_current() -> &'static mut Vec<FirstPacketCurrentSlot> {
    // Every caller holds FIRST_PACKET_LOCK; one exact registration owns the CurrentIrp receipt.
    unsafe { (&mut *core::ptr::addr_of_mut!(FIRST_PACKET_CURRENT)).get_or_insert_with(Vec::new) }
}

fn first_packet_queued() -> &'static mut Vec<QueuedPacketTransaction> {
    // Every caller holds FIRST_PACKET_LOCK. The WDM queue itself remains selection authority.
    unsafe { (&mut *core::ptr::addr_of_mut!(FIRST_PACKET_QUEUED)).get_or_insert_with(Vec::new) }
}

fn first_packet_cleanup() -> &'static mut Vec<FirstPacketCleanupRow> {
    // Every caller holds FIRST_PACKET_LOCK. A reserved row exists before admission can obtain
    // any source/device owner, so a later local cleanup refusal never needs fresh allocation.
    unsafe { (&mut *core::ptr::addr_of_mut!(FIRST_PACKET_CLEANUP)).get_or_insert_with(Vec::new) }
}

fn retry_first_packet_cleanup_locked() -> usize {
    let rows = first_packet_cleanup();
    let mut index = 0;
    let mut progress = 0;
    while index < rows.len() {
        let Some(refused) = rows[index].refused.take() else {
            index += 1;
            continue;
        };
        let result = match refused {
            FirstPacketCommitReleaseRefusal::Callback(refused) =>
                release_first_packet_commit_refusal(refused),
            FirstPacketCommitReleaseRefusal::Packet(mut refused) =>
                retry_first_packet_release(&mut refused)
                    .map_err(|_| FirstPacketCommitReleaseRefusal::Packet(refused)),
            FirstPacketCommitReleaseRefusal::Device(mut device) =>
                device.release(io_manager_mut())
                    .map_err(|_| FirstPacketCommitReleaseRefusal::Device(device)),
        };
        match result {
            Ok(()) => { rows.swap_remove(index); progress += 1; }
            Err(refused) => { rows[index].refused = Some(refused); index += 1; }
        }
    }
    progress
}

fn reserve_first_packet_cleanup() -> Result<u64, i32> {
    let _guard = lock_first_packets();
    let _ = retry_first_packet_cleanup_locked();
    let rows = first_packet_cleanup();
    rows.try_reserve(1).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    let id = FIRST_PACKET_CLEANUP_NEXT_ID.fetch_update(
        Ordering::Relaxed, Ordering::Relaxed,
        |value| value.checked_add(1).filter(|next| *next != 0),
    ).map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    rows.push(FirstPacketCleanupRow { id, refused: None });
    Ok(id)
}

fn finish_first_packet_cleanup(
    id: u64,
    refused: Option<FirstPacketCommitReleaseRefusal>,
) {
    let _guard = lock_first_packets();
    let rows = first_packet_cleanup();
    let index = rows.iter().position(|row| row.id == id)
        .expect("reserved first packet cleanup row disappeared");
    if let Some(refused) = refused {
        rows[index].refused = Some(refused);
    } else {
        rows.swap_remove(index);
    }
}

#[must_use = "retain any no-effect StartIo owner until checked local release"]
struct FirstPacketCommitRefusal {
    prepared: PreparedFirstProjectedPacket,
    callback_owner: Option<nt_io_manager::HostedDeviceProjectionReference>,
}

#[must_use = "retain the no-effect owner until checked local release succeeds"]
enum FirstPacketCommitReleaseRefusal {
    Callback(FirstPacketCommitRefusal),
    Packet(FirstPacketReleaseRefusal),
    Device(nt_io_manager::HostedDeviceProjectionReference),
}

fn release_first_packet_commit_refusal(
    mut refused: FirstPacketCommitRefusal,
) -> Result<(), FirstPacketCommitReleaseRefusal> {
    if let Some(callback) = refused.callback_owner.as_mut() {
        if callback.is_held() && callback.release(io_manager_mut()).is_err() {
            return Err(FirstPacketCommitReleaseRefusal::Callback(refused));
        }
    }
    release_prepared_first_packet(refused.prepared)
        .map_err(FirstPacketCommitReleaseRefusal::Packet)
}

/// Reserve all root ownership before the local queue write. A successful return leaves the
/// CurrentIrp, source pin, projection and callback image pin in the root transaction table.
/// No Reply or callback is issued here; that separate edge must use begin_first_packet_reply.
fn commit_first_projected_packet(
    prepared: PreparedFirstProjectedPacket,
) -> Result<(Option<StartIoTransactionId>,
    Option<nt_io_manager::HostedDeviceProjectionReference>), FirstPacketCommitRefusal> {
    let _guard = lock_first_packets();
    if first_packet_transactions().try_reserve(1).is_err()
        || first_packet_queued().try_reserve(1).is_err()
        || first_packet_current().try_reserve(1).is_err()
    {
        return Err(FirstPacketCommitRefusal { prepared, callback_owner: None });
    }
    let serial = match FIRST_PACKET_NEXT_ID.fetch_update(
        Ordering::Relaxed, Ordering::Relaxed,
        |value| value.checked_add(1).filter(|next| *next != 0),
    ) {
        Ok(serial) => serial,
        Err(_) => return Err(FirstPacketCommitRefusal { prepared, callback_owner: None }),
    };
    let id = StartIoTransactionId::new(serial, prepared.node.generation)
        .expect("admitted pending node has a nonzero generation");
    let mut callback_owner = match io_manager_mut()
        .retain_hosted_device_projection_reference(prepared.registration)
    {
        Ok(owner) => owner,
        Err(_) => return Err(FirstPacketCommitRefusal { prepared, callback_owner: None }),
    };
    let committed = match packet::commit_first_projected_packet(prepared) {
        Ok(committed) => committed,
        Err(prepared) => {
            if callback_owner.release(io_manager_mut()).is_err() {
                return Err(FirstPacketCommitRefusal {
                    prepared, callback_owner: Some(callback_owner),
                });
            }
            return Err(FirstPacketCommitRefusal { prepared, callback_owner: None });
        }
    };
    let committed = match committed {
        packet::PacketCommit::Queued(prepared) => {
            let PreparedFirstProjectedPacket {
                instance_index, instance, registration, node, current, incoming,
            } = prepared;
            let identity = incoming.identity();
            let device = current.into_empty_owner()
                .unwrap_or_else(|_| panic!("queued StartIo unexpectedly acquired CurrentIrp"));
            let owner = QueuedPacketOwner {
                instance_index, instance, registration, node,
                device, source: incoming.into_owner(), callback: callback_owner,
            };
            first_packet_queued().push(QueuedPacketTransaction {
                source: identity, owner: QueuedPacketState::Linked(
                    QueuedStartIo::new(identity, owner)), source_released: false,
                registration, node,
            });
            return Ok((None, None));
        }
        packet::PacketCommit::Started(committed) => committed,
    };
    let stale_device = if let Some(slot) = first_packet_current().iter_mut()
        .find(|slot| slot.registration == committed.registration)
    {
        slot.node = committed.node;
        let old = core::mem::replace(&mut slot.current, committed.current);
        Some(old.into_empty_owner().unwrap_or_else(|_|
            panic!("idle first-packet slot retained an unconsumed current")))
    } else {
        first_packet_current().push(FirstPacketCurrentSlot {
            registration: committed.registration, node: committed.node, current: committed.current,
        });
        None
    };
    let owner = StartIoCallbackFence::new(committed.identity, id, callback_owner);
    first_packet_transactions().push(FirstPacketTransaction {
        id, node: committed.node, registration: committed.registration,
        callback_target: committed.callback_target, source: committed.identity,
        owner: FirstPacketOwnerState::Committed(owner), terminal_pin: None,
        next_performed: false,
    });
    Ok((Some(id), stale_device))
}

/// Mark Reply uncertain before yielding its scalar callback command. A lost or failed Reply
/// outcome cannot re-enter this operation or repeat the WDM queue commit.
fn begin_first_packet_reply(id: StartIoTransactionId) -> Result<(u64, u64, u64), i32> {
    let _guard = lock_first_packets();
    let row = first_packet_transactions().iter_mut().find(|row| row.id == id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let FirstPacketOwnerState::Committed(owner) = &mut row.owner else {
        return Err(STATUS_INVALID_HANDLE);
    };
    owner.begin_reply().map_err(|_| STATUS_INVALID_HANDLE)?;
    Ok((row.callback_target, row.registration.address(), row.source.allocation().component_address))
}

/// Callback return does not retire the source IRP. The independent terminal completion hook is
/// still required before the transaction may release any physical or callback image owner.
fn first_packet_callback_returned(id: StartIoTransactionId) -> Result<(), i32> {
    let _guard = lock_first_packets();
    let index = first_packet_transactions().iter().position(|row| row.id == id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let FirstPacketOwnerState::Committed(owner) = &mut first_packet_transactions()[index].owner else {
        return Err(STATUS_INVALID_HANDLE);
    };
    owner.callback_returned(id).map_err(|_| STATUS_INVALID_HANDLE)?;
    // Callback return is now committed. A checked local cleanup refusal leaves the row in
    // Completed state for retry and must not be presented as a failed callback observation.
    let _ = settle_first_packet(index);
    Ok(())
}

/// Called only after the root caller-projection service has validated a CONSUMING node with a
/// published terminal completion. Its exact ticket and generation fence the source pin release
/// before the component attempts graph retirement.
pub(super) fn observe_terminal_before_retirement(
    ledger: &mut nt_io_manager::source_irp_ledger::SourceIrpLedger,
    observed: PendingStartIoNodeIdentity,
) -> Result<(), i32> {
    // The source service acquired FIRST_PACKET_LOCK before its source/pool guards. Reacquiring
    // here would deadlock and reversing that order would race the WDM queue publication.
    if let Some(row) = first_packet_queued().iter().find(|row| {
        row.node.source == observed.source && row.node.raw_irp == observed.raw_irp
    }) {
        if !row.node.matches(observed) { return Err(STATUS_INVALID_HANDLE); }
        return if row.source_released { Ok(()) }
            else { Err(nt_status::NtStatus::DELETE_PENDING.raw()) };
    }
    let Some(index) = first_packet_transactions().iter().position(|row| {
        row.source.ticket() == observed.source
            && row.source.allocation().component_address == observed.raw_irp
    }) else { return Ok(()); };
    let row = &mut first_packet_transactions()[index];
    if !row.node.matches(observed) {
        return Err(STATUS_INVALID_HANDLE);
    }
    if let FirstPacketOwnerState::Committed(owner) = &mut row.owner {
        if !owner.terminal_observed() {
            owner.observe_terminal(row.source).map_err(|_| STATUS_INVALID_HANDLE)?;
        }
        // The callback can still read this IRP after IoCompleteRequest. Refuse before moving
        // the source pin out of the per-device current or displaced owner.
        if owner.phase() != nt_io_manager::start_io_native_transaction::ReplyPhase::CallbackReturned {
            return Err(nt_status::NtStatus::DELETE_PENDING.raw());
        }
        if !owner.source_retained() {
            let slot = first_packet_current().iter_mut()
                .find(|slot| slot.registration == row.registration)
                .ok_or(STATUS_INVALID_HANDLE)?;
            let packet = slot.current.observe_completion(
                row.registration, row.source, CompletionObservation::Acknowledged,
            ).map_err(|_| STATUS_INVALID_HANDLE)?
                .ok_or(STATUS_INVALID_HANDLE)?;
            owner.retain_source(packet)
                .unwrap_or_else(|_| panic!("exact StartIo source transfer refused after observation"));
        }
        let old = core::mem::replace(&mut row.owner, FirstPacketOwnerState::Vacant);
        let FirstPacketOwnerState::Committed(owner) = old else { unreachable!() };
        let (pin, callback) = match owner.finish() {
            Ok(owners) => owners,
            Err(owner) => {
                row.owner = FirstPacketOwnerState::Committed(owner);
                return Err(STATUS_INVALID_HANDLE);
            }
        };
        row.terminal_pin = Some(pin.into_owner());
        row.owner = FirstPacketOwnerState::Completed { callback };
    }
    if let Some(pin) = row.terminal_pin.as_mut() {
        pin.release(ledger).map_err(|_| STATUS_INVALID_HANDLE)?;
        row.terminal_pin = None;
    }
    // A completion poll can invoke this while IoManager itself is borrowed to pump backends.
    // Retain the completed row for the separate checked cleanup drain after that pump returns.
    Ok(())
}

/// Called only from the READY→COPYING poll claim while FIRST→source→pool are held. WDM unlink
/// commits once, then the row changes to Unlinked before checked source release. A refused
/// release is retried from Unlinked without touching the queue again.
pub(super) fn settle_queued_terminal_locked(
    ledger: &mut nt_io_manager::source_irp_ledger::SourceIrpLedger,
    instance_index: usize,
    inst: DriverInstance,
    observed: PendingStartIoNodeIdentity,
) -> Result<bool, i32> {
    let Some(index) = first_packet_queued().iter().position(|row| {
        row.node.source == observed.source && row.node.raw_irp == observed.raw_irp
    }) else { return Ok(false); };
    if !first_packet_queued()[index].node.matches(observed)
        || first_packet_queued()[index].source.ticket() != observed.source
    { return Err(STATUS_INVALID_HANDLE); }
    if matches!(&first_packet_queued()[index].owner, QueuedPacketState::Linked(_)) {
        let registration = first_packet_queued()[index].registration;
        packet::unlink_queued_terminal_locked(instance_index, inst, registration, observed)?;
        let row = &mut first_packet_queued()[index];
        let old = core::mem::replace(&mut row.owner, QueuedPacketState::Vacant);
        let QueuedPacketState::Linked(receipt) = old else { unreachable!() };
        let owner = receipt.unlink_terminal(row.source)
            .unwrap_or_else(|_| panic!("committed WDM unlink lost exact queued receipt"));
        row.owner = QueuedPacketState::Unlinked(owner);
    }
    let row = &mut first_packet_queued()[index];
    if !row.source_released {
        let QueuedPacketState::Unlinked(owner) = &mut row.owner else {
            return Err(STATUS_INVALID_HANDLE);
        };
        owner.source.release(ledger).map_err(|_| STATUS_INVALID_HANDLE)?;
        row.source_released = true;
    }
    Ok(true)
}

/// Convert and release only when callback return and exact terminal completion were both seen.
/// Any refused checked local release stays in the row for a later settlement attempt.
fn settle_first_packet(index: usize) -> Result<(), i32> {
    let row = &mut first_packet_transactions()[index];
    if row.terminal_pin.is_some() {
        return Ok(());
    }
    let FirstPacketOwnerState::Completed { callback } = &mut row.owner else { return Ok(()); };
    if callback.is_held() { callback.release(io_manager_mut()).map_err(|status| status.raw())?; }
    first_packet_transactions().swap_remove(index);
    Ok(())
}

/// Called by the root completion pump independently of any later packet request. It retries
/// only checked local releases; it never replays a WDM queue write or callback Reply.
pub(super) fn drain_cleanup() -> usize {
    let _guard = lock_first_packets();
    let mut progress = retry_first_packet_cleanup_locked();
    let mut index = 0;
    while index < first_packet_transactions().len() {
        let before = first_packet_transactions().len();
        let _ = settle_first_packet(index);
        if first_packet_transactions().len() < before {
            progress += 1;
        } else {
            index += 1;
        }
    }
    let mut index = 0;
    while index < first_packet_queued().len() {
        let row = &mut first_packet_queued()[index];
        if !row.source_released {
            index += 1;
            continue;
        }
        let QueuedPacketState::Unlinked(owner) = &mut row.owner else {
            index += 1;
            continue;
        };
        if owner.device.is_held() && owner.device.release(io_manager_mut()).is_err() {
            index += 1;
            continue;
        }
        if owner.callback.is_held() && owner.callback.release(io_manager_mut()).is_err() {
            index += 1;
            continue;
        }
        first_packet_queued().swap_remove(index);
        progress += 1;
    }
    let mut index = 0;
    while index < first_packet_current().len() {
        let registration = first_packet_current()[index].registration;
        let idle = first_packet_current()[index].current.snapshot().phase == CurrentPhase::Empty
            && !first_packet_transactions().iter().any(|row| row.registration == registration)
            && !first_packet_queued().iter().any(|row| row.registration == registration);
        if !idle {
            index += 1;
            continue;
        }
        let device = first_packet_current()[index].current.empty_owner_mut()
            .expect("idle current receipt has no packet");
        if device.is_held() && device.release(io_manager_mut()).is_err() {
            index += 1;
            continue;
        }
        first_packet_current().swap_remove(index);
        progress += 1;
    }
    progress
}

/// Admit from the root's own pending-node row and physical source ledger, never from component
/// bytes alone. No queue or callback effect is performed by this preparatory slice.
fn prepare_first_projected_packet(
    ch: &crate::spawn_hosts::PumpChannel,
    device: u64,
    observed: PendingStartIoNodeIdentity,
    active_reply_cap: u64,
) -> Result<PreparedFirstProjectedPacket, i32> {
    let (index, inst, device_id) = authenticated_hosted_device(ch, device, active_reply_cap)
        .map_err(|status| status.raw())?;
    let domain = instance_domain_identity(inst).ok_or(STATUS_INVALID_HANDLE)?;
    let registration = hosted_device_pointer_registration(domain, device, device_id)
        .map_err(|status| status.raw())?;
    if hosted_device_allocations::registration(inst, device) != Ok(Some(registration)) {
        return Err(STATUS_INVALID_HANDLE);
    }
    let admitted = hosted_source_irp_ledger::admit_projected_start_io_packet(
        index, inst, observed, registration,
    )?;
    let identity = admitted.source_identity();
    let (device_owner, source_owner) = admitted.into_owners();
    Ok(PreparedFirstProjectedPacket {
        instance_index: index,
        instance: inst,
        registration,
        node: observed,
        current: CurrentReceipt::new(registration, identity.allocation().domain, device_owner),
        incoming: LivePacket::new(identity, source_owner),
    })
}

/// Select only a live op6 pending node for the exact raw IRP. Its address is an untrusted
/// selector at the service boundary; root reconstructs and revalidates its generation/ticket.
unsafe fn component_first_packet_node(irp: u64) -> Option<u64> {
    let mut node = (&*pending_irp_head(FSD_DATA_VADDR).cast::<AtomicU64>()).load(Ordering::Acquire);
    for _ in 0..POOL_FREE_LIST_MAX {
        if node == 0 { return None; }
        if !pending_irp_node_valid(node) { return None; }
        let identity = pending_irp_start_io_identity(node);
        if identity.is_some_and(|identity| {
            identity.raw_irp == irp
                && hosted_irp_state_kind(pending_irp_owner_state(node).load(Ordering::Acquire))
                    == HOSTED_IRP_DISPATCHING
        }) {
            return Some(node);
        }
        node = read_volatile(node as *const u64);
    }
    None
}

pub(super) extern "win64" fn s_io_start_packet(
    device: u64,
    irp: u64,
    key: u64,
    cancel: u64,
) {
    unsafe {
        if key != 0 || cancel != 0 {
            crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_START_PACKET, device, key, cancel]);
        }
        let Some(node) = component_first_packet_node(irp) else {
            crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_START_PACKET, device, irp, 0]);
        };
        let (words, status, callback, serial, generation) = call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_START_PACKET,
            device,
            irp,
            node,
        );
        if words != 4 || status != STATUS_SUCCESS as u32 as u64
            || (callback == 0 && (serial != 0 || generation != 0))
            || (callback != 0 && (serial == 0 || generation == 0))
        {
            crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_START_PACKET, device, status, words]);
        }
        if callback == 0 { return; }
        call_hosted_pe(callback, &[device, irp]);
        let (words, status, rest0, rest1, rest2) = call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_START_PACKET_CALLBACK_RETURNED,
            serial,
            generation,
            irp,
        );
        if words != 4 || status != STATUS_SUCCESS as u32 as u64
            || rest0 != 0 || rest1 != 0 || rest2 != 0
        {
            crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_START_PACKET_CALLBACK_RETURNED, irp, status, words]);
        }
    }
}

pub(super) extern "win64" fn s_io_start_next_packet(device: u64, cancelable: u8) {
    unsafe {
        let (words, status, callback, serial, selected_irp) = call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_START_NEXT_PACKET,
            device,
            u64::from(cancelable),
            0,
        );
        if words != 4 || status != STATUS_SUCCESS as u32 as u64 {
            crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_START_NEXT_PACKET, device, status, words]);
        }
        if callback == 0 && serial == 0 && selected_irp == 0 { return; }
        if callback == 0 || serial == 0 || selected_irp == 0 {
            crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_START_NEXT_PACKET, device, serial, selected_irp]);
        }
        let start_io: extern "win64" fn(u64, u64) = core::mem::transmute(callback);
        start_io(device, selected_irp);
        let (words, status, rest0, rest1, rest2) = call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_START_NEXT_PACKET_CALLBACK_RETURNED,
            serial, selected_irp, device,
        );
        if words != 4 || status != STATUS_SUCCESS as u32 as u64
            || rest0 != 0 || rest1 != 0 || rest2 != 0
        {
            crate::provider_bugcheck::report(0xc4,
                [HOSTED_DEVICE_OP_START_NEXT_PACKET_CALLBACK_RETURNED, selected_irp, status, words]);
        }
    }
}

pub(super) fn service_start_next_packet(
    ch: &crate::spawn_hosts::PumpChannel,
    device: u64,
    cancelable: u64,
    reserved: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    if cancelable != 0 || reserved != 0 {
        return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0);
    }
    let (index, inst, device_id) = match authenticated_hosted_device(ch, device, active_reply_cap) {
        Ok(identity) => identity,
        Err(status) => return (status.raw(), 0, 0, 0),
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let registration = match hosted_device_pointer_registration(domain, device, device_id) {
        Ok(registration) => registration,
        Err(status) => return (status.raw(), 0, 0, 0),
    };
    if hosted_device_allocations::registration(inst, device) != Ok(Some(registration)) {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let cleanup = match reserve_first_packet_cleanup() {
        Ok(id) => id,
        Err(status) => return (status, 0, 0, 0),
    };
    let result = service_start_next_packet_locked(index, inst, registration, cleanup);
    // A selected packet uses the reserved row for its extra device projection ref. All other
    // paths remove the unused reservation; checked cleanup never replays the WDM queue effect.
    {
        let _guard = lock_first_packets();
        if first_packet_cleanup().iter().any(|row| row.id == cleanup && row.refused.is_none()) {
            first_packet_cleanup().retain(|row| row.id != cleanup);
        }
    }
    result
}

fn service_start_next_packet_locked(
    index: usize,
    inst: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    cleanup: u64,
) -> (i32, u64, u64, u64) {
    let _guard = lock_first_packets();
    let Some(slot) = first_packet_current().iter().find(|slot| slot.registration == registration)
    else { return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0); };
    let snapshot = slot.current.snapshot();
    let Some(source) = snapshot.packet else {
        return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0);
    };
    let observed = slot.node;
    let phase = snapshot.phase;
    if source.allocation().owner
        != nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedCaller(index)
    { return (STATUS_INVALID_HANDLE, 0, 0, 0); }
    let row_index = first_packet_transactions().iter().position(|row| {
        row.registration == registration && !row.next_performed
            && row.node.matches(observed) && row.source == source
    });
    if phase == CurrentPhase::Live && row_index.is_none_or(|row_index| {
        !matches!(&first_packet_transactions()[row_index].owner,
            FirstPacketOwnerState::Committed(owner) if !owner.source_retained())
    }) {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let Some(slot) = first_packet_current().iter_mut().find(|slot| {
        slot.registration == registration && slot.node.matches(observed)
            && slot.current.snapshot().packet == Some(source)
    }) else { return (STATUS_INVALID_HANDLE, 0, 0, 0); };
    if first_packet_queued().iter().any(|row| row.registration == registration
        && matches!(&row.owner, QueuedPacketState::Linked(_)))
    {
        if first_packet_transactions().try_reserve(1).is_err() {
            return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0);
        }
        let serial = match FIRST_PACKET_NEXT_ID.fetch_update(
            Ordering::Relaxed, Ordering::Relaxed,
            |value| value.checked_add(1).filter(|next| *next != 0),
        ) {
            Ok(serial) => serial,
            Err(_) => return (STATUS_INSUFFICIENT_RESOURCES, 0, 0, 0),
        };
        // Verify the old live callback fence before a WDM dequeue can displace its source pin.
        let selected = match packet::advance_selected_next_packet(
            index, inst, registration, observed, source,
        ) {
            Ok(selected) => selected,
            Err(status) => return (status, 0, 0, 0),
        };
        let queued_index = first_packet_queued().iter().position(|row|
            row.registration == registration && row.node.matches(selected.node)
                && row.source == selected.source)
            .expect("selected WDM head lost its preverified root receipt");
        let queued = first_packet_queued().swap_remove(queued_index);
        let QueuedPacketState::Linked(receipt) = queued.owner else {
            panic!("selected WDM head lost its linked owner");
        };
        let owner = receipt.select(selected.source)
            .unwrap_or_else(|_| panic!("selected WDM head mismatched exact queued owner"));
        let id = StartIoTransactionId::new(serial, selected.node.generation)
            .expect("selected node generation is nonzero");
        let slot = first_packet_current().iter_mut().find(|slot|
            slot.registration == registration && slot.node.matches(observed))
            .expect("selected device lost its exact current receipt");
        let update = slot.current.prepare_update(registration, observed.raw_irp,
            Some(LivePacket::new(selected.source, owner.source)))
            .unwrap_or_else(|_| panic!("preverified selected current update refused after WDM dequeue"));
        let displaced = update.commit();
        slot.node = selected.node;
        if let Some(packet) = displaced {
            let old_index = row_index.expect("preverified live callback fence");
            let FirstPacketOwnerState::Committed(old) =
                &mut first_packet_transactions()[old_index].owner
            else { panic!("displaced live callback fence changed under FIRST lock") };
            old.retain_source(packet)
                .unwrap_or_else(|_| panic!("displaced exact source pin refused"));
        }
        if let Some(old_index) = row_index {
            first_packet_transactions()[old_index].next_performed = true;
        }
        let mut fence = StartIoCallbackFence::new(selected.source, id, owner.callback);
        fence.begin_reply().expect("fresh selected callback reply fence");
        first_packet_transactions().push(FirstPacketTransaction {
            id, node: selected.node, registration,
            callback_target: selected.callback_target, source: selected.source,
            owner: FirstPacketOwnerState::Committed(fence), terminal_pin: None,
            next_performed: false,
        });
        first_packet_cleanup().iter_mut().find(|row| row.id == cleanup)
            .expect("reserved selected packet cleanup row")
            .refused = Some(FirstPacketCommitReleaseRefusal::Device(owner.device));
        selected.claim.publish()
            .unwrap_or_else(|_| panic!("selected pending node changed before durable publication"));
        return (STATUS_SUCCESS, selected.callback_target, serial,
            selected.source.allocation().component_address);
    }
    match packet::advance_empty_next_packet(
        index, inst, registration, observed, source, &mut slot.current,
    ) {
        Ok(displaced) => {
            if let Some(packet) = displaced {
                let row_index = row_index.expect("preflighted live StartIo callback fence");
                let FirstPacketOwnerState::Committed(owner) =
                    &mut first_packet_transactions()[row_index].owner
                else { panic!("live StartIo callback fence changed under FIRST lock") };
                owner.retain_source(packet)
                    .unwrap_or_else(|_| panic!("selected old source owner mismatched exact callback fence"));
            }
            if let Some(row_index) = row_index {
                first_packet_transactions()[row_index].next_performed = true;
            }
            (STATUS_SUCCESS, 0, 0, 0)
        }
        Err(status) => (status, 0, 0, 0),
    }
}

pub(super) fn service_start_next_packet_callback_returned(
    ch: &crate::spawn_hosts::PumpChannel,
    serial: u64,
    irp: u64,
    device: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let _guard = lock_first_packets();
    let Some(row_index) = first_packet_transactions().iter().position(|row|
        row.id.id() == serial && row.source.allocation().component_address == irp
            && row.registration.address() == device
            && row.registration.domain() == domain
            && row.source.allocation().domain == domain
            && row.source.allocation().owner
                == nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedCaller(index)
            && hosted_device_allocations::registration(inst, device)
                == Ok(Some(row.registration)))
    else { return (STATUS_INVALID_HANDLE, 0, 0, 0); };
    let row = &mut first_packet_transactions()[row_index];
    let FirstPacketOwnerState::Committed(owner) = &mut row.owner else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    if owner.callback_returned(row.id).is_err() {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let _ = settle_first_packet(row_index);
    (STATUS_SUCCESS, 0, 0, 0)
}

pub(super) fn service_start_packet(
    ch: &crate::spawn_hosts::PumpChannel,
    device: u64,
    irp: u64,
    node: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let (index, inst, _) = match authenticated_hosted_device(ch, device, active_reply_cap) {
        Ok(identity) => identity,
        Err(status) => return (status.raw(), 0, 0, 0),
    };
    let Some(observed) = hosted_source_irp_ledger::observed_projected_start_io_packet(index, node, irp)
    else { return (STATUS_INVALID_HANDLE, 0, 0, 0); };
    let cleanup = match reserve_first_packet_cleanup() {
        Ok(id) => id,
        Err(status) => return (status, 0, 0, 0),
    };
    let prepared = match prepare_first_projected_packet(ch, device, observed, active_reply_cap) {
        Ok(prepared) => prepared,
        Err(status) => {
            finish_first_packet_cleanup(cleanup, None);
            return (status, 0, 0, 0);
        }
    };
    if prepared.instance.hosted_domain_id != inst.hosted_domain_id
        || prepared.node.raw_irp != irp
    {
        let refused = release_prepared_first_packet(prepared).err()
            .map(FirstPacketCommitReleaseRefusal::Packet);
        finish_first_packet_cleanup(cleanup, refused);
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let (id, stale_device) = match commit_first_projected_packet(prepared) {
        Ok(result) => result,
        Err(refused) => {
            let refused = release_first_packet_commit_refusal(refused).err();
            finish_first_packet_cleanup(cleanup, refused);
            return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0);
        }
    };
    let stale_cleanup = stale_device.and_then(|mut device| {
        device.release(io_manager_mut()).err()
            .map(|_| FirstPacketCommitReleaseRefusal::Device(device))
    });
    finish_first_packet_cleanup(cleanup, stale_cleanup);
    let Some(id) = id else { return (STATUS_SUCCESS, 0, 0, 0); };
    let (callback, registered_device, source_irp) = match begin_first_packet_reply(id) {
        Ok(command) => command,
        Err(status) => return (status, 0, 0, 0),
    };
    assert_eq!(registered_device, device, "committed StartIo device changed before Reply");
    assert_eq!(source_irp, irp, "committed StartIo source changed before Reply");
    (STATUS_SUCCESS, callback, id.id(), id.generation())
}

pub(super) fn service_start_packet_callback_returned(
    ch: &crate::spawn_hosts::PumpChannel,
    serial: u64,
    generation: u64,
    irp: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    let Some((index, inst)) = instance_for_pump_channel(ch, active_reply_cap) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let Some(domain) = instance_domain_identity(inst) else {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    };
    let Some(id) = StartIoTransactionId::new(serial, generation) else {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    };
    {
        let _guard = lock_first_packets();
        if !first_packet_transactions().iter().any(|row| {
            row.id == id
                && row.source.allocation().component_address == irp
                && row.source.allocation().owner
                    == nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedCaller(index)
                && row.source.allocation().domain == domain
                && row.registration.domain() == domain
                && hosted_device_allocations::registration(inst, row.registration.address())
                    == Ok(Some(row.registration))
        }) {
            return (STATUS_INVALID_HANDLE, 0, 0, 0);
        }
    }
    match first_packet_callback_returned(id) {
        Ok(()) => (STATUS_SUCCESS, 0, 0, 0),
        Err(status) => (status, 0, 0, 0),
    }
}

/// This trampoline runs in the hosted component. It never reads root I/O Manager state or stores
/// StartIo flags locally: the authenticated device service performs that effect in root space.
pub(super) extern "win64" fn s_io_set_start_io_attributes(
    device: u64,
    deferred: u8,
    no_cancel: u8,
) {
    unsafe {
        let (words, status, value, reserved0, reserved1) = call_on4_raw(
            (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
            HOSTED_DEVICE_OP_SET_START_IO_ATTRIBUTES,
            device,
            u64::from(deferred),
            u64::from(no_cancel),
        );
        // VOID callers cannot handle a refusal. A malformed or failed reply is also potentially
        // post-effect, so never retry this call or synthesize success from the component.
        if words != 4 || status != STATUS_SUCCESS as u32 as u64
            || value != 0 || reserved0 != 0 || reserved1 != 0
        {
            crate::provider_bugcheck::report(
                0xc4,
                [HOSTED_DEVICE_OP_SET_START_IO_ATTRIBUTES, device, status, words],
            );
        }
    }
}

struct AttributeMemory {
    registration: nt_io_manager::HostedDevicePointerRegistration,
    address: u64,
    device_exec: u64,
    extension: u64,
    extension_exec: u64,
}

impl LockedDeviceQueueMemory for AttributeMemory {
    type Error = ();

    fn validate_unpublished_queue_storage(&self, _: u64) -> Result<(), Self::Error> { Err(()) }
    fn queue(&self, _: u64) -> Result<DeviceQueueSnapshot, Self::Error> { Err(()) }
    fn entry(&self, _: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> { Err(()) }
    fn apply(&mut self, _: &DeviceQueueEdits) {
        unreachable!("attribute publication cannot edit the WDM queue")
    }
}

impl LockedStartIoMemory for AttributeMemory {
    type Owner = nt_io_manager::HostedDevicePointerRegistration;

    fn device(&self, address: u64) -> Result<Device<Self::Owner>, Self::Error> {
        if address != self.address { return Err(()); }
        Ok(Device {
            address,
            queue: address + 0xa0,
            extension: self.extension,
            current_irp: unsafe { read_unaligned((self.device_exec + 0x20) as *const u64) },
            start_io: 0, // Attribute policy does not inspect the packet callback.
            count: unsafe { read_unaligned((self.extension_exec + 0x38) as *const u32) },
            key: unsafe { read_unaligned((self.extension_exec + 0x3c) as *const u32) },
            flags: unsafe { read_unaligned((self.extension_exec + 0x40) as *const u32) },
            owner: self.registration,
        })
    }

    fn validate_device_owner(&self, retained: &Device<Self::Owner>) -> Result<(), Self::Error> {
        (retained.address == self.address && retained.owner == self.registration)
            .then_some(()).ok_or(())
    }
    fn packet(&self, _: u64, _: Option<u64>) -> Result<Packet<Self::Owner>, Self::Error> { Err(()) }
    fn classify_current_packet(&self, _: &Device<Self::Owner>, _: &Packet<Self::Owner>)
        -> Result<CurrentPacketRelation, Self::Error> { Err(()) }

    fn commit_start_io(&mut self, writes: &[DeviceQueueWrite]) {
        // set_attributes emits one infallible local store; no IPC or callback occurs in this
        // locked interval. Unexpected policy changes must fail before altering queue storage.
        let [DeviceQueueWrite::U32 { address, value }] = writes else {
            unreachable!("attribute publication made an unexpected WDM edit")
        };
        assert_eq!(*address, self.extension + 0x40);
        unsafe { write_unaligned((self.extension_exec + 0x40) as *mut u32, *value) };
    }
}

unsafe fn attribute_memory(
    inst: DriverInstance,
    address: u64,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    extension_size: u32,
) -> Option<AttributeMemory> {
    let layout = nt_io_manager::WdmDeviceObjectAllocationLayout::plan(extension_size).ok()?;
    let (device_exec, capacity) = hosted_pool_allocation_exec_range(inst.exec_pool_va, address)?;
    if capacity < layout.allocation_size() as u64
        || hosted_instance_pool_allocation_is_free_unlocked(inst, address) != Some(false)
        || read_unaligned(device_exec as *const i16) != WDM_X64_IO_TYPE_DEVICE
        || read_unaligned((device_exec + 2) as *const u16) != layout.size_field()
    { return None; }
    let kernel_offset = layout.kernel_extension_offset() as u64;
    let expected_extension = address.checked_add(kernel_offset)?;
    let extension = read_unaligned((device_exec + 0x138) as *const u64);
    if extension != expected_extension
        || kernel_offset.checked_add(0x50)? > capacity
    { return None; }
    let extension_exec = device_exec.checked_add(kernel_offset)?;
    if read_unaligned(extension_exec as *const u16) != 13
        || read_unaligned((extension_exec + 2) as *const u16) != 0
        || read_unaligned((extension_exec + 8) as *const u64) != address
    { return None; }
    Some(AttributeMemory { registration, address, device_exec, extension, extension_exec })
}

/// Root device-service entry. The surrounding service has authenticated the physical channel
/// and AddDevice mutation ownership; this function admits the exact newly created FDO before a
/// final HostedDeviceBinding exists.
pub(super) fn service_set_attributes(
    ch: &crate::spawn_hosts::PumpChannel,
    device: u64,
    deferred: u64,
    no_cancel: u64,
    active_reply_cap: u64,
) -> (i32, u64, u64, u64) {
    if deferred > 1 || no_cancel > 1 {
        return (STATUS_INVALID_PARAMETER, 0, 0, 0);
    }
    let (_index, inst, device_id) = match authenticated_hosted_device(ch, device, active_reply_cap) {
        Ok(identity) => identity,
        Err(status) => return (status.raw(), 0, 0, 0),
    };
    let domain = match instance_domain_identity(inst) {
        Some(domain) => domain,
        None => return (STATUS_ACCESS_DENIED, 0, 0, 0),
    };
    let registration = match hosted_device_pointer_registration(domain, device, device_id) {
        Ok(registration) => registration,
        Err(status) => return (status.raw(), 0, 0, 0),
    };
    if hosted_device_allocations::registration(inst, device) != Ok(Some(registration)) {
        return (STATUS_INVALID_HANDLE, 0, 0, 0);
    }
    let extension_size = match io_manager_mut().device(device_id) {
        Some(record) if !record.delete_pending => record.extension_size,
        _ => return (STATUS_INVALID_DEVICE_REQUEST, 0, 0, 0),
    };
    let mut reference = match io_manager_mut().retain_hosted_device_projection_reference(registration) {
        Ok(reference) => reference,
        Err(status) => return (status.raw(), 0, 0, 0),
    };
    let result = unsafe {
        (|| {
            let _pool = hosted_instance_pool_lock(inst.exec_pool_va)
                .ok_or(nt_status::NtStatus::DEVICE_BUSY.raw())?;
            let mut memory = attribute_memory(inst, device, registration, extension_size)
                .ok_or(STATUS_INVALID_PARAMETER)?;
            start_io::set_attributes(&mut memory, device, deferred != 0, no_cancel != 0)
                .map_err(|_| STATUS_INVALID_PARAMETER)?;
            Ok::<(), i32>(())
        })()
    };
    // Release only after the root's local effect (or pre-effect refusal) and pool lock settle.
    // A failed release retains the ledger pin; the component sees failure and never retries.
    let released = reference.release(io_manager_mut());
    if released.is_err() {
        core::mem::forget(reference);
        return (STATUS_UNSUCCESSFUL, 0, 0, 0);
    }
    match result {
        Ok(()) => (STATUS_SUCCESS, 0, 0, 0),
        Err(status) => (status, 0, 0, 0),
    }
}
