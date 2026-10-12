//! Root-owned StartIo attributes. Packet and next-packet callbacks still need a retained
//! source/current receipt across callback reentry, so they have no native imports yet.

use super::*;
use nt_io_manager::device_queue::{
    DeviceQueueEdits, DeviceQueueEntrySnapshot, DeviceQueueSnapshot, DeviceQueueWrite,
    LockedDeviceQueueMemory,
};
use nt_io_manager::start_io::{self, CurrentPacketRelation, Device, LockedStartIoMemory, Packet};
use nt_io_manager::start_io_current::{CurrentReceipt, LivePacket};
use nt_io_manager::start_io_native_owner::{PendingStartIoNodeIdentity, StartIoSourcePin};
use nt_io_manager::source_irp_ledger::SourceIrpForwardIdentity;
use nt_io_manager::start_io_native_transaction::{CommittedStartIo, StartIoTransactionId};

#[path = "hosted_start_io_packet.rs"]
mod packet;

/// Exact pre-effect owners for an op6-projected first packet. This does not enqueue or invoke
/// StartIo. The eventual native callback transaction must consume these owners under the queue
/// lock and retain them across its uncertain Reply and terminal completion.
#[must_use = "retain the exact packet and device owners until native callback integration"]
struct PreparedFirstProjectedPacket {
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
        instance, registration, node, current, incoming,
    } = prepared;
    let device = match current.into_empty_owner() {
        Ok(device) => device,
        Err(current) => return Err(FirstPacketReleaseRefusal::NotEmpty(
            PreparedFirstProjectedPacket { instance, registration, node, current, incoming },
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

type FirstPacketOwner = CommittedStartIo<
    nt_io_manager::HostedDeviceProjectionReference,
    StartIoSourcePin,
    nt_io_manager::HostedDeviceProjectionReference,
>;

struct FirstPacketTransaction {
    id: StartIoTransactionId,
    node: PendingStartIoNodeIdentity,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    callback_target: u64,
    source: SourceIrpForwardIdentity,
    owner: FirstPacketOwner,
}

static FIRST_PACKET_NEXT_ID: AtomicU64 = AtomicU64::new(1);
static FIRST_PACKET_LOCK: AtomicU64 = AtomicU64::new(0);
static mut FIRST_PACKET_TRANSACTIONS: Option<Vec<FirstPacketTransaction>> = None;

struct FirstPacketGuard;
impl Drop for FirstPacketGuard {
    fn drop(&mut self) { FIRST_PACKET_LOCK.store(0, Ordering::Release); }
}

fn lock_first_packets() -> FirstPacketGuard {
    while FIRST_PACKET_LOCK.compare_exchange_weak(
        0, 1, Ordering::Acquire, Ordering::Relaxed,
    ).is_err() { crate::yield_now(); }
    FirstPacketGuard
}

fn first_packet_transactions() -> &'static mut Vec<FirstPacketTransaction> {
    // Every caller holds FIRST_PACKET_LOCK; no reference crosses a callback or foreign Reply.
    unsafe { (&mut *core::ptr::addr_of_mut!(FIRST_PACKET_TRANSACTIONS)).get_or_insert_with(Vec::new) }
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
) -> Result<StartIoTransactionId, FirstPacketCommitRefusal> {
    let _guard = lock_first_packets();
    if first_packet_transactions().try_reserve(1).is_err() {
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
    let owner = CommittedStartIo::new(
        committed.current, committed.identity, id, callback_owner,
    ).unwrap_or_else(|_| panic!("committed first packet lost its exact CurrentIrp receipt"));
    first_packet_transactions().push(FirstPacketTransaction {
        id, node: committed.node, registration: committed.registration,
        callback_target: committed.callback_target, source: committed.identity, owner,
    });
    Ok(id)
}

/// Mark Reply uncertain before yielding its scalar callback command. A lost or failed Reply
/// outcome cannot re-enter this operation or repeat the WDM queue commit.
fn begin_first_packet_reply(id: StartIoTransactionId) -> Result<(u64, u64, u64), i32> {
    let _guard = lock_first_packets();
    let row = first_packet_transactions().iter_mut().find(|row| row.id == id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    row.owner.begin_reply().map_err(|_| STATUS_INVALID_HANDLE)?;
    Ok((row.callback_target, row.registration.address(), row.source.allocation().component_address))
}

/// Callback return does not retire the source IRP. The independent terminal completion hook is
/// still required before the transaction may release any physical or callback image owner.
fn first_packet_callback_returned(id: StartIoTransactionId) -> Result<(), i32> {
    let _guard = lock_first_packets();
    let row = first_packet_transactions().iter_mut().find(|row| row.id == id)
        .ok_or(STATUS_INVALID_HANDLE)?;
    row.owner.callback_returned(id).map_err(|_| STATUS_INVALID_HANDLE)
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
        instance: inst,
        registration,
        node: observed,
        current: CurrentReceipt::new(registration, identity.allocation().domain, device_owner),
        incoming: LivePacket::new(identity, source_owner),
    })
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
