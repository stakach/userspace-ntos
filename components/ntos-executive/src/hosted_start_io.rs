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

#[path = "hosted_start_io_packet.rs"]
mod packet;

/// Exact pre-effect owners for an op6-projected first packet. This does not enqueue or invoke
/// StartIo. The eventual native callback transaction must consume these owners under the queue
/// lock and retain them across its uncertain Reply and terminal completion.
#[must_use = "retain the exact packet and device owners until native callback integration"]
struct PreparedFirstProjectedPacket {
    instance: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    current: CurrentReceipt<nt_io_manager::HostedDeviceProjectionReference, StartIoSourcePin>,
    incoming: LivePacket<StartIoSourcePin>,
}

impl PreparedFirstProjectedPacket {
    fn source_identity(&self) -> SourceIrpForwardIdentity { self.incoming.identity() }
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
