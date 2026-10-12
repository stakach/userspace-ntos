//! Locked physical storage adapter for an op6-projected first packet.
//!
//! This is deliberately not an import or a callback executor. It admits only the exact caller
//! packet and an empty CurrentIrp. A later native transaction must retain this lock through the
//! WDM commit and publish its CurrentReceipt before any Reply or driver callback.

use super::*;
use nt_io_manager::device_queue::DEVICE_QUEUE_SIZE;
use nt_io_manager::start_io::Action;

struct LockedFirstPacketMemory {
    registration: nt_io_manager::HostedDevicePointerRegistration,
    source: SourceIrpForwardIdentity,
    _pool: ExecutivePoolLockGuard,
    device: AttributeMemory,
    device_capacity: u64,
    irp: u64,
    irp_exec: u64,
    irp_capacity: u64,
    start_io: u64,
}

fn range_contains(base: u64, capacity: u64, address: u64, bytes: u64) -> bool {
    address >= base
        && address.checked_add(bytes).is_some_and(|end| {
            base.checked_add(capacity).is_some_and(|limit| end <= limit)
        })
}

impl LockedFirstPacketMemory {
    fn exec_address(&self, address: u64, bytes: u64) -> Option<u64> {
        if range_contains(self.device.address, self.device_capacity, address, bytes) {
            return self.device.device_exec.checked_add(address - self.device.address);
        }
        if range_contains(self.irp, self.irp_capacity, address, bytes) {
            return self.irp_exec.checked_add(address - self.irp);
        }
        None
    }

    fn write(&self, edit: DeviceQueueWrite) {
        unsafe {
            match edit {
                DeviceQueueWrite::U8 { address, value } =>
                    write_unaligned(self.exec_address(address, 1).unwrap() as *mut u8, value),
                DeviceQueueWrite::U16 { address, value } =>
                    write_unaligned(self.exec_address(address, 2).unwrap() as *mut u16, value),
                DeviceQueueWrite::U32 { address, value } =>
                    write_unaligned(self.exec_address(address, 4).unwrap() as *mut u32, value),
                DeviceQueueWrite::U64 { address, value } =>
                    write_unaligned(self.exec_address(address, 8).unwrap() as *mut u64, value),
            }
        }
    }
}

/// The source pin and projection pin were acquired from the root's op6 row before this lock.
/// Recheck the same physical generations here; no mutable packet or queue bytes escape the lock.
fn locked_first_packet_memory(
    inst: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    source: SourceIrpForwardIdentity,
) -> Result<LockedFirstPacketMemory, i32> {
    let irp = source.allocation();
    let _pool = unsafe { hosted_instance_pool_lock(inst.exec_pool_va) }
        .ok_or(STATUS_INVALID_HANDLE)?;
    let extension_size = io_manager_mut()
        .device(registration.device_id())
        .filter(|record| !record.delete_pending)
        .map(|record| record.extension_size)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let device = unsafe {
        attribute_memory(inst, registration.address(), registration, extension_size)
    }
    .ok_or(STATUS_INVALID_HANDLE)?;
    if unsafe { read_unaligned((device.device_exec + 0x20) as *const u64) } != 0 {
        return Err(STATUS_INVALID_HANDLE);
    }
    let (device_exec, device_capacity) = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, device.address)
    }
    .ok_or(STATUS_INVALID_HANDLE)?;
    if device_exec != device.device_exec {
        return Err(STATUS_INVALID_HANDLE);
    }
    let (irp_exec, irp_capacity) = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, irp.component_address)
    }
    .ok_or(STATUS_INVALID_HANDLE)?;
    if irp_capacity < irp.bytes
        || irp_exec.checked_sub(8).is_none()
        || unsafe { read_unaligned((irp_exec - 8) as *const u64) } != irp.pool_generation
        || unsafe { read_unaligned(irp_exec as *const u16) } != WDM_X64_IO_TYPE_IRP
        || unsafe { read_unaligned((irp_exec + 2) as *const u16) as u64 } != irp.bytes
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    let driver = unsafe { read_unaligned((device.device_exec + 8) as *const u64) };
    if driver == 0 || driver != inst.driver_object {
        return Err(STATUS_INVALID_HANDLE);
    }
    let (driver_exec, driver_capacity) = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, driver)
    }
    .ok_or(STATUS_INVALID_HANDLE)?;
    if driver_capacity < WDM_X64_DRIVER_OBJECT_SIZE as u64
        || unsafe { read_unaligned(driver_exec as *const i16) } != WDM_X64_IO_TYPE_DRIVER
        || unsafe { read_unaligned((driver_exec + 2) as *const u16) }
            != WDM_X64_DRIVER_OBJECT_SIZE as u16
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    // DRIVER_OBJECT.DriverStartIo is at 0x60 in the x64 WDM layout.
    let start_io = unsafe { read_unaligned((driver_exec + 0x60) as *const u64) };
    let image_end = inst.image_frames.checked_mul(0x1000)
        .and_then(|bytes| FSD_CODE_VA.checked_add(bytes))
        .ok_or(STATUS_INVALID_HANDLE)?;
    if !inst.used || !inst.ready || start_io < FSD_CODE_VA || start_io >= image_end {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    Ok(LockedFirstPacketMemory {
        registration, source, _pool, device, device_capacity,
        irp: irp.component_address, irp_exec, irp_capacity, start_io,
    })
}

pub(super) struct FirstPacketCommit {
    pub current: CurrentReceipt<nt_io_manager::HostedDeviceProjectionReference, StartIoSourcePin>,
    pub identity: SourceIrpForwardIdentity,
    pub registration: nt_io_manager::HostedDevicePointerRegistration,
    pub callback_target: u64,
    pub node: PendingStartIoNodeIdentity,
}

/// No foreign call occurs here. The CurrentReceipt update is prepared before the WDM queue
/// effect, then published under the same pool lock. Refusal returns both original owners.
pub(super) fn commit_first_projected_packet(
    prepared: PreparedFirstProjectedPacket,
) -> Result<FirstPacketCommit, PreparedFirstProjectedPacket> {
    let PreparedFirstProjectedPacket {
        instance, registration, node, mut current, incoming,
    } = prepared;
    let identity = incoming.identity();
    let mut memory = match locked_first_packet_memory(instance, registration, identity) {
        Ok(memory) => memory,
        Err(_) => return Err(PreparedFirstProjectedPacket {
            instance, registration, node, current, incoming,
        }),
    };
    let queue_head = registration.address() + 0xa0 + 8;
    match memory.queue(registration.address() + 0xa0) {
        Ok(queue) if !queue.busy && queue.flink == queue_head && queue.blink == queue_head => {},
        _ => return Err(PreparedFirstProjectedPacket {
            instance, registration, node, current, incoming,
        }),
    }
    let prepared_update = match current.prepare_update(registration, 0, Some(incoming)) {
        Ok(update) => update,
        Err(refusal) => return Err(PreparedFirstProjectedPacket {
            instance, registration, node, current,
            incoming: refusal.incoming.expect("first packet refusal retains incoming owner"),
        }),
    };
    let callback_target = memory.start_io;
    let outcome = start_io::start_packet::<_, ()>(
        &mut memory, registration.address(), identity.allocation().component_address + 0x78,
        None, None, None,
    );
    match outcome {
        Ok(outcome) => {
            assert!(matches!(outcome.action, Action::Start { .. }) && outcome.release_lock.is_none(),
                "idle first-packet queue changed under its lock");
            assert!(prepared_update.commit().is_none(), "empty current displaced a live packet");
            Ok(FirstPacketCommit { current, identity, registration, callback_target, node })
        }
        Err(_) => {
            let incoming = prepared_update.abort()
                .expect("first packet refusal retains incoming owner");
            Err(PreparedFirstProjectedPacket {
                instance, registration, node, current, incoming,
            })
        }
    }
}

impl LockedDeviceQueueMemory for LockedFirstPacketMemory {
    type Error = ();

    fn validate_unpublished_queue_storage(&self, _: u64) -> Result<(), Self::Error> { Err(()) }
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> {
        if address != self.device.address + 0xa0 { return Err(()); }
        let exec = self.exec_address(address, DEVICE_QUEUE_SIZE as u64).ok_or(())?;
        let bytes = unsafe { core::slice::from_raw_parts(exec as *const u8, DEVICE_QUEUE_SIZE) };
        DeviceQueueSnapshot::read(bytes).map_err(|_| ())
    }
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> {
        if address != self.irp + 0x78 { return Err(()); }
        let exec = self.exec_address(address, 24).ok_or(())?;
        let bytes = unsafe { core::slice::from_raw_parts(exec as *const u8, 24) };
        DeviceQueueEntrySnapshot::read(bytes).map_err(|_| ())
    }
    fn apply(&mut self, edits: &DeviceQueueEdits) {
        self.commit_start_io(edits.writes());
    }
}

impl LockedStartIoMemory for LockedFirstPacketMemory {
    type Owner = nt_io_manager::HostedDevicePointerRegistration;

    fn device(&self, address: u64) -> Result<Device<Self::Owner>, Self::Error> {
        if address != self.device.address { return Err(()); }
        Ok(Device {
            address, queue: address + 0xa0, extension: self.device.extension,
            current_irp: unsafe { read_unaligned((self.device.device_exec + 0x20) as *const u64) },
            start_io: self.start_io,
            count: unsafe { read_unaligned((self.device.extension_exec + 0x38) as *const u32) },
            key: unsafe { read_unaligned((self.device.extension_exec + 0x3c) as *const u32) },
            flags: unsafe { read_unaligned((self.device.extension_exec + 0x40) as *const u32) },
            owner: self.registration,
        })
    }
    fn validate_device_owner(&self, retained: &Device<Self::Owner>) -> Result<(), Self::Error> {
        (retained.address == self.device.address
            && retained.owner == self.registration).then_some(()).ok_or(())
    }
    fn packet(&self, entry: u64, cancel: Option<u64>) -> Result<Packet<Self::Owner>, Self::Error> {
        if entry != self.irp + 0x78 || cancel.is_some() { return Err(()); }
        Ok(Packet {
            irp: self.irp, entry,
            cancelled: unsafe { read_unaligned((self.irp_exec + WDM_X64_IRP_CANCEL_OFFSET) as *const u8) != 0 },
            owner: self.registration,
        })
    }
    fn classify_current_packet(
        &self, device: &Device<Self::Owner>, packet: &Packet<Self::Owner>,
    ) -> Result<CurrentPacketRelation, Self::Error> {
        if packet.irp != self.source.allocation().component_address
            || device.owner != self.registration || device.current_irp != 0
        { return Err(()); }
        Ok(CurrentPacketRelation::Empty)
    }
    fn commit_start_io(&mut self, writes: &[DeviceQueueWrite]) {
        // Validate the complete edit set before the first physical store. These are local writes
        // under the same pool lock, with no IPC, allocation, or callback in the commit interval.
        assert!(writes.iter().all(|edit| match *edit {
            DeviceQueueWrite::U8 { address, .. } => self.exec_address(address, 1).is_some(),
            DeviceQueueWrite::U16 { address, .. } => self.exec_address(address, 2).is_some(),
            DeviceQueueWrite::U32 { address, .. } => self.exec_address(address, 4).is_some(),
            DeviceQueueWrite::U64 { address, .. } => self.exec_address(address, 8).is_some(),
        }));
        for &edit in writes { self.write(edit); }
    }
}
