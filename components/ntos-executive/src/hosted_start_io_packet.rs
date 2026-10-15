//! Locked physical storage adapter for an op6-projected first packet.
//!
//! This is deliberately not an import or a callback executor. It admits only the exact caller
//! packet and an empty CurrentIrp. A later native transaction must retain this lock through the
//! WDM commit and publish its CurrentReceipt before any Reply or driver callback.

use super::*;
use nt_io_manager::device_queue;
use nt_io_manager::device_queue::DEVICE_QUEUE_SIZE;
use nt_io_manager::start_io::Action;
use nt_io_manager::start_io_selection::StartIoSelectionClaim;

struct LockedFirstPacketMemory {
    registration: nt_io_manager::HostedDevicePointerRegistration,
    source: SourceIrpForwardIdentity,
    _pool: ExecutivePoolLockGuard,
    device: AttributeMemory,
    device_capacity: u64,
    irp: u64,
    irp_exec: u64,
    irp_capacity: u64,
    queue_entries: Vec<LockedQueueEntry>,
    current_irp: u64,
    current_phase: CurrentPhase,
    start_io: u64,
}

struct LockedQueueEntry {
    address: u64,
    exec: u64,
    capacity: u64,
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
        for entry in &self.queue_entries {
            if range_contains(entry.address, entry.capacity, address, bytes) {
                return entry.exec.checked_add(address - entry.address);
            }
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
    instance_index: usize,
    inst: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    observed: PendingStartIoNodeIdentity,
    source: SourceIrpForwardIdentity,
    terminal_ready: bool,
) -> Result<LockedFirstPacketMemory, i32> {
    let irp = source.allocation();
    let _pool = unsafe { hosted_instance_pool_lock(inst.exec_pool_va) }
        .ok_or(STATUS_INVALID_HANDLE)?;
    if observed.source != source.ticket()
        || observed.raw_irp != source.allocation().component_address
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    let extension_size = io_manager_mut()
        .device(registration.device_id())
        .filter(|record| !record.delete_pending)
        .map(|record| record.extension_size)
        .ok_or(STATUS_INVALID_HANDLE)?;
    let device = unsafe {
        attribute_memory(inst, registration.address(), registration, extension_size)
    }
    .ok_or(STATUS_INVALID_HANDLE)?;
    let current_irp = unsafe { read_unaligned((device.device_exec + 0x20) as *const u64) };
    let current_phase = first_packet_current().iter()
        .find(|slot| slot.registration == registration)
        .map(|slot| {
            let snapshot = slot.current.snapshot();
            if snapshot.packet.map_or(0, |source|
                source.allocation().component_address) == current_irp
            { Some(snapshot.phase) } else { None }
        }).unwrap_or_else(|| (current_irp == 0).then_some(CurrentPhase::Empty));
    if (terminal_ready && current_irp != observed.raw_irp)
        || current_phase.is_none()
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    let current_phase = current_phase.expect("validated current slot");
    let node_valid = unsafe { if terminal_ready {
        match current_phase {
            CurrentPhase::Live =>
                hosted_source_irp_ledger::projected_start_io_live_node_matches_locked(
                    instance_index, observed)
                || hosted_source_irp_ledger::projected_start_io_node_matches_locked(
                    instance_index, observed, true),
            // Completed is a scalar receipt. Its exact terminal ACK may already have retired
            // and recycled the old node; do not dereference the old packet after that ACK.
            CurrentPhase::Completed => true,
            CurrentPhase::Empty => false,
        }
    } else {
        hosted_source_irp_ledger::projected_start_io_node_matches_locked(
            instance_index, observed, false)
    } };
    if !node_valid { return Err(STATUS_INVALID_HANDLE); }
    let (device_exec, device_capacity) = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, device.address)
    }
    .ok_or(STATUS_INVALID_HANDLE)?;
    if device_exec != device.device_exec {
        return Err(STATUS_INVALID_HANDLE);
    }
    let (irp_exec, irp_capacity) = if terminal_ready && current_phase == CurrentPhase::Completed {
        (0, 0)
    } else {
        let (irp_exec, irp_capacity) = unsafe {
            hosted_pool_allocation_exec_range(inst.exec_pool_va, irp.component_address)
        }.ok_or(STATUS_INVALID_HANDLE)?;
        if irp_capacity < irp.bytes
            || irp_exec.checked_sub(8).is_none()
            || unsafe { read_unaligned((irp_exec - 8) as *const u64) } != irp.pool_generation
            || unsafe { read_unaligned(irp_exec as *const u16) } != WDM_X64_IO_TYPE_IRP
            || unsafe { read_unaligned((irp_exec + 2) as *const u16) as u64 } != irp.bytes
        { return Err(STATUS_INVALID_HANDLE); }
        (irp_exec, irp_capacity)
    };
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
    let mut queue_entries = Vec::new();
    queue_entries.try_reserve(first_packet_queued().len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for queued in first_packet_queued().iter().filter(|row|
        row.registration == registration && matches!(&row.owner, QueuedPacketState::Linked(_)))
    {
        if !unsafe {
            hosted_source_irp_ledger::projected_start_io_queued_node_matches_locked(
                instance_index, queued.node,
            )
        } {
            return Err(STATUS_INVALID_HANDLE);
        }
        let source = queued.source.allocation();
        let (exec, capacity) = unsafe {
            hosted_pool_allocation_exec_range(inst.exec_pool_va, source.component_address)
        }.ok_or(STATUS_INVALID_HANDLE)?;
        if capacity < source.bytes || exec.checked_sub(8).is_none()
            || unsafe { read_unaligned((exec - 8) as *const u64) } != source.pool_generation
            || unsafe { read_unaligned(exec as *const u16) } != WDM_X64_IO_TYPE_IRP
        { return Err(STATUS_INVALID_HANDLE); }
        queue_entries.push(LockedQueueEntry {
            address: source.component_address, exec, capacity,
        });
    }
    Ok(LockedFirstPacketMemory {
        registration, source, _pool, device, device_capacity,
        irp: irp.component_address, irp_exec, irp_capacity, queue_entries,
        current_irp, current_phase, start_io,
    })
}

pub(super) struct FirstPacketCommit {
    pub current: CurrentReceipt<nt_io_manager::HostedDeviceProjectionReference, StartIoSourcePin>,
    pub identity: SourceIrpForwardIdentity,
    pub registration: nt_io_manager::HostedDevicePointerRegistration,
    pub callback_target: u64,
    pub node: PendingStartIoNodeIdentity,
}

pub(super) enum PacketCommit {
    Started(FirstPacketCommit),
    Queued(PreparedFirstProjectedPacket),
}

/// No foreign call occurs here. The CurrentReceipt update is prepared before the WDM queue
/// effect, then published under the same pool lock. Refusal returns both original owners.
pub(super) fn commit_first_projected_packet(
    prepared: PreparedFirstProjectedPacket,
) -> Result<PacketCommit, PreparedFirstProjectedPacket> {
    let PreparedFirstProjectedPacket {
        instance_index, instance, registration, node, mut current, incoming,
    } = prepared;
    let identity = incoming.identity();
    let mut memory = match locked_first_packet_memory(
        instance_index, instance, registration, node, identity, false,
    ) {
        Ok(memory) => memory,
        Err(_) => return Err(PreparedFirstProjectedPacket {
            instance_index, instance, registration, node, current, incoming,
        }),
    };
    let busy = match memory.queue(registration.address() + 0xa0) {
        Ok(queue) => queue.busy,
        Err(_) => return Err(PreparedFirstProjectedPacket {
            instance_index, instance, registration, node, current, incoming,
        }),
    };
    if busy {
        // Deferred count and NextRequested need a separate retained callback protocol. Refuse
        // before the WDM insertion rather than accepting an action we cannot settle.
        if !memory.device(registration.address()).is_ok_and(|device|
            device.flags & start_io::DEFERRED == 0)
        {
            return Err(PreparedFirstProjectedPacket {
                instance_index, instance, registration, node, current, incoming,
            });
        }
        let outcome = start_io::start_packet::<_, ()>(
            &mut memory, registration.address(), identity.allocation().component_address + 0x78,
            None, None, None,
        );
        return match outcome {
            Ok(outcome) if matches!(outcome.action, Action::Queued { next: None, .. })
                && outcome.release_lock.is_none() => Ok(PacketCommit::Queued(
                    PreparedFirstProjectedPacket {
                        instance_index, instance, registration, node, current, incoming,
                    },
                )),
            Ok(_) => panic!("busy unkeyed StartIo insertion changed policy under pool lock"),
            Err(_) => Err(PreparedFirstProjectedPacket {
                instance_index, instance, registration, node, current, incoming,
            }),
        };
    }
    if first_packet_current().iter().any(|slot| {
        slot.registration == registration && slot.current.snapshot().phase != CurrentPhase::Empty
    }) {
        return Err(PreparedFirstProjectedPacket {
            instance_index, instance, registration, node, current, incoming,
        });
    }
    let prepared_update = match current.prepare_update(registration, 0, Some(incoming)) {
        Ok(update) => update,
        Err(refusal) => return Err(PreparedFirstProjectedPacket {
            instance_index, instance, registration, node, current,
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
            Ok(PacketCommit::Started(FirstPacketCommit {
                current, identity, registration, callback_target, node,
            }))
        }
        Err(_) => {
            let incoming = prepared_update.abort()
                .expect("first packet refusal retains incoming owner");
            Err(PreparedFirstProjectedPacket {
                instance_index, instance, registration, node, current, incoming,
            })
        }
    }
}

/// ReactOS calls IoStartNextPacket after completing the current IRP. This narrow adapter
/// supports the real empty WDM queue case. A nonempty queue needs its selected packet's exact
/// retained owner and adjacent queue entries; it is refused before any queue write here.
pub(super) fn advance_empty_next_packet(
    instance_index: usize,
    inst: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    observed: PendingStartIoNodeIdentity,
    source: SourceIrpForwardIdentity,
    current: &mut CurrentReceipt<nt_io_manager::HostedDeviceProjectionReference, StartIoSourcePin>,
) -> Result<Option<LivePacket<StartIoSourcePin>>, i32> {
    let mut memory = locked_first_packet_memory(
        instance_index, inst, registration, observed, source, true,
    )?;
    let head = registration.address() + 0xa0 + 8;
    match memory.queue(registration.address() + 0xa0) {
        Ok(queue) if queue.busy && queue.flink == head && queue.blink == head => {},
        _ => return Err(STATUS_INVALID_DEVICE_REQUEST),
    }
    let update = current.prepare_update(registration, observed.raw_irp, None)
        .map_err(|_| STATUS_INVALID_HANDLE)?;
    let outcome = start_io::start_next::<_, ()>(
        &mut memory, registration.address(), None, false, None,
    ).map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?;
    if !matches!(outcome.action, Action::Retained { .. }) || outcome.release_lock.is_some() {
        panic!("empty StartIo queue selected a packet under its physical lock");
    }
    Ok(update.commit())
}

/// A zero-write view of the same locked WDM queue. Selection authority remains the real
/// intrusive head; preview only identifies and validates the owner before any physical write.
struct PreviewQueueMemory<'a>(&'a LockedFirstPacketMemory);
impl LockedDeviceQueueMemory for PreviewQueueMemory<'_> {
    type Error = ();
    fn validate_unpublished_queue_storage(&self, address: u64) -> Result<(), Self::Error> {
        self.0.validate_unpublished_queue_storage(address)
    }
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> {
        self.0.queue(address)
    }
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> {
        self.0.entry(address)
    }
    fn apply(&mut self, _: &DeviceQueueEdits) {}
}

pub(super) struct SelectedNextPacket {
    pub source: SourceIrpForwardIdentity,
    pub node: PendingStartIoNodeIdentity,
    pub callback_target: u64,
    pub claim: StartIoSelectionClaim<'static>,
}

/// Caller holds FIRST while this function takes the physical pool lock. The exact PENDING
/// lifecycle word is claimed before dequeue and stays SELECTING until the caller publishes the
/// per-device current and callback transaction. DISPATCHING is refused for now: dispatch-return
/// handoff would otherwise race a nested Next and must use its own explicit protocol.
pub(super) fn advance_selected_next_packet(
    instance_index: usize,
    inst: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    old_node: PendingStartIoNodeIdentity,
    old_source: SourceIrpForwardIdentity,
) -> Result<SelectedNextPacket, i32> {
    let mut memory = locked_first_packet_memory(
        instance_index, inst, registration, old_node, old_source, true,
    )?;
    let queue = registration.address() + 0xa0;
    let device = memory.device(registration.address()).map_err(|_| STATUS_INVALID_HANDLE)?;
    if device.flags & start_io::DEFERRED != 0 && device.count != 0 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let selected_entry = device_queue::remove_device_queue(&mut PreviewQueueMemory(&memory),
        queue, None).map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let selected_irp = selected_entry.checked_sub(0x78).ok_or(STATUS_INVALID_HANDLE)?;
    let row = first_packet_queued().iter().find(|row| {
        row.registration == registration
            && row.node.raw_irp == selected_irp
            && matches!(&row.owner, QueuedPacketState::Linked(_))
    }).ok_or(STATUS_INVALID_HANDLE)?;
    if row.source.allocation().component_address != selected_irp
        || row.source.ticket() != row.node.source
        || row.source.allocation().owner
            != nt_io_manager::source_irp_ledger::SourceIrpOwner::HostedCaller(instance_index)
        || !unsafe { hosted_source_irp_ledger::projected_start_io_queued_node_matches_locked(
            instance_index, row.node) }
    { return Err(STATUS_INVALID_HANDLE); }
    let selected_exec = memory.exec_address(selected_irp, WDM_X64_IRP_SIZE as u64)
        .ok_or(STATUS_INVALID_HANDLE)?;
    if unsafe { read_unaligned((selected_exec + WDM_X64_IRP_CANCEL_OFFSET) as *const u8) } != 0 {
        return Err(STATUS_INVALID_DEVICE_REQUEST);
    }
    let selected_node = row.node;
    let selected_source = row.source;
    let state: &'static AtomicU64 = unsafe { pending_irp_owner_state(selected_node.node) };
    let pending = selected_node.generation | HOSTED_IRP_PENDING;
    let selecting = selected_node.generation | HOSTED_IRP_START_IO_SELECTING;
    let mut claim = StartIoSelectionClaim::claim(state, pending, selecting)
        .ok_or(STATUS_INVALID_DEVICE_REQUEST)?;
    let callback_target = memory.start_io;
    let outcome = start_io::start_next::<_, ()>(
        &mut memory, registration.address(), None, false, None,
    ).map_err(|_| STATUS_INVALID_DEVICE_REQUEST)?;
    claim.effect_committed();
    if !matches!(outcome.action, Action::Start { packet, .. } if packet.irp == selected_irp)
        || outcome.release_lock.is_some()
    {
        panic!("WDM Next selected a different IRP after exact locked preview");
    }
    Ok(SelectedNextPacket { source: selected_source, node: selected_node,
        callback_target, claim })
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
        if address != self.irp + 0x78
            && !self.queue_entries.iter().any(|row| row.address + 0x78 == address)
        { return Err(()); }
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
        if cancel.is_some() { return Err(()); }
        let irp = entry.checked_sub(0x78).ok_or(())?;
        if irp != self.irp && !self.queue_entries.iter().any(|row| row.address == irp) {
            return Err(());
        }
        let exec = self.exec_address(irp, WDM_X64_IRP_SIZE as u64).ok_or(())?;
        Ok(Packet {
            irp, entry,
            cancelled: unsafe { read_unaligned((exec + WDM_X64_IRP_CANCEL_OFFSET) as *const u8) != 0 },
            owner: self.registration,
        })
    }
    fn classify_current_packet(
        &self, device: &Device<Self::Owner>, packet: &Packet<Self::Owner>,
    ) -> Result<CurrentPacketRelation, Self::Error> {
        if packet.irp != self.source.allocation().component_address
            || device.owner != self.registration || device.current_irp != self.current_irp
        { return Err(()); }
        Ok(match self.current_phase {
            CurrentPhase::Empty => CurrentPacketRelation::Empty,
            CurrentPhase::Completed => CurrentPacketRelation::Completed,
            CurrentPhase::Live if self.current_irp == packet.irp => CurrentPacketRelation::LiveSame,
            CurrentPhase::Live => CurrentPacketRelation::LiveOther,
        })
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

/// This adapter borrows the caller's already-held FIRST→source→pool lock chain. It contains
/// only the device queue and exact pinned linked IRP entries; CurrentIrp is never dereferenced.
struct LockedQueuedUnlinkMemory {
    device: LockedQueueEntry,
    entries: Vec<LockedQueueEntry>,
}

impl LockedQueuedUnlinkMemory {
    fn exec_address(&self, address: u64, bytes: u64) -> Option<u64> {
        for row in core::iter::once(&self.device).chain(self.entries.iter()) {
            if range_contains(row.address, row.capacity, address, bytes) {
                return row.exec.checked_add(address - row.address);
            }
        }
        None
    }
}

impl LockedDeviceQueueMemory for LockedQueuedUnlinkMemory {
    type Error = ();
    fn validate_unpublished_queue_storage(&self, _: u64) -> Result<(), Self::Error> { Err(()) }
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> {
        if address != self.device.address + 0xa0 { return Err(()); }
        let exec = self.exec_address(address, DEVICE_QUEUE_SIZE as u64).ok_or(())?;
        DeviceQueueSnapshot::read(unsafe {
            core::slice::from_raw_parts(exec as *const u8, DEVICE_QUEUE_SIZE)
        }).map_err(|_| ())
    }
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> {
        if !self.entries.iter().any(|row| row.address + 0x78 == address) { return Err(()); }
        let exec = self.exec_address(address, 24).ok_or(())?;
        DeviceQueueEntrySnapshot::read(unsafe {
            core::slice::from_raw_parts(exec as *const u8, 24)
        }).map_err(|_| ())
    }
    fn apply(&mut self, edits: &DeviceQueueEdits) {
        assert!(edits.writes().iter().all(|edit| match *edit {
            DeviceQueueWrite::U8 { address, .. } => self.exec_address(address, 1).is_some(),
            DeviceQueueWrite::U16 { address, .. } => self.exec_address(address, 2).is_some(),
            DeviceQueueWrite::U32 { address, .. } => self.exec_address(address, 4).is_some(),
            DeviceQueueWrite::U64 { address, .. } => self.exec_address(address, 8).is_some(),
        }));
        for edit in edits.writes() {
            let (address, value, width) = match *edit {
                DeviceQueueWrite::U8 { address, value } => (address, value as u64, 1),
                DeviceQueueWrite::U16 { address, value } => (address, value as u64, 2),
                DeviceQueueWrite::U32 { address, value } => (address, value as u64, 4),
                DeviceQueueWrite::U64 { address, value } => (address, value, 8),
            };
            let exec = self.exec_address(address, width).expect("prevalidated queued unlink write");
            unsafe { match width {
                1 => write_unaligned(exec as *mut u8, value as u8),
                2 => write_unaligned(exec as *mut u16, value as u16),
                4 => write_unaligned(exec as *mut u32, value as u32),
                _ => write_unaligned(exec as *mut u64, value),
            } }
        }
    }
}

/// The caller owns FIRST, source ledger and physical pool locks in that order. A successful
/// return commits exactly one WDM unlink; the caller must immediately advance its retained row
/// to Unlinked before attempting checked source release.
pub(super) fn unlink_queued_terminal_locked(
    instance_index: usize,
    inst: DriverInstance,
    registration: nt_io_manager::HostedDevicePointerRegistration,
    observed: PendingStartIoNodeIdentity,
) -> Result<(), i32> {
    if !unsafe {
        hosted_source_irp_ledger::projected_start_io_copying_node_matches_locked(
            instance_index, observed,
        )
    } { return Err(STATUS_INVALID_HANDLE); }
    let (device_exec, device_capacity) = unsafe {
        hosted_pool_allocation_exec_range(inst.exec_pool_va, registration.address())
    }.ok_or(STATUS_INVALID_HANDLE)?;
    if device_capacity < 0xa0 + DEVICE_QUEUE_SIZE as u64
        || unsafe { read_unaligned(device_exec as *const i16) } != WDM_X64_IO_TYPE_DEVICE
    { return Err(STATUS_INVALID_HANDLE); }
    let mut entries = Vec::new();
    entries.try_reserve(first_packet_queued().len())
        .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
    for row in first_packet_queued().iter().filter(|row|
        row.registration == registration && matches!(&row.owner, QueuedPacketState::Linked(_)))
    {
        let source = row.source.allocation();
        let (exec, capacity) = unsafe {
            hosted_pool_allocation_exec_range(inst.exec_pool_va, source.component_address)
        }.ok_or(STATUS_INVALID_HANDLE)?;
        if capacity < source.bytes || exec.checked_sub(8).is_none()
            || unsafe { read_unaligned((exec - 8) as *const u64) } != source.pool_generation
            || unsafe { read_unaligned(exec as *const u16) } != WDM_X64_IO_TYPE_IRP
        { return Err(STATUS_INVALID_HANDLE); }
        entries.push(LockedQueueEntry { address: source.component_address, exec, capacity });
    }
    let mut memory = LockedQueuedUnlinkMemory {
        device: LockedQueueEntry {
            address: registration.address(), exec: device_exec, capacity: device_capacity,
        },
        entries,
    };
    match device_queue::remove_entry_device_queue(
        &mut memory, registration.address() + 0xa0, observed.raw_irp + 0x78,
    ) {
        Ok(true) => Ok(()),
        _ => Err(STATUS_INVALID_HANDLE),
    }
}
