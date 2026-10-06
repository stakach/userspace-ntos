//! NT x64 intrusive device queues. Snapshots describe bytes, not object authority.
//!
//! The native adapter admits the actual DEVICE_OBJECT/IRP storage and holds its queue lock.
//! No shadow queue, allocation, callback, or provider operation occurs in this policy.

pub const DEVICE_QUEUE_TYPE: u16 = 20;
pub const DEVICE_QUEUE_SIZE: usize = 40;
pub const DEVICE_QUEUE_ENTRY_SIZE: usize = 24;
pub const DEVICE_QUEUE_LIST_OFFSET: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceQueueLayoutError {
    Truncated,
    InvalidBoolean,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceQueueSnapshot {
    pub type_: u16,
    pub size: u16,
    pub flink: u64,
    pub blink: u64,
    pub busy: bool,
}

impl DeviceQueueSnapshot {
    pub fn read(bytes: &[u8]) -> Result<Self, DeviceQueueLayoutError> {
        if bytes.len() < DEVICE_QUEUE_SIZE {
            return Err(DeviceQueueLayoutError::Truncated);
        }
        if bytes[32] > 1 {
            return Err(DeviceQueueLayoutError::InvalidBoolean);
        }
        Ok(Self {
            type_: u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
            size: u16::from_le_bytes(bytes[2..4].try_into().unwrap()),
            flink: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            blink: u64::from_le_bytes(bytes[16..24].try_into().unwrap()),
            busy: bytes[32] != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceQueueEntrySnapshot {
    pub flink: u64,
    pub blink: u64,
    pub sort_key: u32,
    pub inserted: bool,
}

impl DeviceQueueEntrySnapshot {
    pub fn read(bytes: &[u8]) -> Result<Self, DeviceQueueLayoutError> {
        if bytes.len() < DEVICE_QUEUE_ENTRY_SIZE {
            return Err(DeviceQueueLayoutError::Truncated);
        }
        if bytes[20] > 1 {
            return Err(DeviceQueueLayoutError::InvalidBoolean);
        }
        Ok(Self {
            flink: u64::from_le_bytes(bytes[0..8].try_into().unwrap()),
            blink: u64::from_le_bytes(bytes[8..16].try_into().unwrap()),
            sort_key: u32::from_le_bytes(bytes[16..20].try_into().unwrap()),
            inserted: bytes[20] != 0,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceQueueWrite {
    U8 { address: u64, value: u8 },
    U16 { address: u64, value: u16 },
    U32 { address: u64, value: u32 },
    U64 { address: u64, value: u64 },
}

/// At most six field stores are needed by an insertion or unpublished initializer.
pub struct DeviceQueueEdits {
    writes: [DeviceQueueWrite; 6],
    length: usize,
}

impl DeviceQueueEdits {
    fn new() -> Self {
        Self {
            writes: [DeviceQueueWrite::U8 {
                address: 0,
                value: 0,
            }; 6],
            length: 0,
        }
    }

    fn push(&mut self, write: DeviceQueueWrite) {
        self.writes[self.length] = write;
        self.length += 1;
    }

    pub fn writes(&self) -> &[DeviceQueueWrite] {
        &self.writes[..self.length]
    }
}

/// The adapter must admit and retain writable storage for every read object and resulting edit
/// under the same exact exclusive lock (or exclusive unpublished construction ownership).
/// Reads may fail before any mutation. `apply` must be ordinary infallible local stores: no IPC,
/// mapping effects, allocation, reentry, or authority changes between validation and application.
/// A backend with potentially uncertain writes does not satisfy this contract.
pub trait LockedDeviceQueueMemory {
    type Error;
    /// Admit exact writable fresh storage under exclusive unpublished construction ownership.
    /// Old bytes have no queue semantics yet; do not decode them or infer an owner from them.
    fn validate_unpublished_queue_storage(&self, address: u64) -> Result<(), Self::Error>;
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error>;
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error>;
    fn apply(&mut self, edits: &DeviceQueueEdits);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceQueueError<E> {
    Memory(E),
    InvalidAddress,
    InvalidQueue,
    MalformedList,
    AlreadyInserted,
}

fn address<E>(value: u64, length: usize) -> Result<(), DeviceQueueError<E>> {
    if value == 0 || value & 7 != 0 || value.checked_add(length as u64).is_none() {
        Err(DeviceQueueError::InvalidAddress)
    } else {
        Ok(())
    }
}

fn entry_address<E>(queue: u64, entry: u64) -> Result<(), DeviceQueueError<E>> {
    address(entry, DEVICE_QUEUE_ENTRY_SIZE)?;
    if entry < queue + DEVICE_QUEUE_SIZE as u64 && queue < entry + DEVICE_QUEUE_ENTRY_SIZE as u64 {
        return Err(DeviceQueueError::InvalidAddress);
    }
    Ok(())
}

/// Initialize only fresh, unpublished queue storage, not a live queue or its held spin lock.
pub fn initialize_device_queue<M: LockedDeviceQueueMemory>(
    memory: &mut M,
    queue: u64,
) -> Result<(), DeviceQueueError<M::Error>> {
    address(queue, DEVICE_QUEUE_SIZE)?;
    memory
        .validate_unpublished_queue_storage(queue)
        .map_err(DeviceQueueError::Memory)?;
    let head = queue + DEVICE_QUEUE_LIST_OFFSET;
    let mut edits = DeviceQueueEdits::new();
    edits.push(DeviceQueueWrite::U16 {
        address: queue,
        value: DEVICE_QUEUE_TYPE,
    });
    edits.push(DeviceQueueWrite::U16 {
        address: queue + 2,
        value: DEVICE_QUEUE_SIZE as u16,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: head,
        value: head,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: head + 8,
        value: head,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: queue + 24,
        value: 0,
    });
    edits.push(DeviceQueueWrite::U8 {
        address: queue + 32,
        value: 0,
    });
    memory.apply(&edits);
    Ok(())
}

fn validated<M: LockedDeviceQueueMemory>(
    memory: &M,
    queue: u64,
) -> Result<DeviceQueueSnapshot, DeviceQueueError<M::Error>> {
    address(queue, DEVICE_QUEUE_SIZE)?;
    let state = memory.queue(queue).map_err(DeviceQueueError::Memory)?;
    if state.type_ != DEVICE_QUEUE_TYPE || usize::from(state.size) != DEVICE_QUEUE_SIZE {
        return Err(DeviceQueueError::InvalidQueue);
    }
    let head = queue + DEVICE_QUEUE_LIST_OFFSET;
    let mut previous = head;
    let mut next = state.flink;
    while next != head {
        entry_address(queue, next)?;
        let entry = memory.entry(next).map_err(DeviceQueueError::Memory)?;
        // Reciprocal backlinks reject a repeated node/cycle without an allocation or capacity cap.
        if !entry.inserted || entry.blink != previous {
            return Err(DeviceQueueError::MalformedList);
        }
        previous = next;
        next = entry.flink;
    }
    if state.blink != previous || (!state.busy && previous != head) {
        return Err(DeviceQueueError::MalformedList);
    }
    Ok(state)
}

/// `false` means the idle queue became busy: the packet was NOT linked and must start immediately.
/// Duplicate active packets (Inserted=false) require the separate DEVICE_OBJECT.CurrentIrp check.
pub fn insert_device_queue<M: LockedDeviceQueueMemory>(
    memory: &mut M,
    queue: u64,
    entry: u64,
    key: Option<u32>,
) -> Result<bool, DeviceQueueError<M::Error>> {
    let state = validated(memory, queue)?;
    entry_address(queue, entry)?;
    let packet = memory.entry(entry).map_err(DeviceQueueError::Memory)?;
    if packet.inserted {
        return Err(DeviceQueueError::AlreadyInserted);
    }
    let mut edits = DeviceQueueEdits::new();
    if let Some(key) = key {
        edits.push(DeviceQueueWrite::U32 {
            address: entry + 16,
            value: key,
        });
    }
    if !state.busy {
        edits.push(DeviceQueueWrite::U8 {
            address: queue + 32,
            value: 1,
        });
        edits.push(DeviceQueueWrite::U8 {
            address: entry + 20,
            value: 0,
        });
        memory.apply(&edits);
        return Ok(false);
    }
    let head = queue + DEVICE_QUEUE_LIST_OFFSET;
    let mut next = head;
    let mut previous = state.blink;
    if let Some(key) = key {
        next = state.flink;
        previous = head;
        while next != head {
            let packet = memory.entry(next).map_err(DeviceQueueError::Memory)?;
            if packet.sort_key > key {
                break;
            }
            previous = next;
            next = packet.flink;
        }
    }
    edits.push(DeviceQueueWrite::U64 {
        address: entry,
        value: next,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: entry + 8,
        value: previous,
    });
    edits.push(DeviceQueueWrite::U8 {
        address: entry + 20,
        value: 1,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: previous,
        value: entry,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: next + 8,
        value: entry,
    });
    memory.apply(&edits);
    Ok(true)
}

fn unlink<M: LockedDeviceQueueMemory>(
    memory: &mut M,
    entry: u64,
    packet: DeviceQueueEntrySnapshot,
) {
    let mut edits = DeviceQueueEdits::new();
    edits.push(DeviceQueueWrite::U64 {
        address: packet.blink,
        value: packet.flink,
    });
    edits.push(DeviceQueueWrite::U64 {
        address: packet.flink + 8,
        value: packet.blink,
    });
    edits.push(DeviceQueueWrite::U8 {
        address: entry + 20,
        value: 0,
    });
    memory.apply(&edits);
}

/// FIFO removal, or NT's keyed elevator selection (first key >= requested, wrapping to head).
pub fn remove_device_queue<M: LockedDeviceQueueMemory>(
    memory: &mut M,
    queue: u64,
    key: Option<u32>,
) -> Result<Option<u64>, DeviceQueueError<M::Error>> {
    let state = validated(memory, queue)?;
    if !state.busy {
        return Err(DeviceQueueError::InvalidQueue);
    }
    let head = queue + DEVICE_QUEUE_LIST_OFFSET;
    if state.flink == head {
        let mut edits = DeviceQueueEdits::new();
        edits.push(DeviceQueueWrite::U8 {
            address: queue + 32,
            value: 0,
        });
        memory.apply(&edits);
        return Ok(None);
    }
    let mut chosen = state.flink;
    if let Some(key) = key {
        while chosen != head {
            let packet = memory.entry(chosen).map_err(DeviceQueueError::Memory)?;
            if packet.sort_key >= key {
                break;
            }
            chosen = packet.flink;
        }
        if chosen == head {
            chosen = state.flink;
        }
    }
    let packet = memory.entry(chosen).map_err(DeviceQueueError::Memory)?;
    unlink(memory, chosen, packet);
    Ok(Some(chosen))
}

/// Remove only this queue's exact inserted member. Removing an active/noninserted entry is false.
pub fn remove_entry_device_queue<M: LockedDeviceQueueMemory>(
    memory: &mut M,
    queue: u64,
    entry: u64,
) -> Result<bool, DeviceQueueError<M::Error>> {
    let state = validated(memory, queue)?;
    if !state.busy {
        return Err(DeviceQueueError::InvalidQueue);
    }
    entry_address(queue, entry)?;
    let packet = memory.entry(entry).map_err(DeviceQueueError::Memory)?;
    if !packet.inserted {
        return Ok(false);
    }
    let head = queue + DEVICE_QUEUE_LIST_OFFSET;
    let mut next = state.flink;
    while next != head && next != entry {
        next = memory.entry(next).map_err(DeviceQueueError::Memory)?.flink;
    }
    if next != entry {
        return Err(DeviceQueueError::MalformedList);
    }
    unlink(memory, entry, packet);
    Ok(true)
}

#[cfg(test)]
#[path = "device_queue_tests.rs"]
mod tests;
