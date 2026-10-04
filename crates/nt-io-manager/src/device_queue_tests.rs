use super::*;
use alloc::vec;
use alloc::vec::Vec;

const Q: u64 = 0x100;
const OTHER: u64 = 0x180;
const A: u64 = 0x200;
const B: u64 = 0x240;
const C: u64 = 0x280;
const D: u64 = 0x2c0;

struct Memory {
    bytes: Vec<u8>,
    applications: usize,
    refuse: Option<u64>,
}

impl Memory {
    fn new() -> Self {
        Self {
            bytes: vec![0; 1024],
            applications: 0,
            refuse: None,
        }
    }
    fn range(&self, address: u64, length: usize) -> Result<&[u8], &'static str> {
        if self.refuse == Some(address) {
            return Err("admission refused");
        }
        let start = usize::try_from(address).map_err(|_| "address")?;
        let end = start.checked_add(length).ok_or("overflow")?;
        self.bytes.get(start..end).ok_or("unmapped")
    }
    fn put64(&mut self, address: u64, value: u64) {
        self.bytes[address as usize..address as usize + 8].copy_from_slice(&value.to_le_bytes());
    }
    fn initialized() -> Self {
        let mut memory = Self::new();
        initialize_device_queue(&mut memory, Q).unwrap();
        memory
    }
    fn active() -> Self {
        let mut memory = Self::initialized();
        assert!(!insert_device_queue(&mut memory, Q, A, None).unwrap());
        memory
    }
}

impl LockedDeviceQueueMemory for Memory {
    type Error = &'static str;
    fn validate_unpublished_queue_storage(&self, address: u64) -> Result<(), Self::Error> {
        self.range(address, DEVICE_QUEUE_SIZE).map(|_| ())
    }
    fn queue(&self, address: u64) -> Result<DeviceQueueSnapshot, Self::Error> {
        DeviceQueueSnapshot::read(self.range(address, DEVICE_QUEUE_SIZE)?)
            .map_err(|_| "queue layout")
    }
    fn entry(&self, address: u64) -> Result<DeviceQueueEntrySnapshot, Self::Error> {
        DeviceQueueEntrySnapshot::read(self.range(address, DEVICE_QUEUE_ENTRY_SIZE)?)
            .map_err(|_| "entry layout")
    }
    fn apply(&mut self, edits: &DeviceQueueEdits) {
        // The test port prevalidates every destination before its first store, like the required
        // locked native adapter. No failure or reentry can occur in the following store loop.
        for write in edits.writes() {
            let (address, length) = match write {
                DeviceQueueWrite::U8 { address, .. } => (*address, 1),
                DeviceQueueWrite::U16 { address, .. } => (*address, 2),
                DeviceQueueWrite::U32 { address, .. } => (*address, 4),
                DeviceQueueWrite::U64 { address, .. } => (*address, 8),
            };
            self.range(address, length).unwrap();
        }
        for write in edits.writes() {
            match *write {
                DeviceQueueWrite::U8 { address, value } => self.bytes[address as usize] = value,
                DeviceQueueWrite::U16 { address, value } => self.bytes
                    [address as usize..address as usize + 2]
                    .copy_from_slice(&value.to_le_bytes()),
                DeviceQueueWrite::U32 { address, value } => self.bytes
                    [address as usize..address as usize + 4]
                    .copy_from_slice(&value.to_le_bytes()),
                DeviceQueueWrite::U64 { address, value } => self.put64(address, value),
            }
        }
        self.applications += 1;
    }
}

#[test]
fn initialization_uses_real_x64_layout_and_preserves_padding() {
    let mut memory = Memory::new();
    memory.bytes[Q as usize + 4..Q as usize + 8].fill(0x55);
    memory.bytes[Q as usize + 33..Q as usize + 40].fill(0x66);
    memory.put64(Q + 24, 0xdead_beef);
    initialize_device_queue(&mut memory, Q).unwrap();
    assert_eq!(
        memory.queue(Q).unwrap(),
        DeviceQueueSnapshot {
            type_: 20,
            size: 40,
            flink: Q + 8,
            blink: Q + 8,
            busy: false,
        }
    );
    assert_eq!(&memory.bytes[Q as usize + 24..Q as usize + 32], &[0; 8]);
    assert_eq!(&memory.bytes[Q as usize + 4..Q as usize + 8], &[0x55; 4]);
    assert_eq!(&memory.bytes[Q as usize + 33..Q as usize + 40], &[0x66; 7]);
    assert_eq!(
        DeviceQueueSnapshot::read(&[0; 39]),
        Err(DeviceQueueLayoutError::Truncated)
    );
    assert_eq!(
        DeviceQueueEntrySnapshot::read(&[0; 23]),
        Err(DeviceQueueLayoutError::Truncated)
    );
}

#[test]
fn initialization_accepts_arbitrary_fresh_unpublished_storage() {
    let mut memory = Memory::new();
    memory.bytes[Q as usize..Q as usize + DEVICE_QUEUE_SIZE].fill(0xaa);
    initialize_device_queue(&mut memory, Q).unwrap();
    assert_eq!(
        memory.queue(Q).unwrap(),
        DeviceQueueSnapshot {
            type_: DEVICE_QUEUE_TYPE,
            size: DEVICE_QUEUE_SIZE as u16,
            flink: Q + 8,
            blink: Q + 8,
            busy: false,
        }
    );
    assert_eq!(&memory.bytes[Q as usize + 24..Q as usize + 32], &[0; 8]);
    assert_eq!(&memory.bytes[Q as usize + 4..Q as usize + 8], &[0xaa; 4]);
    assert_eq!(&memory.bytes[Q as usize + 33..Q as usize + 40], &[0xaa; 7]);
}

#[test]
fn idle_insert_is_not_linked_then_busy_fifo_drains_and_becomes_idle() {
    let mut memory = Memory::initialized();
    memory.put64(Q + 24, 0x1234); // held lock bytes must not be cleared by live operations
    memory.bytes[Q as usize + 33..Q as usize + 40].fill(0x88);
    memory.bytes[B as usize + 21..B as usize + 24].fill(0x99);
    assert!(!insert_device_queue(&mut memory, Q, A, None).unwrap());
    assert!(!memory.entry(A).unwrap().inserted);
    assert_eq!(memory.queue(Q).unwrap().flink, Q + 8);
    assert!(insert_device_queue(&mut memory, Q, B, None).unwrap());
    assert!(insert_device_queue(&mut memory, Q, C, None).unwrap());
    assert_eq!(remove_device_queue(&mut memory, Q, None), Ok(Some(B)));
    assert!(!memory.entry(B).unwrap().inserted);
    assert_eq!(remove_device_queue(&mut memory, Q, None), Ok(Some(C)));
    assert!(memory.queue(Q).unwrap().busy);
    assert_eq!(remove_device_queue(&mut memory, Q, None), Ok(None));
    assert!(!memory.queue(Q).unwrap().busy);
    assert_eq!(
        &memory.bytes[Q as usize + 24..Q as usize + 32],
        &0x1234u64.to_le_bytes()
    );
    assert_eq!(&memory.bytes[Q as usize + 33..Q as usize + 40], &[0x88; 7]);
    assert_eq!(&memory.bytes[B as usize + 21..B as usize + 24], &[0x99; 3]);
}

#[test]
fn sorted_keys_are_stable_and_key_removal_wraps() {
    let mut memory = Memory::active();
    assert!(insert_device_queue(&mut memory, Q, B, Some(30)).unwrap());
    assert!(insert_device_queue(&mut memory, Q, C, Some(10)).unwrap());
    assert!(insert_device_queue(&mut memory, Q, D, Some(30)).unwrap());
    assert_eq!(memory.queue(Q).unwrap().flink, C);
    assert_eq!(memory.entry(C).unwrap().flink, B);
    assert_eq!(memory.entry(B).unwrap().flink, D);
    assert_eq!(remove_device_queue(&mut memory, Q, Some(20)), Ok(Some(B)));
    // NT5 selects the first key >= requested, wrapping only when no key qualifies.
    assert_eq!(remove_device_queue(&mut memory, Q, Some(30)), Ok(Some(D)));
    assert_eq!(remove_device_queue(&mut memory, Q, Some(31)), Ok(Some(C)));
    assert_eq!(remove_device_queue(&mut memory, Q, None), Ok(None));
}

#[test]
fn keyed_equal_tail_selects_matching_entry_instead_of_wrapping() {
    let mut memory = Memory::active();
    insert_device_queue(&mut memory, Q, B, Some(10)).unwrap();
    insert_device_queue(&mut memory, Q, C, Some(30)).unwrap();
    assert_eq!(remove_device_queue(&mut memory, Q, Some(30)), Ok(Some(C)));
    assert!(memory.entry(B).unwrap().inserted);
    assert!(!memory.entry(C).unwrap().inserted);
}

#[test]
fn mixed_fifo_and_keyed_insert_scans_actual_list_not_last_key() {
    let mut memory = Memory::active();
    // FIFO insertion does not promise sorted keys. NT5 keyed insertion scans the actual list.
    memory.bytes[B as usize + 16..B as usize + 20].copy_from_slice(&30u32.to_le_bytes());
    memory.bytes[C as usize + 16..C as usize + 20].copy_from_slice(&10u32.to_le_bytes());
    insert_device_queue(&mut memory, Q, B, None).unwrap();
    insert_device_queue(&mut memory, Q, C, None).unwrap();
    insert_device_queue(&mut memory, Q, D, Some(20)).unwrap();
    assert_eq!(memory.queue(Q).unwrap().flink, D);
    assert_eq!(memory.entry(D).unwrap().flink, B);
    assert_eq!(memory.entry(B).unwrap().flink, C);
    assert_eq!(memory.entry(C).unwrap().flink, Q + 8);
}

#[test]
fn exact_remove_checks_membership_and_clears_only_inserted_flag() {
    let mut memory = Memory::active();
    insert_device_queue(&mut memory, Q, B, Some(7)).unwrap();
    insert_device_queue(&mut memory, Q, C, Some(8)).unwrap();
    let packet = memory.entry(B).unwrap();
    assert_eq!(remove_entry_device_queue(&mut memory, Q, B), Ok(true));
    assert_eq!(
        memory.entry(B).unwrap(),
        DeviceQueueEntrySnapshot {
            inserted: false,
            ..packet
        }
    );
    assert_eq!(remove_entry_device_queue(&mut memory, Q, B), Ok(false));
    assert_eq!(remove_entry_device_queue(&mut memory, Q, A), Ok(false));
    assert_eq!(remove_device_queue(&mut memory, Q, None), Ok(Some(C)));
    assert_eq!(remove_device_queue(&mut memory, Q, None), Ok(None));
}

#[test]
fn foreign_inserted_entry_and_duplicate_are_rejected_without_mutation() {
    let mut memory = Memory::active();
    initialize_device_queue(&mut memory, OTHER).unwrap();
    insert_device_queue(&mut memory, OTHER, C, None).unwrap();
    insert_device_queue(&mut memory, OTHER, D, None).unwrap();
    insert_device_queue(&mut memory, Q, B, None).unwrap();
    let before = memory.bytes.clone();
    let applications = memory.applications;
    assert_eq!(
        insert_device_queue(&mut memory, Q, B, None),
        Err(DeviceQueueError::AlreadyInserted)
    );
    assert_eq!(
        remove_entry_device_queue(&mut memory, Q, D),
        Err(DeviceQueueError::MalformedList)
    );
    assert_eq!(
        insert_device_queue(&mut memory, Q, D, None),
        Err(DeviceQueueError::AlreadyInserted)
    );
    assert_eq!(memory.bytes, before);
    assert_eq!(memory.applications, applications);
}

#[test]
fn malformed_links_cycle_flags_and_storage_refusal_have_no_effect() {
    for corruption in 0..5 {
        let mut memory = Memory::active();
        insert_device_queue(&mut memory, Q, B, None).unwrap();
        insert_device_queue(&mut memory, Q, C, None).unwrap();
        match corruption {
            0 => memory.put64(C + 8, Q + 8), // wrong predecessor
            1 => memory.put64(C, B),         // cycle not returning to head
            2 => memory.bytes[B as usize + 20] = 0,
            3 => memory.put64(Q + 16, B), // wrong final backlink
            _ => memory.refuse = Some(C),
        }
        let before = memory.bytes.clone();
        let applications = memory.applications;
        assert!(insert_device_queue(&mut memory, Q, D, None).is_err());
        assert!(remove_device_queue(&mut memory, Q, None).is_err());
        assert!(remove_entry_device_queue(&mut memory, Q, B).is_err());
        assert_eq!(memory.bytes, before);
        assert_eq!(memory.applications, applications);
    }
}

#[test]
fn null_unaligned_overflow_overlap_and_uninitialized_queues_are_denied() {
    let mut memory = Memory::initialized();
    let before = memory.bytes.clone();
    let applications = memory.applications;
    for queue in [0, Q + 1, u64::MAX - 7, OTHER] {
        assert!(insert_device_queue(&mut memory, queue, B, None).is_err());
    }
    for entry in [0, B + 1, u64::MAX - 7, Q, Q + 8, Q - 8] {
        assert_eq!(
            insert_device_queue(&mut memory, Q, entry, None),
            Err(DeviceQueueError::InvalidAddress)
        );
    }
    assert_eq!(
        remove_device_queue(&mut memory, Q, None),
        Err(DeviceQueueError::InvalidQueue)
    );
    assert_eq!(memory.bytes, before);
    assert_eq!(memory.applications, applications);
}
