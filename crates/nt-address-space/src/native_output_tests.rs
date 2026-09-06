use super::*;
use crate::copy::STATUS_GUARD_PAGE_VIOLATION;
use crate::STATUS_ACCESS_VIOLATION;
use alloc::{collections::BTreeMap, vec, vec::Vec};

const RANGE: VmRangeOutput = VmRangeOutput {
    base_pointer: 0x1001,
    size_pointer: 0x2003,
};
const OLD: u64 = 0x3001;
const LIMIT: u64 = 0x4000;

#[derive(Debug, PartialEq, Eq)]
enum Access {
    Read(u64),
    ProbeWrite(u64),
    Store(u64, Vec<u8>),
}

#[derive(Default)]
struct Memory {
    bytes: BTreeMap<u64, u8>,
    accesses: Vec<Access>,
    fail_read: Option<u64>,
    fail_probe_write: Option<u64>,
    fail_store: Option<usize>,
    stores: usize,
}

impl Memory {
    fn seed(&mut self, address: u64, bytes: &[u8]) {
        for (offset, byte) in bytes.iter().enumerate() {
            self.bytes.insert(address + offset as u64, *byte);
        }
    }

    fn initialized() -> Self {
        let mut memory = Self::default();
        memory.seed(RANGE.base_pointer, &0x1234u64.to_le_bytes());
        memory.seed(RANGE.size_pointer, &0x5678u64.to_le_bytes());
        memory.seed(OLD, &0x20u32.to_le_bytes());
        memory
    }
}

impl WriteProbeMemory for Memory {
    fn read_byte(&mut self, address: u64) -> Result<u8, u32> {
        self.accesses.push(Access::Read(address));
        if self.fail_read == Some(address) {
            return Err(STATUS_GUARD_PAGE_VIOLATION);
        }
        self.bytes
            .get(&address)
            .copied()
            .ok_or(STATUS_ACCESS_VIOLATION)
    }

    fn write_byte(&mut self, address: u64, value: u8) -> Result<(), u32> {
        self.accesses.push(Access::ProbeWrite(address));
        if self.fail_probe_write == Some(address) {
            return Err(STATUS_ACCESS_VIOLATION);
        }
        self.bytes.insert(address, value);
        Ok(())
    }
}

impl VmOutputMemory for Memory {
    fn write_bytes(&mut self, address: u64, bytes: &[u8]) -> Result<(), u32> {
        self.accesses.push(Access::Store(address, bytes.to_vec()));
        self.stores += 1;
        if self.fail_store == Some(self.stores) {
            return Err(STATUS_GUARD_PAGE_VIOLATION);
        }
        self.seed(address, bytes);
        Ok(())
    }
}

#[test]
fn unaligned_capture_probes_base_size_old_before_reading_inputs() {
    let mut memory = Memory::initialized();
    let original = memory.bytes.clone();
    assert_eq!(
        RANGE.capture(&mut memory, Some(OLD), LIMIT),
        Ok((0x1234, 0x5678))
    );
    let mut expected = Vec::new();
    for (address, length) in [(RANGE.base_pointer, 8), (RANGE.size_pointer, 8), (OLD, 4)] {
        expected.extend((0..length).map(|offset| Access::Read(address + offset)));
        expected.extend((0..length).map(|offset| Access::ProbeWrite(address + offset)));
    }
    for address in [RANGE.base_pointer, RANGE.size_pointer] {
        expected.extend((0..8).map(|offset| Access::Read(address + offset)));
    }
    assert_eq!(memory.accesses, expected);
    assert_eq!(memory.bytes, original);
}

#[test]
fn each_probe_fault_stops_capture_and_retains_its_exact_status() {
    for address in [RANGE.base_pointer, RANGE.size_pointer, OLD] {
        let mut memory = Memory::initialized();
        memory.fail_read = Some(address);
        assert_eq!(
            RANGE.capture(&mut memory, Some(OLD), LIMIT),
            Err(STATUS_GUARD_PAGE_VIOLATION)
        );
        assert_eq!(memory.accesses.last(), Some(&Access::Read(address)));
        assert_eq!(memory.stores, 0);
    }
}

#[test]
fn readonly_scalar_stops_before_later_outputs_or_capture() {
    let mut memory = Memory::initialized();
    memory.fail_probe_write = Some(RANGE.base_pointer);
    assert_eq!(
        RANGE.capture(&mut memory, None, LIMIT),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert_eq!(memory.accesses.len(), 9);
    assert_eq!(
        memory.accesses.last(),
        Some(&Access::ProbeWrite(RANGE.base_pointer))
    );
}

#[test]
fn invalid_first_scalar_is_rejected_without_accessing_memory() {
    let mut memory = Memory::initialized();
    let range = VmRangeOutput {
        base_pointer: LIMIT - 7,
        ..RANGE
    };
    assert_eq!(
        range.capture(&mut memory, None, LIMIT),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert!(memory.accesses.is_empty());
}

#[test]
fn publication_writes_size_then_base() {
    let mut memory = Memory::initialized();
    assert_eq!(RANGE.publish(&mut memory, 0x8000, 0x9000), Ok(()));
    assert_eq!(
        memory.accesses,
        vec![
            Access::Store(RANGE.size_pointer, 0x9000u64.to_le_bytes().to_vec()),
            Access::Store(RANGE.base_pointer, 0x8000u64.to_le_bytes().to_vec()),
        ]
    );
}

#[test]
fn publication_stops_at_each_fault_without_undoing_prior_stores() {
    for failed_store in 1..=2 {
        let mut memory = Memory::initialized();
        memory.fail_store = Some(failed_store);
        assert_eq!(
            RANGE.publish(&mut memory, 0x8000, 0x9000),
            Err(STATUS_GUARD_PAGE_VIOLATION)
        );
        assert_eq!(memory.stores, failed_store);
        assert_eq!(read_u64(&mut memory, RANGE.base_pointer), Ok(0x1234));
        assert_eq!(
            read_u64(&mut memory, RANGE.size_pointer),
            Ok(if failed_store == 1 { 0x5678 } else { 0x9000 })
        );
    }
}

#[test]
fn aliased_range_outputs_retain_native_store_order() {
    let mut memory = Memory::initialized();
    let range = VmRangeOutput {
        size_pointer: RANGE.base_pointer,
        ..RANGE
    };
    assert_eq!(range.publish(&mut memory, 0x8000, 0x9000), Ok(()));
    assert_eq!(read_u64(&mut memory, RANGE.base_pointer), Ok(0x8000));
}

#[test]
fn protection_reprobes_every_output_before_any_final_store() {
    for inaccessible in [RANGE.base_pointer, RANGE.size_pointer, OLD] {
        let mut memory = Memory::initialized();
        memory.fail_probe_write = Some(inaccessible);
        assert_eq!(
            RANGE.publish_protection(&mut memory, 0x8000, 0x9000, (OLD, 0x40), LIMIT),
            Err(STATUS_ACCESS_VIOLATION)
        );
        assert_eq!(memory.stores, 0);
    }
}

#[test]
fn protection_stores_size_base_old_and_stops_at_each_late_fault() {
    for failed_store in [None, Some(1), Some(2), Some(3)] {
        let mut memory = Memory::initialized();
        memory.fail_store = failed_store;
        assert_eq!(
            RANGE.publish_protection(&mut memory, 0x8000, 0x9000, (OLD, 0x40), LIMIT),
            failed_store.map_or(Ok(()), |_| Err(STATUS_GUARD_PAGE_VIOLATION))
        );
        let stores: Vec<_> = memory
            .accesses
            .iter()
            .filter_map(|access| match access {
                Access::Store(address, _) => Some(*address),
                _ => None,
            })
            .collect();
        assert_eq!(
            stores,
            [RANGE.size_pointer, RANGE.base_pointer, OLD][..failed_store.unwrap_or(3)]
        );
    }
}
