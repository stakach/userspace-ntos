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
const FLUSH: VmFlushOutput = VmFlushOutput {
    range: RANGE,
    iosb: OLD,
};
const QUERY: VmBasicQueryOutput = VmBasicQueryOutput {
    information: 0x800,
    length: crate::MEMORY_BASIC_INFORMATION_X64_SIZE as u64,
    return_length: OLD,
};

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

    fn with_outputs() -> Self {
        let mut memory = Self::initialized();
        memory.seed(OLD, &[0x7f; 16]);
        memory.seed(
            QUERY.information,
            &[0x5a; crate::MEMORY_BASIC_INFORMATION_X64_SIZE],
        );
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

#[test]
fn flush_probes_full_unaligned_iosb_before_capturing_range() {
    let mut memory = Memory::with_outputs();
    let original = memory.bytes.clone();
    assert_eq!(FLUSH.capture(&mut memory, LIMIT), Ok((0x1234, 0x5678)));
    let mut expected = Vec::new();
    for (address, length) in [(RANGE.base_pointer, 8), (RANGE.size_pointer, 8), (OLD, 16)] {
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
fn flush_cross_page_iosb_read_fault_prevents_its_self_write_and_capture() {
    let mut memory = Memory::with_outputs();
    let output = VmFlushOutput {
        iosb: 0x3ff8,
        ..FLUSH
    };
    memory.seed(output.iosb, &[0x77; 16]);
    memory.fail_read = Some(0x4000);
    assert_eq!(
        output.capture(&mut memory, 0x5000),
        Err(STATUS_GUARD_PAGE_VIOLATION)
    );
    assert_eq!(memory.accesses.len(), 32 + 9);
    assert!(memory.accesses[32..]
        .iter()
        .all(|access| matches!(access, Access::Read(_))));
    assert_eq!(memory.accesses.last(), Some(&Access::Read(0x4000)));
}

#[test]
fn flush_probe_failures_stop_before_later_outputs_or_input_capture() {
    for address in [RANGE.base_pointer, RANGE.size_pointer, OLD] {
        let mut memory = Memory::with_outputs();
        memory.fail_read = Some(address);
        assert_eq!(
            FLUSH.capture(&mut memory, LIMIT),
            Err(STATUS_GUARD_PAGE_VIOLATION)
        );
        assert_eq!(memory.accesses.last(), Some(&Access::Read(address)));
        assert_eq!(memory.stores, 0);
    }
}

#[test]
fn flush_stops_at_each_late_store_fault_and_retains_operation_status() {
    for status in [0, 0xC000_0185] {
        for failed_store in [None, Some(1), Some(2), Some(3)] {
            let mut memory = Memory::with_outputs();
            memory.fail_store = failed_store;
            assert_eq!(
                FLUSH.publish(&mut memory, 0x8000, 0x9000, status, 0x1200),
                status
            );
            let addresses: Vec<_> = memory
                .accesses
                .iter()
                .filter_map(|access| match access {
                    Access::Store(address, _) => Some(*address),
                    _ => None,
                })
                .collect();
            assert_eq!(
                addresses,
                [RANGE.size_pointer, RANGE.base_pointer, OLD][..failed_store.unwrap_or(3)]
            );
        }
    }
}

#[test]
fn flush_publishes_the_complete_initialized_iosb() {
    let mut memory = Memory::with_outputs();
    assert_eq!(
        FLUSH.publish(&mut memory, 0x8000, 0x9000, 0xC000_0185, 0x123456789),
        0xC000_0185
    );
    assert_eq!(read_u64(&mut memory, OLD), Ok(0xC000_0185));
    assert_eq!(read_u64(&mut memory, OLD + 8), Ok(0x123456789));
}

#[test]
fn flush_aliased_iosb_is_published_after_range_fields() {
    let mut memory = Memory::with_outputs();
    let output = VmFlushOutput {
        iosb: RANGE.base_pointer,
        ..FLUSH
    };
    assert_eq!(output.publish(&mut memory, 0x8000, 0x9000, 0, 0x42), 0);
    assert_eq!(read_u64(&mut memory, RANGE.base_pointer), Ok(0));
    assert_eq!(read_u64(&mut memory, RANGE.base_pointer + 8), Ok(0x42));
}

#[test]
fn query_minimum_length_and_alignment_precede_range_probing() {
    let mut memory = Memory::with_outputs();
    let output = VmBasicQueryOutput {
        information: u64::MAX,
        length: 47,
        ..QUERY
    };
    assert_eq!(output.probe(&mut memory, LIMIT), Err(0xC000_0004));
    let output = VmBasicQueryOutput {
        length: 48,
        ..output
    };
    assert_eq!(output.probe(&mut memory, LIMIT), Err(0x8000_0002));
    let output = VmBasicQueryOutput {
        information: u64::MAX - 7,
        ..output
    };
    assert_eq!(
        output.probe(&mut memory, LIMIT),
        Err(STATUS_ACCESS_VIOLATION)
    );
    assert!(memory.accesses.is_empty());
}

#[test]
fn query_probes_caller_length_beyond_the_fixed_information_structure() {
    let mut memory = Memory::with_outputs();
    memory.fail_read = Some(0x1000);
    let output = VmBasicQueryOutput {
        length: 0x801,
        ..QUERY
    };
    assert_eq!(
        output.probe(&mut memory, LIMIT),
        Err(STATUS_GUARD_PAGE_VIOLATION)
    );
    assert_eq!(
        memory.accesses,
        vec![
            Access::Read(0x800),
            Access::ProbeWrite(0x800),
            Access::Read(0x1000)
        ]
    );
}

#[test]
fn query_probes_information_before_unaligned_pointer_sized_return_length() {
    let mut memory = Memory::with_outputs();
    assert_eq!(QUERY.probe(&mut memory, LIMIT), Ok(()));
    let mut expected = vec![
        Access::Read(QUERY.information),
        Access::ProbeWrite(QUERY.information),
    ];
    expected.extend((0..8).map(|offset| Access::Read(OLD + offset)));
    expected.extend((0..8).map(|offset| Access::ProbeWrite(OLD + offset)));
    assert_eq!(memory.accesses, expected);
}

#[test]
fn query_cross_page_length_read_fault_precedes_its_self_write() {
    let mut memory = Memory::with_outputs();
    let output = VmBasicQueryOutput {
        return_length: 0x2ffc,
        ..QUERY
    };
    memory.seed(output.return_length, &[0x77; 8]);
    memory.fail_read = Some(0x3000);
    assert_eq!(
        output.probe(&mut memory, LIMIT),
        Err(STATUS_GUARD_PAGE_VIOLATION)
    );
    assert_eq!(memory.accesses.len(), 2 + 5);
    assert!(memory.accesses[2..]
        .iter()
        .all(|access| matches!(access, Access::Read(_))));
    assert_eq!(memory.accesses.last(), Some(&Access::Read(0x3000)));
    assert_eq!(memory.stores, 0);
}

#[test]
fn query_information_copy_fault_skips_return_length_but_length_fault_retains_success() {
    for failed_store in [Some(1), Some(2), None] {
        let mut memory = Memory::with_outputs();
        memory.fail_store = failed_store;
        let bytes = [0x33; crate::MEMORY_BASIC_INFORMATION_X64_SIZE];
        assert_eq!(
            QUERY.publish(&mut memory, &bytes),
            if failed_store == Some(1) {
                Err(STATUS_GUARD_PAGE_VIOLATION)
            } else {
                Ok(())
            }
        );
        assert_eq!(memory.stores, if failed_store == Some(1) { 1 } else { 2 });
        if failed_store != Some(1) {
            assert_eq!(
                read_u64(&mut memory, QUERY.information),
                Ok(0x3333333333333333)
            );
        }
        if failed_store.is_none() {
            assert_eq!(read_u64(&mut memory, OLD), Ok(48));
        }
    }
}

#[test]
fn query_writes_only_the_fixed_structure_and_omits_absent_return_length() {
    let mut memory = Memory::with_outputs();
    let output = VmBasicQueryOutput {
        length: 64,
        return_length: 0,
        ..QUERY
    };
    let bytes = [0x33; crate::MEMORY_BASIC_INFORMATION_X64_SIZE];
    assert_eq!(output.publish(&mut memory, &bytes), Ok(()));
    assert_eq!(
        memory.accesses,
        vec![Access::Store(QUERY.information, bytes.to_vec())]
    );
    assert!(!memory.bytes.contains_key(&(QUERY.information + 48)));
}
