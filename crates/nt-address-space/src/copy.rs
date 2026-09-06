//! Bounded, fault-aware virtual-memory copy ordering, independent of physical page ownership.

use crate::{
    vm_access_page_plan, FaultAccess, VmBasicInformation, VmResidencyPagePlan, PAGE_GUARD,
    PAGE_SIZE, STATUS_ACCESS_VIOLATION, STATUS_SUCCESS,
};

pub const STATUS_PARTIAL_COPY: u32 = 0x8000_000D;
pub const STATUS_GUARD_PAGE_VIOLATION: u32 = 0x8000_0001;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyPagePlan {
    Resident(VmResidencyPagePlan),
    ConsumeGuard(VmResidencyPagePlan),
}

/// Guard consumption is a protection transition, not residency admission. The caller must publish
/// it before raising the guard exception, and must not consume another process's guard.
pub fn copy_page_plan(
    page: u64,
    mut info: VmBasicInformation,
    access: FaultAccess,
    attached: bool,
) -> Result<CopyPagePlan, u32> {
    let guarded = info.protect & PAGE_GUARD != 0;
    info.protect &= !PAGE_GUARD;
    let plan = vm_access_page_plan(page, info, access)?;
    if !guarded {
        return Ok(CopyPagePlan::Resident(plan));
    }
    if attached {
        return Err(STATUS_ACCESS_VIOLATION);
    }
    Ok(CopyPagePlan::ConsumeGuard(plan))
}

pub trait WriteProbeMemory {
    fn read_byte(&mut self, address: u64) -> Result<u8, u32>;
    fn write_byte(&mut self, address: u64, value: u8) -> Result<(), u32>;
}

/// Copy stable kernel bytes through exact page-contained writes. Validate the whole destination
/// range first; a later fault preserves completed chunks and never retries via another alias.
pub fn write_kernel_buffer(
    address: u64,
    input: &[u8],
    user_limit: u64,
    mut write_page: impl FnMut(u64, &[u8]) -> Result<(), u32>,
) -> Result<(), u32> {
    if input.is_empty() {
        return Ok(());
    }
    address
        .checked_add(input.len() as u64)
        .filter(|end| *end <= user_limit)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    let chunks = crate::page_chunks(address, input.len()).ok_or(STATUS_ACCESS_VIOLATION)?;
    let mut copied = 0;
    for chunk in chunks {
        write_page(
            address + copied as u64,
            &input[copied..copied + chunk.length],
        )?;
        copied += chunk.length;
    }
    Ok(())
}

#[cfg(test)]
#[path = "copy_kernel_buffer_tests.rs"]
mod kernel_buffer_tests;

/// The native SIZE_T output probe captures the complete value before its self-write. This differs
/// from probing a range page by page when an unaligned count straddles a guard page.
pub fn probe_write_u64(memory: &mut impl WriteProbeMemory, address: u64) -> Result<(), u32> {
    probe_write_scalar::<8>(memory, address, u64::MAX)
}

/// Scalar outputs may be unaligned. Capture every byte before the first self-write so a later
/// read fault cannot cause an earlier page's COW promotion.
pub fn probe_write_scalar<const N: usize>(
    memory: &mut impl WriteProbeMemory,
    address: u64,
    user_limit: u64,
) -> Result<(), u32> {
    if N == 0 {
        return Ok(());
    }
    address
        .checked_add(N as u64)
        .filter(|end| *end <= user_limit)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    let mut value = [0; N];
    for (offset, byte) in value.iter_mut().enumerate() {
        *byte = memory.read_byte(address + offset as u64)?;
    }
    for (offset, byte) in value.into_iter().enumerate() {
        memory.write_byte(address + offset as u64, byte)?;
    }
    Ok(())
}

/// Validate the entire user range before probing any page; an empty output touches no address.
pub fn probe_write_user_range(
    memory: &mut impl WriteProbeMemory,
    address: u64,
    length: u64,
    user_limit: u64,
) -> Result<(), u32> {
    if length == 0 {
        return Ok(());
    }
    address
        .checked_add(length)
        .filter(|end| *end <= user_limit)
        .ok_or(STATUS_ACCESS_VIOLATION)?;
    probe_write_range(memory, address, length)
}

/// Native write probing reads before self-writing each touched page. A readable guard therefore
/// faults before write permission is tested; a write-only metadata check has different semantics.
pub fn probe_write_range(
    memory: &mut impl WriteProbeMemory,
    address: u64,
    length: u64,
) -> Result<(), u32> {
    let end = address.checked_add(length).ok_or(STATUS_ACCESS_VIOLATION)?;
    let mut current = address;
    while current < end {
        let value = memory.read_byte(current)?;
        memory.write_byte(current, value)?;
        let step = (PAGE_SIZE - current % PAGE_SIZE).min(end - current);
        current += step;
    }
    Ok(())
}

/// Each transfer is contained in one source and one destination page. Implementations must
/// validate access and make backing resident before touching bytes. An unsuccessful write must
/// leave that chunk unchanged; completed earlier chunks are not rolled back.
pub trait VirtualMemoryCopy {
    fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), u32>;
    fn probe_write(&mut self, address: u64, length: u64) -> Result<(), u32>;
    fn write(&mut self, address: u64, input: &[u8]) -> Result<(), u32>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CopyResult {
    pub status: u32,
    pub transferred: u64,
}

/// Stage source bytes before probing the destination: paging the destination can evict source
/// backing. The first destination probe covers the whole range before any copy writes occur.
pub fn copy_virtual_memory(
    memory: &mut impl VirtualMemoryCopy,
    source: u64,
    destination: u64,
    length: u64,
) -> CopyResult {
    let mut result = CopyResult {
        status: STATUS_SUCCESS,
        transferred: 0,
    };
    if source.checked_add(length).is_none() || destination.checked_add(length).is_none() {
        result.status = STATUS_ACCESS_VIOLATION;
        return result;
    }
    let mut staging = [0; 256];
    while result.transferred < length {
        let source_address = source + result.transferred;
        let destination_address = destination + result.transferred;
        let chunk = (length - result.transferred)
            .min(staging.len() as u64)
            .min(PAGE_SIZE - source_address % PAGE_SIZE)
            .min(PAGE_SIZE - destination_address % PAGE_SIZE) as usize;
        if memory.read(source_address, &mut staging[..chunk]).is_err() {
            result.status = STATUS_PARTIAL_COPY;
            return result;
        }
        if result.transferred == 0 {
            if let Err(status) = memory.probe_write(destination, length) {
                result.status = status;
                return result;
            }
        }
        if memory
            .write(destination_address, &staging[..chunk])
            .is_err()
        {
            result.status = STATUS_PARTIAL_COPY;
            return result;
        }
        result.transferred += chunk as u64;
    }
    result
}

#[cfg(test)]
#[path = "copy_guard_tests.rs"]
mod guard_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{vec, vec::Vec};

    #[derive(Debug, PartialEq, Eq)]
    enum Event {
        Read(u64, usize),
        Probe(u64, u64),
        Write(u64, usize),
    }

    struct Memory {
        bytes: Vec<u8>,
        events: Vec<Event>,
        read_failure: Option<u64>,
        write_failure: Option<u64>,
        probe_failure: Option<u32>,
        erase_source_on_probe: bool,
    }

    impl Memory {
        fn new() -> Self {
            Self {
                bytes: vec![0x5a; 0x10000],
                events: Vec::new(),
                read_failure: None,
                write_failure: None,
                probe_failure: None,
                erase_source_on_probe: false,
            }
        }
    }

    impl VirtualMemoryCopy for Memory {
        fn read(&mut self, address: u64, output: &mut [u8]) -> Result<(), u32> {
            self.events.push(Event::Read(address, output.len()));
            if self.read_failure.is_some_and(|start| address >= start) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            output.copy_from_slice(&self.bytes[address as usize..address as usize + output.len()]);
            Ok(())
        }
        fn probe_write(&mut self, address: u64, length: u64) -> Result<(), u32> {
            self.events.push(Event::Probe(address, length));
            if self.erase_source_on_probe {
                self.bytes[..0x1000].fill(0);
            }
            self.probe_failure.map_or(Ok(()), Err)
        }
        fn write(&mut self, address: u64, input: &[u8]) -> Result<(), u32> {
            self.events.push(Event::Write(address, input.len()));
            if self.write_failure.is_some_and(|start| address >= start) {
                return Err(STATUS_ACCESS_VIOLATION);
            }
            self.bytes[address as usize..address as usize + input.len()].copy_from_slice(input);
            Ok(())
        }
    }

    #[test]
    fn staging_survives_source_eviction_during_destination_probe() {
        let mut memory = Memory::new();
        memory.erase_source_on_probe = true;
        assert_eq!(
            copy_virtual_memory(&mut memory, 0, 0x2000, 16),
            CopyResult {
                status: 0,
                transferred: 16
            }
        );
        assert_eq!(&memory.bytes[0x2000..0x2010], &[0x5a; 16]);
        assert_eq!(
            memory.events,
            vec![
                Event::Read(0, 16),
                Event::Probe(0x2000, 16),
                Event::Write(0x2000, 16)
            ]
        );
    }

    #[test]
    fn chunks_obey_both_page_boundaries_and_probe_only_once() {
        let mut memory = Memory::new();
        assert_eq!(
            copy_virtual_memory(&mut memory, 0xff0, 0x2ff8, 0x321),
            CopyResult {
                status: 0,
                transferred: 0x321
            }
        );
        assert_eq!(memory.events[0], Event::Read(0xff0, 8));
        assert_eq!(memory.events[3], Event::Read(0xff8, 8));
        assert_eq!(
            memory
                .events
                .iter()
                .filter(|event| matches!(event, Event::Probe(..)))
                .count(),
            1
        );
        for event in memory.events {
            if let Event::Read(address, size) | Event::Write(address, size) = event {
                assert!(size <= 256);
                assert!(address % PAGE_SIZE + size as u64 <= PAGE_SIZE);
            }
        }
    }

    #[test]
    fn source_failure_precedes_destination_probe() {
        let mut memory = Memory::new();
        memory.read_failure = Some(0);
        memory.probe_failure = Some(STATUS_ACCESS_VIOLATION);
        assert_eq!(
            copy_virtual_memory(&mut memory, 0, 0x2000, 512),
            CopyResult {
                status: STATUS_PARTIAL_COPY,
                transferred: 0
            }
        );
        assert_eq!(memory.events, vec![Event::Read(0, 256)]);
    }

    #[test]
    fn destination_probe_failure_preserves_status_and_all_bytes() {
        let mut memory = Memory::new();
        memory.probe_failure = Some(0x8000_0001);
        let before = memory.bytes.clone();
        assert_eq!(
            copy_virtual_memory(&mut memory, 0, 0x2000, 512),
            CopyResult {
                status: 0x8000_0001,
                transferred: 0
            }
        );
        assert_eq!(memory.bytes, before);
        assert!(!memory
            .events
            .iter()
            .any(|event| matches!(event, Event::Write(..))));
    }

    #[test]
    fn later_faults_count_only_completed_destination_chunks() {
        for write in [false, true] {
            let mut memory = Memory::new();
            if write {
                memory.write_failure = Some(0x2100);
            } else {
                memory.read_failure = Some(0x100);
            }
            assert_eq!(
                copy_virtual_memory(&mut memory, 0, 0x2000, 512),
                CopyResult {
                    status: STATUS_PARTIAL_COPY,
                    transferred: 256
                }
            );
        }
    }

    #[test]
    fn empty_and_overflowing_copies_do_not_touch_memory() {
        let mut memory = Memory::new();
        assert_eq!(
            copy_virtual_memory(&mut memory, u64::MAX, u64::MAX, 0),
            CopyResult {
                status: 0,
                transferred: 0
            }
        );
        for (source, destination) in [(u64::MAX, 0), (0, u64::MAX)] {
            assert_eq!(
                copy_virtual_memory(&mut memory, source, destination, 1),
                CopyResult {
                    status: STATUS_ACCESS_VIOLATION,
                    transferred: 0
                }
            );
        }
        assert!(memory.events.is_empty());
    }
}
