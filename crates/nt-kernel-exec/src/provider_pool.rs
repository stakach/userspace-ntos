//! Offset-based reclaiming pool mechanics for shared kernel-provider arenas.
//!
//! Serialization is deliberately supplied by the embedding component: the executive and provider
//! can map the same physical arena into separate address spaces, so the lock must live in that
//! shared arena. Once locked, this module validates the complete address-ordered free list before
//! mutating it and uses offsets exclusively, making the mechanics host-testable.

pub const ALIGNMENT: u64 = 16;
pub const HEADER_SIZE: u64 = 32;
pub const DATA_OFFSET: u64 = 0x1000;
pub const LOCK_OFFSET: u64 = 0x10;
pub const MAGIC_OFFSET: u64 = 0x18;
pub const MAGIC: u64 = 0x504f_4f4c_0000_0003;

const BUMP_OFFSET: u64 = 0;
const FREE_HEAD_OFFSET: u64 = 8;
const ALLOC_MARKER: u64 = 0xffff_ffff_ffff_fffc;
const ALLOCATION_GENERATION_OFFSET: u64 = 16;
const HEADER_RESERVED_OFFSET: u64 = 24;
const STATS_ALLOCATIONS: u64 = 0x20;
const STATS_FREES: u64 = 0x28;
const STATS_REUSES: u64 = 0x30;
const STATS_INVALID_FREES: u64 = 0x38;
const STATS_LIVE_BYTES: u64 = 0x40;
const STATS_LIVE_HIGH_WATER: u64 = 0x48;
const STATS_ARENA_HIGH_WATER: u64 = 0x50;
const STATS_OOM: u64 = 0x58;
const STATS_CORRUPTION: u64 = 0x60;
const NEXT_ALLOCATION_GENERATION: u64 = 0x68;

/// Minimal memory boundary used by both the volatile provider mapping and host specs.
pub trait PoolMemory {
    fn len(&self) -> u64;
    fn read_u64(&self, offset: u64) -> Option<u64>;
    fn write_u64(&mut self, offset: u64, value: u64) -> bool;
    fn zero(&mut self, offset: u64, len: u64) -> bool;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PoolCensus {
    pub allocations: u64,
    pub frees: u64,
    pub reuses: u64,
    pub invalid_frees: u64,
    pub live_bytes: u64,
    pub live_high_water: u64,
    pub arena_high_water: u64,
    pub out_of_memory: u64,
    pub corruptions: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Allocation {
    pub payload_offset: u64,
    pub capacity: u64,
    pub reused: bool,
    pub identity: AllocationIdentity,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationIdentity {
    pub allocation_id: u64,
    pub allocation_generation: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocationLocation {
    pub identity: AllocationIdentity,
    pub payload_offset: u64,
    pub capacity: u64,
    pub offset: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PoolError {
    ArenaTooSmall,
    NotInitialized,
    InvalidSize,
    OutOfMemory,
    InvalidPointer,
    NotAllocated,
    GenerationExhausted,
    Corrupt,
}

fn read<M: PoolMemory>(memory: &M, offset: u64) -> Result<u64, PoolError> {
    memory.read_u64(offset).ok_or(PoolError::Corrupt)
}

fn write<M: PoolMemory>(memory: &mut M, offset: u64, value: u64) -> Result<(), PoolError> {
    if memory.write_u64(offset, value) {
        Ok(())
    } else {
        Err(PoolError::Corrupt)
    }
}

fn add_stat<M: PoolMemory>(memory: &mut M, offset: u64, amount: u64) {
    if let Some(value) = memory.read_u64(offset) {
        let _ = memory.write_u64(offset, value.saturating_add(amount));
    }
}

fn set_max<M: PoolMemory>(memory: &mut M, offset: u64, candidate: u64) {
    if let Some(value) = memory.read_u64(offset) {
        if candidate > value {
            let _ = memory.write_u64(offset, candidate);
        }
    }
}

fn checked_align(value: u64) -> Result<u64, PoolError> {
    value
        .checked_add(ALIGNMENT - 1)
        .map(|v| v & !(ALIGNMENT - 1))
        .ok_or(PoolError::InvalidSize)
}

fn initialized<M: PoolMemory>(memory: &M) -> bool {
    memory.len() >= DATA_OFFSET + HEADER_SIZE + ALIGNMENT
        && memory.read_u64(MAGIC_OFFSET) == Some(MAGIC)
}

/// Initialize a freshly mapped arena. The embedding boundary must guarantee exclusive access and
/// publish the magic word only after these writes complete.
pub fn initialize<M: PoolMemory>(memory: &mut M) -> Result<(), PoolError> {
    if memory.len() < DATA_OFFSET + HEADER_SIZE + ALIGNMENT {
        return Err(PoolError::ArenaTooSmall);
    }
    for offset in (0..=NEXT_ALLOCATION_GENERATION).step_by(8) {
        write(memory, offset, 0)?;
    }
    write(memory, BUMP_OFFSET, DATA_OFFSET)?;
    write(memory, STATS_ARENA_HIGH_WATER, DATA_OFFSET)?;
    write(memory, MAGIC_OFFSET, MAGIC)?;
    Ok(())
}

fn next_allocation_generation<M: PoolMemory>(memory: &mut M) -> Result<u64, PoolError> {
    let generation = read(memory, NEXT_ALLOCATION_GENERATION)?
        .checked_add(1)
        .ok_or(PoolError::GenerationExhausted)?;
    write(memory, NEXT_ALLOCATION_GENERATION, generation)?;
    Ok(generation)
}

pub fn is_initialized<M: PoolMemory>(memory: &M) -> bool {
    initialized(memory)
}

/// Return the aligned capacity of an exact live allocation without mutating allocator state.
/// Embedders use this to validate typed ownership before clearing the final published pointer.
pub fn allocation_capacity<M: PoolMemory>(memory: &M, payload: u64) -> Result<u64, PoolError> {
    live_allocation(memory, payload).map(|(capacity, _)| capacity)
}

/// Return the exact generation of a live allocation. A recycled payload offset never retains the
/// previous identity, allowing embedded dispatcher objects to fence address reuse.
pub fn allocation_identity<M: PoolMemory>(
    memory: &M,
    payload: u64,
) -> Result<AllocationIdentity, PoolError> {
    let (_, generation) = live_allocation(memory, payload)?;
    Ok(AllocationIdentity {
        allocation_id: payload,
        allocation_generation: generation,
    })
}

/// Locate the live allocation containing an embedded provider object. Free blocks and header bytes
/// never resolve, and `required` must fit wholly within the same payload.
pub fn containing_allocation<M: PoolMemory>(
    memory: &M,
    address: u64,
    required: u64,
) -> Result<AllocationLocation, PoolError> {
    if !initialized(memory) {
        return Err(PoolError::NotInitialized);
    }
    if required == 0 {
        return Err(PoolError::InvalidSize);
    }
    validate_free_list(memory)?;
    let required_end = address
        .checked_add(required)
        .ok_or(PoolError::InvalidPointer)?;
    let bump = read(memory, BUMP_OFFSET)?;
    let mut header = DATA_OFFSET;
    while header < bump {
        let capacity = read(memory, header)?;
        if capacity == 0 || capacity & (ALIGNMENT - 1) != 0 {
            return Err(PoolError::Corrupt);
        }
        let payload = header.checked_add(HEADER_SIZE).ok_or(PoolError::Corrupt)?;
        let end = payload.checked_add(capacity).ok_or(PoolError::Corrupt)?;
        if end > bump {
            return Err(PoolError::Corrupt);
        }
        if address >= payload && required_end <= end {
            if read(memory, header + 8)? != ALLOC_MARKER {
                return Err(PoolError::NotAllocated);
            }
            let generation = read(memory, header + ALLOCATION_GENERATION_OFFSET)?;
            if generation == 0 || read(memory, header + HEADER_RESERVED_OFFSET)? != 0 {
                return Err(PoolError::Corrupt);
            }
            return Ok(AllocationLocation {
                identity: AllocationIdentity {
                    allocation_id: payload,
                    allocation_generation: generation,
                },
                payload_offset: payload,
                capacity,
                offset: address - payload,
            });
        }
        header = end;
    }
    Err(PoolError::InvalidPointer)
}

fn live_allocation<M: PoolMemory>(memory: &M, payload: u64) -> Result<(u64, u64), PoolError> {
    if !initialized(memory) {
        return Err(PoolError::NotInitialized);
    }
    if payload < DATA_OFFSET + HEADER_SIZE
        || payload >= memory.len()
        || payload & (ALIGNMENT - 1) != 0
    {
        return Err(PoolError::InvalidPointer);
    }
    validate_free_list(memory)?;
    let header = payload - HEADER_SIZE;
    let capacity = read(memory, header)?;
    let marker = read(memory, header + 8)?;
    let generation = read(memory, header + ALLOCATION_GENERATION_OFFSET)?;
    let reserved = read(memory, header + HEADER_RESERVED_OFFSET)?;
    let end = header
        .checked_add(HEADER_SIZE)
        .and_then(|value| value.checked_add(capacity))
        .ok_or(PoolError::Corrupt)?;
    let bump = read(memory, BUMP_OFFSET)?;
    if marker != ALLOC_MARKER || capacity == 0 || capacity & (ALIGNMENT - 1) != 0 || end > bump {
        return Err(PoolError::NotAllocated);
    }
    if generation == 0 || reserved != 0 {
        return Err(PoolError::Corrupt);
    }
    Ok((capacity, generation))
}

fn note_corruption<M: PoolMemory>(memory: &mut M) -> PoolError {
    add_stat(memory, STATS_CORRUPTION, 1);
    PoolError::Corrupt
}

/// Validate the complete free list before any allocator mutation. Nodes must be aligned, bounded,
/// strictly ordered, non-overlapping, and contained below the current bump pointer.
fn validate_free_list<M: PoolMemory>(memory: &M) -> Result<(), PoolError> {
    let bump = read(memory, BUMP_OFFSET)?;
    if bump < DATA_OFFSET || bump > memory.len() || bump & (ALIGNMENT - 1) != 0 {
        return Err(PoolError::Corrupt);
    }
    let mut node = read(memory, FREE_HEAD_OFFSET)?;
    let mut previous_end = DATA_OFFSET;
    let max_nodes = ((memory.len() - DATA_OFFSET) / (HEADER_SIZE + ALIGNMENT)).max(1);
    let mut visited = 0u64;
    while node != 0 {
        if visited >= max_nodes
            || node < DATA_OFFSET
            || node & (ALIGNMENT - 1) != 0
            || node < previous_end
        {
            return Err(PoolError::Corrupt);
        }
        let capacity = read(memory, node)?;
        if capacity == 0 || capacity & (ALIGNMENT - 1) != 0 {
            return Err(PoolError::Corrupt);
        }
        let end = node
            .checked_add(HEADER_SIZE)
            .and_then(|v| v.checked_add(capacity))
            .ok_or(PoolError::Corrupt)?;
        if end > bump {
            return Err(PoolError::Corrupt);
        }
        let next = read(memory, node + 8)?;
        if read(memory, node + HEADER_RESERVED_OFFSET)? != 0 {
            return Err(PoolError::Corrupt);
        }
        if next != 0 && next < end {
            return Err(PoolError::Corrupt);
        }
        previous_end = end;
        node = next;
        visited += 1;
    }
    Ok(())
}

pub fn allocate<M: PoolMemory>(
    memory: &mut M,
    size: u64,
    zero: bool,
) -> Result<Allocation, PoolError> {
    if !initialized(memory) {
        return Err(PoolError::NotInitialized);
    }
    if size == 0 {
        return Err(PoolError::InvalidSize);
    }
    let wanted = checked_align(size)?;
    if validate_free_list(memory).is_err() {
        return Err(note_corruption(memory));
    }

    let mut previous = 0u64;
    let mut node = read(memory, FREE_HEAD_OFFSET)?;
    while node != 0 {
        let capacity = read(memory, node)?;
        let next = read(memory, node + 8)?;
        if capacity >= wanted {
            let generation = next_allocation_generation(memory)?;
            let allocation_capacity;
            if capacity
                .checked_sub(wanted)
                .is_some_and(|remainder| remainder >= HEADER_SIZE + ALIGNMENT)
            {
                let split = node + HEADER_SIZE + wanted;
                write(memory, split, capacity - wanted - HEADER_SIZE)?;
                write(memory, split + 8, next)?;
                write(memory, split + ALLOCATION_GENERATION_OFFSET, 0)?;
                write(memory, split + HEADER_RESERVED_OFFSET, 0)?;
                if previous == 0 {
                    write(memory, FREE_HEAD_OFFSET, split)?;
                } else {
                    write(memory, previous + 8, split)?;
                }
                write(memory, node, wanted)?;
                allocation_capacity = wanted;
            } else {
                if previous == 0 {
                    write(memory, FREE_HEAD_OFFSET, next)?;
                } else {
                    write(memory, previous + 8, next)?;
                }
                allocation_capacity = capacity;
            }
            write(memory, node + 8, ALLOC_MARKER)?;
            write(memory, node + ALLOCATION_GENERATION_OFFSET, generation)?;
            write(memory, node + HEADER_RESERVED_OFFSET, 0)?;
            let payload = node + HEADER_SIZE;
            if zero && !memory.zero(payload, size) {
                return Err(note_corruption(memory));
            }
            record_allocation(memory, allocation_capacity, true);
            return Ok(Allocation {
                payload_offset: payload,
                capacity: allocation_capacity,
                reused: true,
                identity: AllocationIdentity {
                    allocation_id: payload,
                    allocation_generation: generation,
                },
            });
        }
        previous = node;
        node = next;
    }

    let bump = read(memory, BUMP_OFFSET)?;
    let header = checked_align(bump)?;
    let end = header
        .checked_add(HEADER_SIZE)
        .and_then(|v| v.checked_add(wanted))
        .ok_or(PoolError::InvalidSize)?;
    if end > memory.len() {
        add_stat(memory, STATS_OOM, 1);
        return Err(PoolError::OutOfMemory);
    }
    let generation = next_allocation_generation(memory)?;
    write(memory, header, wanted)?;
    write(memory, header + 8, ALLOC_MARKER)?;
    write(memory, header + ALLOCATION_GENERATION_OFFSET, generation)?;
    write(memory, header + HEADER_RESERVED_OFFSET, 0)?;
    write(memory, BUMP_OFFSET, end)?;
    set_max(memory, STATS_ARENA_HIGH_WATER, end);
    let payload = header + HEADER_SIZE;
    if zero && !memory.zero(payload, size) {
        return Err(note_corruption(memory));
    }
    record_allocation(memory, wanted, false);
    Ok(Allocation {
        payload_offset: payload,
        capacity: wanted,
        reused: false,
        identity: AllocationIdentity {
            allocation_id: payload,
            allocation_generation: generation,
        },
    })
}

fn record_allocation<M: PoolMemory>(memory: &mut M, capacity: u64, reused: bool) {
    add_stat(memory, STATS_ALLOCATIONS, 1);
    if reused {
        add_stat(memory, STATS_REUSES, 1);
    }
    let live = read(memory, STATS_LIVE_BYTES)
        .unwrap_or(0)
        .saturating_add(capacity);
    let _ = memory.write_u64(STATS_LIVE_BYTES, live);
    set_max(memory, STATS_LIVE_HIGH_WATER, live);
}

pub fn free<M: PoolMemory>(memory: &mut M, payload: u64) -> Result<u64, PoolError> {
    if !initialized(memory) {
        return Err(PoolError::NotInitialized);
    }
    if payload < DATA_OFFSET + HEADER_SIZE
        || payload >= memory.len()
        || payload & (ALIGNMENT - 1) != 0
    {
        add_stat(memory, STATS_INVALID_FREES, 1);
        return Err(PoolError::InvalidPointer);
    }
    if validate_free_list(memory).is_err() {
        return Err(note_corruption(memory));
    }
    let header = payload - HEADER_SIZE;
    let capacity = read(memory, header)?;
    let marker = read(memory, header + 8)?;
    let generation = read(memory, header + ALLOCATION_GENERATION_OFFSET)?;
    let reserved = read(memory, header + HEADER_RESERVED_OFFSET)?;
    let end = header
        .checked_add(HEADER_SIZE)
        .and_then(|v| v.checked_add(capacity))
        .ok_or_else(|| note_corruption(memory))?;
    let bump = read(memory, BUMP_OFFSET)?;
    if marker != ALLOC_MARKER || capacity == 0 || capacity & (ALIGNMENT - 1) != 0 || end > bump {
        add_stat(memory, STATS_INVALID_FREES, 1);
        return Err(PoolError::NotAllocated);
    }
    if generation == 0 || reserved != 0 {
        return Err(note_corruption(memory));
    }

    let mut previous = 0u64;
    let mut next = read(memory, FREE_HEAD_OFFSET)?;
    while next != 0 && next < header {
        previous = next;
        next = read(memory, next + 8)?;
    }
    if (previous != 0 && previous + HEADER_SIZE + read(memory, previous)? > header)
        || (next != 0 && end > next)
    {
        return Err(note_corruption(memory));
    }

    write(memory, header, capacity)?;
    write(memory, header + 8, next)?;
    if previous == 0 {
        write(memory, FREE_HEAD_OFFSET, header)?;
    } else {
        write(memory, previous + 8, header)?;
    }

    let mut block = header;
    let mut block_capacity = capacity;
    if next != 0 && block + HEADER_SIZE + block_capacity == next {
        block_capacity = block_capacity
            .checked_add(HEADER_SIZE + read(memory, next)?)
            .ok_or_else(|| note_corruption(memory))?;
        write(memory, block, block_capacity)?;
        write(memory, block + 8, read(memory, next + 8)?)?;
    }
    if previous != 0 {
        let previous_capacity = read(memory, previous)?;
        if previous + HEADER_SIZE + previous_capacity == block {
            block_capacity = previous_capacity
                .checked_add(HEADER_SIZE + block_capacity)
                .ok_or_else(|| note_corruption(memory))?;
            write(memory, previous, block_capacity)?;
            write(memory, previous + 8, read(memory, block + 8)?)?;
            block = previous;
        }
    }

    if block + HEADER_SIZE + block_capacity == bump {
        let mut block_previous = 0u64;
        let mut cursor = read(memory, FREE_HEAD_OFFSET)?;
        while cursor != block {
            if cursor == 0 {
                return Err(note_corruption(memory));
            }
            block_previous = cursor;
            cursor = read(memory, cursor + 8)?;
        }
        let after = read(memory, block + 8)?;
        if block_previous == 0 {
            write(memory, FREE_HEAD_OFFSET, after)?;
        } else {
            write(memory, block_previous + 8, after)?;
        }
        write(memory, BUMP_OFFSET, block)?;
    }

    add_stat(memory, STATS_FREES, 1);
    let live = read(memory, STATS_LIVE_BYTES)?.saturating_sub(capacity);
    write(memory, STATS_LIVE_BYTES, live)?;
    Ok(capacity)
}

pub fn census<M: PoolMemory>(memory: &M) -> Result<PoolCensus, PoolError> {
    if !initialized(memory) {
        return Err(PoolError::NotInitialized);
    }
    Ok(PoolCensus {
        allocations: read(memory, STATS_ALLOCATIONS)?,
        frees: read(memory, STATS_FREES)?,
        reuses: read(memory, STATS_REUSES)?,
        invalid_frees: read(memory, STATS_INVALID_FREES)?,
        live_bytes: read(memory, STATS_LIVE_BYTES)?,
        live_high_water: read(memory, STATS_LIVE_HIGH_WATER)?,
        arena_high_water: read(memory, STATS_ARENA_HIGH_WATER)?,
        out_of_memory: read(memory, STATS_OOM)?,
        corruptions: read(memory, STATS_CORRUPTION)?,
    })
}

/// Account a rejected free that could not be represented as an in-arena payload offset.
pub fn note_invalid_free<M: PoolMemory>(memory: &mut M) -> Result<(), PoolError> {
    if !initialized(memory) {
        return Err(PoolError::NotInitialized);
    }
    add_stat(memory, STATS_INVALID_FREES, 1);
    Ok(())
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct Bytes(Vec<u8>);

    impl PoolMemory for Bytes {
        fn len(&self) -> u64 {
            self.0.len() as u64
        }

        fn read_u64(&self, offset: u64) -> Option<u64> {
            let bytes = self.0.get(offset as usize..offset as usize + 8)?;
            Some(u64::from_le_bytes(bytes.try_into().ok()?))
        }

        fn write_u64(&mut self, offset: u64, value: u64) -> bool {
            let Some(bytes) = self.0.get_mut(offset as usize..offset as usize + 8) else {
                return false;
            };
            bytes.copy_from_slice(&value.to_le_bytes());
            true
        }

        fn zero(&mut self, offset: u64, len: u64) -> bool {
            let Some(bytes) = self
                .0
                .get_mut(offset as usize..offset as usize + len as usize)
            else {
                return false;
            };
            bytes.fill(0);
            true
        }
    }

    fn arena() -> Bytes {
        let mut memory = Bytes(vec![0; 0x3000]);
        initialize(&mut memory).unwrap();
        memory
    }

    #[test]
    fn reuses_splits_coalesces_and_trims_tail() {
        let mut memory = arena();
        let a = allocate(&mut memory, 33, false).unwrap();
        let b = allocate(&mut memory, 80, false).unwrap();
        let c = allocate(&mut memory, 48, false).unwrap();
        assert_eq!(a.payload_offset & 15, 0);
        free(&mut memory, b.payload_offset).unwrap();
        let reused = allocate(&mut memory, 32, false).unwrap();
        assert!(reused.reused);
        assert_eq!(reused.payload_offset, b.payload_offset);
        free(&mut memory, reused.payload_offset).unwrap();
        free(&mut memory, c.payload_offset).unwrap();
        free(&mut memory, a.payload_offset).unwrap();
        assert_eq!(memory.read_u64(BUMP_OFFSET), Some(DATA_OFFSET));
        assert_eq!(memory.read_u64(FREE_HEAD_OFFSET), Some(0));
        let stats = census(&memory).unwrap();
        assert_eq!(stats.allocations, 4);
        assert_eq!(stats.frees, 4);
        assert_eq!(stats.reuses, 1);
        assert_eq!(stats.live_bytes, 0);
    }

    #[test]
    fn zeroing_is_explicit_on_reuse() {
        let mut memory = arena();
        let first = allocate(&mut memory, 32, false).unwrap();
        memory.0[first.payload_offset as usize..first.payload_offset as usize + 32].fill(0x5a);
        let blocker = allocate(&mut memory, 32, false).unwrap();
        free(&mut memory, first.payload_offset).unwrap();
        let stale = allocate(&mut memory, 32, false).unwrap();
        assert_eq!(memory.0[stale.payload_offset as usize], 0x5a);
        free(&mut memory, stale.payload_offset).unwrap();
        let zeroed = allocate(&mut memory, 32, true).unwrap();
        assert!(
            memory.0[zeroed.payload_offset as usize..zeroed.payload_offset as usize + 32]
                .iter()
                .all(|byte| *byte == 0)
        );
        free(&mut memory, zeroed.payload_offset).unwrap();
        free(&mut memory, blocker.payload_offset).unwrap();
    }

    #[test]
    fn allocation_identity_changes_when_an_address_is_reused() {
        let mut memory = arena();
        let first = allocate(&mut memory, 32, false).unwrap();
        let blocker = allocate(&mut memory, 32, false).unwrap();
        assert_eq!(
            allocation_identity(&memory, first.payload_offset),
            Ok(first.identity)
        );
        free(&mut memory, first.payload_offset).unwrap();
        assert_eq!(
            allocation_identity(&memory, first.payload_offset),
            Err(PoolError::NotAllocated)
        );
        let second = allocate(&mut memory, 32, false).unwrap();
        assert_eq!(second.payload_offset, first.payload_offset);
        assert_eq!(second.identity.allocation_id, first.identity.allocation_id);
        assert!(second.identity.allocation_generation > first.identity.allocation_generation);
        free(&mut memory, second.payload_offset).unwrap();
        free(&mut memory, blocker.payload_offset).unwrap();
    }

    #[test]
    fn generation_does_not_trust_payload_bytes_after_tail_relayout() {
        let mut memory = arena();
        let first = allocate(&mut memory, 32, false).unwrap();
        let tail = allocate(&mut memory, 256, false).unwrap();
        assert!(memory.write_u64(tail.payload_offset + 16, u64::MAX));
        free(&mut memory, first.payload_offset).unwrap();
        free(&mut memory, tail.payload_offset).unwrap();

        let resized_prefix = allocate(&mut memory, 64, false).unwrap();
        let successor = allocate(&mut memory, 32, false).unwrap();
        assert_eq!(successor.payload_offset, tail.payload_offset + 32);
        assert_eq!(successor.identity.allocation_generation, 4);
        assert_eq!(
            allocation_identity(&memory, successor.payload_offset),
            Ok(successor.identity)
        );
        free(&mut memory, successor.payload_offset).unwrap();
        free(&mut memory, resized_prefix.payload_offset).unwrap();
    }

    #[test]
    fn containing_allocation_identifies_embedded_storage_and_bounds() {
        let mut memory = arena();
        let allocation = allocate(&mut memory, 96, false).unwrap();
        let embedded = allocation.payload_offset + 24;
        assert_eq!(
            containing_allocation(&memory, embedded, 32),
            Ok(AllocationLocation {
                identity: allocation.identity,
                payload_offset: allocation.payload_offset,
                capacity: allocation.capacity,
                offset: 24,
            })
        );
        assert_eq!(
            containing_allocation(&memory, embedded, 80),
            Err(PoolError::InvalidPointer)
        );
        free(&mut memory, allocation.payload_offset).unwrap();
        assert_eq!(
            containing_allocation(&memory, embedded, 32),
            Err(PoolError::InvalidPointer)
        );
    }

    #[test]
    fn rejects_bad_and_duplicate_frees_without_mutating_live_accounting() {
        let mut memory = arena();
        let allocation = allocate(&mut memory, 64, false).unwrap();
        assert_eq!(
            allocation_capacity(&memory, allocation.payload_offset),
            Ok(allocation.capacity)
        );
        assert_eq!(
            allocation_capacity(&memory, allocation.payload_offset + 16),
            Err(PoolError::NotAllocated)
        );
        assert_eq!(
            free(&mut memory, allocation.payload_offset + 16),
            Err(PoolError::NotAllocated)
        );
        free(&mut memory, allocation.payload_offset).unwrap();
        assert_eq!(
            allocation_capacity(&memory, allocation.payload_offset),
            Err(PoolError::NotAllocated)
        );
        assert_eq!(
            free(&mut memory, allocation.payload_offset),
            Err(PoolError::NotAllocated)
        );
        let stats = census(&memory).unwrap();
        assert_eq!(stats.invalid_frees, 2);
        assert_eq!(stats.live_bytes, 0);
    }

    #[test]
    fn exhaustion_and_corruption_fail_closed() {
        let mut memory = arena();
        assert_eq!(
            allocate(&mut memory, u64::MAX, false),
            Err(PoolError::InvalidSize)
        );
        assert_eq!(
            allocate(&mut memory, 0x4000, false),
            Err(PoolError::OutOfMemory)
        );
        assert!(memory.write_u64(FREE_HEAD_OFFSET, DATA_OFFSET));
        memory.write_u64(DATA_OFFSET, 16);
        memory.write_u64(DATA_OFFSET + 8, DATA_OFFSET);
        assert_eq!(allocate(&mut memory, 16, false), Err(PoolError::Corrupt));
        let stats = census(&memory).unwrap();
        assert_eq!(stats.out_of_memory, 1);
        assert_eq!(stats.corruptions, 1);
    }
}
