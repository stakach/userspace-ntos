use super::*;
use alloc::vec::Vec;

const LIFETIME: MemoryLifetime = MemoryLifetime::Process(crate::ProcessIdentity {
    pid: 44,
    generation: crate::ProcessGeneration::Hosted(7),
});
const MAX_RECORD_BACKING_BYTES: usize = 64 * 1024;

// Measure real allocation capacity, not live record count or aggregate reserved capacity.
fn largest_record_backing_bytes(registry: &ClientFrameRegistry) -> usize {
    registry.records.largest_backing_bytes()
}

fn populated(count: usize) -> ClientFrameRegistry {
    let mut registry = ClientFrameRegistry::new();
    assert!(registry.reserve_initial(count));
    registry
        .insert(3, LIFETIME, 0x1000, 0x40, 0, 0, 0, true)
        .unwrap();
    let template = registry.records[0];
    // Seed valid distinct records directly: repeated public insert would make fixture setup O(n^2).
    for index in 1..count {
        registry.records.push(ClientFrameRecord {
            record_id: allocate_record_id(&NEXT_RECORD_ID).unwrap(),
            page: 0x1000 + index as u64 * 0x1000,
            frame: 0x40 + index as u64,
            owned_backing_cap: 0x40 + index as u64,
            age: index as u64 + 1,
            ..template
        });
    }
    registry.next_age = count as u64 + 1;
    registry.high_water = count;
    registry
}

#[test]
fn large_registry_growth_uses_bounded_record_backing_allocations() {
    let mut registry = populated(16_384);
    let first = registry.get(3, 0x1000).unwrap();
    let last = registry.get(3, 16_384 * 0x1000).unwrap();
    registry
        .insert(3, LIFETIME, 16_385 * 0x1000, 0x9000, 0, 0, 0, true)
        .unwrap();
    assert_eq!(registry.stats().records, 16_385);
    assert_eq!(registry.get(3, first.page), Some(first));
    assert_eq!(registry.get(3, last.page), Some(last));
    assert!(
        largest_record_backing_bytes(&registry) <= MAX_RECORD_BACKING_BYTES,
        "registry growth must not allocate a contiguous copy of all retained frame owners"
    );
}

#[test]
fn initial_registry_reservation_uses_bounded_record_backing_allocations() {
    let mut registry = ClientFrameRegistry::new();
    assert!(registry.reserve_initial(16_384));
    assert!(registry.stats().capacity >= 16_384);
    assert!(largest_record_backing_bytes(&registry) <= MAX_RECORD_BACKING_BYTES);
}

#[test]
fn impossible_storage_reservation_preserves_exact_reclaim_and_transfer_owners() {
    let mut registry = populated(3);
    let reclaim = registry.get(3, 0x1000).unwrap();
    let reclaim = registry
        .begin_reclaim_exact(reclaim, ClientFrameReclaimIntent::Release)
        .unwrap();
    let transferred = registry.get(3, 0x2000).unwrap();
    let transfer = registry.prepare_transfer_exact(&[transferred]).unwrap();
    let held = transfer.records()[0];
    let resident = registry.get(3, 0x3000).unwrap();
    let before = registry.stats();
    assert!(!registry.reserve_initial(usize::MAX));
    assert_eq!(registry.get(3, reclaim.page), Some(reclaim));
    assert_eq!(registry.get(3, held.page), Some(held));
    assert_eq!(registry.get(3, resident.page), Some(resident));
    assert_eq!(registry.reclaiming_count(), 2);
    assert_eq!(transfer.records(), &[held]);
    assert_eq!(registry.stats().records, before.records);
    assert_eq!(registry.stats().capacity, before.capacity);
    assert_eq!(
        registry.stats().allocation_failures,
        before.allocation_failures + 1
    );
    assert!(!registry.memory_available(3, reclaim.page, 0x1000));
    assert!(!registry.memory_available(3, held.page, 0x1000));
    assert!(registry.memory_available(3, resident.page, 0x1000));
}

#[test]
fn chunk_boundary_swap_remove_preserves_exact_held_record_identities() {
    let mut registry = populated(storage::RECORDS_PER_CHUNK + 2);
    let first = registry.record_at(0).unwrap();
    let transfer = registry.prepare_transfer_exact(&[first]).unwrap();
    let held = transfer.records()[0];
    let boundary = registry.record_at(storage::RECORDS_PER_CHUNK - 1).unwrap();
    let reclaim = registry
        .begin_reclaim_exact(boundary, ClientFrameReclaimIntent::Release)
        .unwrap();
    let moved = registry.record_at(storage::RECORDS_PER_CHUNK + 1).unwrap();
    let removed = registry.record_at(storage::RECORDS_PER_CHUNK).unwrap();
    assert_eq!(registry.take_exact(removed), Some(removed));
    assert_eq!(registry.record_at(storage::RECORDS_PER_CHUNK), Some(moved));
    assert_eq!(registry.get(3, held.page), Some(held));
    assert_eq!(registry.get(3, reclaim.page), Some(reclaim));
    registry.finish_transfer(transfer).unwrap();
    assert_eq!(registry.record_at(0), Some(moved));
    assert_eq!(registry.get(3, reclaim.page), Some(reclaim));
    assert_eq!(registry.reclaiming_count(), 1);
    assert_eq!(registry.records().count(), storage::RECORDS_PER_CHUNK);
    assert_eq!(registry.record_at(registry.len()), None);
}

#[test]
fn refused_chunk_growth_retains_owners_and_reuses_only_empty_reserved_storage() {
    let mut registry = populated(storage::RECORDS_PER_CHUNK);
    let reclaim = registry.record_at(0).unwrap();
    let reclaim = registry
        .begin_reclaim_exact(reclaim, ClientFrameReclaimIntent::Release)
        .unwrap();
    let source = registry.record_at(1).unwrap();
    let transfer = registry.prepare_transfer_exact(&[source]).unwrap();
    let held = transfer.records()[0];
    let before = registry.records().copied().collect::<Vec<_>>();
    let mut allocations = 0;
    let result = registry
        .records
        .try_reserve_with(storage::RECORDS_PER_CHUNK * 2, || {
            allocations += 1;
            if allocations == 2 {
                return Err(());
            }
            let mut chunk = Vec::new();
            chunk
                .try_reserve_exact(storage::RECORDS_PER_CHUNK)
                .map_err(|_| ())?;
            Ok(chunk)
        });
    assert_eq!(result, Err(()));
    assert_eq!(allocations, 2);
    assert_eq!(registry.records().copied().collect::<Vec<_>>(), before);
    assert_eq!(registry.reclaiming_count(), 2);
    assert_eq!(registry.stats().capacity, storage::RECORDS_PER_CHUNK * 2);
    assert_eq!(registry.get(3, reclaim.page), Some(reclaim));
    assert_eq!(registry.get(3, held.page), Some(held));
    registry
        .insert(3, LIFETIME, 0x500000, 0x9000, 0, 0, 0, true)
        .unwrap();
    assert_eq!(registry.len(), storage::RECORDS_PER_CHUNK + 1);
    assert_eq!(registry.get(3, reclaim.page), Some(reclaim));
    assert_eq!(registry.get(3, held.page), Some(held));
    registry.finish_transfer(transfer).unwrap();
    assert_eq!(registry.get(3, reclaim.page), Some(reclaim));
}
