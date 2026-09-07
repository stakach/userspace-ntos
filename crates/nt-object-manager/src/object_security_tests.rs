use super::*;
use crate::win32k_ob::{ObHandleTable, ObKind};
use alloc::collections::BTreeMap;

#[derive(Default)]
struct Io {
    next: u64,
    allocations: BTreeMap<u64, Vec<u8>>,
    calls: Vec<(&'static str, u64)>,
    allocation_error: Option<u32>,
    free_errors: BTreeMap<u64, u32>,
    return_null: bool,
}

impl ObjectSecurityCacheIo for Io {
    fn allocate_copy(&mut self, bytes: &[u8]) -> Result<u64, u32> {
        self.calls.push(("allocate", bytes.len() as u64));
        if let Some(error) = self.allocation_error {
            return Err(error);
        }
        if self.return_null {
            return Ok(0);
        }
        self.next += 0x1000;
        assert!(self.allocations.insert(self.next, bytes.to_vec()).is_none());
        Ok(self.next)
    }
    fn free(&mut self, pointer: u64) -> Result<(), u32> {
        self.calls.push(("free", pointer));
        if let Some(error) = self.free_errors.get(&pointer) {
            return Err(*error);
        }
        assert!(self.allocations.remove(&pointer).is_some());
        Ok(())
    }
}

#[test]
fn null_descriptor_and_release_are_valid_allocation_free_noops() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    assert_eq!(cache.acquire(None, &mut io), Ok(0));
    assert_eq!(cache.release(0, &mut io), Ok(()));
    assert_eq!(cache.retry_retirements(&mut io), 0);
    assert_eq!(cache.reference_count(0), None);
    assert!(!cache.contains(0));
    assert_eq!(cache.stats(), ObjectSecurityCacheStats::default());
    assert!(io.calls.is_empty());
}

#[test]
fn complete_immutable_copy_survives_source_replacement() {
    let mut source = [1, 2, 3, 4];
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let pointer = cache.acquire(Some(&source), &mut io).unwrap();
    source.fill(9);
    assert_eq!(io.allocations[&pointer], [1, 2, 3, 4]);
    assert_eq!(cache.entries[0].descriptor, [1, 2, 3, 4]);
    assert_eq!(cache.reference_count(pointer), Some(1));
    cache.release(pointer, &mut io).unwrap();
    assert!(!cache.contains(pointer));
    assert!(io.allocations.is_empty());
}

#[test]
fn equal_content_shares_one_allocation_until_the_last_reference() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let a = cache.acquire(Some(&[1, 2, 3]), &mut io).unwrap();
    let b = cache.acquire(Some(&[1, 2, 3]), &mut io).unwrap();
    assert_eq!(a, b);
    assert_eq!(cache.reference_count(a), Some(2));
    assert_eq!(cache.entry_count(), 1);
    assert_eq!(io.calls, [("allocate", 3)]);
    cache.release(a, &mut io).unwrap();
    assert_eq!(cache.reference_count(b), Some(1));
    assert_eq!(io.calls.len(), 1);
    cache.release(b, &mut io).unwrap();
    assert_eq!(io.calls, [("allocate", 3), ("free", a)]);
    assert_eq!(cache.stats().acquisitions, 2);
    assert_eq!(cache.stats().releases, 2);
    assert_eq!(cache.stats().live_references, 0);
    assert_eq!(cache.entry_count(), 0);
}

#[test]
fn descriptors_with_different_length_or_content_do_not_alias() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let a = cache.acquire(Some(&[1, 2]), &mut io).unwrap();
    let b = cache.acquire(Some(&[1, 2, 0]), &mut io).unwrap();
    let c = cache.acquire(Some(&[1, 3]), &mut io).unwrap();
    assert_ne!(a, b);
    assert_ne!(b, c);
    assert_ne!(a, c);
    for pointer in [b, a, c] {
        cache.release(pointer, &mut io).unwrap();
    }
    assert_eq!(cache.entry_count(), 0);
}

#[test]
fn allocation_failure_publishes_no_reference_and_retry_copies_once() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io {
        allocation_error: Some(61),
        ..Io::default()
    };
    assert_eq!(cache.acquire(Some(&[1, 2]), &mut io), Err(61));
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.stats().live_references, 0);
    assert_eq!(cache.stats().acquisitions, 0);
    assert_eq!(cache.stats().allocation_failures, 1);
    assert!(io.allocations.is_empty());
    io.allocation_error = None;
    let pointer = cache.acquire(Some(&[1, 2]), &mut io).unwrap();
    assert_eq!(cache.reference_count(pointer), Some(1));
    assert_eq!(io.calls, [("allocate", 2), ("allocate", 2)]);
    cache.release(pointer, &mut io).unwrap();
}

#[test]
fn null_allocator_result_is_not_published_as_a_valid_descriptor() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io {
        return_null: true,
        ..Io::default()
    };
    assert_eq!(
        cache.acquire(Some(&[1]), &mut io),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(cache.entry_count(), 0);
    assert_eq!(cache.stats().allocation_failures, 1);
    assert_eq!(cache.reference_count(0), None);
}

#[test]
fn empty_nonnull_descriptor_is_rejected_before_allocation() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    assert_eq!(
        cache.acquire(Some(&[]), &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(io.calls.is_empty());
    assert_eq!(cache.stats(), ObjectSecurityCacheStats::default());
}

#[test]
fn reference_count_exhaustion_changes_no_owned_state() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let pointer = cache.acquire(Some(&[1]), &mut io).unwrap();
    cache.entries[0].references = u32::MAX;
    cache.stats.live_references = u32::MAX as u64;
    let before = cache.stats();
    assert_eq!(
        cache.acquire(Some(&[1]), &mut io),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(cache.stats(), before);
    assert_eq!(cache.reference_count(pointer), Some(u32::MAX));
    assert_eq!(io.calls.len(), 1);
}

#[test]
fn global_reference_count_exhaustion_precedes_new_allocation() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    cache.stats.live_references = u64::MAX;
    assert_eq!(
        cache.acquire(Some(&[1]), &mut io),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(cache.entry_count(), 0);
    assert!(io.calls.is_empty());
}

#[test]
fn unknown_interior_and_duplicate_releases_never_free_another_owner() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let pointer = cache.acquire(Some(&[1, 2]), &mut io).unwrap();
    for invalid in [pointer + 1, pointer - 1, 99] {
        assert_eq!(
            cache.release(invalid, &mut io),
            Err(STATUS_INVALID_PARAMETER)
        );
    }
    assert_eq!(io.calls.len(), 1);
    assert_eq!(cache.reference_count(pointer), Some(1));
    cache.release(pointer, &mut io).unwrap();
    assert_eq!(
        cache.release(pointer, &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(cache.stats().invalid_releases, 4);
    assert_eq!(cache.stats().release_failures, 0);
    assert_eq!(cache.stats().releases, 1);
    assert_eq!(io.calls.len(), 2);
}

#[test]
fn failed_final_free_consumes_reference_and_retains_exact_retirement() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let pointer = cache.acquire(Some(&[1, 2]), &mut io).unwrap();
    io.free_errors.insert(pointer, 62);
    assert_eq!(cache.release(pointer, &mut io), Err(62));
    assert!(cache.contains(pointer));
    assert_eq!(cache.reference_count(pointer), Some(0));
    assert_eq!(cache.retiring_count(), 1);
    assert_eq!(cache.stats().live_references, 0);
    assert_eq!(cache.stats().releases, 1);
    assert_eq!(cache.stats().release_failures, 1);
    assert_eq!(
        cache.release(pointer, &mut io),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(io.calls.len(), 2);
    assert_eq!(cache.retry_retirements(&mut io), 0);
    assert_eq!(cache.stats().release_failures, 2);
    assert!(io.allocations.contains_key(&pointer));
    io.free_errors.clear();
    assert_eq!(cache.retry_retirements(&mut io), 1);
    assert_eq!(cache.retry_retirements(&mut io), 0);
    assert!(!cache.contains(pointer));
    assert_eq!(cache.retiring_count(), 0);
    assert_eq!(cache.stats().releases, 1);
}

#[test]
fn retiring_descriptor_is_not_resurrected_by_equal_content_acquisition() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let old = cache.acquire(Some(&[1]), &mut io).unwrap();
    io.free_errors.insert(old, 62);
    assert_eq!(cache.release(old, &mut io), Err(62));
    let new = cache.acquire(Some(&[1]), &mut io).unwrap();
    assert_ne!(old, new);
    assert_eq!(cache.entry_count(), 2);
    assert_eq!(cache.reference_count(old), Some(0));
    assert_eq!(cache.reference_count(new), Some(1));
    io.free_errors.clear();
    assert_eq!(cache.retry_retirements(&mut io), 1);
    assert_eq!(cache.reference_count(new), Some(1));
    assert_eq!(io.allocations[&new], [1]);
    cache.release(new, &mut io).unwrap();
}

#[test]
fn one_failed_retirement_does_not_starve_others_or_touch_active_entries() {
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let a = cache.acquire(Some(&[1]), &mut io).unwrap();
    let b = cache.acquire(Some(&[2]), &mut io).unwrap();
    let c = cache.acquire(Some(&[3]), &mut io).unwrap();
    for pointer in [a, b] {
        io.free_errors.insert(pointer, 62);
        assert_eq!(cache.release(pointer, &mut io), Err(62));
    }
    io.free_errors.remove(&b);
    io.calls.clear();
    assert_eq!(cache.retry_retirements(&mut io), 1);
    assert_eq!(io.calls, [("free", a), ("free", b)]);
    assert_eq!(cache.reference_count(a), Some(0));
    assert_eq!(cache.reference_count(b), None);
    assert_eq!(cache.reference_count(c), Some(1));
    io.free_errors.clear();
    assert_eq!(cache.retry_retirements(&mut io), 1);
    cache.release(c, &mut io).unwrap();
}

#[test]
fn cache_snapshot_survives_descriptor_replacement_and_object_table_destruction() {
    let mut table = ObHandleTable::new();
    let handle = table.register_with_security(ObKind::Desktop, 0x7000, Some(&[1, 2]));
    let mut cache = ObjectSecurityCache::new();
    let mut io = Io::default();
    let (_, descriptor) = table.security_descriptor_by_body(0x7000).unwrap();
    let old = cache.acquire(descriptor, &mut io).unwrap();
    assert!(table.set_security_descriptor(handle, &[3, 4]));
    let (_, descriptor) = table.security_descriptor_by_body(0x7000).unwrap();
    let new = cache.acquire(descriptor, &mut io).unwrap();
    drop(table);
    assert_eq!(io.allocations[&old], [1, 2]);
    assert_eq!(io.allocations[&new], [3, 4]);
    cache.release(new, &mut io).unwrap();
    assert_eq!(io.allocations[&old], [1, 2]);
    cache.release(old, &mut io).unwrap();
}

#[test]
fn body_lookup_distinguishes_unknown_null_and_descriptor() {
    let mut table = ObHandleTable::new();
    table.register(ObKind::Desktop, 0x7000);
    table.register_with_security(ObKind::WindowStation, 0x8000, Some(&[1, 2]));
    assert_eq!(table.security_descriptor_by_body(0), None);
    assert_eq!(table.security_descriptor_by_body(0x9000), None);
    assert_eq!(
        table.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, None))
    );
    assert_eq!(
        table.security_descriptor_by_body(0x8000),
        Some((ObKind::WindowStation, Some([1, 2].as_slice())))
    );
    table.register(ObKind::Other, 0);
    assert_eq!(table.security_descriptor_by_body(0), None);
}

#[test]
fn pending_body_exposes_kind_and_security_before_handle_publication() {
    let mut table = ObHandleTable::new();
    assert!(table.latch_pending_with_security(ObKind::Desktop, 0x7000, Some(&[1, 2])));
    assert_eq!(
        table.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, Some([1, 2].as_slice())))
    );
    let handle = table.insert_pending(0x7000);
    assert_ne!(handle, 0);
    assert_eq!(
        table.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, Some([1, 2].as_slice())))
    );
    table.latch_pending(ObKind::WindowStation, 0x8000);
    assert_eq!(
        table.security_descriptor_by_body(0x8000),
        Some((ObKind::WindowStation, None))
    );
}

#[test]
fn aliases_resolve_only_one_canonical_body_and_observe_security_replacement() {
    let mut table = ObHandleTable::new();
    let handle = table.register(ObKind::Desktop, 0x7000);
    let alias = table.duplicate(handle).unwrap();
    assert!(table.set_security_descriptor(alias, &[3, 4]));
    assert_eq!(
        table.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, Some([3, 4].as_slice())))
    );
    assert!(table.close(alias));
    assert_eq!(
        table.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, Some([3, 4].as_slice())))
    );
    assert!(table.set_security_descriptor(handle, &[]));
    assert_eq!(
        table.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, None))
    );
}

#[test]
fn duplicate_canonical_or_pending_bodies_are_rejected_as_ambiguous() {
    let mut table = ObHandleTable::new();
    table.register(ObKind::Desktop, 0x7000);
    table.register(ObKind::WindowStation, 0x7000);
    assert_eq!(table.security_descriptor_by_body(0x7000), None);
    table.register(ObKind::Desktop, 0x8000);
    table.latch_pending(ObKind::Desktop, 0x8000);
    assert_eq!(table.security_descriptor_by_body(0x8000), None);
    table.latch_pending(ObKind::Other, 0x9000);
    assert_eq!(
        table.security_descriptor_by_body(0x8000),
        Some((ObKind::Desktop, None))
    );
    assert_eq!(
        table.security_descriptor_by_body(0x9000),
        Some((ObKind::Other, None))
    );
}
