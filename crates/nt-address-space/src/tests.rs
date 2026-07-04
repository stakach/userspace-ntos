use super::*;
use nt_cache_manager::{FileSizes, MemoryBacking, SharedCacheMap};

fn file_cache(bytes: &[u8]) -> SharedCacheMap<MemoryBacking> {
    let n = bytes.len() as u64;
    SharedCacheMap::cc_initialize_cache_map(
        MemoryBacking::with_bytes(bytes.to_vec()),
        FileSizes {
            allocation_size: n,
            file_size: n,
            valid_data_length: n,
        },
        false,
    )
}
fn space() -> AddressSpace {
    AddressSpace::new(0x1_0000, 0x1000_0000, 0x1000_0000)
}

#[test]
fn va_allocation_and_overlap() {
    let mut a = space();
    let (_, b1) = a
        .reserve_view(
            None,
            0x2000,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(b1 % ALLOCATION_GRANULARITY, 0); // granularity-aligned
    let (_, b2) = a
        .reserve_view(
            None,
            0x2000,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_ne!(b1, b2); // distinct regions
                        // Reserving over an existing region conflicts.
    assert_eq!(
        a.reserve_view(
            Some(b1),
            0x1000,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0
        ),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    assert_eq!(a.vad_count(), 2);
}

#[test]
fn demand_paging_faults_on_touch() {
    // A reserved section view is NOT resident until a fault touches it (spec §10.3, §12).
    let mut cache = file_cache(b"abcdef");
    let mut a = space();
    let (_, base) = a
        .reserve_view(
            None,
            6,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(a.resident_page_count(), 0); // demand mode: nothing resident yet
    let got = a.read(base, 6, &mut cache).unwrap();
    assert_eq!(&got[..], b"abcdef"); // fault materialised the page from the cache
    assert_eq!(a.resident_page_count(), 1);
}

#[test]
fn acceptance_mapped_edit_through_fault_path() {
    // Map a file view, edit through the fault/write path, unmap → writeback, flush → file edited.
    let mut cache = file_cache(b"abcdef");
    let mut a = space();
    let (vad, base) = a
        .reserve_view(
            None,
            6,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(a.read(base, 6, &mut cache).unwrap(), b"abcdef");
    a.write(base + 1, b"XYZ", &mut cache).unwrap(); // "aXYZef"
    a.unmap_view(vad, &mut cache).unwrap(); // dirty page → CcCopyWrite
    cache.cc_flush_cache(None, None);
    assert_eq!(&cache.backing().bytes[..], b"aXYZef");
    assert_eq!(a.commit_charge(), 0); // commit released on unmap
}

#[test]
fn anonymous_view_zero_fill_and_private() {
    let mut a = space();
    let (vad, base) = a
        .reserve_view(
            None,
            0x1000,
            PAGE_READWRITE,
            ViewType::PrivateAnonymous,
            None,
            0,
        )
        .unwrap();
    assert_eq!(a.fault_anonymous(base, FaultAccess::Read), STATUS_SUCCESS);
    // A fresh anonymous page is zero.
    let mut c = file_cache(b"");
    assert_eq!(a.read(base, 4, &mut c).unwrap(), &[0, 0, 0, 0]);
    a.unmap_anonymous(vad).unwrap();
}

#[test]
fn access_violations() {
    let mut cache = file_cache(b"data");
    let mut a = space();
    // Fault on an unreserved address → access violation (spec §12.2).
    assert_eq!(
        a.fault(0x5000_0000, FaultAccess::Read, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
    // Write to a read-only view → access violation (spec §12.4).
    let (_, ro) = a
        .reserve_view(
            None,
            4,
            PAGE_READONLY,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(
        a.fault(ro, FaultAccess::Write, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
    assert_eq!(a.fault(ro, FaultAccess::Read, &mut cache), STATUS_SUCCESS); // read is fine
                                                                            // A NOACCESS view rejects everything.
    let (_, na) = a
        .reserve_view(
            None,
            4,
            PAGE_NOACCESS,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert_eq!(
        a.fault(na, FaultAccess::Read, &mut cache),
        STATUS_ACCESS_VIOLATION
    );
}

#[test]
fn commit_limit_enforced() {
    let mut a = AddressSpace::new(0x1_0000, 0x1000_0000, 0x8000); // 32 KiB commit limit
    a.reserve_view(
        None,
        0x4000,
        PAGE_READWRITE,
        ViewType::PrivateAnonymous,
        None,
        0,
    )
    .unwrap();
    a.reserve_view(
        None,
        0x4000,
        PAGE_READWRITE,
        ViewType::PrivateAnonymous,
        None,
        0,
    )
    .unwrap();
    assert_eq!(a.commit_charge(), 0x8000);
    // The next reservation exceeds the commit limit.
    assert_eq!(
        a.reserve_view(
            None,
            0x1000,
            PAGE_READWRITE,
            ViewType::PrivateAnonymous,
            None,
            0
        ),
        Err(STATUS_COMMITMENT_LIMIT)
    );
}

#[test]
fn mdl_probe_lock_unlock() {
    let mut cache = file_cache(b"lockable data here");
    let mut a = space();
    let (_, base) = a
        .reserve_view(
            None,
            18,
            PAGE_READWRITE,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    let mut mdl = a
        .mm_probe_and_lock_pages(base, 18, LockAccess::Write, &mut cache)
        .unwrap();
    assert!(mdl.is_locked());
    assert_eq!(a.page_locked_count(base), 1); // page faulted in + locked
    a.mm_unlock_pages(&mut mdl);
    assert!(!mdl.is_locked());
    assert_eq!(a.page_locked_count(base), 0);
    // Locking a read-only view for write fails.
    let (_, ro) = a
        .reserve_view(
            None,
            4,
            PAGE_READONLY,
            ViewType::MappedDataSection,
            Some(1),
            0,
        )
        .unwrap();
    assert!(a
        .mm_probe_and_lock_pages(ro, 4, LockAccess::Write, &mut cache)
        .is_err());
}
