use super::*;

fn sizes(file_size: u64) -> FileSizes {
    FileSizes {
        allocation_size: file_size,
        file_size,
        valid_data_length: file_size,
    }
}

#[test]
fn copy_read_faults_pages_from_backing() {
    // A backing store with 10000 bytes of known data; cached read faults pages in.
    let data: Vec<u8> = (0..10000u32).map(|i| i as u8).collect();
    let backing = MemoryBacking::with_bytes(data.clone());
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(backing, sizes(10000), false);
    let mut buf = alloc::vec![0u8; 5000];
    let (st, n) = ccm.cc_copy_read(3000, 5000, &mut buf);
    assert_eq!((st, n), (STATUS_SUCCESS, 5000));
    assert_eq!(&buf[..], &data[3000..8000]);
    assert!(ccm.cached_page_count() > 0); // pages were faulted in + cached
}

#[test]
fn copy_write_dirties_and_flush_writes_back() {
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(MemoryBacking::new(), sizes(0), false);
    // Write extends EOF; the page is dirty but the backing is untouched until flush.
    assert_eq!(ccm.cc_copy_write(0, b"hello cache", false), STATUS_SUCCESS);
    assert_eq!(ccm.cc_get_file_size(), 11);
    assert!(ccm.cc_is_there_dirty_data());
    assert!(ccm.backing().bytes.is_empty()); // not yet flushed
                                             // A cached read returns the just-written bytes (served from the dirty page).
    let mut buf = [0u8; 11];
    let (_, n) = ccm.cc_copy_read(0, 11, &mut buf);
    assert_eq!((n, &buf[..]), (11, &b"hello cache"[..]));
    // Flush writes the page back + clears dirty.
    assert_eq!(ccm.cc_flush_cache(None, None), STATUS_SUCCESS);
    assert!(!ccm.cc_is_there_dirty_data());
    assert_eq!(&ccm.backing().bytes[..], b"hello cache");
    assert_eq!(ccm.backing().flushes, 1);
}

#[test]
fn eof_behaviour() {
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(
        MemoryBacking::with_bytes(alloc::vec![7u8; 100]),
        sizes(100),
        false,
    );
    let mut buf = [0u8; 50];
    // Read starting at EOF → zero bytes (spec §9.4).
    assert_eq!(ccm.cc_copy_read(100, 50, &mut buf), (STATUS_END_OF_FILE, 0));
    // Read crossing EOF → short read clipped to file size.
    let (st, n) = ccm.cc_copy_read(80, 50, &mut buf);
    assert_eq!((st, n), (STATUS_SUCCESS, 20));
}

#[test]
fn set_file_sizes_truncate_drops_pages() {
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(
        MemoryBacking::with_bytes(alloc::vec![9u8; 20000]),
        sizes(20000),
        false,
    );
    let mut buf = alloc::vec![0u8; 20000];
    ccm.cc_copy_read(0, 20000, &mut buf); // fault all pages (0..5)
    assert!(ccm.cached_page_count() >= 5);
    ccm.cc_set_file_sizes(sizes(5000)); // truncate → drop pages past 5000
    assert_eq!(ccm.cc_get_file_size(), 5000);
    assert!(ccm.cached_page_count() <= 2); // only pages 0,1 remain
                                           // A read past the new EOF returns nothing.
    assert_eq!(ccm.cc_copy_read(6000, 100, &mut buf).1, 0);
}

#[test]
fn pin_write_unpin_and_flush() {
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(MemoryBacking::new(), sizes(0), true);
    let bcb = ccm.cc_prepare_pin_write(0, 8);
    assert_eq!(bcb.page_count(), 1);
    // Write into the pinned page directly, then mark it dirty via the BCB.
    ccm.cc_copy_write(0, b"pinned!!", false);
    ccm.cc_set_dirty_pinned_data(&bcb);
    // A pinned page can't be purged.
    assert!(!ccm.cc_purge_cache_section(0, 8));
    ccm.cc_unpin_data(bcb);
    assert_eq!(ccm.lazy_write_pass(), STATUS_SUCCESS);
    assert_eq!(&ccm.backing().bytes[..8], b"pinned!!");
}

#[test]
fn purge_and_evict_clean_pages() {
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(
        MemoryBacking::with_bytes(alloc::vec![1u8; 12000]),
        sizes(12000),
        false,
    );
    let mut buf = alloc::vec![0u8; 12000];
    ccm.cc_copy_read(0, 12000, &mut buf); // clean pages 0,1,2
    let before = ccm.cached_page_count();
    assert!(ccm.cc_purge_cache_section(0, 4096)); // page 0 clean → purged
    assert_eq!(ccm.cached_page_count(), before - 1);
    // Evict the LRU clean page.
    assert!(ccm.evict());
    // A dirty page is neither purged nor evicted.
    ccm.cc_copy_write(8192, b"dirty", false);
    assert!(!ccm.cc_purge_cache_section(8192, 5));
}

#[test]
fn write_through_flushes_immediately() {
    let mut ccm = SharedCacheMap::cc_initialize_cache_map(MemoryBacking::new(), sizes(0), false);
    assert_eq!(ccm.cc_copy_write(0, b"wt", true), STATUS_SUCCESS); // write-through
    assert!(!ccm.cc_is_there_dirty_data()); // already flushed
    assert_eq!(&ccm.backing().bytes[..], b"wt");
}
