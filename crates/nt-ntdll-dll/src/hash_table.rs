//! Intrusive `RTL_DYNAMIC_HASH_TABLE` exports.
//!
//! Layout and signatures follow Windows Kits `km/ntddk.h` (10.0.28000). The
//! table owns its bucket directory; callers own and keep entries alive until
//! removal. A zero signature is reserved for enumerator sentinels.

use core::ptr::null_mut;

#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct Link {
    pub flink: *mut Link,
    pub blink: *mut Link,
}

#[repr(C)]
#[derive(Debug)]
pub struct Entry {
    pub linkage: Link,
    pub signature: usize,
}

#[repr(C)]
pub struct Context {
    pub chain_head: *mut Link,
    pub prev_linkage: *mut Link,
    pub signature: usize,
}

#[repr(C)]
pub struct Enumerator {
    pub current: *mut Link,
    pub chain_head: *mut Link,
    pub bucket_index: u32,
}

#[repr(C)]
pub struct Table {
    pub flags: u32,
    pub shift: u32,
    pub table_size: u32,
    pub pivot: u32,
    pub divisor_mask: u32,
    pub num_entries: u32,
    pub non_empty_buckets: u32,
    pub num_enumerators: u32,
    pub directory: *mut Link,
}

const ALLOCATED_HEADER: u32 = 1;
const DEFAULT_BUCKETS: u32 = 128;
const MAX_BUCKETS: u32 = 1 << 20;

#[cfg(test)]
extern crate std;

#[cfg(test)]
unsafe fn allocate(bytes: usize) -> *mut u8 {
    let layout = std::alloc::Layout::from_size_align(bytes, 16).unwrap();
    unsafe { std::alloc::alloc(layout) }
}

#[cfg(test)]
unsafe fn release(ptr: *mut u8, bytes: usize) {
    let layout = std::alloc::Layout::from_size_align(bytes, 16).unwrap();
    unsafe { std::alloc::dealloc(ptr, layout) }
}

#[cfg(all(not(test), target_arch = "x86_64"))]
unsafe fn allocate(bytes: usize) -> *mut u8 {
    unsafe { crate::process_heap_alloc(bytes) }
}

#[cfg(all(not(test), target_arch = "x86_64"))]
unsafe fn release(ptr: *mut u8, _bytes: usize) {
    let _ = unsafe { crate::process_heap_free(ptr) };
}

#[cfg(all(not(test), not(target_arch = "x86_64")))]
unsafe fn allocate(_bytes: usize) -> *mut u8 {
    null_mut()
}

#[cfg(all(not(test), not(target_arch = "x86_64")))]
unsafe fn release(_ptr: *mut u8, _bytes: usize) {}

#[inline]
fn bucket_count(size: u32) -> Option<usize> {
    (size.is_power_of_two() && size >= 2 && size <= MAX_BUCKETS).then_some(size as usize)
}

unsafe fn bucket(table: *mut Table, signature: usize) -> *mut Link {
    let shift = unsafe { (*table).shift };
    let mask = unsafe { (*table).divisor_mask };
    let directory = unsafe { (*table).directory };
    let index = ((signature >> shift) as u32 & mask) as usize;
    unsafe { directory.add(index) }
}

unsafe fn init_directory(directory: *mut Link, count: usize) {
    for index in 0..count {
        let head = unsafe { directory.add(index) };
        unsafe {
            (*head).flink = head;
            (*head).blink = head;
        }
    }
}

unsafe fn append_after(previous: *mut Link, link: *mut Link) {
    let next = unsafe { (*previous).flink };
    unsafe {
        (*link).blink = previous;
        (*link).flink = next;
        (*previous).flink = link;
        (*next).blink = link;
    }
}

unsafe fn unlink(link: *mut Link) {
    let (previous, next) = unsafe { ((*link).blink, (*link).flink) };
    unsafe {
        (*previous).flink = next;
        (*next).blink = previous;
        (*link).flink = null_mut();
        (*link).blink = null_mut();
    }
}

unsafe fn create(table: *mut *mut Table, size: u32, shift: u32, flags: u32) -> u8 {
    if table.is_null() || flags != 0 || shift >= usize::BITS || bucket_count(size).is_none() {
        return 0;
    }
    let bytes = size as usize * core::mem::size_of::<Link>();
    let directory = unsafe { allocate(bytes) } as *mut Link;
    if directory.is_null() {
        return 0;
    }
    unsafe {
        init_directory(directory, size as usize);
    }
    let allocated = unsafe { (*table).is_null() };
    let header = if allocated {
        (unsafe { allocate(core::mem::size_of::<Table>()) }) as *mut Table
    } else {
        unsafe { *table }
    };
    if header.is_null() {
        unsafe {
            release(directory.cast(), bytes);
        }
        return 0;
    }
    unsafe {
        *header = Table {
            flags: if allocated { ALLOCATED_HEADER } else { 0 },
            shift,
            table_size: size,
            pivot: 0,
            divisor_mask: size - 1,
            num_entries: 0,
            non_empty_buckets: 0,
            num_enumerators: 0,
            directory,
        };
        *table = header;
    }
    1
}

/// `BOOLEAN RtlCreateHashTable(PRTL_DYNAMIC_HASH_TABLE *, ULONG, ULONG)`.
///
/// # Safety
/// The output pointer must be writable, and an existing header must be writable.
#[export_name = "RtlCreateHashTable"]
pub unsafe extern "system" fn rtl_create_hash_table(
    table: *mut *mut Table,
    shift: u32,
    flags: u32,
) -> u8 {
    unsafe { create(table, DEFAULT_BUCKETS, shift, flags) }
}

/// # Safety
/// The table must be a live table created by this module. Entries must outlive removal/deletion.
#[export_name = "RtlDeleteHashTable"]
pub unsafe extern "system" fn rtl_delete_hash_table(table: *mut Table) {
    if table.is_null() {
        return;
    }
    let t = unsafe { &mut *table };
    if t.directory.is_null() || bucket_count(t.table_size).is_none() {
        return;
    }
    // Leave caller-owned entries detached; the table never frees them.
    for index in 0..t.table_size as usize {
        let head = unsafe { t.directory.add(index) };
        while unsafe { (*head).flink } != head {
            unsafe {
                unlink((*head).flink);
            }
        }
    }
    unsafe {
        release(
            t.directory.cast(),
            t.table_size as usize * core::mem::size_of::<Link>(),
        );
    }
    t.directory = null_mut();
    let allocated = t.flags & ALLOCATED_HEADER != 0;
    if allocated {
        unsafe {
            release(table.cast(), core::mem::size_of::<Table>());
        }
    }
}

/// # Safety
/// `table` must be live and `entry` must be an unlinked caller-owned entry.
#[export_name = "RtlInsertEntryHashTable"]
pub unsafe extern "system" fn rtl_insert_entry_hash_table(
    table: *mut Table,
    entry: *mut Entry,
    signature: usize,
    context: *mut Context,
) -> u8 {
    if table.is_null() || entry.is_null() || signature == 0 {
        return 0;
    }
    let t = unsafe { &mut *table };
    if t.directory.is_null() || t.num_entries == u32::MAX {
        return 0;
    }
    let head = unsafe { bucket(table, signature) };
    let mut previous = unsafe { (*head).blink };
    if !context.is_null()
        && unsafe { (*context).chain_head == head && (*context).signature == signature }
    {
        let requested = unsafe { (*context).prev_linkage };
        let mut link = head;
        loop {
            if link == requested {
                previous = link;
                break;
            }
            link = unsafe { (*link).flink };
            if link == head {
                break;
            }
        }
    }
    if unsafe { (*head).flink == head } {
        t.non_empty_buckets += 1;
    }
    unsafe {
        (*entry).signature = signature;
        append_after(previous, &mut (*entry).linkage);
    }
    t.num_entries += 1;
    1
}

/// # Safety
/// `entry` must be linked into this live table; stale pointers are invalid.
#[export_name = "RtlRemoveEntryHashTable"]
pub unsafe extern "system" fn rtl_remove_entry_hash_table(
    table: *mut Table,
    entry: *mut Entry,
    _context: *mut Context,
) -> u8 {
    if table.is_null() || entry.is_null() {
        return 0;
    }
    let t = unsafe { &mut *table };
    if t.directory.is_null() || t.num_entries == 0 {
        return 0;
    }
    let signature = unsafe { (*entry).signature };
    if signature == 0 {
        return 0;
    }
    let head = unsafe { bucket(table, signature) };
    // Scan the owning bucket: this also rejects stale and foreign entries.
    let mut link = unsafe { (*head).flink };
    while link != head {
        if link == unsafe { &mut (*entry).linkage } {
            unsafe {
                unlink(link);
            }
            t.num_entries -= 1;
            if unsafe { (*head).flink == head } {
                t.non_empty_buckets -= 1;
            }
            return 1;
        }
        link = unsafe { (*link).flink };
    }
    0
}

/// # Safety
/// `table` must be live; `context`, when supplied, must be writable.
#[export_name = "RtlLookupEntryHashTable"]
pub unsafe extern "system" fn rtl_lookup_entry_hash_table(
    table: *mut Table,
    signature: usize,
    context: *mut Context,
) -> *mut Entry {
    if table.is_null() || signature == 0 || unsafe { (*table).directory.is_null() } {
        return null_mut();
    }
    let head = unsafe { bucket(table, signature) };
    let mut previous = head;
    let mut link = unsafe { (*head).flink };
    while link != head {
        let entry = link.cast::<Entry>();
        if unsafe { (*entry).signature == signature } {
            if !context.is_null() {
                unsafe {
                    *context = Context {
                        chain_head: head,
                        prev_linkage: link,
                        signature,
                    };
                }
            }
            return entry;
        }
        previous = link;
        link = unsafe { (*link).flink };
    }
    if !context.is_null() {
        unsafe {
            *context = Context {
                chain_head: head,
                prev_linkage: previous,
                signature,
            };
        }
    }
    null_mut()
}

/// # Safety
/// `context` must come from a lookup on this table, without intervening mutation.
#[export_name = "RtlGetNextEntryHashTable"]
pub unsafe extern "system" fn rtl_get_next_entry_hash_table(
    table: *mut Table,
    context: *mut Context,
) -> *mut Entry {
    if table.is_null() || context.is_null() {
        return null_mut();
    }
    let c = unsafe { &mut *context };
    if c.signature == 0
        || c.chain_head.is_null()
        || c.prev_linkage.is_null()
        || unsafe { bucket(table, c.signature) != c.chain_head }
    {
        return null_mut();
    }
    let mut link = unsafe { (*c.prev_linkage).flink };
    while link != c.chain_head {
        let entry = link.cast::<Entry>();
        if unsafe { (*entry).signature == c.signature } {
            c.prev_linkage = link;
            return entry;
        }
        link = unsafe { (*link).flink };
    }
    null_mut()
}

unsafe fn init_enumeration(table: *mut Table, enumeration: *mut Enumerator) -> u8 {
    if table.is_null() || enumeration.is_null() {
        return 0;
    }
    let t = unsafe { &mut *table };
    if t.directory.is_null() || t.num_enumerators == u32::MAX {
        return 0;
    }
    unsafe {
        *enumeration = Enumerator {
            current: null_mut(),
            chain_head: null_mut(),
            bucket_index: 0,
        };
    }
    t.num_enumerators += 1;
    1
}

unsafe fn enumerate(table: *mut Table, enumeration: *mut Enumerator) -> *mut Entry {
    if table.is_null() || enumeration.is_null() {
        return null_mut();
    }
    let t = unsafe { &*table };
    let e = unsafe { &mut *enumeration };
    if t.directory.is_null() || e.bucket_index >= t.table_size {
        return null_mut();
    }
    let mut index = e.bucket_index;
    let mut link = if e.current.is_null() {
        let head = unsafe { t.directory.add(index as usize) };
        unsafe { (*head).flink }
    } else {
        unsafe { (*e.current).flink }
    };
    loop {
        let head = unsafe { t.directory.add(index as usize) };
        if link != head {
            e.current = link;
            e.chain_head = head;
            e.bucket_index = index;
            return link.cast();
        }
        index += 1;
        if index >= t.table_size {
            e.current = null_mut();
            e.chain_head = null_mut();
            e.bucket_index = index;
            return null_mut();
        }
        link = unsafe { (*t.directory.add(index as usize)).flink };
    }
}

unsafe fn end_enumeration(table: *mut Table, enumeration: *mut Enumerator) {
    if table.is_null() || enumeration.is_null() {
        return;
    }
    let t = unsafe { &mut *table };
    let e = unsafe { &mut *enumeration };
    if t.num_enumerators > 0 && e.bucket_index <= t.table_size {
        t.num_enumerators -= 1;
    }
    e.bucket_index = u32::MAX;
    e.chain_head = null_mut();
    e.current = null_mut();
}

/// # Safety
/// The table and enumerator must remain live until EndEnumeration.
#[export_name = "RtlInitEnumerationHashTable"]
pub unsafe extern "system" fn rtl_init_enumeration_hash_table(
    table: *mut Table,
    enumeration: *mut Enumerator,
) -> u8 {
    unsafe { init_enumeration(table, enumeration) }
}

/// # Safety
/// The table and initialized enumerator must remain live without concurrent mutation.
#[export_name = "RtlEnumerateEntryHashTable"]
pub unsafe extern "system" fn rtl_enumerate_entry_hash_table(
    table: *mut Table,
    enumeration: *mut Enumerator,
) -> *mut Entry {
    unsafe { enumerate(table, enumeration) }
}

/// # Safety
/// The table and initialized enumerator must remain live.
#[export_name = "RtlEndEnumerationHashTable"]
pub unsafe extern "system" fn rtl_end_enumeration_hash_table(
    table: *mut Table,
    enumeration: *mut Enumerator,
) {
    unsafe { end_enumeration(table, enumeration) }
}

/// # Safety
/// The table and enumerator must remain live until EndWeakEnumeration.
#[export_name = "RtlInitWeakEnumerationHashTable"]
pub unsafe extern "system" fn rtl_init_weak_enumeration_hash_table(
    table: *mut Table,
    enumeration: *mut Enumerator,
) -> u8 {
    unsafe { init_enumeration(table, enumeration) }
}

/// # Safety
/// The table and initialized enumerator must remain live.
#[export_name = "RtlWeaklyEnumerateEntryHashTable"]
pub unsafe extern "system" fn rtl_weakly_enumerate_entry_hash_table(
    table: *mut Table,
    enumeration: *mut Enumerator,
) -> *mut Entry {
    unsafe { enumerate(table, enumeration) }
}

/// # Safety
/// The table and initialized enumerator must remain live.
#[export_name = "RtlEndWeakEnumerationHashTable"]
pub unsafe extern "system" fn rtl_end_weak_enumeration_hash_table(
    table: *mut Table,
    enumeration: *mut Enumerator,
) {
    unsafe { end_enumeration(table, enumeration) }
}

unsafe fn resize(table: *mut Table, size: u32) -> u8 {
    if table.is_null() || bucket_count(size).is_none() {
        return 0;
    }
    let t = unsafe { &mut *table };
    if t.directory.is_null() || t.num_enumerators != 0 {
        return 0;
    }
    let bytes = size as usize * core::mem::size_of::<Link>();
    let directory = unsafe { allocate(bytes) } as *mut Link;
    if directory.is_null() {
        return 0;
    }
    unsafe {
        init_directory(directory, size as usize);
    }
    for index in 0..t.table_size as usize {
        let head = unsafe { t.directory.add(index) };
        while unsafe { (*head).flink } != head {
            let link = unsafe { (*head).flink };
            let signature = unsafe { (*(link.cast::<Entry>())).signature };
            unsafe {
                unlink(link);
            }
            let target =
                unsafe { directory.add(((signature >> t.shift) as u32 & (size - 1)) as usize) };
            unsafe {
                append_after((*target).blink, link);
            }
        }
    }
    unsafe {
        release(
            t.directory.cast(),
            t.table_size as usize * core::mem::size_of::<Link>(),
        );
    }
    t.directory = directory;
    t.table_size = size;
    t.divisor_mask = size - 1;
    t.pivot = 0;
    t.non_empty_buckets = 0;
    for index in 0..size as usize {
        let head = unsafe { directory.add(index) };
        if unsafe { (*head).flink != head } {
            t.non_empty_buckets += 1;
        }
    }
    1
}

/// # Safety
/// The table must be live and no callers may retain contexts across resize.
#[export_name = "RtlExpandHashTable"]
pub unsafe extern "system" fn rtl_expand_hash_table(table: *mut Table) -> u8 {
    if table.is_null() {
        return 0;
    }
    let Some(size) = (unsafe { (*table).table_size.checked_mul(2) }) else {
        return 0;
    };
    unsafe { resize(table, size) }
}

/// # Safety
/// The table must be live and no callers may retain contexts across resize.
#[export_name = "RtlContractHashTable"]
pub unsafe extern "system" fn rtl_contract_hash_table(table: *mut Table) -> u8 {
    if table.is_null() {
        return 0;
    }
    let size = unsafe { (*table).table_size / 2 };
    unsafe { resize(table, size) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_matches_x64_wdk() {
        assert_eq!(core::mem::size_of::<Entry>(), 24);
        assert_eq!(core::mem::size_of::<Context>(), 24);
        assert_eq!(core::mem::size_of::<Enumerator>(), 24);
        assert_eq!(core::mem::size_of::<Table>(), 40);
    }

    #[test]
    fn collisions_lookup_context_and_removal() {
        unsafe {
            let mut table = null_mut();
            assert_eq!(rtl_create_hash_table(&mut table, 0, 0), 1);
            let mut first = Entry {
                linkage: Link {
                    flink: null_mut(),
                    blink: null_mut(),
                },
                signature: 0,
            };
            let mut second = Entry {
                linkage: Link {
                    flink: null_mut(),
                    blink: null_mut(),
                },
                signature: 0,
            };
            assert_eq!(
                rtl_insert_entry_hash_table(table, &mut first, 7, null_mut()),
                1
            );
            assert_eq!(
                rtl_insert_entry_hash_table(table, &mut second, 135, null_mut()),
                1
            );
            assert_eq!((*table).num_entries, 2);
            assert_eq!((*table).non_empty_buckets, 1);
            let mut context = Context {
                chain_head: null_mut(),
                prev_linkage: null_mut(),
                signature: 0,
            };
            assert!(rtl_lookup_entry_hash_table(table, 7, &mut context) == &mut first);
            assert_eq!(
                rtl_get_next_entry_hash_table(table, &mut context),
                null_mut()
            );
            assert!(rtl_lookup_entry_hash_table(table, 135, &mut context) == &mut second);
            assert_eq!(
                rtl_remove_entry_hash_table(table, &mut first, null_mut()),
                1
            );
            assert_eq!((*table).non_empty_buckets, 1);
            assert_eq!(
                rtl_remove_entry_hash_table(table, &mut second, null_mut()),
                1
            );
            assert_eq!((*table).non_empty_buckets, 0);
            rtl_delete_hash_table(table);
        }
    }

    #[test]
    fn enumeration_and_resize_preserve_entries() {
        unsafe {
            let mut table = null_mut();
            assert_eq!(rtl_create_hash_table(&mut table, 0, 0), 1);
            let mut entries: [Entry; 3] = core::array::from_fn(|_| Entry {
                linkage: Link {
                    flink: null_mut(),
                    blink: null_mut(),
                },
                signature: 0,
            });
            for (entry, key) in entries.iter_mut().zip([1, 129, 257]) {
                assert_eq!(
                    rtl_insert_entry_hash_table(table, entry, key, null_mut()),
                    1
                );
            }
            let mut enumeration = Enumerator {
                current: null_mut(),
                chain_head: null_mut(),
                bucket_index: 0,
            };
            assert_eq!(rtl_init_enumeration_hash_table(table, &mut enumeration), 1);
            assert_eq!((*table).num_enumerators, 1);
            assert_eq!(rtl_expand_hash_table(table), 0);
            let mut found = 0;
            while !rtl_enumerate_entry_hash_table(table, &mut enumeration).is_null() {
                found += 1;
            }
            assert_eq!(found, 3);
            rtl_end_enumeration_hash_table(table, &mut enumeration);
            assert_eq!((*table).num_enumerators, 0);
            assert_eq!(rtl_expand_hash_table(table), 1);
            for (entry, key) in entries.iter_mut().zip([1, 129, 257]) {
                assert!(rtl_lookup_entry_hash_table(table, key, null_mut()) == entry);
            }
            assert_eq!(rtl_contract_hash_table(table), 1);
            rtl_delete_hash_table(table);
        }
    }
}
