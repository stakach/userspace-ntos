//! Exercise the native exact-size small-block caches against ordinary aligned host memory,
//! alongside the address-ordered free list they sit in front of (#348).
#[path = "../../../components/ntos-executive/src/allocator_free_list.rs"]
mod free_list;
#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/allocator_quick_lists.rs"]
mod quick_lists;

use free_list::FreeList;
use quick_lists::{class_cap, QuickCorruption, QuickLists, QUICK_MAX_BLOCK, QUICK_WORDS};

const WORD: usize = core::mem::size_of::<usize>();

/// `[bump, head, quick metadata..., data...]`; the whole data region counts as bumped.
struct Heap {
    words: Box<[usize]>,
    data: usize,
    list: FreeList,
    quick: QuickLists,
}

impl Heap {
    fn new(bytes: usize) -> Self {
        let mut words = vec![0usize; 2 + QUICK_WORDS + bytes.div_ceil(WORD)].into_boxed_slice();
        let base = words.as_mut_ptr() as usize;
        let meta = base + 2 * WORD;
        let data = meta + QUICK_WORDS * WORD;
        words[0] = bytes;
        Self {
            words,
            data,
            list: FreeList { data, counter: base, head: base + WORD },
            quick: QuickLists { meta, data },
        }
    }
    fn top(&self) -> usize { self.data + self.words[0] }
}

/// A fragmented heap: `fragments` non-adjacent free blocks of mixed small sizes, all smaller
/// than `probe`, ahead of one block that fits it.
fn fragmented(fragments: usize, probe: usize) -> Heap {
    let heap = Heap::new(fragments * 64 + 4096);
    for index in 0..fragments {
        let size = 16 + (index % 3) * 8;
        assert!(size < probe);
        unsafe { heap.list.insert(heap.data + index * 64, size).unwrap() };
    }
    unsafe { heap.list.insert(heap.data + fragments * 64, 1024).unwrap() };
    heap
}

/// RED baseline and GREEN: a hot allocate/release cycle of one small object visits every
/// fragment twice per cycle on the address-ordered list alone, and no node through the caches.
#[test]
fn hot_small_cycle_stops_walking_the_address_ordered_list() {
    const FRAGMENTS: usize = 200;
    const CYCLES: usize = 1000;
    const PROBE: usize = 48;

    let heap = fragmented(FRAGMENTS, PROBE);
    let mut list_only = 0usize;
    for _ in 0..CYCLES {
        let taken = unsafe { heap.list.take_fit(WORD, PROBE) }.unwrap();
        list_only += taken.inspected
            + taken.prefix_reinsert_visits.unwrap_or(0) + taken.suffix_reinsert_visits.unwrap_or(0);
        list_only += unsafe { heap.list.insert(taken.address.unwrap(), PROBE) }.unwrap();
    }
    assert!(list_only >= CYCLES * FRAGMENTS * 2, "list-only visits: {list_only}");

    let heap = fragmented(FRAGMENTS, PROBE);
    let mut cached = 0usize;
    let first = unsafe { heap.list.take_fit(WORD, PROBE) }.unwrap();
    cached += first.inspected + first.suffix_reinsert_visits.unwrap_or(0);
    let mut live = first.address.unwrap();
    for _ in 0..CYCLES {
        assert!(unsafe { heap.quick.push(live, PROBE) });
        live = unsafe { heap.quick.pop(PROBE, WORD, heap.top()) }.unwrap().unwrap();
    }
    assert_eq!(live, first.address.unwrap(), "the same block is reused");
    assert_eq!(cached, FRAGMENTS + 1, "only the first allocation walks the list");
}

#[test]
fn caches_are_exact_size_lifo_bounded_and_counted() {
    #[allow(non_snake_case)]
    let QUICK_CLASS_CAP = class_cap(32);
    assert_eq!(class_cap(QUICK_MAX_BLOCK), 512, "each cache holds a bounded byte budget");
    let heap = Heap::new(QUICK_CLASS_CAP * 64 + 4096);
    let block = |index: usize| heap.data + index * 64;
    // Outside the cached sizes: undersized, unaligned and large blocks are refused.
    for size in [8, 20, QUICK_MAX_BLOCK + 8] {
        assert!(!unsafe { heap.quick.push(block(0), size) });
    }
    for index in 0..QUICK_CLASS_CAP {
        assert!(unsafe { heap.quick.push(block(index), 32) });
    }
    assert!(!unsafe { heap.quick.push(block(QUICK_CLASS_CAP), 32) }, "a full class falls back");
    assert!(unsafe { heap.quick.push(block(QUICK_CLASS_CAP + 1), QUICK_MAX_BLOCK) });
    assert_eq!(unsafe { heap.quick.cached() },
        (QUICK_CLASS_CAP * 32 + QUICK_MAX_BLOCK, QUICK_MAX_BLOCK));

    // Another size never serves this one; the most recent release is reused first.
    assert_eq!(unsafe { heap.quick.pop(40, WORD, heap.top()) }, Ok(None));
    assert_eq!(unsafe { heap.quick.pop(32, WORD, heap.top()) },
        Ok(Some(block(QUICK_CLASS_CAP - 1))));

    let mut released = Vec::new();
    let drained = unsafe { heap.quick.drain(|start, size| released.push((start, size))) };
    assert_eq!(drained, QUICK_CLASS_CAP);
    assert_eq!(released.len(), QUICK_CLASS_CAP);
    assert!(released.contains(&(block(QUICK_CLASS_CAP + 1), QUICK_MAX_BLOCK)));
    assert!(released.contains(&(block(0), 32)));
    assert_eq!(unsafe { heap.quick.cached() }, (0, 0));
    assert_eq!(unsafe { heap.quick.pop(32, WORD, heap.top()) }, Ok(None));
}

#[test]
fn a_misaligned_head_is_left_for_the_list_and_a_damaged_node_is_refused() {
    let heap = Heap::new(4096);
    let odd = if (heap.data + 64) % 16 == 0 { heap.data + 72 } else { heap.data + 64 };
    assert!(unsafe { heap.quick.push(odd, 32) });
    assert_eq!(unsafe { heap.quick.pop(32, 16, heap.top()) }, Ok(None));
    assert_eq!(unsafe { heap.quick.cached() }.0, 32, "the misaligned block stays cached");
    assert_eq!(unsafe { heap.quick.pop(32, WORD, heap.top()) }, Ok(Some(odd)));

    // A cached node whose size word was overwritten is corruption, not a reusable block.
    assert!(unsafe { heap.quick.push(heap.data + 128, 32) });
    unsafe { ((heap.data + 128) as *mut usize).write(48) };
    assert_eq!(unsafe { heap.quick.pop(32, WORD, heap.top()) },
        Err(QuickCorruption { node: heap.data + 128, size: 48, next: 0 }));
    // A node above the bump top is refused too.
    let heap = Heap::new(4096);
    assert!(unsafe { heap.quick.push(heap.data + 4096 - 32, 32) });
    assert!(unsafe { heap.quick.pop(32, WORD, heap.data + 1024) }.is_err());
}

/// Boot 44717077667 spent 262,949 Mtick in 57.4 M grow-in-place walks (~300 nodes each).
/// Growth to a cached size moves through the caches instead.
#[test]
fn growth_to_a_cached_size_moves_through_the_caches() {
    for size in [16, 24, 128, QUICK_MAX_BLOCK] {
        assert!(QuickLists::serves(size), "{size}");
    }
    for size in [8, 20, QUICK_MAX_BLOCK + 8, 4096] {
        assert!(!QuickLists::serves(size), "{size}");
    }
    // A 64 -> 128 byte growth: one pop and one push, no address-ordered walk.
    let heap = fragmented(200, 48);
    let old = heap.data + 200 * 64 + 2048;
    let new = heap.data + 200 * 64 + 3072;
    assert!(unsafe { heap.quick.push(new, 128) });
    let moved = unsafe { heap.quick.pop(128, WORD, heap.top()) }.unwrap().unwrap();
    assert_eq!(moved, new);
    assert!(unsafe { heap.quick.push(old, 64) });
    assert_eq!(unsafe { heap.quick.cached() }, (64, 64));
}
