#[path = "../../../components/ntos-executive/src/allocator_free_list.rs"]
mod free_list;

use free_list::FreeList;

const WORD: usize = core::mem::size_of::<usize>();
const NODE: usize = WORD * 2;

#[test]
fn native_deallocation_and_shrink_use_the_host_tested_insertion_core() {
    let source = include_str!("../../../components/ntos-executive/src/allocator.rs");
    assert!(source.contains("#[path = \"allocator_free_list.rs\"]"));
    assert!(source.contains("list.insert(start, size)"));
    assert!(source.contains("insert_free_block(start + new_block_size, tail)"));
    assert!(!source.contains("release_top_free_blocks"));
}

struct Heap {
    words: Box<[usize]>,
    data: usize,
    list: FreeList,
}

impl Heap {
    fn new(bytes: usize) -> Self {
        let mut words = vec![0usize; 2 + bytes.div_ceil(WORD)].into_boxed_slice();
        let base = words.as_mut_ptr() as usize;
        let data = base + 2 * WORD;
        words[0] = bytes;
        Self {
            words,
            data,
            list: FreeList {
                data,
                counter: base,
                head: base + WORD,
            },
        }
    }

    fn insert(&mut self, offset: usize, size: usize) -> usize {
        unsafe { self.list.insert(self.data + offset, size).unwrap() }
    }

    fn bump(&self) -> usize {
        self.words[0]
    }

    fn blocks(&self) -> Vec<(usize, usize)> {
        let mut result = Vec::new();
        let mut node = self.words[1];
        while node != 0 {
            assert!(result.len() <= self.words.len(), "free-list cycle");
            let size = unsafe { (node as *const usize).read() };
            result.push((node - self.data, size));
            node = unsafe { ((node + WORD) as *const usize).read() };
        }
        result
    }
}

#[test]
fn top_dealloc_uses_existing_insertion_walk_even_after_many_interior_blocks() {
    const INTERIOR: usize = 256;
    let top = INTERIOR * 64 + 64;
    let mut heap = Heap::new(top);
    for i in 0..INTERIOR {
        heap.insert(i * 64, NODE);
    }
    assert_eq!(heap.blocks().len(), INTERIOR);

    // The existing address-order search visits each interior node once. Tail release should use
    // the predecessor link found by that search rather than scan those nodes a second time.
    let visits = heap.insert(top - NODE, NODE);
    assert_eq!(visits, INTERIOR, "telemetry must count each inspected free node once");
    assert_eq!(heap.bump(), top - NODE);
    assert_eq!(heap.blocks().len(), INTERIOR);
}

#[test]
fn realloc_shrink_and_adjacent_coalescing_trim_exactly_the_final_top_block() {
    let mut heap = Heap::new(112);
    heap.insert(16, NODE);
    heap.insert(48, NODE);
    heap.insert(32, NODE);
    assert_eq!(heap.blocks(), [(16, 48)]);

    // A shrinking top allocation publishes its now-unused aligned suffix as a free block.
    heap.insert(80, 32);
    assert_eq!(heap.bump(), 80);
    assert_eq!(heap.blocks(), [(16, 48)]);

    // A later deallocation joins the interior block and reaches the new top. Both coalescing and
    // bump release must remove the resulting node, with no stale link left in the list.
    heap.insert(64, NODE);
    assert_eq!(heap.bump(), 16);
    assert!(heap.blocks().is_empty());
}

#[test]
fn insertion_refuses_a_corrupt_successor_before_following_it() {
    let mut heap = Heap::new(256);
    heap.words[1] = heap.data + 16;
    unsafe {
        ((heap.data + 16) as *mut usize).write(NODE);
        ((heap.data + 16 + WORD) as *mut usize).write(heap.data + 256);
    }
    let error = unsafe { heap.list.insert(heap.data + 64, NODE) }.unwrap_err();
    assert_eq!(error.operation, b"insert-walk");
    assert_eq!(heap.bump(), 256);
}

#[test]
fn adjacent_growth_stops_at_first_free_block_past_target() {
    let mut heap = Heap::new(8192);
    for index in 0..128 {
        heap.insert(1024 + index * 32, NODE);
    }
    let before = heap.blocks();
    let miss = unsafe { heap.list.grow_adjacent(heap.data, 512, 512 + NODE) };
    assert!(!miss.grown);
    assert_eq!(miss.inspected, 1, "miss must inspect only the first free node past target");
    assert_eq!(heap.blocks(), before);

    let hit = unsafe { heap.list.grow_adjacent(heap.data + 1008, NODE, NODE * 2) };
    assert!(hit.grown);
    assert_eq!(hit.inspected, 1);
    assert_eq!(heap.blocks().len(), 127);
}

#[test]
fn first_fit_preserves_aligned_prefix_suffix_and_earlier_free_nodes() {
    let mut heap = Heap::new(1024);
    let high = 128 + ((16 + 64 - ((heap.data + 128) % 64)) % 64);
    heap.insert(16, NODE);
    heap.insert(high, 192);

    let taken = unsafe { heap.list.take_fit(64, 32).unwrap() };
    assert_eq!(taken.address, Some(heap.data + high + 48));
    assert_eq!(taken.inspected, 2);
    assert_eq!(taken.prefix_reinsert_visits, Some(1));
    assert_eq!(taken.suffix_reinsert_visits, Some(2));
    assert_eq!(heap.blocks(), [(16, NODE), (high, 48), (high + 80, 112)]);
    assert_eq!(heap.bump(), 1024);
}

#[test]
fn first_fit_preserves_top_trim_when_a_top_ending_node_is_present() {
    let mut heap = Heap::new(512);
    let high = 256 + ((16 + 64 - ((heap.data + 256) % 64)) % 64);
    let node = heap.data + high;
    // Ordinarily insert() trims a top-ending node immediately. Seed this boundary directly to
    // prove that take_fit retains the old split path's top-trim behavior as well.
    heap.words[1] = node;
    unsafe {
        (node as *mut usize).write(512 - high);
        ((node + WORD) as *mut usize).write(0);
    }

    let taken = unsafe { heap.list.take_fit(64, 32).unwrap() };
    assert_eq!(taken.address, Some(node + 48));
    assert_eq!(heap.bump(), high + 80);
    assert_eq!(heap.blocks(), [(high, 48)]);
}
