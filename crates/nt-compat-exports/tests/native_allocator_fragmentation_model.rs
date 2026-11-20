//! Host model of the native durable heap's reuse policy (#348): a random mixed workload drives
//! the real free list, size caches and policy, and the address-ordered list's walk cost is
//! compared with the previous composition (caches, then plain first fit).
#[path = "../../../components/ntos-executive/src/allocator_free_list.rs"]
mod free_list;
#[allow(dead_code)]
#[path = "../../../components/ntos-executive/src/allocator_quick_lists.rs"]
mod quick_lists;
#[path = "../../../components/ntos-executive/src/allocator_durable_policy.rs"]
mod durable_policy;

use durable_policy::DurablePolicy;
use free_list::FreeList;
use quick_lists::{QuickLists, QUICK_MAX_BLOCK, QUICK_WORDS};

const WORD: usize = core::mem::size_of::<usize>();

/// `[bump, head, cache metadata..., data...]`.
struct Heap {
    words: Box<[usize]>,
    policy: DurablePolicy,
}

impl Heap {
    fn new(bytes: usize) -> Self {
        let mut words = vec![0usize; 2 + QUICK_WORDS + bytes / WORD].into_boxed_slice();
        let base = words.as_mut_ptr() as usize;
        let meta = base + 2 * WORD;
        let data = meta + QUICK_WORDS * WORD;
        Self {
            words,
            policy: DurablePolicy {
                list: FreeList { data, counter: base, head: base + WORD },
                quick: QuickLists { meta, data },
            },
        }
    }
    fn data(&self) -> usize { self.policy.list.data }
    fn top(&self) -> usize { self.data() + self.words[0] }
    fn bump(&mut self, size: usize) -> usize {
        let start = self.top();
        self.words[0] += size;
        start
    }
    /// (nodes, nodes of at most QUICK_MAX_BLOCK bytes) in the address-ordered list.
    fn list_nodes(&self) -> (usize, usize) {
        let (mut nodes, mut small) = (0, 0);
        let mut node = self.words[1];
        while node != 0 {
            let size = unsafe { (node as *const usize).read() };
            nodes += 1;
            small += usize::from(size <= QUICK_MAX_BLOCK);
            node = unsafe { ((node + WORD) as *const usize).read() };
        }
        (nodes, small)
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

/// 70% 16..=256 bytes, 25% up to ~2 KiB, 5% up to ~16 KiB.
fn block(rng: &mut Rng) -> usize {
    let class = rng.next() % 100;
    let size = if class < 70 { 16 + rng.next() % 241 }
        else if class < 95 { 264 + rng.next() % 1800 }
        else { 2048 + rng.next() % 14000 };
    (size as usize + 7) & !7
}

#[derive(Debug)]
struct Outcome { visits_per_op: usize, nodes: usize, small_nodes: usize, bump: usize }

/// `spilling`: the native policy; otherwise the previous composition (cache pop, plain first
/// fit, cache or insert on release) over the same real list and caches.
fn run(spilling: bool) -> Outcome {
    let mut heap = Heap::new(256 << 20);
    let mut rng = Rng(7);
    let mut live: Vec<(usize, usize)> = Vec::new();
    let (mut ops, mut visits) = (0usize, 0usize);
    for step in 0..400_000 {
        let allocate = live.len() < 2000 || rng.next() % 100 < if step < 200_000 { 55 } else { 50 };
        if allocate {
            let size = block(&mut rng);
            let address = if spilling {
                let reuse = unsafe { heap.policy.reuse(WORD, size, heap.top()) }.unwrap();
                for walk in [reuse.fit_visits, reuse.insert_visits].into_iter().flatten() {
                    ops += 1;
                    visits += walk;
                }
                reuse.address
            } else {
                match unsafe { heap.policy.quick.pop(size, WORD, heap.top()) }.unwrap() {
                    Some(address) => Some(address),
                    None => {
                        let taken = unsafe { heap.policy.list.take_fit(WORD, size) }.unwrap();
                        ops += 1;
                        visits += taken.inspected;
                        taken.address
                    }
                }
            };
            let address = address.unwrap_or_else(|| heap.bump(size));
            live.push((address, size));
        } else if !live.is_empty() {
            let (start, size) = live.swap_remove(rng.next() as usize % live.len());
            if let Some(walk) = unsafe { heap.policy.release(start, size, heap.top()) }.unwrap() {
                ops += 1;
                visits += walk;
            }
        }
    }
    let (nodes, small_nodes) = heap.list_nodes();
    Outcome { visits_per_op: visits / ops.max(1), nodes, small_nodes, bump: heap.words[0] }
}

#[test]
fn small_split_suffixes_no_longer_fragment_the_address_ordered_list() {
    let previous = run(false);
    let current = run(true);
    // RED (previous composition): 1,712 visits per walk; 3,243 of 4,654 list nodes were
    // small split remainders that cached small allocations never consumed.
    assert!(previous.small_nodes * 2 > previous.nodes, "{previous:?}");
    // GREEN: no small fragment reaches the list, and each walk visits a third as many nodes.
    assert_eq!(current.small_nodes, 0, "{current:?}");
    assert!(current.visits_per_op * 2 < previous.visits_per_op, "{previous:?} {current:?}");
    // The bounded caches cost at most a few percent of heap growth.
    assert!(current.bump < previous.bump + previous.bump / 10, "{previous:?} {current:?}");
}
