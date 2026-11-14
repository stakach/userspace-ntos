//! The durable heap's owner ledger: who holds the live bytes, within fixed tables.

#[path = "../../../components/ntos-executive/src/allocator_sites.rs"]
mod sites;

use sites::{Frames, Site, SiteLedger, Tally, BLOCK_CAPACITY, SITE_CAPACITY, SITE_FRAMES};
use std::collections::HashMap;

fn ledger() -> Box<SiteLedger> {
    // The allocator carves the ledger from zeroed heap; all-zero is its empty state.
    unsafe { Box::<SiteLedger>::new_zeroed().assume_init() }
}

fn site(id: usize) -> Frames {
    let mut frames = [0; SITE_FRAMES];
    frames[0] = 0x40_0000 + id * 16;
    frames[1] = 0x50_0000;
    frames
}

fn top(ledger: &SiteLedger, count: usize) -> Vec<Site> {
    let mut out = vec![Site::default(); count];
    let filled = ledger.top_sites(&mut out);
    out.truncate(filled);
    out
}

/// The shape of the logon-time wall: one retained 9 MiB image above many small objects.
#[test]
fn the_largest_live_owner_is_named_first() {
    let mut ledger = ledger();
    ledger.record_alloc(0x1000_0000, 9_043_944, &site(1));
    ledger.record_alloc(0x2000_0000, 1_880_400, &site(2));
    ledger.record_alloc(0x3000_0000, 1_880_400, &site(2));
    ledger.record_alloc(0x4000_0000, 3_307_784, &site(3));
    ledger.record_free(0x4000_0000, 3_307_784);
    for small in 0..1000 {
        ledger.record_alloc(0x5000_0000 + small * 64, 48, &[0; SITE_FRAMES]);
    }
    let top = top(&ledger, 8);
    assert_eq!(top.len(), 2, "a site with nothing live is not an owner");
    assert_eq!(top[0].frames, site(1));
    assert_eq!(top[0].live, Tally { bytes: 9_043_944, count: 1 });
    assert_eq!(top[1].frames, site(2));
    assert_eq!(top[1].live, Tally { bytes: 3_760_800, count: 2 });
    assert_eq!(ledger.attributed(), Tally { bytes: 12_804_744, count: 3 });
    assert_eq!(ledger.classes()[5], Tally { bytes: 48_000, count: 1000 });
    assert_eq!(ledger.classes()[23], Tally { bytes: 9_043_944, count: 1 });
    assert_eq!(ledger.classes()[21], Tally::default(), "the freed read buffer left its class");
    assert_eq!(ledger.sites_used(), 3);
    assert_eq!(ledger.site_of(0x1000_0000).unwrap().frames, site(1));
    assert!(ledger.site_of(0x4000_0000).is_none());
}

#[test]
fn a_site_keeps_its_peak_and_allocation_count_after_release() {
    let mut ledger = ledger();
    for round in 0..3 {
        ledger.record_alloc(0x1000, 1 << 20, &site(7));
        ledger.record_alloc(0x20_0000, 1 << 20, &site(7));
        ledger.record_free(0x1000, 1 << 20);
        if round != 2 {
            ledger.record_free(0x20_0000, 1 << 20);
        }
    }
    let top = top(&ledger, 4);
    assert_eq!(top.len(), 1);
    assert_eq!(top[0].live, Tally { bytes: 1 << 20, count: 1 });
    assert_eq!(top[0].peak_bytes, 2 << 20);
    assert_eq!(top[0].allocations, 6);
}

#[test]
fn only_the_requested_number_of_owners_is_returned_in_order() {
    let mut ledger = ledger();
    for id in 0..40usize {
        // Sizes ascend then descend so insertion order is not already sorted.
        let bytes = 8192 + ((id * 17) % 40) * 4096;
        ledger.record_alloc(0x10_0000 * (id + 1), bytes, &site(id));
    }
    let top = top(&ledger, 5);
    assert_eq!(top.len(), 5);
    let bytes: Vec<usize> = top.iter().map(|site| site.live.bytes).collect();
    assert_eq!(bytes, [8192 + 39 * 4096, 8192 + 38 * 4096, 8192 + 37 * 4096, 8192 + 36 * 4096, 8192 + 35 * 4096]);
}

/// Full tables must read as a named shortfall, never as memory nobody holds.
#[test]
fn sites_and_blocks_beyond_the_tables_are_counted_as_unattributed() {
    let mut ledger = ledger();
    for id in 0..SITE_CAPACITY + 10 {
        ledger.record_alloc(0x10_0000 + id * 0x2000, 8192, &site(id));
    }
    assert_eq!(ledger.sites_used(), SITE_CAPACITY);
    assert_eq!(ledger.unattributed(), Tally { bytes: 10 * 8192, count: 10 });
    assert_eq!(ledger.attributed(), Tally { bytes: SITE_CAPACITY * 8192, count: SITE_CAPACITY });
    for id in 0..SITE_CAPACITY + 10 {
        ledger.record_free(0x10_0000 + id * 0x2000, 8192);
    }
    assert_eq!(ledger.unattributed(), Tally::default());
    assert_eq!(ledger.attributed(), Tally::default());

    let mut ledger = self::ledger();
    for block in 0..BLOCK_CAPACITY + 100 {
        ledger.record_alloc(0x1000_0000 + block * 0x1000, 4096, &site(1));
    }
    let attributed = ledger.attributed();
    let unattributed = ledger.unattributed();
    assert_eq!(attributed.count, BLOCK_CAPACITY - 1, "one slot stays empty to end probes");
    assert_eq!(attributed.count + unattributed.count, BLOCK_CAPACITY + 100);
    assert_eq!(ledger.classes()[12].count, BLOCK_CAPACITY + 100);
    for block in 0..BLOCK_CAPACITY + 100 {
        ledger.record_free(0x1000_0000 + block * 0x1000, 4096);
    }
    assert_eq!(ledger.attributed(), Tally::default());
    assert_eq!(ledger.unattributed(), Tally::default());
    assert_eq!(ledger.classes()[12], Tally::default());
}

/// Releases in any order leave every other block findable (open-addressing deletion).
#[test]
fn the_ledger_agrees_with_a_model_under_churn() {
    let mut ledger = ledger();
    let mut model: HashMap<usize, (usize, usize)> = HashMap::new();
    let mut per_site: HashMap<usize, Tally> = HashMap::new();
    let mut state = 0x243f_6a88_85a3_08d3u64;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state as usize
    };
    for _ in 0..200_000 {
        let roll = next();
        if model.len() < 6000 && roll % 5 < 3 {
            // Clustered addresses, as a bump allocator hands them out.
            let address = 0x1e00_0000 + (next() % 20_000) * 0x1000;
            if model.contains_key(&address) {
                continue;
            }
            let bytes = 4096 + (next() % 64) * 4096;
            let id = next() % 100;
            ledger.record_alloc(address, bytes, &site(id));
            model.insert(address, (bytes, id));
            let tally = per_site.entry(id).or_default();
            tally.bytes += bytes;
            tally.count += 1;
        } else if let Some((&address, &(bytes, id))) = model.iter().nth(roll % model.len().max(1)) {
            ledger.record_free(address, bytes);
            model.remove(&address);
            let tally = per_site.get_mut(&id).unwrap();
            tally.bytes -= bytes;
            tally.count -= 1;
        }
    }
    assert_eq!(ledger.unattributed(), Tally::default());
    for (&address, &(_, id)) in &model {
        assert_eq!(ledger.site_of(address).unwrap().frames, site(id));
    }
    let live_sites = per_site.values().filter(|tally| tally.bytes != 0).count();
    let top = top(&ledger, SITE_CAPACITY);
    assert_eq!(top.len(), live_sites);
    for row in &top {
        let id = (row.frames[0] - 0x40_0000) / 16;
        assert_eq!(row.live, per_site[&id]);
    }
    let total: usize = model.values().map(|&(bytes, _)| bytes).sum();
    assert_eq!(ledger.attributed(), Tally { bytes: total, count: model.len() });
    let classes: usize = ledger.classes().iter().map(|class| class.bytes).sum();
    assert_eq!(classes, total);
}

/// A stack image: `words[i]` is the word at `base + 8 * i`.
struct Stack {
    words: Vec<usize>,
}

impl Stack {
    fn base(&self) -> usize {
        self.words.as_ptr() as usize
    }
    fn range(&self) -> core::ops::Range<usize> {
        self.base()..self.base() + self.words.len() * 8
    }
    fn at(&self, index: usize) -> usize {
        self.base() + index * 8
    }
    fn record(&mut self, index: usize, next: usize, ret: usize) {
        self.words[index] = next;
        self.words[index + 1] = ret;
    }
}

const TEXT: core::ops::Range<usize> = 0x40_0000..0x80_0000;

#[test]
fn a_frame_chain_yields_return_addresses_innermost_first() {
    let mut stack = Stack { words: vec![0; 64] };
    let (a, b, c) = (stack.at(4), stack.at(20), stack.at(40));
    stack.record(4, b, 0x40_1000);
    stack.record(20, c, 0x40_2000);
    stack.record(40, 0, 0x40_3000);
    let frames = unsafe { sites::walk_frames(a, stack.range(), TEXT) };
    assert_eq!(frames[..4], [0x40_1000, 0x40_2000, 0x40_3000, 0]);
}

#[test]
fn a_long_chain_is_cut_at_the_site_depth() {
    let mut stack = Stack { words: vec![0; 64] };
    for frame in 0..20 {
        let next = stack.at(2 * frame + 2);
        stack.record(2 * frame, next, 0x40_0000 + frame);
    }
    let frames = unsafe { sites::walk_frames(stack.at(0), stack.range(), TEXT) };
    let expected: Vec<usize> = (0..SITE_FRAMES).map(|frame| 0x40_0000 + frame).collect();
    assert_eq!(frames.to_vec(), expected);
}

/// Whatever the register or the stack holds, the walk reads nothing outside the stack. The
/// test would fault or read a poisoned neighbour if it did; here it must simply stop.
#[test]
fn a_register_or_link_that_is_not_a_frame_pointer_ends_the_walk_inside_the_stack() {
    let mut stack = Stack { words: vec![0; 32] };
    let range = stack.range();
    let none = [0usize; SITE_FRAMES];
    for start in [0, 1, 8, range.start - 8, range.start + 1, range.end - 8, range.end, usize::MAX - 7, usize::MAX] {
        assert_eq!(unsafe { sites::walk_frames(start, range.clone(), TEXT) }, none, "start={start:#x}");
    }
    // A return address outside the image text is not a frame.
    stack.record(0, stack.at(4), 0x90_0000);
    assert_eq!(unsafe { sites::walk_frames(stack.at(0), range.clone(), TEXT) }, none);
    // Links that go down, loop, leave the stack or straddle its end stop after the valid frame.
    for link in [stack.at(0), stack.at(2), 0x10, range.end, range.end - 8, stack.at(5) + 4, usize::MAX] {
        stack.record(4, link, 0x40_1000);
        let frames = unsafe { sites::walk_frames(stack.at(4), range.clone(), TEXT) };
        assert_eq!(frames[0], 0x40_1000);
        assert_eq!(frames[1], 0, "link={link:#x}");
    }
}

/// The image must keep frame pointers for the walk to name real callers, and the allocator
/// must confine the walk to the published boot stack.
#[test]
fn the_executive_image_is_built_with_frame_pointers_and_text_bounds() {
    let target = include_str!("../../../components/ntos-executive/triplet.json");
    assert!(target.contains("\"frame-pointer\": \"always\""));
    let script = include_str!("../../../components/ntos-executive/link.ld");
    let text = script.split(".text : {").nth(1).unwrap().split('}').next().unwrap();
    let start = text.find("__executive_text_start = .;").unwrap();
    let end = text.find("__executive_text_end = .;").unwrap();
    assert!(start < text.find("*(.text._start)").unwrap());
    assert!(end > text.find("*(.ltext .ltext.*)").unwrap());
}
