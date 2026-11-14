//! Who owns the durable heap: a bounded ledger of live bytes per allocating site.
//!
//! The ledger has two parts. Every durable allocation is counted in a power-of-two size class,
//! so the classes always sum to the live heap. An allocation of at least [`TRACKED_MIN_BYTES`]
//! is also charged to its site, the return-address chain that requested it, and remembered by
//! address so its release is credited to the same site.
//!
//! Both tables are fixed. A site or block that does not fit is counted in `unattributed`
//! rather than dropped, so a full table reads as a named shortfall and never as free memory.
//! The ledger is plain data that is valid when zeroed; the owning heap supplies the storage.

/// Return addresses kept per site, innermost first. The first few are usually inside `alloc`
/// (`RawVec` growth and the like), so the chain has to be long enough to leave it.
pub const SITE_FRAMES: usize = 8;
/// Distinct sites remembered. Must be a power of two.
pub const SITE_CAPACITY: usize = 256;
/// Live site-charged blocks remembered. Must be a power of two.
pub const BLOCK_CAPACITY: usize = 8192;
/// Allocations at least this large are charged to their site.
pub const TRACKED_MIN_BYTES: usize = 4096;
/// Size classes: class `n` holds blocks of `2^n ..= 2^(n+1) - 1` bytes, the last is open-ended.
pub const SIZE_CLASSES: usize = 28;

const _: () = assert!(SITE_CAPACITY.is_power_of_two() && SITE_CAPACITY <= u16::MAX as usize);
const _: () = assert!(BLOCK_CAPACITY.is_power_of_two());

pub type Frames = [usize; SITE_FRAMES];

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Tally {
    pub bytes: usize,
    pub count: usize,
}

impl Tally {
    fn add(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_add(bytes);
        self.count = self.count.saturating_add(1);
    }

    fn sub(&mut self, bytes: usize) {
        self.bytes = self.bytes.saturating_sub(bytes);
        self.count = self.count.saturating_sub(1);
    }
}

/// One allocating site. A slot is in use once `allocations` is nonzero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C)]
pub struct Site {
    pub frames: Frames,
    pub live: Tally,
    /// Highest `live.bytes` this site has reached.
    pub peak_bytes: usize,
    /// Allocations ever charged to this site.
    pub allocations: usize,
}

/// A live site-charged block. `address == 0` is an empty slot.
#[derive(Clone, Copy)]
#[repr(C)]
struct Block {
    address: usize,
    bytes: u32,
    site: u32,
}

#[repr(C)]
pub struct SiteLedger {
    classes: [Tally; SIZE_CLASSES],
    /// Live blocks of site-charged size that no site row or block row could hold.
    unattributed: Tally,
    sites: [Site; SITE_CAPACITY],
    /// Occupied `blocks` slots. At least one always stays empty so every probe run ends.
    blocks_used: usize,
    blocks: [Block; BLOCK_CAPACITY],
}

fn class_of(bytes: usize) -> usize {
    (bytes.max(1).ilog2() as usize).min(SIZE_CLASSES - 1)
}

fn mix(mut value: usize) -> usize {
    value ^= value >> 29;
    value = value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    value ^ (value >> 32)
}

fn site_hash(frames: &Frames) -> usize {
    let mut hash = 0usize;
    for &frame in frames {
        hash = mix(hash ^ frame);
    }
    hash
}

impl SiteLedger {
    fn find_block(&self, address: usize) -> Option<usize> {
        let mask = BLOCK_CAPACITY - 1;
        let mut index = mix(address) & mask;
        for _ in 0..BLOCK_CAPACITY {
            let block = &self.blocks[index];
            if block.address == address {
                return Some(index);
            }
            if block.address == 0 {
                return None;
            }
            index = (index + 1) & mask;
        }
        None
    }

    fn insert_block(&mut self, address: usize, bytes: usize, site: usize) -> bool {
        let (Ok(bytes), Ok(site)) = (u32::try_from(bytes), u32::try_from(site)) else {
            return false;
        };
        if self.blocks_used >= BLOCK_CAPACITY - 1 {
            return false;
        }
        let mask = BLOCK_CAPACITY - 1;
        let mut index = mix(address) & mask;
        while self.blocks[index].address != 0 {
            index = (index + 1) & mask;
        }
        self.blocks[index] = Block { address, bytes, site };
        self.blocks_used += 1;
        true
    }

    /// Empty `hole` and move later members of its probe run back so none becomes unreachable.
    fn remove_block(&mut self, mut hole: usize) {
        let mask = BLOCK_CAPACITY - 1;
        let mut index = hole;
        loop {
            index = (index + 1) & mask;
            let candidate = self.blocks[index];
            if candidate.address == 0 {
                break;
            }
            let home = mix(candidate.address) & mask;
            // `candidate` may fill the hole only if its home is not between hole and index.
            let between = if hole <= index {
                hole < home && home <= index
            } else {
                hole < home || home <= index
            };
            if !between {
                self.blocks[hole] = candidate;
                hole = index;
            }
        }
        self.blocks[hole].address = 0;
        self.blocks_used -= 1;
    }

    fn site_for(&mut self, frames: &Frames) -> Option<usize> {
        let mask = SITE_CAPACITY - 1;
        let mut index = site_hash(frames) & mask;
        for _ in 0..SITE_CAPACITY {
            let site = &mut self.sites[index];
            if site.allocations == 0 {
                site.frames = *frames;
                return Some(index);
            }
            if site.frames == *frames {
                return Some(index);
            }
            index = (index + 1) & mask;
        }
        None
    }

    /// Whether an allocation of `bytes` is charged to a site, and so needs its frames captured.
    pub fn charges_site(bytes: usize) -> bool {
        bytes >= TRACKED_MIN_BYTES
    }

    /// Count a new live block. `frames` is consulted only when [`Self::charges_site`] holds.
    pub fn record_alloc(&mut self, address: usize, bytes: usize, frames: &Frames) {
        self.classes[class_of(bytes)].add(bytes);
        if !Self::charges_site(bytes) {
            return;
        }
        let Some(index) = self.site_for(frames) else {
            self.unattributed.add(bytes);
            return;
        };
        if !self.insert_block(address, bytes, index) {
            // Leave a first-seen site row unclaimed: it has no allocation to its name.
            self.unattributed.add(bytes);
            return;
        }
        let site = &mut self.sites[index];
        site.allocations = site.allocations.saturating_add(1);
        site.live.add(bytes);
        site.peak_bytes = site.peak_bytes.max(site.live.bytes);
    }

    /// Count the release of a block recorded with the same `address` and `bytes`.
    pub fn record_free(&mut self, address: usize, bytes: usize) {
        self.classes[class_of(bytes)].sub(bytes);
        if !Self::charges_site(bytes) {
            return;
        }
        match self.find_block(address) {
            Some(slot) => {
                let Block { bytes: recorded, site, .. } = self.blocks[slot];
                self.remove_block(slot);
                self.sites[site as usize].live.sub(recorded as usize);
            }
            None => self.unattributed.sub(bytes),
        }
    }

    /// The site charged for the live block at `address`.
    pub fn site_of(&self, address: usize) -> Option<&Site> {
        self.find_block(address).map(|slot| &self.sites[self.blocks[slot].site as usize])
    }

    pub fn classes(&self) -> &[Tally; SIZE_CLASSES] {
        &self.classes
    }

    pub fn unattributed(&self) -> Tally {
        self.unattributed
    }

    /// Live bytes and blocks charged to sites.
    pub fn attributed(&self) -> Tally {
        let mut total = Tally::default();
        for site in &self.sites {
            total.bytes = total.bytes.saturating_add(site.live.bytes);
            total.count = total.count.saturating_add(site.live.count);
        }
        total
    }

    /// Site rows in use.
    pub fn sites_used(&self) -> usize {
        self.sites.iter().filter(|site| site.allocations != 0).count()
    }

    /// Fill `out` with the sites holding the most live bytes, largest first. Returns how many.
    pub fn top_sites(&self, out: &mut [Site]) -> usize {
        let mut filled = 0;
        for site in self.sites.iter().filter(|site| site.live.bytes != 0) {
            let mut at = filled;
            while at != 0 && out[at - 1].live.bytes < site.live.bytes {
                at -= 1;
            }
            if at == out.len() {
                continue;
            }
            let last = (filled + 1).min(out.len()) - 1;
            let mut index = last;
            while index > at {
                out[index] = out[index - 1];
                index -= 1;
            }
            out[at] = *site;
            filled = last + 1;
        }
        filled
    }
}

/// Follow a frame-pointer chain and collect return addresses, innermost first.
///
/// `frame` is the address of a frame record (`[saved frame pointer, return address]`). Every
/// read is confined to `stack`, and each record must lie above the one before it, so a chain
/// that leaves the stack, or a register that never held a frame pointer, ends the walk and
/// cannot fault. A return address outside `text` ends it too.
///
/// # Safety
/// Every word in `stack` must be readable.
pub unsafe fn walk_frames(
    mut frame: usize,
    stack: core::ops::Range<usize>,
    text: core::ops::Range<usize>,
) -> Frames {
    const RECORD: usize = 2 * core::mem::size_of::<usize>();
    let mut frames = [0usize; SITE_FRAMES];
    let mut filled = 0;
    while filled < SITE_FRAMES {
        if frame < stack.start
            || frame % core::mem::align_of::<usize>() != 0
            || frame.checked_add(RECORD).is_none_or(|end| end > stack.end)
        {
            break;
        }
        // SAFETY: the record lies inside `stack`, checked above.
        let (next, ret) = unsafe {
            let record = frame as *const usize;
            (record.read_volatile(), record.add(1).read_volatile())
        };
        if !text.contains(&ret) {
            break;
        }
        frames[filled] = ret;
        filled += 1;
        if next <= frame {
            break;
        }
        frame = next;
    }
    frames
}
