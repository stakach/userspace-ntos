//! Bounded observation of path lookup parent directories, without retaining path names.

#[derive(Clone, Copy)]
struct Candidate {
    cluster: u32,
    count: u64,
}

/// A Misra-Gries summary: candidates are approximate and no physical I/O is performed.
/// The Executive updates this on its serialized filesystem service loop.
pub struct FatPathLookupCensus<const N: usize> {
    lookups: u64,
    found: u64,
    not_found: u64,
    directory_sectors: u64,
    candidates: [Candidate; N],
}

impl<const N: usize> FatPathLookupCensus<N> {
    pub const fn new() -> Self {
        Self {
            lookups: 0,
            found: 0,
            not_found: 0,
            directory_sectors: 0,
            candidates: [Candidate { cluster: 0, count: 0 }; N],
        }
    }

    pub fn begin(&mut self) { self.lookups = self.lookups.saturating_add(1); }
    pub fn found(&mut self) { self.found = self.found.saturating_add(1); }
    pub fn not_found(&mut self) { self.not_found = self.not_found.saturating_add(1); }
    pub const fn lookups(&self) -> u64 { self.lookups }
    pub const fn found_count(&self) -> u64 { self.found }
    pub const fn not_found_count(&self) -> u64 { self.not_found }
    pub const fn directory_sectors(&self) -> u64 { self.directory_sectors }

    /// Count a successfully read path directory sector under its current parent cluster.
    pub fn directory_sector(&mut self, parent: u32) {
        self.directory_sectors = self.directory_sectors.saturating_add(1);
        if parent < 2 { return; }
        if let Some(slot) = self.candidates.iter_mut().find(|slot| slot.count != 0 && slot.cluster == parent) {
            slot.count = slot.count.saturating_add(1);
        } else if let Some(slot) = self.candidates.iter_mut().find(|slot| slot.count == 0) {
            *slot = Candidate { cluster: parent, count: 1 };
        } else {
            for slot in &mut self.candidates { slot.count -= 1; }
        }
    }

    /// Remaining heavy-hitter candidate and lower-bound count; absent slots are ignored.
    pub fn parent_candidate(&self, index: usize) -> Option<(u32, u64)> {
        self.candidates.get(index).filter(|slot| slot.count != 0)
            .map(|slot| (slot.cluster, slot.count))
    }
}

impl<const N: usize> Default for FatPathLookupCensus<N> {
    fn default() -> Self { Self::new() }
}
