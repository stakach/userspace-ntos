//! Verified FAT-chain positions for repeated and interleaved file reads.
//!
//! Callers own these cursors with their volume and invalidate them before any possible FAT
//! mutation. They only optimize traversal; a position is published after its links are verified.

const FAT_EOC_MIN: u32 = 0x0fff_fff8;

/// A read of one-sector FAT clusters that may be submitted as one bounded DMA transfer.
/// `next_cluster` is present only when more file bytes remain and the observed chain continues.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FatRangeBatch {
    pub sectors: u32,
    pub skip_bytes: usize,
    pub copy_bytes: usize,
    pub next_cluster: Option<u32>,
}

impl FatRangeBatch {
    pub fn plan(
        first_cluster: u32,
        skip_bytes: u32,
        remaining_bytes: usize,
        sector_bytes: u32,
        max_sectors: u32,
        mut next: impl FnMut(u32) -> u32,
    ) -> Option<Self> {
        if !(2..FAT_EOC_MIN).contains(&first_cluster)
            || sector_bytes == 0
            || skip_bytes >= sector_bytes
            || remaining_bytes == 0
            || max_sectors == 0
        {
            return None;
        }
        let needed_bytes = u64::try_from(remaining_bytes)
            .ok()?
            .checked_add(skip_bytes as u64)?;
        let needed_sectors = needed_bytes.div_ceil(sector_bytes as u64);
        let limit = needed_sectors.min(max_sectors as u64) as u32;
        let mut sectors = 1;
        let mut last = first_cluster;
        let mut following = None;
        while sectors < limit {
            let candidate = next(last);
            if !(2..FAT_EOC_MIN).contains(&candidate) || candidate == last {
                break;
            }
            if Some(candidate) != last.checked_add(1) {
                following = Some(candidate);
                break;
            }
            last = candidate;
            sectors += 1;
        }
        let capacity = (sectors as u64)
            .checked_mul(sector_bytes as u64)?
            .checked_sub(skip_bytes as u64)?;
        let copy_bytes = remaining_bytes.min(usize::try_from(capacity).ok()?);
        if copy_bytes < remaining_bytes && following.is_none() && sectors == limit {
            let candidate = next(last);
            if (2..FAT_EOC_MIN).contains(&candidate) && candidate != last {
                following = Some(candidate);
            }
        }
        Some(Self {
            sectors,
            skip_bytes: skip_bytes as usize,
            copy_bytes,
            next_cluster: following,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FatRangeCursor {
    first_cluster: u32,
    file_size: u32,
    cluster_index: u32,
    cluster: u32,
    valid: bool,
}

impl FatRangeCursor {
    pub const fn new() -> Self {
        Self {
            first_cluster: 0,
            file_size: 0,
            cluster_index: 0,
            cluster: 0,
            valid: false,
        }
    }

    pub fn invalidate(&mut self) {
        self.valid = false;
    }

    /// Find a logical cluster through observed FAT links, reusing only a position verified for
    /// this same file. The callback is invoked exactly once per traversed link.
    pub fn locate(
        &mut self,
        first_cluster: u32,
        file_size: u32,
        target_index: u32,
        mut next: impl FnMut(u32) -> u32,
    ) -> Option<u32> {
        if first_cluster < 2 || first_cluster >= FAT_EOC_MIN {
            return None;
        }
        let (mut index, mut cluster) = if self.valid
            && self.first_cluster == first_cluster
            && self.file_size == file_size
            && self.cluster_index <= target_index
        {
            (self.cluster_index, self.cluster)
        } else {
            (0, first_cluster)
        };
        while index < target_index {
            let following = next(cluster);
            if following < 2 || following >= FAT_EOC_MIN || following == cluster {
                return None;
            }
            cluster = following;
            index += 1;
        }
        *self = Self {
            first_cluster,
            file_size,
            cluster_index: index,
            cluster,
            valid: true,
        };
        Some(cluster)
    }
}

impl Default for FatRangeCursor {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy)]
struct FatRangeCursorEntry {
    mount_generation: u64,
    cursor: FatRangeCursor,
}

impl FatRangeCursorEntry {
    const EMPTY: Self = Self {
        mount_generation: 0,
        cursor: FatRangeCursor::new(),
    };
}

/// Bounded verified positions shared by interleaved readers of one or more mounted volumes.
/// Entries are identified by mount generation, first cluster, and file size. For backward seeks,
/// the closest position at or before the target is used; a later position remains available.
pub struct FatRangeCursorSet<const N: usize> {
    entries: [FatRangeCursorEntry; N],
    next_evict: usize,
}

impl<const N: usize> FatRangeCursorSet<N> {
    pub const fn new() -> Self {
        Self {
            entries: [FatRangeCursorEntry::EMPTY; N],
            next_evict: 0,
        }
    }

    /// Discard every position before a possible FAT mutation or mount replacement.
    pub fn invalidate(&mut self) {
        for entry in &mut self.entries {
            entry.cursor.invalidate();
        }
        self.next_evict = 0;
    }

    /// Find a logical cluster using only verified links for the exact mounted file identity.
    /// A failed traversal leaves all previously verified positions unchanged.
    pub fn locate(
        &mut self,
        mount_generation: u64,
        first_cluster: u32,
        file_size: u32,
        target_index: u32,
        next: impl FnMut(u32) -> u32,
    ) -> Option<u32> {
        let best = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, entry)| {
                entry.cursor.valid
                    && entry.mount_generation == mount_generation
                    && entry.cursor.first_cluster == first_cluster
                    && entry.cursor.file_size == file_size
                    && entry.cursor.cluster_index <= target_index
            })
            .max_by_key(|(_, entry)| entry.cursor.cluster_index)
            .map(|(index, _)| index);

        if let Some(index) = best {
            return self.entries[index]
                .cursor
                .locate(first_cluster, file_size, target_index, next);
        }

        // Do not displace a verified position until the new traversal succeeds.
        let mut cursor = FatRangeCursor::new();
        let cluster = cursor.locate(first_cluster, file_size, target_index, next)?;
        if N != 0 {
            let slot = self
                .entries
                .iter()
                .position(|entry| !entry.cursor.valid)
                .unwrap_or(self.next_evict);
            self.entries[slot] = FatRangeCursorEntry {
                mount_generation,
                cursor,
            };
            self.next_evict = (slot + 1) % N;
        }
        Some(cluster)
    }
}

impl<const N: usize> Default for FatRangeCursorSet<N> {
    fn default() -> Self {
        Self::new()
    }
}
