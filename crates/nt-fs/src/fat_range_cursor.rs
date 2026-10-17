//! A small verified FAT-chain position for repeated reads from one file.
//!
//! Callers own the cursor with their volume and invalidate it before any possible FAT mutation.
//! It is only an optimization: backward seeks and a different file restart at the first cluster.

const FAT_EOC_MIN: u32 = 0x0fff_fff8;

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
