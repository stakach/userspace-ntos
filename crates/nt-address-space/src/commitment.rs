//! Process commitment reserved by view policy or retained by private backing.

use crate::*;

fn reserves_private_backing(mapping_type: u32, protection: u32) -> bool {
    mapping_type == MEM_PRIVATE
        || matches!(protection & 0xff, PAGE_WRITECOPY | PAGE_EXECUTE_WRITECOPY)
}

/// Additional commitment needed before publishing a new private page. Existing COW reservation
/// is consumed, not charged again; an already-private page keeps its existing charge.
pub fn private_backing_admission_bytes(info: VmBasicInformation, already_private: bool) -> u64 {
    if already_private || reserves_private_backing(info.type_, info.protect) {
        0
    } else if info.state == MEM_COMMIT && matches!(info.type_, MEM_IMAGE | MEM_MAPPED) {
        PAGE_SIZE
    } else {
        0
    }
}

impl<const N: usize> VmCommittedRangeTable<N> {
    /// Include retained private backing outside current COW reservations. Pages must be unique,
    /// process-local addresses supplied by the backing owner, including nonresident transitions.
    pub fn process_commit_bytes_with_private_pages(
        &self,
        private_pages: impl IntoIterator<Item = u64>,
    ) -> u64 {
        self.retained_private_commit_bytes(None, private_pages)
            .saturating_add(self.process_commit_bytes())
    }

    pub fn allocation_process_commit_bytes_with_private_pages(
        &self,
        allocation_base: u64,
        private_pages: impl IntoIterator<Item = u64>,
    ) -> u64 {
        self.retained_private_commit_bytes(Some(allocation_base), private_pages)
            .saturating_add(self.allocation_process_commit_bytes(allocation_base))
    }

    fn retained_private_commit_bytes(
        &self,
        allocation_base: Option<u64>,
        private_pages: impl IntoIterator<Item = u64>,
    ) -> u64 {
        private_pages.into_iter().fold(0u64, |bytes, page| {
            let additional = self
                .query_basic(page)
                .filter(|info| allocation_base.is_none_or(|base| base == info.allocation_base))
                .map_or(0, |info| private_backing_admission_bytes(info, false));
            bytes.saturating_add(additional)
        })
    }
}

#[cfg(test)]
mod tests;
