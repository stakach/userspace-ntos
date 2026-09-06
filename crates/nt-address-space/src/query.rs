//! Native query policy, separate from the view policy used by fault and writeback handlers.

use crate::*;

pub fn page_protection(mapping_type: u32, protection: u32, private: bool) -> u32 {
    if private && matches!(mapping_type, MEM_IMAGE | MEM_MAPPED) {
        private_backing_protection(protection)
    } else {
        protection
    }
}

impl<const N: usize> VmCommittedRangeTable<N> {
    /// Query effective protection using a sparse snapshot of privately owned backing addresses.
    /// The caller supplies both resident and nonresident pages for this process, without side
    /// effects during the query. Raw view metadata and backing residency are never changed.
    pub fn query_basic_with_private_pages(
        &self,
        address: u64,
        private_pages: impl IntoIterator<Item = u64>,
    ) -> Result<Option<VmBasicInformation>, u32> {
        let Some(mut result) = self.query_basic(address) else {
            return Ok(None);
        };
        if !matches!(result.type_, MEM_IMAGE | MEM_MAPPED) {
            return Ok(Some(result));
        }
        let start = result.base_address;
        let allocation_end = self
            .ranges
            .iter()
            .flatten()
            .filter(|range| range.allocation_base == result.allocation_base)
            .map(|range| range.end())
            .max()
            .expect("the queried allocation contains its first range");

        // Index only relevant COW pages, not the virtual span. Sorting also unifies resident and
        // transition records without introducing a second persistent ownership authority.
        let mut pages = Vec::new();
        for page in private_pages {
            if page < start || page >= allocation_end {
                continue;
            }
            if page & (PAGE_SIZE - 1) != 0 {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if !self.query_basic(page).is_some_and(|info| {
                info.allocation_base == result.allocation_base
                    && page_protection(info.type_, info.protect, true) != info.protect
            }) {
                continue;
            }
            pages
                .try_reserve(1)
                .map_err(|_| STATUS_INSUFFICIENT_RESOURCES)?;
            pages.push(page);
        }
        pages.sort_unstable();
        pages.dedup();
        result.protect = page_protection(
            result.type_,
            result.protect,
            pages.binary_search(&start).is_ok(),
        );

        let mut cursor = start;
        while let Some(info) = self.query_basic(cursor) {
            if info.allocation_base != result.allocation_base
                || info.allocation_protect != result.allocation_protect
                || info.type_ != result.type_
                || info.state != result.state
            {
                break;
            }
            let index = pages.partition_point(|page| *page < cursor);
            let private = pages.get(index) == Some(&cursor);
            if page_protection(info.type_, info.protect, private) != result.protect {
                break;
            }
            let mut end = info.base_address + info.region_size;
            if page_protection(info.type_, info.protect, true) != info.protect {
                if private {
                    end = cursor + PAGE_SIZE;
                    for page in &pages[index + 1..] {
                        if *page != end || end >= info.base_address + info.region_size {
                            break;
                        }
                        end += PAGE_SIZE;
                    }
                } else if let Some(page) = pages.get(index) {
                    end = end.min(*page);
                }
            }
            cursor = end;
            if cursor >= allocation_end {
                break;
            }
        }
        result.region_size = cursor - start;
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests;
