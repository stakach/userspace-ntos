//! A read-only union of existing private backing authorities, keyed by owner and virtual page.

use crate::{ClientFrameRegistry, PagefileStore};

pub fn private_backing_pages<'a>(
    owner: u64,
    resident: &'a ClientFrameRegistry,
    transition: &'a PagefileStore,
) -> impl Iterator<Item = u64> + 'a {
    let frames = resident
        .records()
        .iter()
        .filter(move |record| record.pi == owner && record.owns_frame)
        .map(|record| record.page);
    let pages = transition.pages_for_owner(owner).filter(move |page| {
        !resident
            .get(owner, *page)
            .is_some_and(|record| record.owns_frame)
    });
    frames.chain(pages)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PagefilePage;
    use alloc::vec::Vec;

    #[test]
    fn union_filters_owner_shared_frames_and_duplicate_virtual_pages() {
        let mut frames = ClientFrameRegistry::new();
        for (owner, page, frame, owned) in [
            (1, 0x1000, 9, true),
            (1, 0x2000, 10, false),
            (2, 0x3000, 11, true),
            (1, 0x4000, 9, true),
        ] {
            frames.insert(owner, page, frame, 0, 0, 0, owned).unwrap();
        }
        let mut transitions = PagefileStore::new();
        for (owner, page, backing) in [(1, 0x1000, 9), (1, 0x2000, 12), (2, 0x5000, 13)] {
            let plan = transitions
                .prepare_publish(PagefilePage {
                    owner,
                    page,
                    backing,
                    protection: 2,
                })
                .unwrap();
            transitions.commit_publish(plan).unwrap();
        }
        let mut pages = private_backing_pages(1, &frames, &transitions).collect::<Vec<_>>();
        pages.sort_unstable();
        assert_eq!(pages, [0x1000, 0x2000, 0x4000]);
        frames.take(1, 0x1000).unwrap();
        let mut after = private_backing_pages(1, &frames, &transitions).collect::<Vec<_>>();
        after.sort_unstable();
        assert_eq!(after, pages);
        transitions.take(1, 0x1000).unwrap();
        assert_eq!(private_backing_pages(1, &frames, &transitions).count(), 2);
        assert_eq!(private_backing_pages(3, &frames, &transitions).count(), 0);
    }
}
