use crate::{ClientFrameRegistry, PagefileStore};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcessSlotBlocker {
    ClientFrame,
    Pagefile,
}

pub fn admit_empty_process_slot(
    pi: u64,
    frames: &ClientFrameRegistry,
    pagefile: &PagefileStore,
) -> Result<(), ProcessSlotBlocker> {
    if !frames.is_process_empty(pi) {
        return Err(ProcessSlotBlocker::ClientFrame);
    }
    if pagefile.first_for_owner(pi).is_some() {
        return Err(ProcessSlotBlocker::Pagefile);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MemoryLifetime, PagefilePage, ProcessGeneration, ProcessIdentity};

    #[test]
    fn old_generation_ownership_blocks_spawn_without_mutation() {
        let old = MemoryLifetime::Process(ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(7),
        });
        let mut frames = ClientFrameRegistry::new();
        let mut pagefile = PagefileStore::new();
        frames.insert(3, old, 0x1000, 11, 0, 0, 0, true).unwrap();
        let page = PagefilePage {
            owner: 3,
            lifetime: old,
            page: 0x2000,
            protection: 4,
            backing: 12,
        };
        let plan = pagefile.prepare_publish(page).unwrap();
        pagefile.commit_publish(plan).unwrap();

        assert_eq!(
            admit_empty_process_slot(3, &frames, &pagefile),
            Err(ProcessSlotBlocker::ClientFrame)
        );
        assert_eq!(frames.get_for(3, old, 0x1000).unwrap().frame, 11);
        assert_eq!(pagefile.page_for(3, old, 0x2000), Some(page));

        frames.take_for(3, old, 0x1000).unwrap();
        assert_eq!(
            admit_empty_process_slot(3, &frames, &pagefile),
            Err(ProcessSlotBlocker::Pagefile)
        );
        pagefile.take_for(3, old, 0x2000).unwrap();
        assert_eq!(admit_empty_process_slot(3, &frames, &pagefile), Ok(()));
    }
}
