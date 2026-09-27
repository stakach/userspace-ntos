use crate::{
    ClientFrameRegistry, MemoryLifetime, PagefileStore, ProcessIdentity, STATUS_INVALID_HANDLE,
};

/// Validate both possible backing owners before either can be retired.
pub fn admit_private_page_retirement(
    pi: u64,
    process: ProcessIdentity,
    page: u64,
    frames: &ClientFrameRegistry,
    pagefile: &PagefileStore,
) -> Result<(), u32> {
    if !process.is_valid() {
        return Err(STATUS_INVALID_HANDLE);
    }
    let lifetime = MemoryLifetime::Process(process);
    if frames
        .get(pi, page)
        .is_some_and(|record| record.lifetime != lifetime)
        || pagefile
            .lifetime(pi, page)
            .is_some_and(|owner| owner != lifetime)
    {
        return Err(STATUS_INVALID_HANDLE);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PagefilePage, ProcessGeneration};

    #[test]
    fn mixed_generation_backing_is_rejected_without_mutation() {
        let old = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(1),
        };
        let new = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(2),
        };
        let mut frames = ClientFrameRegistry::new();
        let mut pagefile = PagefileStore::new();
        frames
            .insert(7, MemoryLifetime::Process(old), 0x1000, 11, 0, 0, 0, true)
            .unwrap();
        let newer_page = PagefilePage {
            owner: 7,
            lifetime: MemoryLifetime::Process(new),
            page: 0x1000,
            protection: 4,
            backing: 12,
        };
        let plan = pagefile.prepare_publish(newer_page).unwrap();
        pagefile.commit_publish(plan).unwrap();

        assert_eq!(
            admit_private_page_retirement(7, old, 0x1000, &frames, &pagefile),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            admit_private_page_retirement(7, new, 0x1000, &frames, &pagefile),
            Err(STATUS_INVALID_HANDLE)
        );
        assert_eq!(
            frames.get(7, 0x1000).unwrap().lifetime,
            MemoryLifetime::Process(old)
        );
        assert_eq!(
            pagefile.page_for(7, MemoryLifetime::Process(new), 0x1000),
            Some(newer_page)
        );
    }

    #[test]
    fn absent_backing_and_matching_generation_are_admitted() {
        let process = ProcessIdentity {
            pid: 42,
            generation: ProcessGeneration::Hosted(2),
        };
        let mut frames = ClientFrameRegistry::new();
        let pagefile = PagefileStore::new();
        assert_eq!(
            admit_private_page_retirement(7, process, 0x1000, &frames, &pagefile),
            Ok(())
        );
        frames
            .insert(
                7,
                MemoryLifetime::Process(process),
                0x1000,
                11,
                0,
                0,
                0,
                true,
            )
            .unwrap();
        assert_eq!(
            admit_private_page_retirement(7, process, 0x1000, &frames, &pagefile),
            Ok(())
        );
    }
}
