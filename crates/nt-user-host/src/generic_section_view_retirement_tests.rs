use crate::section_view_retirement::{
    commit_generic_section_view_retirement, prepare_generic_section_view_retirement,
};
use nt_address_space::{
    VmCommittedRange, VmCommittedRangeTable, VmRegionMap, MEM_COMMIT, MEM_MAPPED, MEM_RESERVE,
    PAGE_READWRITE,
};
use nt_memory_manager::{
    GenericSectionBacking, GenericSectionTable, MemoryLifetime, ProcessGeneration,
    ProcessIdentity, SECTION_ATTR_SEC_COMMIT,
};

const BASE: u64 = 0x10000;
const SIZE: u64 = 0x3000;
const DETACH_FAILED: u32 = 0xc000_009a;

#[test]
fn failed_generic_section_view_detach_retains_all_metadata_for_exact_retry() {
    let process = ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(7),
    };
    let mut sections = GenericSectionTable::new();
    let section = sections
        .create(
            2,
            0x40,
            SIZE,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap();
    assert!(sections.map_view_with_lifetime(
        2,
        MemoryLifetime::Process(process),
        section,
        BASE,
        SIZE,
        0,
    ));
    let view = sections.view_for_page(2, BASE + 0x1000).unwrap().1;

    let mut vad = VmRegionMap::<8>::new(BASE, 0x100000);
    let allocation = vad
        .allocate_mapped_between(
            Some(BASE),
            SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
            BASE,
            0x100000,
        )
        .unwrap();
    assert_eq!((allocation.base, allocation.size), (BASE, SIZE));
    let mut committed = VmCommittedRangeTable::<8>::new();
    committed
        .register(VmCommittedRange::mapped(BASE, SIZE, PAGE_READWRITE))
        .unwrap();
    let mut vad_scratch = vad;
    let mut committed_scratch = committed;

    let mut attempted = [0u64; 3];
    let mut count = 0usize;
    assert_eq!(
        prepare_generic_section_view_retirement(
            view,
            &sections,
            &vad,
            &committed,
            &mut vad_scratch,
            &mut committed_scratch,
        ),
        Ok(())
    );
    let failed = (BASE..BASE + SIZE)
        .step_by(0x1000)
        .try_for_each(|page| {
            attempted[count] = page;
            count += 1;
            if page == BASE + 0x1000 {
                Err(DETACH_FAILED)
            } else {
                Ok(())
            }
        });
    assert_eq!(failed, Err(DETACH_FAILED));
    assert_eq!(&attempted[..count], &[BASE, BASE + 0x1000]);
    assert_eq!(sections.view_for_page(2, BASE + 0x2000).unwrap().1, view);
    assert_eq!(vad.query_basic(BASE + 0x2000, 0x100000).unwrap().type_, MEM_MAPPED);
    assert_eq!(committed.query_basic(BASE + 0x2000).unwrap().type_, MEM_MAPPED);

    let mut retried = 0usize;
    assert_eq!(
        prepare_generic_section_view_retirement(
            view,
            &sections,
            &vad,
            &committed,
            &mut vad_scratch,
            &mut committed_scratch,
        ),
        Ok(())
    );
    for _ in (BASE..BASE + SIZE).step_by(0x1000) {
        retried += 1;
    }
    assert_eq!(retried, 3);
    assert_eq!(sections.view_for_page(2, BASE).unwrap().1, view);
    assert!(vad.extent_at(BASE).is_some());
    assert!(committed.query_basic(BASE).is_some());
    assert_eq!(
        commit_generic_section_view_retirement(
            view,
            &mut sections,
            &mut vad,
            &mut committed,
            &mut vad_scratch,
            &mut committed_scratch,
        ),
        Ok(())
    );
    assert!(sections.view_for_page(2, BASE).is_none());
    assert!(vad.extent_at(BASE).is_none());
    assert!(committed.query_basic(BASE).is_none());
}

#[test]
fn stale_generic_section_view_cannot_retire_replacement_at_same_base() {
    let process = ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(7),
    };
    let mut sections = GenericSectionTable::new();
    let section = sections
        .create(
            2,
            0x40,
            SIZE,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap();
    assert!(sections.map_view_with_lifetime(
        2, MemoryLifetime::Process(process), section, BASE, SIZE, 0,
    ));
    let stale = sections.view_for_page(2, BASE).unwrap().1;
    let mut vad = VmRegionMap::<8>::new(BASE, 0x100000);
    vad.allocate_mapped_between(
        Some(BASE), SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, BASE, 0x100000,
    )
    .unwrap();
    let mut committed = VmCommittedRangeTable::<8>::new();
    committed
        .register(VmCommittedRange::mapped(BASE, SIZE, PAGE_READWRITE))
        .unwrap();
    let mut vad_scratch = vad;
    let mut committed_scratch = committed;

    assert_eq!(
        prepare_generic_section_view_retirement(
            stale,
            &sections,
            &vad,
            &committed,
            &mut vad_scratch,
            &mut committed_scratch,
        ),
        Ok(())
    );
    assert_eq!(sections.unmap_view_identity(stale), Some(stale));
    assert!(sections.map_view_with_lifetime(
        2, MemoryLifetime::Process(process), section, BASE, SIZE, 0,
    ));
    let replacement = sections.view_for_page(2, BASE).unwrap().1;
    assert_ne!(stale.generation, replacement.generation);
    assert_eq!(
        commit_generic_section_view_retirement(
            stale,
            &mut sections,
            &mut vad,
            &mut committed,
            &mut vad_scratch,
            &mut committed_scratch,
        ),
        Err(nt_memory_manager::STATUS_NOT_MAPPED_VIEW)
    );
    assert_eq!(sections.view_for_page(2, BASE).unwrap().1, replacement);
    assert!(vad.extent_at(BASE).is_some());
    assert!(committed.query_basic(BASE).is_some());
}

#[test]
fn missing_committed_record_fails_before_detach() {
    let process = ProcessIdentity {
        pid: 42,
        generation: ProcessGeneration::Hosted(7),
    };
    let mut sections = GenericSectionTable::new();
    let section = sections
        .create(
            2,
            0x40,
            SIZE,
            PAGE_READWRITE,
            SECTION_ATTR_SEC_COMMIT,
            GenericSectionBacking::anonymous(),
        )
        .unwrap();
    assert!(sections.map_view_with_lifetime(
        2, MemoryLifetime::Process(process), section, BASE, SIZE, 0,
    ));
    let view = sections.view_for_page(2, BASE).unwrap().1;
    let mut vad = VmRegionMap::<8>::new(BASE, 0x100000);
    vad.allocate_mapped_between(
        Some(BASE), SIZE, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE, BASE, 0x100000,
    )
    .unwrap();
    let mut committed = VmCommittedRangeTable::<8>::new();
    let mut vad_scratch = vad;
    let mut committed_scratch = committed;

    assert_eq!(
        prepare_generic_section_view_retirement(
            view,
            &sections,
            &vad,
            &committed,
            &mut vad_scratch,
            &mut committed_scratch,
        ),
        Err(nt_address_space::STATUS_CONFLICTING_ADDRESSES)
    );
    assert_eq!(sections.view_for_page(2, BASE).unwrap().1, view);
    assert!(vad.extent_at(BASE).is_some());
}
