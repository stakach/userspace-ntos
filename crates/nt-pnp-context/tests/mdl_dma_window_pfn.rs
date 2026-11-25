//! An MDL over a SCSI data buffer in the hosted PCI DMA window has real PFNs (#321).
//!
//! Boot 44461724169 bugchecked 0xC4 'MDLS' with STATUS_INVALID_PARAMETER on every SCSI request.
//! The SRB DataBuffer was 0x10017500000: the storage instance's DMA window, which is mapped
//! through the root resource-mapping table, not one of the instance's own frame runs. Translation
//! that consulted only the owned runs refused the MDL.

use nt_mdl::pfn::{populate, PfnError};
use nt_pnp_context::{
    resource_mapping::{
        Admission, MappingCache, MappingDomain, MappingKey, MappingOwner, ResourceMappingTable,
    },
    ContextRegistry,
};

const DOMAIN: MappingDomain = MappingDomain {
    id: 0x1_0000_000c,
    cookie: 0x1_0000_000c,
};
const PML4: u64 = 0x4_2000;
/// The SRB DataBuffer from boot 44461724169.
const SRB_DATA: u64 = 0x100_1750_0000;
/// The instance's own pool run; the window lies outside it.
const POOL: (u64, u64) = (0x100_0E80_0000, 2048);
/// Noncontiguous frames backing the first four window pages.
const FRAMES: [u64; 4] = [0x7f3_1000, 0x7f2_8000, 0x7f4_0000, 0x7f3_f000];

fn window() -> ResourceMappingTable {
    let mut registry = ContextRegistry::new();
    registry.publish((), ()).unwrap();
    let owner = MappingOwner {
        instance: 11,
        device_id: 1_099_511_627_843,
        context_lease: registry.acquire_active().unwrap().into_identity(),
    };
    let mut table = ResourceMappingTable::new();
    for (index, physical_page) in FRAMES.into_iter().enumerate() {
        let key = MappingKey {
            domain: DOMAIN,
            pml4: PML4,
            virtual_page: SRB_DATA + index as u64 * 0x1000,
            physical_page,
            source_cap: 0x900 + index as u64,
            rights: 3,
            cache: MappingCache::WriteBack,
        };
        let Admission::New(receipt) = table.prepare(key, owner).unwrap() else {
            panic!()
        };
        table.attach_cap(receipt, 0xa00 + index as u64).unwrap();
        let (_, effect) = table.begin_map(receipt).unwrap();
        table.acknowledge_map(effect).unwrap();
    }
    table
}

fn owned_run(page: u64) -> Option<u64> {
    let index = page.checked_sub(POOL.0)? / 0x1000;
    (index < POOL.1).then(|| 0x1_0000_0000 + index * 0x1000)
}

fn populated(translate: impl Fn(u64) -> Option<u64>) -> (Result<u64, PfnError>, Vec<u64>) {
    let mut pfns = vec![0; 4];
    let result = populate(SRB_DATA, 0, 0x4000, 4, translate, |index, pfn| {
        pfns[index as usize] = pfn
    });
    (result, pfns)
}

#[test]
fn owned_runs_alone_refuse_the_dma_window_buffer_as_in_boot_44461724169() {
    assert_eq!(
        populated(owned_run),
        (Err(PfnError::Untranslated { page: SRB_DATA }), vec![0; 4])
    );
}

#[test]
fn an_mdl_over_a_projected_srb_buffer_records_the_window_frames() {
    let table = window();
    let translate =
        |page| owned_run(page).or_else(|| table.mapped_physical_page(DOMAIN, PML4, page));
    let expected = FRAMES
        .iter()
        .map(|frame| frame / 0x1000)
        .collect::<Vec<_>>();
    assert_eq!(populated(translate), (Ok(4), expected));
}

#[test]
fn another_domain_generation_or_vspace_has_no_window_translation() {
    let table = window();
    let stale = MappingDomain {
        cookie: DOMAIN.cookie + 1,
        ..DOMAIN
    };
    assert_eq!(table.mapped_physical_page(stale, PML4, SRB_DATA), None);
    assert_eq!(
        table.mapped_physical_page(DOMAIN, PML4 + 0x1000, SRB_DATA),
        None
    );
    assert_eq!(
        table.mapped_physical_page(DOMAIN, PML4, SRB_DATA + 0x4000),
        None
    );
}
