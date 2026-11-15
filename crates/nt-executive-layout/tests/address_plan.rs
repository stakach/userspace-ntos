//! The address plan: no two bands of a VSpace overlap, and every quantity derived from a band
//! agrees with it. A band that is moved or resized fails here before it reaches a boot.

use nt_executive_layout::{
    component, first_overlap, is_ascending, root, Region, COMPONENT_HEAP_MAX_FRAMES,
    DEMAND_SCRATCH_WINDOW, DYNAMIC_RUNTIME_STRIDE, HEAP_BASE, HOSTED_PROCESS_LIMIT, PAGE,
    PRIVATE_VM_LIMIT, ROOT_HEAP_RESERVATION_FRAMES, STATIC_PROCESS_COUNT, TABLE_SPAN,
    WORKER_LANES_PER_PROCESS, WORKER_MIRROR_STRIDE,
};

fn assert_disjoint(space: &str, regions: &[Region]) {
    if let Some((first, second)) = first_overlap(regions) {
        panic!(
            "{space}: {} [{:#x}, {:#x}) overlaps {} [{:#x}, {:#x})",
            regions[first].name,
            regions[first].base,
            regions[first].end(),
            regions[second].name,
            regions[second].base,
            regions[second].end(),
        );
    }
    assert!(is_ascending(regions), "{space}: table is not in ascending order");
}

#[test]
fn no_two_root_bands_overlap() {
    assert_disjoint("root", root::REGIONS);
}

#[test]
fn no_two_component_bands_overlap() {
    assert_disjoint("component", component::REGIONS);
}

/// The checks themselves: a band that reaches into its neighbour by one page is reported, by
/// both the pairwise scan and the ordering scan, and bands that only touch are not.
#[test]
fn an_overlap_of_one_page_is_reported() {
    let low = Region::new("low", 0x1000_0000, 0x20_0000);
    let touching = Region::new("touching", low.end(), 0x20_0000);
    assert_eq!(first_overlap(&[low, touching]), None);
    assert!(is_ascending(&[low, touching]));
    let reaching = Region::new("reaching", low.end() - PAGE, 0x20_0000);
    assert_eq!(first_overlap(&[low, touching, reaching]), Some((0, 2)));
    assert!(!is_ascending(&[low, reaching]));
    assert!(!is_ascending(&[touching, low]), "descending order is not accepted");
}

/// The addresses themselves. Moving a band is a decision; it is made here as well as in the
/// table, with the neighbours in view.
#[test]
fn every_root_band_is_where_the_plan_says() {
    let plan: &[(&Region, u64, u64)] = &[
        (&root::FIXED_LOW, 0x0100_0000_0000, 0x0100_1500_0000),
        (&root::FILE_POOL, 0x0100_1500_0000, 0x0100_1800_0000),
        (&root::HEAP, 0x0100_1e00_0000, 0x0100_2e00_0000),
        (&root::PROVIDER_LARGE_POOL, 0x0100_4000_0000, 0x0100_4400_0000),
        (&root::PROVIDER_BULK_ARENA, 0x0100_4400_0000, 0x0100_4800_0000),
        (&root::PE_SCRATCH, 0x0100_4800_0000, 0x0100_4820_0000),
        (&root::WIN32K_STACK_ALIASES, 0x0100_4820_0000, 0x0100_48a0_0000),
        (&root::DRIVER_HOST_VIEWS, 0x0100_5000_0000, 0x0101_5000_0000),
        (&root::DIAGNOSTIC_ALIASES, 0x0101_5000_0000, 0x0101_5200_0000),
        (&root::DYNAMIC_RUNTIME, 0x0101_6000_0000, 0x0101_e800_0000),
        (&root::DRIVER_WORKER_ALIASES, 0x0102_0000_0000, 0x0103_0000_0000),
        (&root::CONTIGUOUS_RAM_APERTURE, 0x0103_0000_0000, 0x0103_2000_0000),
        (&root::WORKER_MIRRORS, 0x0104_0000_0000, 0x0105_0000_0000),
        (&root::STATIC_SCRATCH, 0x0105_0000_0000, 0x0105_1c00_0000),
        (&root::SHELL_MIRRORS, 0x0105_1c00_0000, 0x0105_1c40_0000),
        (&root::DMA_GRAPH_SLOTS, 0x0106_0000_0000, 0x0106_1000_0000),
    ];
    assert_eq!(plan.len(), root::REGIONS.len(), "a band is missing from the plan");
    for ((region, base, end), listed) in plan.iter().zip(root::REGIONS) {
        assert_eq!(*region, listed, "{} is out of order in the table", region.name);
        assert_eq!((region.base, region.end()), (*base, *end), "{}", region.name);
    }
}

#[test]
fn every_component_band_is_where_the_plan_says() {
    let plan: &[(&Region, u64, u64)] = &[
        (&component::RESOURCE_WINDOWS, 0x0100_1600_0000, 0x0100_1e00_0000),
        (&component::HEAP, 0x0100_1e00_0000, 0x0100_2380_0000),
        (&component::SECTION_VIEWS, 0x0100_2380_0000, 0x0100_3000_0000),
    ];
    assert_eq!(plan.len(), component::REGIONS.len());
    for ((region, base, end), listed) in plan.iter().zip(component::REGIONS) {
        assert_eq!(*region, listed);
        assert_eq!((region.base, region.end()), (*base, *end), "{}", region.name);
    }
}

/// Both kinds of VSpace run one allocator whose metadata sits at one address.
#[test]
fn the_root_and_component_heaps_share_a_base_and_nothing_else() {
    assert_eq!(root::HEAP.base, HEAP_BASE);
    assert_eq!(component::HEAP.base, HEAP_BASE);
    assert_eq!(root::HEAP.frames(), ROOT_HEAP_RESERVATION_FRAMES);
    assert_eq!(component::HEAP.frames(), COMPONENT_HEAP_MAX_FRAMES);
    assert_eq!(ROOT_HEAP_RESERVATION_FRAMES * PAGE, 256 << 20);
    assert_eq!(COMPONENT_HEAP_MAX_FRAMES * PAGE, 88 << 20);
    // The root builds one leaf page table per 2 MiB of its reservation at boot.
    assert_eq!(root::HEAP.base % TABLE_SPAN, 0);
    assert_eq!(root::HEAP.len % TABLE_SPAN, 0);
    // A component's neighbours are placed against the component maximum, not the root's.
    assert_eq!(component::RESOURCE_WINDOWS.end(), component::HEAP.base);
    assert_eq!(component::SECTION_VIEWS.base, component::HEAP.end());
    assert_eq!(component::RESOURCE_WINDOWS.len % TABLE_SPAN, 0);
}

#[test]
fn every_static_process_has_a_whole_scratch_window() {
    assert_eq!(
        root::STATIC_SCRATCH.len,
        STATIC_PROCESS_COUNT as u64 * DEMAND_SCRATCH_WINDOW
    );
    assert_eq!(root::STATIC_SCRATCH.base % TABLE_SPAN, 0);
    assert_eq!(DEMAND_SCRATCH_WINDOW % TABLE_SPAN, 0);
    assert_eq!(root::SHELL_MIRRORS.base, root::STATIC_SCRATCH.end());
}

#[test]
fn every_dynamic_process_has_a_whole_runtime_window() {
    let dynamic = (HOSTED_PROCESS_LIMIT - STATIC_PROCESS_COUNT) as u64;
    assert_eq!(root::DYNAMIC_RUNTIME.len, dynamic * DYNAMIC_RUNTIME_STRIDE);
    assert!(DYNAMIC_RUNTIME_STRIDE >= DEMAND_SCRATCH_WINDOW + 4 * 0x10_0000);
    assert_eq!(root::DYNAMIC_RUNTIME.base % TABLE_SPAN, 0);
    assert_eq!(DYNAMIC_RUNTIME_STRIDE % TABLE_SPAN, 0);
}

#[test]
fn every_lane_of_every_process_has_a_mirror() {
    let lanes = (HOSTED_PROCESS_LIMIT * WORKER_LANES_PER_PROCESS) as u64;
    assert!(lanes * WORKER_MIRROR_STRIDE <= root::WORKER_MIRRORS.len);
    assert_eq!(root::WORKER_MIRRORS.base % WORKER_MIRROR_STRIDE, 0);
    // Lane sets are 64-bit masks.
    assert!(WORKER_LANES_PER_PROCESS <= 64);
}

/// A dynamic process is named on its fault endpoint by a badge, and the badges run out.
#[test]
fn every_process_slot_has_a_badge() {
    assert_eq!(STATIC_PROCESS_COUNT, nt_exe_image::DYNAMIC_PROCESS_FIRST_PI);
    assert!(HOSTED_PROCESS_LIMIT <= nt_exe_image::DYNAMIC_PROCESS_PI_LIMIT);
    for pi in STATIC_PROCESS_COUNT..HOSTED_PROCESS_LIMIT {
        assert!(nt_exe_image::dynamic_top_badge_for_pi(pi).is_some(), "pi {pi} has no badge");
    }
}

/// Bands numbered below the private-memory limit stay below it; root-only bands start at it.
#[test]
fn the_private_memory_limit_separates_the_two_groups() {
    assert!(root::HEAP.end() <= PRIVATE_VM_LIMIT);
    assert!(root::STATIC_SCRATCH.base >= PRIVATE_VM_LIMIT);
    assert_eq!(root::PROVIDER_LARGE_POOL.base, PRIVATE_VM_LIMIT);
    assert!(component::SECTION_VIEWS.end() <= PRIVATE_VM_LIMIT);
}
