//! Native rootserver loader sizing follows the installed source-built ELF, before page effects.

const BOOT: &str = include_str!("../../../rust-micro/src/boot.rs");
const ROOTSERVER: &str = include_str!("../../../rust-micro/src/rootserver.rs");
const MAIN: &str = include_str!("../../../rust-micro/src/main.rs");

#[test]
fn user_page_region_uses_checked_live_elf_budget_and_keeps_iommu_separate() {
    let reserve = BOOT.split("pub fn reserve_user_page_region()").nth(1).unwrap()
        .split("const ROOTSERVER_UT_MIN_SIZE_BITS").next().unwrap();
    for required in [
        "rootserver_image::rootserver_elf()",
        "elf::parse",
        "rootserver_page_budget::budget",
        "rootserver_page_budget::reserve_bytes",
        "IMAGE_PAGES_CAP",
        "user_pages_size.checked_add(IOMMU_POOL_SIZE)",
        "install_user_page_region(user_pages_base, user_pages_size)",
    ] {
        assert!(reserve.contains(required), "missing checked rootserver carve: {required}");
    }
    assert!(!reserve.contains("const USER_PAGES_SIZE: u64 = 16 * 1024 * 1024"));
}

#[test]
fn image_table_capacity_and_boot_refusal_are_checked_before_loader_allocation() {
    assert!(ROOTSERVER.contains("pub const IMAGE_PAGES_CAP: usize = 8192"));
    let reserve = BOOT.split("pub fn reserve_user_page_region()").nth(1).unwrap()
        .split("let user_pages_base = carve_chunk").next().unwrap();
    assert!(reserve.contains("IMAGE_PAGES_CAP"), "table capacity preflight before carve");
    let early = MAIN.split("if let Err(e) = boot::reserve_user_page_region()").nth(1).unwrap()
        .split("// Phase 44").next().unwrap();
    assert!(early.contains("RootserverImageTooLarge"));
    assert!(early.contains("halt_cpu"), "failed reserve must not fall through to loader");
}
