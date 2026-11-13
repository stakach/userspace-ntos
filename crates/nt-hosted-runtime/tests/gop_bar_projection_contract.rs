use nt_hosted_runtime::{GopLegacyVgaPortAuthority, GopPciBarAuthority};

#[test]
fn live_vga_scanout_owner_may_read_only_legacy_status_port() {
    let bar = GopPciBarAuthority::new(
        0, 1, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0000, 0x300000, 7, 11, 12, 13,
    ).unwrap();
    let grant = GopLegacyVgaPortAuthority::new(bar, 0x03_00_00, 0x0003, true)
        .expect("live VGA-compatible PCI function with mapped GOP scanout");
    assert!(grant.admit_read8(0x3da, 7, 11, 12, 13));
    assert!(!grant.admit_read8(0x3c0, 7, 11, 12, 13));
    assert!(!grant.admit_read8(0x3da, 8, 11, 12, 13));
    assert!(!grant.admit_read8(0x3da, 7, 11, 99, 13));
    assert!(!grant.admit_read8(0x3da, 7, 11, 12, 14));
    assert!(GopLegacyVgaPortAuthority::new(bar, 0x03_80_00, 0x0003, true).is_none());
    assert!(GopLegacyVgaPortAuthority::new(bar, 0x03_00_00, 0x0002, true).is_none());
    assert!(GopLegacyVgaPortAuthority::new(bar, 0x03_00_00, 0x0003, false).is_none());
}

#[test]
fn scanout_projection_requires_exact_bar_and_live_provider_generation() {
    let grant = GopPciBarAuthority::new(
        0, 1, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0000, 0x300000, 7, 11, 12, 13,
    ).expect("released GOP scanout lies in the discovered display BAR");
    let projection = grant.project(0x8000_0000, 0x300000, 7, 11, 12, 13)
        .expect("exact live provider may map all 3 MiB");
    assert_eq!(projection.first_bar_frame(), 0);
    assert_eq!(projection.frame_count(), 768);
    assert_eq!(projection.page_offset(), 0);
    assert!(grant.project(0x8000_0000, 0x300000, 8, 11, 12, 13).is_none());
    assert!(grant.project(0x8000_0000, 0x300000, 7, 11, 12, 14).is_none());
    assert!(grant.project(0x8000_0000, 0x300000, 7, 11, 99, 13).is_none());
    assert!(grant.project(0x8000_0000, 0x300000, 7, 99, 12, 13).is_none());
    assert!(grant.project(0x8000_0000, 0x300001, 7, 11, 12, 13).is_none());
    assert!(grant.project(0x8000_0000, 0x400000, 7, 11, 12, 13).is_none());
    assert!(grant.project(0x7fff_f000, 0x300000, 7, 11, 12, 13).is_none());
    assert!(grant.project(u64::MAX, 2, 7, 11, 12, 13).is_none());
}

#[test]
fn scanout_authority_rejects_unbacked_or_unidentified_bar() {
    assert!(GopPciBarAuthority::new(
        0, 1, 0, 0, 0x9000_0000, 0x1000,
        0x8000_0000, 0x300000, 7, 11, 12, 13,
    ).is_none());
    assert!(GopPciBarAuthority::new(
        0, 1, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0000, 0x300000, 0, 11, 12, 13,
    ).is_none());
    assert!(GopPciBarAuthority::new(
        0, 1, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0000, 0x300000, 7, 11, 0, 13,
    ).is_none());
    assert!(GopPciBarAuthority::new(
        0, 32, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0000, 0x300000, 7, 11, 12, 13,
    ).is_none());
}

#[test]
fn scanout_grant_does_not_expose_adjacent_bar_bytes() {
    assert!(GopPciBarAuthority::new(
        0, 1, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0800, 0x300000, 7, 11, 12, 13,
    ).is_none());
    assert!(GopPciBarAuthority::new(
        0, 1, 0, 0, 0x8000_0000, 0x1000,
        0x8000_0000, 0x300001, 7, 11, 12, 13,
    ).is_none());
}
