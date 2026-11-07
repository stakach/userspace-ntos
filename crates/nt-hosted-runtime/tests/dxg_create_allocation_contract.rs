//! Pinned LiberNT x64 CreateAllocation request and one-allocation projection.

use nt_hosted_runtime::{DxgAllocationAliasKey, DxgAllocationCallbackDisposition,
    DxgAllocationCookieRetirement,
    DxgCreateAllocationLayout, DxgDestroyAllocationLayout, DxgDdiSignature,
    DxgPdoAliasAuthority, DxgProcessFreeRoute, HostedProviderObjectOwner};

fn request(private: (u64, u32), info: u64, resource: u64, flags: u32) -> [u8; 0x28] {
    let mut bytes = [0u8; 0x28];
    bytes[..8].copy_from_slice(&private.0.to_le_bytes());
    bytes[8..12].copy_from_slice(&private.1.to_le_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_le_bytes());
    bytes[16..24].copy_from_slice(&info.to_le_bytes());
    bytes[24..32].copy_from_slice(&resource.to_le_bytes());
    bytes[32..36].copy_from_slice(&flags.to_le_bytes());
    bytes
}

fn info(private: (u64, u32)) -> [u8; 0x58] {
    let mut bytes = [0u8; 0x58];
    bytes[..8].copy_from_slice(&private.0.to_le_bytes());
    bytes[8..12].copy_from_slice(&private.1.to_le_bytes());
    bytes
}

#[test]
fn create_allocation_uses_exact_versioned_nested_abi() {
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0x98),
            Some(DxgDdiSignature::CreateAllocation));
        assert_eq!(DxgDdiSignature::CreateAllocation.argument_count(), 2);
        let header = request((0, 0), 0x2000, 0, 1);
        let entry = info((0x3000, 60));
        let layout = DxgCreateAllocationLayout::parse(version, 0x1000,
            &header, &entry, 0x10000).unwrap();
        assert_eq!(layout.request_bytes(), 0x28);
        assert_eq!(layout.info_bytes(), 0x58);
        assert_eq!(layout.private_driver_data(), (0x3000, 60));
        assert_eq!(layout.allocation_count(), 1);
        assert_eq!(layout.info_address(), 0x2000);
        assert!(layout.marshal_bytes() <= 0x10000);
    }
}

#[test]
fn create_allocation_rejects_aliasing_and_unbounded_nested_data() {
    let valid = request((0, 0), 0x2000, 0, 1);
    let private = info((0x3000, 60));
    assert!(DxgCreateAllocationLayout::parse(0x11008, 0x1000,
        &valid, &private, 0x10000).is_none());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x2000,
        &valid, &private, 0x10000).is_none());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x1000,
        &valid, &info((0x2010, 60)), 0x10000).is_none());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x1000,
        &valid, &info((0x3000, 0x10001)), 0x20000).is_none());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x1000,
        &valid, &private, 0x60).is_none());
    let mut two = valid;
    two[12..16].copy_from_slice(&2u32.to_le_bytes());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x1000,
        &two, &private, 0x10000).is_none());
    let mut preexisting_cookie = private;
    preexisting_cookie[0x38..0x40].copy_from_slice(&0x4000u64.to_le_bytes());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x1000,
        &valid, &preexisting_cookie, 0x10000).is_none());
    let mut usage_hint = private;
    usage_hint[0x48..0x50].copy_from_slice(&0x5000u64.to_le_bytes());
    assert!(DxgCreateAllocationLayout::parse(0x11007, 0x1000,
        &valid, &usage_hint, 0x10000).is_none());
}

#[test]
fn created_allocation_cookie_is_bound_to_adapter_and_pool_generation() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgAllocationAliasKey::new(adapter, 0x3000, 77, 0x4000, 88).unwrap();
    assert!(key.matches_destroy(adapter, 0x4000, 88));
    assert!(!key.matches_destroy(adapter, 0x4000, 89));
    assert!(key.cookie_address_conflicts(
        DxgAllocationAliasKey::new(adapter, 0x3000, 77, 0x4000, 89).unwrap()));
    let stale = DxgPdoAliasAuthority::new(owner, 34, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    assert!(!key.matches_destroy(stale, 0x4000, 88));
    assert!(DxgAllocationAliasKey::new(adapter, 0x3000, 0, 0x4000, 88).is_none());
    assert!(DxgAllocationAliasKey::new(adapter, 0x3000, 77, 0, 88).is_none());
}

#[test]
fn destroy_allocation_projects_one_exact_cookie_and_seals_free_interval() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgAllocationAliasKey::new(adapter, 0x3000, 77, 0x4000, 88).unwrap();
    let route = DxgProcessFreeRoute::new(2, 22, 3, 4, 5, 6).unwrap();
    let wrong_route = DxgProcessFreeRoute::new(2, 22, 3, 4, 5, 7).unwrap();
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0xa0),
            Some(DxgDdiSignature::DestroyAllocation));
        assert_eq!(DxgDdiSignature::DestroyAllocation.argument_count(), 2);
        let mut request = [0u8; 0x20];
        request[..4].copy_from_slice(&1u32.to_le_bytes());
        request[8..16].copy_from_slice(&0x5000u64.to_le_bytes());
        request[24..28].copy_from_slice(&1u32.to_le_bytes());
        let layout = DxgDestroyAllocationLayout::parse(version, 0x6000,
            &request, 0x4000, 0x1000).unwrap();
        assert_eq!(layout.request_bytes(), 0x20);
        assert_eq!(layout.list_bytes(), 8);
        assert_eq!(layout.cookie(), 0x4000);
        request[0] = 2;
        assert!(DxgDestroyAllocationLayout::parse(version, 0x6000,
            &request, 0x4000, 0x1000).is_none());
    }
    let mut retirement = DxgAllocationCookieRetirement::new(key, route).unwrap();
    assert!(!retirement.request_free(key, wrong_route, 0x4000, 88));
    assert!(!retirement.request_free(key, route, 0x4000, 89));
    assert!(retirement.request_free(key, route, 0x4000, 88));
    assert!(!retirement.complete(true, true));
    retirement.close_callback_interval();
    assert!(!retirement.request_free(key, route, 0x4000, 88));
    assert!(retirement.complete(true, true));
    assert!(!retirement.complete(true, true));
}

#[test]
fn allocation_terminal_failure_releases_only_effect_free_work() {
    use DxgAllocationCallbackDisposition as Disposition;
    assert_eq!(Disposition::create(true, -1, 0), Disposition::ReleaseProvisional);
    assert_eq!(Disposition::create(true, -1, 0x4000), Disposition::Retain);
    assert_eq!(Disposition::create(false, -1, 0), Disposition::Retain);
    assert_eq!(Disposition::create(true, 0, 0x4000), Disposition::Publish);
    assert_eq!(Disposition::destroy(true, -1, false), Disposition::RetryWithCookie);
    assert_eq!(Disposition::destroy(true, -1, true), Disposition::Retain);
    assert_eq!(Disposition::destroy(false, -1, false), Disposition::Retain);
    assert_eq!(Disposition::destroy(true, 0, true), Disposition::RetireCookie);
    assert_eq!(Disposition::destroy(true, 0, false), Disposition::Retain);
}
