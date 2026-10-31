//! Pinned LiberNT WDDM system-context ABI and cookie ownership.

use nt_hosted_runtime::{DxgContextAliasKey, DxgContextCookieRetirement,
    DxgCreateContextLayout,
    DxgDdiSignature, DxgDeviceAliasKey, DxgPdoAliasAuthority,
    DxgProcessFreeRoute, HostedProviderObjectOwner};

fn request() -> [u8; 0x48] {
    let mut bytes = [0u8; 0x48];
    bytes[0x0c..0x10].copy_from_slice(&1u32.to_le_bytes()); // EngineAffinity
    bytes[0x10..0x14].copy_from_slice(&1u32.to_le_bytes()); // SystemContext
    bytes
}

#[test]
fn context_cookie_retirement_requires_active_exact_route_and_ack() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let device = DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0x5000, 88, 0x6000, 99).unwrap();
    let key = DxgContextAliasKey::new(device, 0, 0, 0x7000, 100).unwrap();
    let route = DxgProcessFreeRoute::new(2, 22, 3, 4, 5, 6).unwrap();
    let stale = DxgProcessFreeRoute::new(2, 22, 3, 4, 5, 7).unwrap();
    let mut retirement = DxgContextCookieRetirement::new(key, route).unwrap();
    assert!(!retirement.request_free(key, stale, 0x7000, 100));
    assert!(!retirement.request_free(key, route, 0x7000, 101));
    assert!(retirement.request_free(key, route, 0x7000, 100));
    assert!(!retirement.complete(true, true));
    retirement.close_callback_interval();
    assert!(!retirement.request_free(key, route, 0x7000, 100));
    assert!(!retirement.complete(true, false));
    assert!(retirement.complete(true, true));
    assert!(!retirement.complete(true, true));
}

#[test]
fn system_context_has_exact_bounded_input_and_output_fields() {
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0x1d0),
            Some(DxgDdiSignature::CreateContext));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x1d8),
            Some(DxgDdiSignature::DestroyContext));
        assert_eq!(DxgDdiSignature::CreateContext.argument_count(), 2);
        assert_eq!(DxgDdiSignature::DestroyContext.argument_count(), 1);
        let original = request();
        let layout = DxgCreateContextLayout::parse(version, &original, 0x1000).unwrap();
        assert_eq!(layout.bytes(), 0x48);
        assert_eq!(layout.runtime_context(), 0);
        let mut projected = original;
        let mut returned = original;
        returned[..8].copy_from_slice(&0x6000u64.to_le_bytes());
        returned[0x24..0x44].fill(0x5a); // DXGK_CONTEXTINFO output
        assert!(layout.copyback(&mut projected, &returned));
        assert_eq!(&projected[..8], &returned[..8]);
        assert_eq!(&projected[0x24..0x44], &returned[0x24..0x44]);
        assert_eq!(&projected[8..0x24], &original[8..0x24]);
        assert_eq!(&projected[0x44..], &original[0x44..]);
        assert!(DxgCreateContextLayout::parse(version, &original[..0x47], 0x1000).is_none());
        assert!(DxgCreateContextLayout::parse(version, &original, 0x47).is_none());
    }
    let mut invalid = request();
    invalid[0x18] = 1; // nested private driver data needs separate ownership
    assert!(DxgCreateContextLayout::parse(0x5023, &invalid, 0x1000).is_none());
    invalid = request();
    invalid[0x20] = 1; // nonzero size with null pointer is invalid
    assert!(DxgCreateContextLayout::parse(0x5023, &invalid, 0x1000).is_none());
    invalid = request();
    invalid[0x10] = 2; // GDI or other flags require typed support
    assert!(DxgCreateContextLayout::parse(0x5023, &invalid, 0x1000).is_none());
}

#[test]
fn context_destroy_requires_exact_device_and_context_cookie_generations() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let device = DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0x5000, 88, 0x6000, 99).unwrap();
    let key = DxgContextAliasKey::new(device, 0, 0, 0x7000, 100).unwrap();
    assert!(key.matches_destroy(device, 0x7000, 100));
    assert!(!key.matches_destroy(device, 0x7000, 101));
    let other_device = DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0x5000, 88, 0x6000, 101).unwrap();
    assert!(!key.matches_destroy(other_device, 0x7000, 100));
    assert!(DxgContextAliasKey::new(device, 0, 1, 0x7000, 100).is_none());
}
