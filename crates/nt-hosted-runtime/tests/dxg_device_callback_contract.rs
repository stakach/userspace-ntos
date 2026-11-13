//! Pinned LiberNT WDDM device callback ABI and generation-bound cookie owner.

use nt_hosted_runtime::{
    DxgCreateDeviceLayout, DxgDdiSignature, DxgDeviceAliasKey,
    DxgDeviceCookieRetirement, DxgProcessFreeRoute,
    DxgPdoAliasAuthority, HostedProviderObjectOwner,
};

fn request(process: u64) -> [u8; 0x20] {
    let mut bytes = [0u8; 0x20];
    bytes[8..12].copy_from_slice(&1u32.to_le_bytes()); // SystemDevice
    bytes[0x18..0x20].copy_from_slice(&process.to_le_bytes());
    bytes
}

#[test]
fn destroy_cookie_free_requires_exact_active_route_and_terminal_ack() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0x5000, 88, 0x6000, 99).unwrap();
    let route = DxgProcessFreeRoute::new(2, 22, 3, 4, 5, 6).unwrap();
    let wrong_route = DxgProcessFreeRoute::new(2, 22, 3, 4, 5, 7).unwrap();
    let mut retirement = DxgDeviceCookieRetirement::new(key, route).unwrap();
    assert!(!retirement.request_free(key, wrong_route, 0x6000, 99));
    assert!(!retirement.request_free(key, route, 0x6000, 100));
    assert!(retirement.request_free(key, route, 0x6000, 99));
    assert!(!retirement.complete(true, true)); // callback still in progress
    retirement.close_callback_interval();
    assert!(!retirement.request_free(key, route, 0x6000, 99));
    assert!(!retirement.complete(true, false));
    assert!(retirement.complete(true, true));
    assert!(!retirement.complete(true, true));
}

#[test]
fn create_device_uses_fixed_wddm2_record_and_only_handle_copyback() {
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0x90),
            Some(DxgDdiSignature::CreateDevice));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x190),
            Some(DxgDdiSignature::DestroyDevice));
        assert_eq!(DxgDdiSignature::CreateDevice.argument_count(), 2);
        assert_eq!(DxgDdiSignature::DestroyDevice.argument_count(), 1);
        let original = request(0x5000);
        let layout = DxgCreateDeviceLayout::parse(version, &original, 0x1000).unwrap();
        assert_eq!(layout.bytes(), 0x20);
        assert_eq!(layout.kmd_process(), 0x5000);
        let mut projected = original;
        assert!(layout.copyback_device(&mut projected, 0x6000, 1));
        assert_eq!(&projected[..8], &0x6000u64.to_le_bytes());
        assert_eq!(&projected[8..], &original[8..]);
        assert!(DxgCreateDeviceLayout::parse(version, &original[..0x1f], 0x1000).is_none());
        assert!(DxgCreateDeviceLayout::parse(version, &original, 0x1f).is_none());
        assert!(DxgCreateDeviceLayout::parse(version, &request(0), 0x1000).is_some());
    }
    let mut invalid = request(0x5000);
    invalid[0] = 1; // output handle was not empty
    assert!(DxgCreateDeviceLayout::parse(0x5023, &invalid, 0x1000).is_none());
    invalid = request(0x5000);
    invalid[8] = 2; // unprojected flag
    assert!(DxgCreateDeviceLayout::parse(0x5023, &invalid, 0x1000).is_none());
    invalid = request(0x5000);
    invalid[0x10] = 1; // PASID needs its own typed owner
    assert!(DxgCreateDeviceLayout::parse(0x5023, &invalid, 0x1000).is_none());
}

#[test]
fn live_gdi_device_request_retains_runtime_handle_and_driver_copyback() {
    // Captured from LiberNT's first DxgkDdiCreateDevice on its released BasicDisplay stack.
    let mut request = [0u8; 0x20];
    request[..8].copy_from_slice(&0x0000_0100_0e8c_4000u64.to_le_bytes());
    request[8..12].copy_from_slice(&2u32.to_le_bytes()); // GdiDevice
    request[0x18..0x20].copy_from_slice(&0x0000_0100_0e80_18a0u64.to_le_bytes());
    let layout = DxgCreateDeviceLayout::parse(0x11007, &request, 2048)
        .expect("the released GDI-device request must be admitted");
    assert_eq!(layout.kmd_process(), 0x0000_0100_0e80_18a0);
    let original = request;
    assert!(layout.copyback_device(&mut request, 0x0000_0100_0e8c_9000, 2));
    assert_eq!(&request[..8], &0x0000_0100_0e8c_9000u64.to_le_bytes());
    assert_eq!(&request[8..16], &[0; 8], "no pInfo output must not expose the input flags as a pointer");
    assert_eq!(&request[16..], &original[16..]);

    let mut unexpected_info = original;
    assert!(!layout.copyback_device(&mut unexpected_info, 0x0000_0100_0e8c_9000,
        0x0000_0100_0e8c_a000));
    assert_eq!(unexpected_info, original);

    let mut invalid = original;
    invalid[..8].fill(0);
    assert!(DxgCreateDeviceLayout::parse(0x11007, &invalid, 2048).is_none());
    invalid = original;
    invalid[8] = 3; // neither a sole system nor a sole GDI-device request
    assert!(DxgCreateDeviceLayout::parse(0x11007, &invalid, 2048).is_none());
}

#[test]
fn device_destroy_requires_exact_adapter_and_cookie_generation() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0x5000, 88, 0x6000, 99).unwrap();
    assert!(key.matches_destroy(adapter, 0x6000, 99));
    assert!(!key.matches_destroy(adapter, 0x6000, 100));
    let stale = DxgPdoAliasAuthority::new(owner, 34, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    assert!(!key.matches_destroy(stale, 0x6000, 99));
    assert!(DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0, 0, 0x6000, 99).is_some()); // system device with no process cookie
    assert!(DxgDeviceAliasKey::new(adapter, 0x3000, 77,
        0, 88, 0x6000, 99).is_none());
}
