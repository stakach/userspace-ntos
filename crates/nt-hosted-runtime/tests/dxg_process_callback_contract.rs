//! Pinned LiberNT WDDM process callback ABI and cross-domain ownership.

use nt_hosted_runtime::{
    DxgCreateProcessLayout, DxgDdiSignature, DxgPdoAliasAuthority,
    DxgNullProcessCredits, DxgProcessAliasKey, DxgProcessCookieRetirement,
    DxgProcessFreeRoute,
    HostedProviderObjectOwner,
};

fn args(bytes: usize) -> Vec<u8> {
    let mut request = vec![0u8; bytes];
    request[0..8].copy_from_slice(&0x1000u64.to_le_bytes());
    request[0x10..0x14].copy_from_slice(&1u32.to_le_bytes()); // SystemProcess
    request
}

#[test]
fn successful_null_cookie_still_owns_one_exact_destroy() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let alias = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgProcessAliasKey::new(alias, 0x3000, 77,
        0x4000, 88, 0, 0).unwrap();
    assert!(key.matches_destroy(alias, 0x3000, 77, 0, 0));
    assert!(!key.matches_destroy(alias, 0x3000, 78, 0, 0));
    assert!(DxgProcessAliasKey::new(alias, 0x3000, 77,
        0x4000, 88, 0, 99).is_none());
    assert!(DxgProcessAliasKey::new(alias, 0x3000, 77,
        0x4000, 88, 0x5000, 0).is_none());
}

#[test]
fn null_cookie_destroys_consume_aggregate_adapter_credits() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let alias = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let stale = DxgPdoAliasAuthority::new(owner, 34, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let mut credits = DxgNullProcessCredits::new(alias, 0x3000, 77).unwrap();
    // Create callbacks can identify different DXG processes, but the later
    // Destroy(NULL) ABI cannot identify which one is being destroyed.
    assert!(credits.record_create(alias, 0x3000, 77, true, true));
    assert!(credits.record_create(alias, 0x3000, 77, true, true));
    assert_eq!(credits.count(), 2);
    assert!(!credits.begin_destroy(stale, 0x3000, 77));
    assert!(!credits.begin_destroy(alias, 0x3000, 78));
    assert!(credits.begin_destroy(alias, 0x3000, 77));
    assert!(!credits.finish_destroy(false, true));
    assert_eq!(credits.count(), 2);
    // A failed native effect remains fenced; no second NULL callback replay.
    assert!(!credits.begin_destroy(alias, 0x3000, 77));

    let mut completed = DxgNullProcessCredits::new(alias, 0x3000, 77).unwrap();
    assert!(completed.record_create(alias, 0x3000, 77, true, true));
    assert!(completed.record_create(alias, 0x3000, 77, true, true));
    for expected in [1, 0] {
        assert!(completed.begin_destroy(alias, 0x3000, 77));
        assert!(completed.finish_destroy(true, true));
        assert_eq!(completed.count(), expected);
    }
    assert!(!completed.begin_destroy(alias, 0x3000, 77));
}

#[test]
fn process_cookie_free_requires_exact_callback_route_and_completion() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let alias = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgProcessAliasKey::new(alias, 0x3000, 77,
        0x4000, 88, 0x5000, 99).unwrap();
    let route = DxgProcessFreeRoute::new(2, 22, 0x9000, 0xa000, 23, 0xb000).unwrap();
    let stale = DxgProcessFreeRoute::new(2, 22, 0x9000, 0xa000, 24, 0xb000).unwrap();
    let mut retirement = DxgProcessCookieRetirement::new(key, route).unwrap();
    assert!(!retirement.request_free(key, stale, 0x5000, 99));
    assert!(!retirement.complete(true, true));
    assert!(retirement.request_free(key, route, 0x5000, 99));
    assert!(!retirement.request_free(key, route, 0x5000, 99));
    retirement.close_callback_interval();
    assert!(!retirement.complete(true, false));
    assert!(!retirement.complete(false, true));
    assert!(retirement.complete(true, true));
    assert!(!retirement.complete(true, true));

    let mut retained_by_miniport = DxgProcessCookieRetirement::new(key, route).unwrap();
    retained_by_miniport.close_callback_interval();
    assert!(!retained_by_miniport.release_without_free(true, false));
    assert!(retained_by_miniport.release_without_free(true, true));
    assert!(!retained_by_miniport.release_without_free(true, true));
    assert!(!retained_by_miniport.request_free(key, route, 0x5000, 99));

    let mut returned_failure = DxgProcessCookieRetirement::new(key, route).unwrap();
    returned_failure.close_callback_interval();
    assert!(!returned_failure.request_free(key, route, 0x5000, 99));
}

#[test]
fn shared_nonzero_cookie_cannot_select_one_source_process_for_destroy() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let adapter = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let first = DxgProcessAliasKey::new(adapter, 0x3000, 77,
        0x4000, 88, 0x5000, 99).unwrap();
    let second = DxgProcessAliasKey::new(adapter, 0x3000, 77,
        0x4100, 89, 0x5000, 99).unwrap();
    let stale_generation = DxgProcessAliasKey::new(adapter, 0x3000, 77,
        0x4200, 90, 0x5000, 100).unwrap();
    let independent = DxgProcessAliasKey::new(adapter, 0x3000, 77,
        0x4300, 91, 0x6000, 101).unwrap();
    assert!(first.cookie_address_conflicts(second));
    assert!(first.cookie_address_conflicts(stale_generation));
    assert!(!first.cookie_address_conflicts(independent));
}

#[test]
fn create_and_destroy_process_use_versioned_two_argument_ddis() {
    for (version, bytes) in [(0x5022, 0x20), (0x5023, 0x20), (0x11007, 0x38)] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0x300),
            Some(DxgDdiSignature::CreateProcess));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x308),
            Some(DxgDdiSignature::DestroyProcess));
        assert_eq!(DxgDdiSignature::CreateProcess.argument_count(), 2);
        assert_eq!(DxgDdiSignature::DestroyProcess.argument_count(), 2);
        let request = args(bytes);
        let layout = DxgCreateProcessLayout::parse(version, &request, 0x1000).unwrap();
        assert_eq!(layout.bytes(), bytes);
        assert_eq!(layout.dxg_process(), 0x1000);
        assert_eq!(layout.flags(), 1);
        assert!(DxgCreateProcessLayout::parse(version, &request[..bytes - 1], 0x1000).is_none());
        assert!(DxgCreateProcessLayout::parse(version, &request, (bytes - 1) as u64).is_none());
    }
    assert_eq!(DxgDdiSignature::for_offset(0x5023, 0x300),
        Some(DxgDdiSignature::CreateProcess));
    assert!(DxgCreateProcessLayout::parse(0x7777, &args(0x38), 0x1000).is_none());
}

#[test]
fn create_process_rejects_unprojected_nested_data_and_copies_only_kmd_handle() {
    let mut request = args(0x38);
    let layout = DxgCreateProcessLayout::parse(0x11007, &request, 0x1000).unwrap();
    let original = request.clone();
    assert!(layout.copyback_kmd_process(&mut request, 0x2000));
    assert_eq!(&request[8..16], &0x2000u64.to_le_bytes());
    assert_eq!(&request[..8], &original[..8]);
    assert_eq!(&request[16..], &original[16..]);
    request.copy_from_slice(&original);
    request[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    assert!(DxgCreateProcessLayout::parse(0x11007, &request, 0x1000).is_none());
    request[0x14..0x18].fill(0);
    request[0x18..0x20].copy_from_slice(&0x3000u64.to_le_bytes());
    assert!(DxgCreateProcessLayout::parse(0x11007, &request, 0x1000).is_none());
    request[0x18..0x20].fill(0);
    request[0x30..0x38].copy_from_slice(&0x4000u64.to_le_bytes());
    assert!(DxgCreateProcessLayout::parse(0x11007, &request, 0x1000).is_none());
}

#[test]
fn process_cookie_destroy_requires_exact_adapter_and_both_allocation_generations() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let alias = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    let key = DxgProcessAliasKey::new(alias, 0x3000, 77,
        0x4000, 88, 0x5000, 99).unwrap();
    assert!(key.matches_destroy(alias, 0x3000, 77, 0x5000, 99));
    assert!(!key.matches_destroy(alias, 0x3000, 78, 0x5000, 99));
    assert!(!key.matches_destroy(alias, 0x3000, 77, 0x5000, 100));
    let stale = DxgPdoAliasAuthority::new(owner, 34, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    assert!(!key.matches_destroy(stale, 0x3000, 77, 0x5000, 99));
    assert!(DxgProcessAliasKey::new(alias, 0x3000, 77,
        0x4000, 88, 0x5000, 0).is_none());
}
