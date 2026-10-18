//! Pinned LiberNT 8e478a22a1e8f8a22bab17131f3184a7b4548c3d display registration ABI.
//!
//! `drivers/directx/dxgkrnl/adapter.c` derives an append-only table prefix from
//! the DDI selector; `sdk/lib/drivers/displib/displib.c` calls its resolved
//! entry with the caller's driver object, registry path, and callback table.

use nt_hosted_runtime::{
    hosted_dxg_registration_marshal_policy, DxgEntryAuthority, DxgInitializationData,
    DxgInitializationDataError, DxgRegistrationKey, DxgSourceDriverObject, DxgDdiSignature,
    DxgPdoAliasAuthority, DxgStartInterface, DxgStartInterfaceError,
    hosted_dxg_acquire_post_display_marshal_policy,
    dxg_scanout_dependent_admitted,
    HostedProviderArgumentMarshal,
    HostedProviderExportResultSemantics, HostedProviderExportSideEffect, HostedProviderObjectOwner,
};

#[test]
fn child_relations_callback_uses_bounded_descriptor_array() {
    use nt_hosted_runtime::{DxgChildRelationsLayout, DxgDdiSignature};
    let version = 0x11007;
    assert_eq!(DxgDdiSignature::for_offset(version, 0x40),
        Some(DxgDdiSignature::QueryChildRelations));
    assert_eq!(DxgDdiSignature::QueryChildRelations.argument_count(), 3);
    assert_eq!(DxgChildRelationsLayout::new(0x38, 0x1000).unwrap().bytes(), 0x38);
    assert_eq!(DxgChildRelationsLayout::new(0x1c, 0x1000).unwrap().bytes(), 0x1c);
    assert!(DxgChildRelationsLayout::new(0x1b, 0x1000).is_none());
    assert!(DxgChildRelationsLayout::new(0x39, 0x1000).is_none());
    assert!(DxgChildRelationsLayout::new(0x38, 0x37).is_none());
    assert!(DxgChildRelationsLayout::new(0x1c000, 0x1000).is_none());
}

#[test]
fn query_adapter_info_uses_pinned_x64_pointer_and_size_prefix() {
    use nt_hosted_runtime::{DxgDdiSignature, DxgQueryAdapterInfoPrefix};
    assert_eq!(DxgDdiSignature::for_offset(0x11007, 0x88),
        Some(DxgDdiSignature::QueryAdapterInfo));
    assert_eq!(DxgDdiSignature::QueryAdapterInfo.argument_count(), 2);
    let mut bytes = [0u8; 0x28];
    bytes[0..4].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&0x1000u64.to_le_bytes());
    bytes[0x20..0x24].copy_from_slice(&0x100u32.to_le_bytes());
    let query = DxgQueryAdapterInfoPrefix::parse(&bytes, 0x1000).unwrap();
    assert_eq!(query.kind(), 1);
    assert_eq!(query.output(), (0x1000, 0x100));
    assert_eq!(query.input(), (0, 0));
    assert!(DxgQueryAdapterInfoPrefix::parse(&bytes[..0x27], 0x1000).is_none());
    assert!(DxgQueryAdapterInfoPrefix::parse(&bytes, 0xff).is_none());
    bytes[0x18..0x20].fill(0);
    assert!(DxgQueryAdapterInfoPrefix::parse(&bytes, 0x1000).is_none());
}

#[test]
fn query_segment_nested_descriptors_are_bounded_by_pinned_version() {
    use nt_hosted_runtime::{DxgQueryAdapterInfoPrefix, DxgSegmentQueryLayout};
    for (kind, input_len, output_len, descriptor_len) in [
        (2u32, 0x18u32, 0x20u32, 0x38u64),
        (5, 0x18, 0x20, 0x48),
        (11, 4, 0x28, 0x60),
    ] {
        let mut query = [0u8; 0x28];
        query[0..4].copy_from_slice(&kind.to_le_bytes());
        query[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
        query[0x10..0x14].copy_from_slice(&input_len.to_le_bytes());
        query[0x18..0x20].copy_from_slice(&0x2000u64.to_le_bytes());
        query[0x20..0x24].copy_from_slice(&output_len.to_le_bytes());
        let prefix = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
        let mut output = [0u8; 0x28];
        output[0..4].copy_from_slice(&2u32.to_le_bytes());
        if kind == 11 {
            output[0x20..0x28].copy_from_slice(&descriptor_len.to_le_bytes());
        }
        let first = DxgSegmentQueryLayout::parse(prefix, &output[..output_len as usize], 0x800).unwrap();
        assert_eq!(first.descriptors(), (0, 0));
        output[8..16].copy_from_slice(&0x3000u64.to_le_bytes());
        let nested = DxgSegmentQueryLayout::parse(prefix, &output[..output_len as usize], 0x800).unwrap();
        assert_eq!(nested.descriptors(), (0x3000, descriptor_len * 2));
        assert!(DxgSegmentQueryLayout::parse(prefix, &output[..output_len as usize], descriptor_len * 2 - 1).is_none());
        output[8..16].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(DxgSegmentQueryLayout::parse(prefix, &output[..output_len as usize], 0x800).is_none());
    }
}

#[test]
fn query_segment_rejects_unknown_kind_and_short_fixed_buffers() {
    use nt_hosted_runtime::{DxgQueryAdapterInfoPrefix, DxgSegmentQueryLayout};
    let mut query = [0u8; 0x28];
    query[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    query[0x10..0x14].copy_from_slice(&0x18u32.to_le_bytes());
    query[0x18..0x20].copy_from_slice(&0x2000u64.to_le_bytes());
    query[0x20..0x24].copy_from_slice(&0x20u32.to_le_bytes());
    let output = [0u8; 0x28];
    let unknown = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
    assert!(DxgSegmentQueryLayout::parse(unknown, &output, 0x800).is_none());
    query[0..4].copy_from_slice(&5u32.to_le_bytes());
    query[0x10..0x14].copy_from_slice(&0x17u32.to_le_bytes());
    let short_input = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
    assert!(DxgSegmentQueryLayout::parse(short_input, &output, 0x800).is_none());
    query[0x10..0x14].copy_from_slice(&0x18u32.to_le_bytes());
    query[0x20..0x24].copy_from_slice(&0x1fu32.to_le_bytes());
    let short_output = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
    assert!(DxgSegmentQueryLayout::parse(short_output, &output, 0x800).is_none());
}

#[test]
fn query_driver_caps_accepts_pinned_fixed_prefix_and_larger_provider_output() {
    use nt_hosted_runtime::{DxgDriverCapsLayout, DxgQueryAdapterInfoPrefix};
    let mut query = [0u8; 0x28];
    query[0..4].copy_from_slice(&1u32.to_le_bytes());
    query[0x18..0x20].copy_from_slice(&0x2000u64.to_le_bytes());
    for size in [0x250u32, 0x400] {
        query[0x20..0x24].copy_from_slice(&size.to_le_bytes());
        let prefix = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
        assert_eq!(DxgDriverCapsLayout::parse(prefix, 0x800).unwrap().output_bytes(), size as u64);
    }
    query[0x20..0x24].copy_from_slice(&0x24fu32.to_le_bytes());
    let short = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
    assert!(DxgDriverCapsLayout::parse(short, 0x800).is_none());
    query[0x20..0x24].copy_from_slice(&0x250u32.to_le_bytes());
    query[8..16].copy_from_slice(&0x1000u64.to_le_bytes());
    query[0x10..0x14].copy_from_slice(&4u32.to_le_bytes());
    let input = DxgQueryAdapterInfoPrefix::parse(&query, 0x800).unwrap();
    assert!(DxgDriverCapsLayout::parse(input, 0x800).is_none());
}

#[test]
fn query_copyback_restores_only_segment_nested_pointer() {
    use nt_hosted_runtime::dxg_query_restores_nested_pointer;
    assert!(!dxg_query_restores_nested_pointer(1));
    for kind in [2, 5, 11] {
        assert!(dxg_query_restores_nested_pointer(kind));
    }
    assert!(!dxg_query_restores_nested_pointer(0));
}

#[test]
fn query_fixed_and_nested_output_regions_must_not_overlap() {
    use nt_hosted_runtime::dxg_query_output_regions_disjoint;
    assert!(dxg_query_output_regions_disjoint(0x1000, 0x28, 0, 0));
    assert!(dxg_query_output_regions_disjoint(0x1000, 0x28, 0x1028, 0x60));
    assert!(!dxg_query_output_regions_disjoint(0x1000, 0x28, 0x1010, 0x60));
    assert!(!dxg_query_output_regions_disjoint(0x1000, 0x28, 0xff0, 0x20));
    assert!(!dxg_query_output_regions_disjoint(u64::MAX - 4, 0x28, 0, 0));
}

#[test]
fn stop_device_rollback_requires_exact_started_context_once() {
    use nt_hosted_runtime::dxg_stop_device_admitted;
    assert!(dxg_stop_device_admitted(true, true, false, false, false, false,
        0x1000, 0x1000));
    assert!(!dxg_stop_device_admitted(true, true, true, false, false, false,
        0x1000, 0x1000));
    assert!(!dxg_stop_device_admitted(true, true, false, true, false, false,
        0x1000, 0x1000));
    assert!(!dxg_stop_device_admitted(true, true, false, false, true, false,
        0x1000, 0x1000));
    assert!(!dxg_stop_device_admitted(true, true, false, false, false, false,
        0x1000, 0x2000));
    assert!(!dxg_stop_device_admitted(true, false, false, false, false, false,
        0x1000, 0x1000));
}

fn table(version: u32, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&version.to_le_bytes());
    bytes
}

#[test]
fn active_start_callback_may_use_scanout_while_retained_uncertainty_stays_blocked() {
    assert!(dxg_scanout_dependent_admitted(true, true, false, true, true, false, 0x1000));
    assert!(dxg_scanout_dependent_admitted(true, true, true, false, false, false, 0x1000));
    assert!(!dxg_scanout_dependent_admitted(true, true, true, false, true, false, 0x1000));
    assert!(!dxg_scanout_dependent_admitted(true, true, true, true, true, true, 0x1000));
    assert!(!dxg_scanout_dependent_admitted(true, false, false, true, true, false, 0x1000));
    assert!(!dxg_scanout_dependent_admitted(false, true, false, true, true, false, 0x1000));
    assert!(!dxg_scanout_dependent_admitted(true, true, false, true, true, false, 0));
}

#[test]
fn failed_start_cannot_reopen_scanout_after_callback_returns() {
    assert!(!dxg_scanout_dependent_admitted(
        true, true, false, false, false, false, 0x1000));
}

#[test]
fn provider_worker_scanout_requires_exact_live_dxg_registration() {
    use nt_hosted_runtime::dxg_scanout_provider_admitted;
    assert!(dxg_scanout_provider_admitted(7, 11, 12, 13, 7, 11, 12, 13, true));
    assert!(!dxg_scanout_provider_admitted(7, 11, 12, 13, 7, 11, 12, 13, false));
    assert!(!dxg_scanout_provider_admitted(7, 11, 12, 13, 8, 11, 12, 13, true));
    assert!(!dxg_scanout_provider_admitted(7, 11, 12, 13, 7, 11, 99, 13, true));
    assert!(!dxg_scanout_provider_admitted(7, 11, 12, 13, 7, 11, 12, 14, true));
}

fn put_callback(bytes: &mut [u8], offset: usize, address: u64) {
    bytes[offset..offset + 8].copy_from_slice(&address.to_le_bytes());
}

#[test]
fn pinned_libernt_wddm_20_full_prefix_has_x64_layout() {
    // 0x5022 is the Windows 10 10240 selector, 0x5023 the published WDDM 2.0 selector.
    // Pinned adapter.c computes FIELD_END(DxgkDdiSetVideoProtectedRegion) == 0x340.
    for version in [0x5022, 0x5023] {
        let bytes = table(version, 0x340);
        let init = DxgInitializationData::parse(&bytes).unwrap();
        assert_eq!(init.version(), version);
        assert_eq!(init.prefix_len(), 0x340);
        assert_eq!(init.first_callback_offset(), 8);
        assert_eq!(init.callback_slot_count(), (0x340 - 8) / 8 - 9);
    }
    assert_eq!(
        DxgInitializationData::parse(&table(0x5023, 0x33f)),
        Err(DxgInitializationDataError::Truncated)
    );
    assert_eq!(
        DxgInitializationData::parse(&table(0x5024, 0x340)),
        Err(DxgInitializationDataError::UnknownVersion)
    );
}

#[test]
fn only_non_null_callbacks_inside_versioned_prefix_are_projected() {
    let mut bytes = table(0x5023, 0x348);
    put_callback(&mut bytes, 8, 0x1000); // AddDevice
    put_callback(&mut bytes, 16, 0x2000); // StartDevice
    put_callback(&mut bytes, 32, 0x4000); // RemoveDevice; StopDevice is null
    put_callback(&mut bytes, 0x338, 0x5000); // final callback in the WDDM 2.0 prefix
    put_callback(&mut bytes, 0x340, 0xdead); // outside the declared version's prefix

    let init = DxgInitializationData::parse(&bytes).unwrap();
    let callbacks: Vec<_> = init.callbacks().collect();
    assert_eq!(
        callbacks
            .iter()
            .map(|slot| (slot.offset, slot.target))
            .collect::<Vec<_>>(),
        [(8, 0x1000), (16, 0x2000), (32, 0x4000), (0x338, 0x5000)]
    );
    assert_eq!(init.callback_at(24), Some(0));
    assert_eq!(init.callback_at(0x340), None);
    assert_eq!(init.callback_at(9), None);
}

#[test]
fn pinned_reserved_slots_are_not_callable_and_must_be_zero() {
    // Pinned sdk/include/ddk/dispmprt.h marks these PVOID fields reserved/set zero.
    // Their offsets follow the pinned x64 C_ASSERTs for +0x1F0 and +0x2C8.
    const RESERVED: [usize; 9] = [
        0x1f0, 0x1f8, 0x200, 0x208, 0x210, 0x218, 0x228, 0x318, 0x320,
    ];
    let empty = table(0x5023, 0x340);
    let init = DxgInitializationData::parse(&empty).unwrap();
    for offset in RESERVED {
        assert_eq!(init.callback_at(offset), None);
        let mut invalid = empty.clone();
        put_callback(&mut invalid, offset, 0x1000);
        assert_eq!(
            DxgInitializationData::parse(&invalid),
            Err(DxgInitializationDataError::NonZeroReserved)
        );
    }
}

#[test]
fn released_basicdisplay_wddm_32_selector_has_pinned_full_prefix() {
    // Released BasicDisplay.sys DriverEntry writes Version 0x11007 and clears
    // a 0x608-byte table. Pinned adapter.c and dispmprt.h assert this prefix.
    let bytes = table(0x11007, 0x608);
    let init = DxgInitializationData::parse(&bytes).unwrap();
    assert_eq!(init.prefix_len(), 0x608);
    assert_eq!(init.callback_slot_count(), (0x608 - 8) / 8 - 11);
    assert_eq!(
        DxgInitializationData::parse(&table(0x11007, 0x607)),
        Err(DxgInitializationDataError::Truncated)
    );
    // The pinned release uses 0x11007; accepting adjacent revisions would
    // assume the same ABI without evidence.
    assert_eq!(
        DxgInitializationData::parse(&table(0x11008, 0x608)),
        Err(DxgInitializationDataError::UnknownVersion)
    );
}

#[test]
fn wddm_32_reserved_tail_cells_are_never_callable() {
    let empty = table(0x11007, 0x608);
    let init = DxgInitializationData::parse(&empty).unwrap();
    for offset in [0x4c0, 0x558] {
        assert_eq!(init.callback_at(offset), None);
        let mut invalid = empty.clone();
        put_callback(&mut invalid, offset, 0x1000);
        assert_eq!(
            DxgInitializationData::parse(&invalid),
            Err(DxgInitializationDataError::NonZeroReserved)
        );
    }
    let mut last = empty;
    put_callback(&mut last, 0x600, 0x6000);
    assert_eq!(
        DxgInitializationData::parse(&last)
            .unwrap()
            .callbacks()
            .last()
            .map(|callback| (callback.offset, callback.target)),
        Some((0x600, 0x6000))
    );
}

#[test]
fn registration_key_binds_both_domains_publication_and_driver_object_generation() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let key = DxgRegistrationKey::new(owner, 33, 0x1000, 44).unwrap();
    assert!(key.matches(owner, 33, 0x1000, 44));
    assert!(!key.matches(HostedProviderObjectOwner::new(1, 12, 2, 22).unwrap(), 33, 0x1000, 44));
    assert!(!key.matches(HostedProviderObjectOwner::new(1, 11, 2, 23).unwrap(), 33, 0x1000, 44));
    assert!(!key.matches(owner, 34, 0x1000, 44));
    assert!(!key.matches(owner, 33, 0x2000, 44));
    assert!(!key.matches(owner, 33, 0x1000, 45));
    assert!(DxgRegistrationKey::new(owner, 0, 0x1000, 44).is_none());
    assert!(DxgRegistrationKey::new(owner, 33, 0, 44).is_none());
    assert!(DxgRegistrationKey::new(owner, 33, 0x1000, 0).is_none());
}

#[test]
fn registration_key_rejects_manually_constructed_invalid_domain_authority() {
    let valid = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    for invalid in [
        HostedProviderObjectOwner {
            provider_domain_id: 0,
            ..valid
        },
        HostedProviderObjectOwner {
            provider_domain_cookie: 0,
            ..valid
        },
        HostedProviderObjectOwner {
            dependent_domain_id: 0,
            ..valid
        },
        HostedProviderObjectOwner {
            dependent_domain_cookie: 0,
            ..valid
        },
    ] {
        assert!(DxgRegistrationKey::new(invalid, 33, 0x1000, 44).is_none());
    }
}

#[test]
fn resolved_entry_requires_executable_provider_extent_and_exact_source_identity() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let key = DxgRegistrationKey::new(owner, 33, 0x1000, 44).unwrap();
    let entry = DxgEntryAuthority::new(key, 55, 66, 77, 0x8120, 0x8000, 0x300).unwrap();
    assert!(entry.matches(key, 55, 66, 77, 0x8120));
    assert!(!entry.matches(key, 56, 66, 77, 0x8120));
    assert!(!entry.matches(key, 55, 67, 77, 0x8120));
    assert!(!entry.matches(key, 55, 66, 78, 0x8120));
    assert!(!entry.matches(key, 55, 66, 77, 0x8130));
    let stale_owner = HostedProviderObjectOwner::new(1, 12, 2, 22).unwrap();
    let stale_key = DxgRegistrationKey::new(stale_owner, 33, 0x1000, 44).unwrap();
    assert!(!entry.matches(stale_key, 55, 66, 77, 0x8120));
    assert!(DxgEntryAuthority::new(key, 55, 66, 77, 0x7fff, 0x8000, 0x300).is_none());
    assert!(DxgEntryAuthority::new(key, 55, 66, 77, 0x8300, 0x8000, 0x300).is_none());
    assert!(DxgEntryAuthority::new(key, 55, 66, 77, 0x8120, u64::MAX - 1, 4).is_none());
    assert!(DxgEntryAuthority::new(key, 0, 66, 77, 0x8120, 0x8000, 0x300).is_none());
    assert!(DxgEntryAuthority::new(key, 55, 0, 77, 0x8120, 0x8000, 0x300).is_none());
    assert!(DxgEntryAuthority::new(key, 55, 66, 0, 0x8120, 0x8000, 0x300).is_none());
}

#[test]
fn dxg_registration_policy_marshals_all_three_pointer_arguments() {
    let policy = hosted_dxg_registration_marshal_policy();
    assert_eq!(policy.argument_count, 3);
    assert_eq!(policy.args[0], HostedProviderArgumentMarshal::CallerInDriverObject);
    assert_eq!(policy.args[1], HostedProviderArgumentMarshal::CallerInUnicodeString);
    assert_eq!(policy.args[2], HostedProviderArgumentMarshal::CallerInDxgInitializationData);
    assert_eq!(policy.side_effect, HostedProviderExportSideEffect::DxgRegistration);
    assert_eq!(policy.result_semantics, HostedProviderExportResultSemantics::NtStatus);
}

#[test]
fn driver_entry_bootstrap_object_uses_exact_live_pool_generation() {
    let bootstrap = DxgSourceDriverObject::admit(0, 0x1000, 91, 27).unwrap();
    assert!(bootstrap.matches(0, 0x1000, 91, 27));
    assert!(!bootstrap.matches(0, 0x1000, 92, 27));
    assert!(!bootstrap.matches(0, 0x2000, 91, 27));
    assert!(!bootstrap.matches(0, 0x1000, 91, 28));
    assert!(DxgSourceDriverObject::admit(0x2000, 0x1000, 91, 27).is_none());
    assert!(DxgSourceDriverObject::admit(0, 0, 91, 27).is_none());
    assert!(DxgSourceDriverObject::admit(0, 0x1000, 0, 27).is_none());
    assert!(DxgSourceDriverObject::admit(0, 0x1000, 91, 0).is_none());
}

#[test]
fn pinned_libernt_lifecycle_callbacks_have_explicit_x64_signatures() {
    for version in [0x5022, 0x5023, 0x11007] {
        assert_eq!(DxgDdiSignature::for_offset(version, 0x8), Some(DxgDdiSignature::AddDevice));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x10), Some(DxgDdiSignature::StartDevice));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x18), Some(DxgDdiSignature::StopDevice));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x20), Some(DxgDdiSignature::RemoveDevice));
        assert_eq!(DxgDdiSignature::for_offset(version, 0x28), None);
    }
    assert_eq!(DxgDdiSignature::for_offset(0x11008, 0x8), None);
    assert_eq!(DxgDdiSignature::AddDevice.argument_count(), 2);
    assert_eq!(DxgDdiSignature::StartDevice.argument_count(), 5);
    assert_eq!(DxgDdiSignature::StopDevice.argument_count(), 1);
    assert_eq!(DxgDdiSignature::RemoveDevice.argument_count(), 1);
}

#[test]
fn reverse_add_device_alias_binds_both_pdo_generations_and_canonical_device() {
    let owner = HostedProviderObjectOwner::new(1, 11, 2, 22).unwrap();
    let alias = DxgPdoAliasAuthority::new(owner, 33, 44,
        0x1000, 55, 0x2000, 66).unwrap();
    assert!(alias.matches(owner, 33, 44, 0x1000, 55, 0x2000, 66));
    assert!(!alias.matches(owner, 33, 45, 0x1000, 55, 0x2000, 66));
    assert!(!alias.matches(owner, 33, 44, 0x1000, 56, 0x2000, 66));
    assert!(!alias.matches(owner, 33, 44, 0x1000, 55, 0x2000, 67));
    assert!(!alias.matches(HostedProviderObjectOwner::new(1, 12, 2, 22).unwrap(),
        33, 44, 0x1000, 55, 0x2000, 66));
    assert!(DxgPdoAliasAuthority::new(owner, 33, 44, 0x1000, 55, 0x2000, 0).is_none());
    assert!(DxgPdoAliasAuthority::new(owner, 33, 44, 0x1000, 0, 0x2000, 66).is_none());
}

#[test]
fn pinned_wddm_32_start_interface_is_bounded_and_requires_first_callbacks() {
    let mut interface = vec![0u8; 0x240];
    interface[0..4].copy_from_slice(&0x240u32.to_le_bytes());
    interface[4..8].copy_from_slice(&0x11007u32.to_le_bytes());
    put_callback(&mut interface, 0x8, 0x1000); // provider-owned DeviceHandle
    put_callback(&mut interface, 0x80, 0x2080); // NotifyInterrupt
    put_callback(&mut interface, 0x88, 0x2088); // NotifyDpc
    put_callback(&mut interface, 0x90, 0x2090); // QueryChildRelations
    put_callback(&mut interface, 0xd8, 0x20d8); // AcquirePostDisplayOwnership
    let parsed = DxgStartInterface::parse(&interface).unwrap();
    assert_eq!(parsed.size(), 0x240);
    assert_eq!(parsed.version(), 0x11007);
    assert_eq!(parsed.device_handle(), 0x1000);
    assert_eq!(parsed.callback_at(0xd8), Some(0x20d8));
    assert_eq!(parsed.callback_at(0x240), None);
    assert_eq!(parsed.callbacks().count(), 4);

    let mut bad = interface.clone();
    put_callback(&mut bad, 0x90, 0);
    assert_eq!(DxgStartInterface::parse(&bad), Err(DxgStartInterfaceError::MissingRequired));
    let mut bad = interface.clone();
    put_callback(&mut bad, 0xd8, 0);
    assert_eq!(DxgStartInterface::parse(&bad), Err(DxgStartInterfaceError::MissingRequired));
    let mut bad = interface.clone();
    bad[4..8].copy_from_slice(&0x11008u32.to_le_bytes());
    assert_eq!(DxgStartInterface::parse(&bad), Err(DxgStartInterfaceError::UnknownVersion));
    let mut bad = interface.clone();
    bad[0..4].copy_from_slice(&0x238u32.to_le_bytes());
    assert_eq!(DxgStartInterface::parse(&bad), Err(DxgStartInterfaceError::BadSize));
    assert_eq!(DxgStartInterface::parse(&interface[..0x23f]),
        Err(DxgStartInterfaceError::Truncated));
}

#[test]
fn acquire_post_display_has_exact_two_argument_output_policy() {
    let policy = hosted_dxg_acquire_post_display_marshal_policy();
    assert_eq!(policy.argument_count, 2);
    assert_eq!(policy.args[0], HostedProviderArgumentMarshal::Scalar);
    assert_eq!(policy.args[1], HostedProviderArgumentMarshal::CallerOutFixed { bytes: 32 });
    assert_eq!(policy.side_effect, HostedProviderExportSideEffect::DxgInterfaceCallback);
    assert_eq!(policy.result_semantics, HostedProviderExportResultSemantics::NtStatus);
}
