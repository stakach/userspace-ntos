//! Pinned LiberNT 8e478a22a1e8f8a22bab17131f3184a7b4548c3d display registration ABI.
//!
//! `drivers/directx/dxgkrnl/adapter.c` derives an append-only table prefix from
//! the DDI selector; `sdk/lib/drivers/displib/displib.c` calls its resolved
//! entry with the caller's driver object, registry path, and callback table.

use nt_hosted_runtime::{
    hosted_dxg_registration_marshal_policy, DxgEntryAuthority, DxgInitializationData,
    DxgInitializationDataError, DxgRegistrationKey, DxgSourceDriverObject, DxgDdiSignature,
    HostedProviderArgumentMarshal,
    HostedProviderExportResultSemantics, HostedProviderExportSideEffect, HostedProviderObjectOwner,
};

fn table(version: u32, size: usize) -> Vec<u8> {
    let mut bytes = vec![0; size];
    bytes[..4].copy_from_slice(&version.to_le_bytes());
    bytes
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
