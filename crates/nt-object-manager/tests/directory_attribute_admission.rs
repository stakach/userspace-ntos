use nt_object_manager::directory::admit_directory_object_attributes;
use nt_status::NtStatus;
use nt_types::AccessMode;

#[test]
fn ordinary_attributes_are_preserved_without_inventing_privilege_authority() {
    for mode in [AccessMode::UserMode, AccessMode::KernelMode] {
        for attributes in [0, 0x2, 0x10, 0x40, 0x80, 0x400, 0x4d2] {
            assert_eq!(
                admit_directory_object_attributes(attributes, mode),
                Ok(attributes)
            );
        }
    }
    // Permanent-object privilege and forced access checks belong to real subject admission.
    assert_eq!(
        admit_directory_object_attributes(0x10 | 0x400, AccessMode::UserMode),
        Ok(0x410)
    );
}

#[test]
fn only_the_actual_kernel_requestor_preserves_kernel_handle_attributes() {
    assert_eq!(
        admit_directory_object_attributes(0x200 | 0x40, AccessMode::KernelMode),
        Ok(0x240)
    );
    assert_eq!(
        admit_directory_object_attributes(0x200 | 0x40, AccessMode::UserMode),
        Ok(0x40)
    );
    assert_eq!(
        admit_directory_object_attributes(0x200 | 0x400, AccessMode::UserMode),
        Ok(0x400)
    );
}

#[test]
fn unknown_bits_and_directory_openlink_are_invalid_before_any_feature_refusal() {
    for mode in [AccessMode::UserMode, AccessMode::KernelMode] {
        for attributes in [
            1,
            4,
            8,
            0x800,
            0x8000_0000,
            0x100,
            0x100 | 0x80,
            0x8000_0000 | 0x20,
            0x8000_0000 | 0x10000,
        ] {
            assert_eq!(
                admit_directory_object_attributes(attributes, mode),
                Err(NtStatus::INVALID_PARAMETER)
            );
        }
    }
}

#[test]
fn exclusive_inherit_combination_is_invalid_not_a_supported_or_deferred_open() {
    for mode in [AccessMode::UserMode, AccessMode::KernelMode] {
        for attributes in [0x22, 0x22 | 0x40, 0x22 | 0x10000] {
            assert_eq!(
                admit_directory_object_attributes(attributes, mode),
                Err(NtStatus::INVALID_PARAMETER)
            );
        }
    }
}

#[test]
fn valid_but_unimplemented_exclusivity_is_honestly_refused() {
    for mode in [AccessMode::UserMode, AccessMode::KernelMode] {
        for attributes in [0x20, 0x20 | 0x40, 0x10020] {
            assert_eq!(
                admit_directory_object_attributes(attributes, mode),
                Err(NtStatus::NOT_SUPPORTED)
            );
        }
    }
    for attributes in [0x10000, 0x10000 | 0x40] {
        assert_eq!(
            admit_directory_object_attributes(attributes, AccessMode::KernelMode),
            Err(NtStatus::NOT_SUPPORTED)
        );
        // ReactOS oblife only applies this recognized extension in KernelMode.
        // NT5 instead rejects it as outside OBJ_VALID_ATTRIBUTES.
        assert_eq!(
            admit_directory_object_attributes(attributes, AccessMode::UserMode),
            Ok(attributes & !0x10000)
        );
    }
}
