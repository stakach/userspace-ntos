use nt_memory_manager::validate_section_creation_parameters;

const INVALID_PARAMETER_6: u32 = 0xc000_00f4;
const INVALID_PAGE_PROTECTION: u32 = 0xc000_0045;
const IMAGE: u32 = 0x0100_0000;
const COMMIT: u32 = 0x0800_0000;
const RESERVE: u32 = 0x0400_0000;
const BASED: u32 = 0x0020_0000;
const NO_CHANGE: u32 = 0x0040_0000;
const NO_CACHE: u32 = 0x1000_0000;

#[test]
fn invalid_allocation_attributes_precede_protection_or_pointer_capture() {
    // NT5 NtCreateSection rejects parameter 6 before probing SectionHandle/MaximumSize.
    for attributes in [0, BASED, IMAGE | COMMIT, IMAGE | RESERVE, IMAGE | NO_CACHE,
        IMAGE | NO_CHANGE, COMMIT | RESERVE, IMAGE | 1, COMMIT | 0x8000_0000] {
        assert_eq!(validate_section_creation_parameters(attributes, 0x02), Err(INVALID_PARAMETER_6));
        assert_eq!(validate_section_creation_parameters(attributes, 0), Err(INVALID_PARAMETER_6));
    }
}

#[test]
fn forbidden_protection_flags_are_rejected_before_user_pointer_capture() {
    // NT5's public entry rejects NOACCESS/GUARD/NOCACHE here; the full
    // MiMakeProtectionMask check runs later, after output/MaximumSize capture.
    for protection in [1, 3, 0x100 | 0x02, 0x200 | 0x02] {
        assert_eq!(validate_section_creation_parameters(IMAGE, protection), Err(INVALID_PAGE_PROTECTION));
    }
}

#[test]
fn full_protection_validation_is_deferred_until_after_pointer_capture() {
    // ReactOS ARM3 follows the same two-stage validation for these values.
    for protection in [0, 0x06] {
        assert_eq!(validate_section_creation_parameters(IMAGE, protection), Ok(()));
        assert_eq!(nt_memory_manager::data_section::data_section_file_access(protection),
            Err(INVALID_PAGE_PROTECTION));
    }
}

#[test]
fn scalar_validation_keeps_all_valid_nt_protections_independent_of_image_kind() {
    for protection in [0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80] {
        for attributes in [IMAGE, IMAGE | BASED, COMMIT, RESERVE, COMMIT | NO_CACHE,
            RESERVE | NO_CHANGE] {
            assert_eq!(validate_section_creation_parameters(attributes, protection), Ok(()));
        }
    }
}
