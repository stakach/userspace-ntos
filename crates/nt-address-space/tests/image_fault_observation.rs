use nt_address_space::ImageFaultObservation;

#[test]
fn x86_fault_observation_preserves_present_independently_of_access_and_mode() {
    for access_and_mode in [0, 2, 4, 6, 0x10, 0x12, 0x14, 0x16] {
        assert_eq!(
            ImageFaultObservation::from_x86_error(access_and_mode),
            ImageFaultObservation::NotPresent,
        );
        assert_eq!(
            ImageFaultObservation::from_x86_error(access_and_mode | 1),
            ImageFaultObservation::Protection,
        );
    }
    assert_ne!(
        ImageFaultObservation::from_x86_error(0),
        ImageFaultObservation::CopyAccess,
    );
}

#[test]
fn x86_reserved_bit_fault_is_never_classified_as_missing_mapping() {
    for error in [8, 9, 0x0c, 0x0d, 0x18, 0x19, 0x1c, 0x1d] {
        assert_eq!(
            ImageFaultObservation::from_x86_error(error),
            ImageFaultObservation::Protection,
        );
    }
}
