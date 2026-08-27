//! NT volume-information operation contracts owned by the I/O Manager.

use nt_types::AccessMask;

const FILE_READ_DATA: u32 = 0x0000_0001;
const FILE_WRITE_DATA: u32 = 0x0000_0002;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenericGrant {
    None,
    Read,
    Write,
}

/// Minimum buffer, alignment, and access contract for one volume-information operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VolumeInformationContract {
    minimum_length: usize,
    alignment: usize,
    required_access: u32,
    generic_grant: GenericGrant,
}

impl VolumeInformationContract {
    const fn new(
        minimum_length: usize,
        alignment: usize,
        required_access: u32,
        generic_grant: GenericGrant,
    ) -> Self {
        Self {
            minimum_length,
            alignment,
            required_access,
            generic_grant,
        }
    }

    pub const fn minimum_length(self) -> usize {
        self.minimum_length
    }

    pub const fn alignment(self) -> usize {
        self.alignment
    }

    pub const fn required_access(self) -> AccessMask {
        AccessMask::from_bits_retain(self.required_access)
    }

    pub fn access_granted(self, granted: AccessMask) -> bool {
        if self.required_access == 0 || granted.contains(AccessMask::GENERIC_ALL) {
            return true;
        }
        match self.generic_grant {
            GenericGrant::Read if granted.contains(AccessMask::GENERIC_READ) => return true,
            GenericGrant::Write if granted.contains(AccessMask::GENERIC_WRITE) => return true,
            GenericGrant::None | GenericGrant::Read | GenericGrant::Write => {}
        }
        granted.bits() & self.required_access == self.required_access
    }
}

const fn query(
    minimum_length: usize,
    alignment: usize,
    required_access: u32,
) -> VolumeInformationContract {
    VolumeInformationContract::new(
        minimum_length,
        alignment,
        required_access,
        if required_access == FILE_READ_DATA {
            GenericGrant::Read
        } else {
            GenericGrant::None
        },
    )
}

const fn set(
    minimum_length: usize,
    alignment: usize,
    required_access: u32,
) -> VolumeInformationContract {
    VolumeInformationContract::new(
        minimum_length,
        alignment,
        required_access,
        if required_access == FILE_WRITE_DATA {
            GenericGrant::Write
        } else {
            GenericGrant::None
        },
    )
}

/// Return the NT5 query contract for `FS_INFORMATION_CLASS`, or `None` for a
/// class that `NtQueryVolumeInformationFile` rejects before dispatch.
pub const fn query_volume_information_contract(class: u32) -> Option<VolumeInformationContract> {
    Some(match class {
        1 => query(24, 8, 0),              // FileFsVolumeInformation
        3 => query(24, 8, 0),              // FileFsSizeInformation
        4 => query(8, 4, 0),               // FileFsDeviceInformation
        5 => query(16, 4, 0),              // FileFsAttributeInformation
        6 => query(48, 8, FILE_READ_DATA), // FileFsControlInformation
        7 => query(32, 8, 0),              // FileFsFullSizeInformation
        8 => query(64, 8, 0),              // FileFsObjectIdInformation
        9 => query(12, 8, 0),              // FileFsDriverPathInformation
        _ => return None,
    })
}

/// Return the NT5 set contract for `FS_INFORMATION_CLASS`, or `None` for a
/// class that `NtSetVolumeInformationFile` rejects before dispatch.
pub const fn set_volume_information_contract(class: u32) -> Option<VolumeInformationContract> {
    Some(match class {
        2 => set(8, 4, FILE_WRITE_DATA),  // FileFsLabelInformation
        6 => set(48, 8, FILE_WRITE_DATA), // FileFsControlInformation
        8 => set(64, 8, FILE_WRITE_DATA), // FileFsObjectIdInformation
        _ => return None,
    })
}

/// Captured `IRP_MJ_QUERY_VOLUME_INFORMATION` stack parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct QueryVolumeInformationParameters {
    pub information_class: u32,
    pub length: u32,
}

/// Captured `IRP_MJ_SET_VOLUME_INFORMATION` stack parameters.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct SetVolumeInformationParameters {
    pub information_class: u32,
    pub length: u32,
}

/// Validate class-specific fields in captured set-volume input.
pub fn validate_set_volume_information(class: u32, input: &[u8]) -> bool {
    let Some(contract) = set_volume_information_contract(class) else {
        return false;
    };
    if input.len() < contract.minimum_length() {
        return false;
    }
    if class == 2 {
        let label_length = u32::from_le_bytes(input[0..4].try_into().unwrap());
        let extent_valid = (label_length as usize)
            .checked_add(4)
            .is_some_and(|length| length <= input.len());
        if (label_length as i32) < 0 || label_length & 1 != 0 || !extent_valid {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_contract_matches_nt5_tables() {
        let expected = [
            (1, 24, 8, 0),
            (3, 24, 8, 0),
            (4, 8, 4, 0),
            (5, 16, 4, 0),
            (6, 48, 8, FILE_READ_DATA),
            (7, 32, 8, 0),
            (8, 64, 8, 0),
            (9, 12, 8, 0),
        ];
        for (class, length, alignment, access) in expected {
            let contract = query_volume_information_contract(class).unwrap();
            assert_eq!(contract.minimum_length(), length);
            assert_eq!(contract.alignment(), alignment);
            assert_eq!(contract.required_access().bits(), access);
        }
        assert_eq!(query_volume_information_contract(2), None);
        assert_eq!(query_volume_information_contract(10), None);
    }

    #[test]
    fn set_contract_matches_nt5_tables_and_access() {
        for (class, length, alignment) in [(2, 8, 4), (6, 48, 8), (8, 64, 8)] {
            let contract = set_volume_information_contract(class).unwrap();
            assert_eq!(contract.minimum_length(), length);
            assert_eq!(contract.alignment(), alignment);
            assert_eq!(contract.required_access().bits(), FILE_WRITE_DATA);
            assert!(contract.access_granted(AccessMask::GENERIC_WRITE));
            assert!(!contract.access_granted(AccessMask::GENERIC_READ));
        }
        assert_eq!(set_volume_information_contract(1), None);
        assert_eq!(set_volume_information_contract(9), None);
    }

    #[test]
    fn query_control_requires_volume_read_access() {
        let contract = query_volume_information_contract(6).unwrap();
        assert!(contract.access_granted(AccessMask::GENERIC_READ));
        assert!(contract.access_granted(AccessMask::from_bits_retain(FILE_READ_DATA)));
        assert!(!contract.access_granted(AccessMask::GENERIC_WRITE));
        assert!(query_volume_information_contract(4)
            .unwrap()
            .access_granted(AccessMask::empty()));
    }

    #[test]
    fn validates_captured_volume_label_extent() {
        let mut input = alloc::vec![0u8; 10];
        input[0..4].copy_from_slice(&6u32.to_le_bytes());
        assert!(validate_set_volume_information(2, &input));

        input[0..4].copy_from_slice(&7u32.to_le_bytes());
        assert!(!validate_set_volume_information(2, &input));
        input[0..4].copy_from_slice(&0x8000_0000u32.to_le_bytes());
        assert!(!validate_set_volume_information(2, &input));
        assert!(!validate_set_volume_information(2, &[0; 7]));
        assert!(validate_set_volume_information(6, &[0; 48]));
        assert!(!validate_set_volume_information(5, &[0; 48]));
    }
}
