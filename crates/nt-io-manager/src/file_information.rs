//! NT File-information operation contracts owned by the I/O Manager.

use nt_types::AccessMask;

const FILE_READ_ATTRIBUTES: u32 = 0x0000_0080;
const FILE_WRITE_DATA: u32 = 0x0000_0002;
const FILE_WRITE_ATTRIBUTES: u32 = 0x0000_0100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GenericGrant {
    None,
    Read,
    Write,
}

/// Minimum buffer and access contract for one valid query/set File-information operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FileInformationContract {
    minimum_length: usize,
    required_access: u32,
    generic_grant: GenericGrant,
}

impl FileInformationContract {
    const fn new(minimum_length: usize, required_access: u32, generic_grant: GenericGrant) -> Self {
        Self {
            minimum_length,
            required_access,
            generic_grant,
        }
    }

    pub const fn minimum_length(self) -> usize {
        self.minimum_length
    }

    pub const fn required_access(self) -> AccessMask {
        AccessMask::from_bits_retain(self.required_access)
    }

    /// Check an already-granted process File handle mask against this operation contract.
    pub fn access_granted(self, granted: AccessMask) -> bool {
        if self.required_access == 0 {
            return true;
        }
        if granted.contains(AccessMask::GENERIC_ALL) {
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

const fn query(minimum_length: usize, required_access: u32) -> FileInformationContract {
    FileInformationContract::new(
        minimum_length,
        required_access,
        if required_access == FILE_READ_ATTRIBUTES {
            GenericGrant::Read
        } else {
            GenericGrant::None
        },
    )
}

const fn set(minimum_length: usize, required_access: u32) -> FileInformationContract {
    FileInformationContract::new(
        minimum_length,
        required_access,
        if required_access != 0 && required_access != AccessMask::DELETE.bits() {
            GenericGrant::Write
        } else {
            GenericGrant::None
        },
    )
}

/// Return the native NT query contract, or `None` when this class is not valid for
/// `NtQueryInformationFile`.
pub const fn query_information_contract(class: u32) -> Option<FileInformationContract> {
    Some(match class {
        4 => query(40, FILE_READ_ATTRIBUTES),   // FileBasicInformation
        5 => query(24, 0),                      // FileStandardInformation
        6 => query(8, 0),                       // FileInternalInformation
        7 => query(4, 0),                       // FileEaInformation
        8 => query(4, 0),                       // FileAccessInformation
        9 => query(8, 0),                       // FileNameInformation
        14 => query(8, 0),                      // FilePositionInformation
        16 => query(4, 0),                      // FileModeInformation
        17 => query(4, 0),                      // FileAlignmentInformation
        18 => query(104, FILE_READ_ATTRIBUTES), // FileAllInformation
        21 => query(8, 0),                      // FileAlternateNameInformation
        22 => query(32, 0),                     // FileStreamInformation
        23 => query(8, FILE_READ_ATTRIBUTES),   // FilePipeInformation
        24 => query(40, FILE_READ_ATTRIBUTES),  // FilePipeLocalInformation
        25 => query(16, FILE_READ_ATTRIBUTES),  // FilePipeRemoteInformation
        26 => query(24, 0),                     // FileMailslotQueryInformation
        28 => query(16, 0),                     // FileCompressionInformation
        29 => query(72, 0),                     // FileObjectIdInformation
        32 => query(56, 0),                     // FileQuotaInformation
        33 => query(16, 0),                     // FileReparsePointInformation
        34 => query(56, FILE_READ_ATTRIBUTES),  // FileNetworkOpenInformation
        35 => query(8, FILE_READ_ATTRIBUTES),   // FileAttributeTagInformation
        // Later classes already implemented by this kernel.
        41 => query(4, 0), // FileIoCompletionNotificationInformation
        _ => return None,
    })
}

/// Return the native NT set contract, or `None` when this class is not valid for
/// `NtSetInformationFile`.
pub const fn set_information_contract(class: u32) -> Option<FileInformationContract> {
    Some(match class {
        4 => set(40, FILE_WRITE_ATTRIBUTES),      // FileBasicInformation
        10 => set(24, AccessMask::DELETE.bits()), // FileRenameInformation
        11 => set(24, 0),                         // FileLinkInformation
        13 => set(1, AccessMask::DELETE.bits()),  // FileDispositionInformation
        14 => set(8, 0),                          // FilePositionInformation
        16 => set(4, 0),                          // FileModeInformation
        19 => set(8, FILE_WRITE_DATA),            // FileAllocationInformation
        20 => set(8, FILE_WRITE_DATA),            // FileEndOfFileInformation
        23 => set(8, FILE_WRITE_ATTRIBUTES),      // FilePipeInformation
        27 => set(8, 0),                          // FileMailslotSetInformation
        29 => set(72, 0),                         // FileObjectIdInformation
        30 => set(16, 0),                         // FileCompletionInformation
        31 => set(24, FILE_WRITE_DATA),           // FileMoveClusterInformation
        32 => set(56, 0),                         // FileQuotaInformation
        36 => set(16, FILE_WRITE_DATA),           // FileTrackingInformation
        39 => set(8, FILE_WRITE_DATA),            // FileValidDataLengthInformation
        40 => set(16, AccessMask::DELETE.bits()), // FileShortNameInformation
        // Later classes already implemented by this kernel.
        41 => set(4, 0), // FileIoCompletionNotificationInformation
        64 => set(4, AccessMask::DELETE.bits()), // FileDispositionInformationEx
        _ => return None,
    })
}

/// Compatibility wrapper for existing I/O Manager dispatch validation.
pub fn set_information_access_granted(granted: AccessMask, information_class: u32) -> bool {
    set_information_contract(information_class)
        .is_some_and(|contract| contract.access_granted(granted))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_contract_matches_nt5_lengths_and_access() {
        let basic = query_information_contract(4).unwrap();
        assert_eq!(basic.minimum_length(), 40);
        assert_eq!(basic.required_access().bits(), FILE_READ_ATTRIBUTES);
        assert!(basic.access_granted(AccessMask::GENERIC_READ));
        assert!(!basic.access_granted(AccessMask::empty()));

        let all = query_information_contract(18).unwrap();
        assert_eq!(all.minimum_length(), 104);
        assert!(!all.access_granted(AccessMask::GENERIC_WRITE));
        assert!(all.access_granted(AccessMask::GENERIC_ALL));

        assert_eq!(query_information_contract(22).unwrap().minimum_length(), 32);
        assert_eq!(query_information_contract(29).unwrap().minimum_length(), 72);
        assert_eq!(query_information_contract(33).unwrap().minimum_length(), 16);
    }

    #[test]
    fn query_contract_rejects_set_only_and_directory_classes() {
        for class in [
            0, 1, 2, 3, 10, 11, 12, 13, 15, 19, 20, 27, 30, 31, 36, 39, 40, 64,
        ] {
            assert_eq!(query_information_contract(class), None, "class {class}");
        }
    }

    #[test]
    fn set_contract_matches_nt5_lengths_and_access() {
        let rename = set_information_contract(10).unwrap();
        assert_eq!(rename.minimum_length(), 24);
        assert!(rename.access_granted(AccessMask::DELETE));
        assert!(!rename.access_granted(AccessMask::GENERIC_WRITE));

        let eof = set_information_contract(20).unwrap();
        assert_eq!(eof.minimum_length(), 8);
        assert!(eof.access_granted(AccessMask::GENERIC_WRITE));
        assert!(!eof.access_granted(AccessMask::GENERIC_READ));

        let link = set_information_contract(11).unwrap();
        assert!(link.access_granted(AccessMask::empty()));
        assert_eq!(set_information_contract(64).unwrap().minimum_length(), 4);
    }

    #[test]
    fn set_contract_rejects_query_only_and_unknown_classes() {
        for class in [
            0,
            5,
            6,
            7,
            8,
            9,
            12,
            15,
            17,
            18,
            21,
            22,
            24,
            25,
            26,
            28,
            33,
            34,
            35,
            42,
            u32::MAX,
        ] {
            assert_eq!(set_information_contract(class), None, "class {class}");
            assert!(!set_information_access_granted(
                AccessMask::GENERIC_ALL,
                class
            ));
        }
    }
}
