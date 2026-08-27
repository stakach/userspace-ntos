//! Typed `IRP_MJ_DIRECTORY_CONTROL` notification parameters.

use nt_types::AccessMask;

pub const IRP_MN_QUERY_DIRECTORY: u8 = 0x01;
pub const IRP_MN_NOTIFY_CHANGE_DIRECTORY: u8 = 0x02;
pub const SL_WATCH_TREE: u8 = 0x01;

pub const FILE_NOTIFY_VALID_MASK: u32 = 0x0000_0fff;
const FILE_LIST_DIRECTORY: u32 = 0x0000_0001;

#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryNotifyParameters {
    pub length: u32,
    pub completion_filter: u32,
}

pub const fn valid_directory_notify_parameters(parameters: DirectoryNotifyParameters) -> bool {
    parameters.completion_filter != 0 && parameters.completion_filter & !FILE_NOTIFY_VALID_MASK == 0
}

pub fn directory_notify_access_granted(granted: AccessMask) -> bool {
    granted.contains(AccessMask::GENERIC_ALL)
        || granted.contains(AccessMask::GENERIC_READ)
        || granted.bits() & FILE_LIST_DIRECTORY != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_filter_and_directory_access() {
        assert!(valid_directory_notify_parameters(
            DirectoryNotifyParameters {
                length: 0,
                completion_filter: 1,
            }
        ));
        assert!(!valid_directory_notify_parameters(
            DirectoryNotifyParameters {
                length: 64,
                completion_filter: 0,
            }
        ));
        assert!(!valid_directory_notify_parameters(
            DirectoryNotifyParameters {
                length: 64,
                completion_filter: 0x1000,
            }
        ));
        assert!(directory_notify_access_granted(
            AccessMask::from_bits_retain(FILE_LIST_DIRECTORY)
        ));
        assert!(!directory_notify_access_granted(AccessMask::GENERIC_WRITE));
    }
}
