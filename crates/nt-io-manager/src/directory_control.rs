//! Typed `IRP_MJ_DIRECTORY_CONTROL` query and notification parameters.

use nt_status::NtStatus;
use nt_types::{AccessMask, UnicodeString};

use crate::{IoParameters, IrpProjection, StackFlags};

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

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DirectoryQueryParameters {
    pub length: u32,
    pub information_class: u32,
    pub file_index: u32,
    pub pattern: Option<UnicodeString>,
}

pub fn valid_directory_query_parameters(parameters: &DirectoryQueryParameters) -> bool {
    parameters
        .pattern
        .as_ref()
        .is_none_or(|pattern| pattern.as_units().len() <= nt_fs::MAX_DIRECTORY_NAME)
}

pub const fn valid_directory_notify_parameters(parameters: DirectoryNotifyParameters) -> bool {
    parameters.completion_filter != 0 && parameters.completion_filter & !FILE_NOTIFY_VALID_MASK == 0
}

pub fn directory_notify_access_granted(granted: AccessMask) -> bool {
    granted.contains(AccessMask::GENERIC_ALL)
        || granted.contains(AccessMask::GENERIC_READ)
        || granted.bits() & FILE_LIST_DIRECTORY != 0
}

/// An admitted `IRP_MN_QUERY_DIRECTORY` on a directory File. A filesystem keeps this owned
/// request across a pending completion and runs it against the File's own cursor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryQueryRequest {
    parameters: DirectoryQueryParameters,
    return_single_entry: bool,
    restart_scan: bool,
}

impl DirectoryQueryRequest {
    /// Admit the exact stack location. Positional (`SL_INDEX_SPECIFIED`) queries are refused
    /// until seek semantics exist; no part of the request is synthesized.
    pub fn admit(
        irp: &IrpProjection,
        is_directory: bool,
        granted_access: u32,
        system_buffer_len: usize,
    ) -> Result<Self, NtStatus> {
        if !is_directory {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if !directory_notify_access_granted(AccessMask::from_bits_retain(granted_access)) {
            return Err(NtStatus::ACCESS_DENIED);
        }
        let IoParameters::QueryDirectory(parameters) = &irp.parameters else {
            return Err(NtStatus::INVALID_PARAMETER);
        };
        if irp.minor != IRP_MN_QUERY_DIRECTORY {
            return Err(NtStatus::INVALID_DEVICE_REQUEST);
        }
        if irp.flags.contains(StackFlags::INDEX_SPECIFIED) || parameters.file_index != 0 {
            return Err(NtStatus::NOT_SUPPORTED);
        }
        if parameters.length as usize > system_buffer_len {
            return Err(NtStatus::INVALID_PARAMETER);
        }
        Ok(Self {
            parameters: parameters.clone(),
            return_single_entry: irp.flags.contains(StackFlags::RETURN_SINGLE_ENTRY),
            restart_scan: irp.flags.contains(StackFlags::RESTART_SCAN),
        })
    }

    /// The caller's output length; the encoder never writes beyond it.
    pub fn length(&self) -> usize {
        self.parameters.length as usize
    }

    /// Encode the next records of a complete directory listing into `output` and advance the
    /// File's cursor. The returned status and information are the IRP's `IoStatus`.
    pub fn query(
        &self,
        cursor: &mut nt_fs::DirectoryQueryState,
        entries: &[nt_fs::DirectoryEntry],
        output: &mut [u8],
    ) -> nt_fs::DirectoryQueryResult {
        let length = self.length().min(output.len());
        nt_fs::query_directory(
            cursor,
            entries,
            self.parameters.information_class,
            self.return_single_entry,
            self.parameters.pattern.as_ref().map(|pattern| pattern.as_units()),
            self.restart_scan,
            &mut output[..length],
        )
    }
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

    #[test]
    fn query_pattern_is_bounded_without_changing_notification_policy() {
        let query = DirectoryQueryParameters {
            length: 512,
            information_class: nt_fs::FILE_BOTH_DIRECTORY_INFORMATION,
            file_index: 4,
            pattern: Some(UnicodeString::from_str("*.dll")),
        };
        assert!(valid_directory_query_parameters(&query));
        let oversized = UnicodeString::from_units(&[b'x' as u16; nt_fs::MAX_DIRECTORY_NAME + 1]);
        assert!(!valid_directory_query_parameters(&DirectoryQueryParameters {
            pattern: Some(oversized),
            ..query
        }));
    }
}
