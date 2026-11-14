//! `IRP_MJ_SET_INFORMATION` policy across the installed (immutable) and writable layers of one
//! volume, for the classes vfatfs serves besides rename (`layered_rename` decides that one).
//!
//! The writable filesystem owns every mutation and validates each class for its own Files. This
//! module only decides what the layering adds: a File the installed image backs cannot change,
//! and a name the installed image also holds cannot be deleted without a whiteout.

use crate::{
    BasicInformationChange, FILE_ALLOCATION_INFORMATION, FILE_BASIC_INFORMATION,
    FILE_DISPOSITION_INFORMATION, FILE_END_OF_FILE_INFORMATION, FILE_POSITION_INFORMATION,
    STATUS_ACCESS_DENIED, STATUS_INFO_LENGTH_MISMATCH, STATUS_INVALID_DEVICE_REQUEST,
    STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED,
};

/// Which layer holds the File a request names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayeredFileBacking {
    /// The volume itself, opened by its device name.
    Volume,
    /// An entry of the immutable installed image.
    Installed,
    /// A node of the writable filesystem.
    Writable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayeredSetInformation {
    pub class: u32,
    pub backing: LayeredFileBacking,
    pub is_directory: bool,
    /// An installed entry also exists under the File's name. Always true for an installed File.
    pub shadows_installed: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayeredSetInformationAction {
    /// The writable filesystem validates and applies the request to its own File.
    Writable,
    /// Move the byte offset the installed File's own open keeps.
    InstalledPosition(u64),
    /// The request asks for no change, so the immutable File already satisfies it.
    Unchanged,
}

/// Decide one set-information request. Statuses follow vfatfs `VfatSetInformation`: a class it
/// does not serve is `STATUS_NOT_SUPPORTED`. The same status marks what this volume cannot yet
/// do to an installed name; such a request is refused, never reported as done.
pub fn layered_set_information_decision(
    request: LayeredSetInformation,
    payload: &[u8],
) -> Result<LayeredSetInformationAction, u32> {
    use LayeredFileBacking::{Installed, Volume, Writable};
    use LayeredSetInformationAction as Action;

    let minimum = match request.class {
        FILE_BASIC_INFORMATION => 40,
        FILE_DISPOSITION_INFORMATION => 1,
        FILE_POSITION_INFORMATION | FILE_ALLOCATION_INFORMATION | FILE_END_OF_FILE_INFORMATION => 8,
        _ => return Err(STATUS_NOT_SUPPORTED),
    };
    if request.backing == Volume {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if payload.len() < minimum {
        return Err(STATUS_INFO_LENGTH_MISMATCH);
    }
    match (request.class, request.backing) {
        (FILE_DISPOSITION_INFORMATION, backing) => {
            let delete = payload[0] != 0;
            match (delete, backing) {
                // Deleting the writable entry would let the installed one reappear.
                (true, _) if request.shadows_installed || backing == Installed => {
                    Err(STATUS_NOT_SUPPORTED)
                }
                // An installed File is never delete-pending.
                (false, Installed) => Ok(Action::Unchanged),
                _ => Ok(Action::Writable),
            }
        }
        (_, Writable) => Ok(Action::Writable),
        (FILE_BASIC_INFORMATION, _) => {
            if BasicInformationChange::parse(payload, request.is_directory)?.is_empty() {
                Ok(Action::Unchanged)
            } else {
                Err(STATUS_NOT_SUPPORTED)
            }
        }
        (FILE_POSITION_INFORMATION, _) if !request.is_directory => Ok(Action::InstalledPosition(
            u64::from_le_bytes(payload[..8].try_into().unwrap()),
        )),
        // An installed directory's open keeps no byte offset.
        (FILE_POSITION_INFORMATION, _) => Err(STATUS_INVALID_PARAMETER),
        // Sizes: a directory has none to set, and an installed file was not opened for writing.
        _ if request.is_directory => Err(STATUS_INVALID_DEVICE_REQUEST),
        _ => Err(STATUS_ACCESS_DENIED),
    }
}

/// Remembers which refusals a volume already reported, so a boot log names each distinct gap
/// once however often a caller retries it. A full ledger reports nothing further.
#[derive(Clone, Copy, Debug)]
pub struct RefusalLedger<const CAP: usize> {
    seen: [(u32, u32); CAP],
    len: usize,
}

impl<const CAP: usize> Default for RefusalLedger<CAP> {
    fn default() -> Self {
        Self { seen: [(0, 0); CAP], len: 0 }
    }
}

impl<const CAP: usize> RefusalLedger<CAP> {
    /// True the first time this `(class, status)` pair is recorded.
    pub fn first_report(&mut self, class: u32, status: u32) -> bool {
        if self.len == CAP || self.seen[..self.len].contains(&(class, status)) {
            return false;
        }
        self.seen[self.len] = (class, status);
        self.len += 1;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        FILE_ATTRIBUTE_HIDDEN, FILE_LINK_INFORMATION, FILE_RENAME_INFORMATION,
        FILE_SHORT_NAME_INFORMATION,
    };
    use LayeredFileBacking::{Installed, Volume, Writable};
    use LayeredSetInformationAction as Action;

    fn request(class: u32, backing: LayeredFileBacking) -> LayeredSetInformation {
        LayeredSetInformation {
            class,
            backing,
            is_directory: false,
            shadows_installed: backing == Installed,
        }
    }

    fn basic(last_write_time: u64, attributes: u32) -> [u8; 40] {
        let mut data = [0u8; 40];
        data[16..24].copy_from_slice(&last_write_time.to_le_bytes());
        data[32..36].copy_from_slice(&attributes.to_le_bytes());
        data
    }

    const SERVED: [u32; 5] = [
        FILE_BASIC_INFORMATION,
        FILE_DISPOSITION_INFORMATION,
        FILE_POSITION_INFORMATION,
        FILE_ALLOCATION_INFORMATION,
        FILE_END_OF_FILE_INFORMATION,
    ];

    #[test]
    fn the_writable_filesystem_applies_every_served_class_to_its_own_file() {
        for class in SERVED {
            for is_directory in [false, true] {
                assert_eq!(
                    layered_set_information_decision(
                        LayeredSetInformation { is_directory, ..request(class, Writable) },
                        &[0u8; 40],
                    ),
                    Ok(Action::Writable),
                    "class {class}"
                );
            }
        }
    }

    #[test]
    fn a_class_vfatfs_does_not_serve_is_not_supported() {
        for class in [
            FILE_LINK_INFORMATION,
            FILE_SHORT_NAME_INFORMATION,
            // Rename has its own decision and never reaches this one.
            FILE_RENAME_INFORMATION,
            0,
            99,
        ] {
            for backing in [Volume, Installed, Writable] {
                assert_eq!(
                    layered_set_information_decision(request(class, backing), &[0u8; 64]),
                    Err(STATUS_NOT_SUPPORTED)
                );
            }
        }
    }

    #[test]
    fn the_volume_file_has_no_file_information_to_set() {
        for class in SERVED {
            assert_eq!(
                layered_set_information_decision(request(class, Volume), &[0u8; 40]),
                Err(STATUS_INVALID_PARAMETER)
            );
        }
    }

    #[test]
    fn a_short_buffer_is_refused_before_it_is_read() {
        for (class, minimum) in SERVED.into_iter().zip([40usize, 1, 8, 8, 8]) {
            assert_eq!(
                layered_set_information_decision(request(class, Writable), &[1u8; 40][..minimum - 1]),
                Err(STATUS_INFO_LENGTH_MISMATCH)
            );
        }
    }

    #[test]
    fn deleting_a_name_the_installed_image_holds_is_refused_not_faked() {
        // The writable copy of an installed file, and a directory materialised over one.
        for is_directory in [false, true] {
            assert_eq!(
                layered_set_information_decision(
                    LayeredSetInformation {
                        is_directory,
                        shadows_installed: true,
                        ..request(FILE_DISPOSITION_INFORMATION, Writable)
                    },
                    &[1],
                ),
                Err(STATUS_NOT_SUPPORTED)
            );
        }
        assert_eq!(
            layered_set_information_decision(request(FILE_DISPOSITION_INFORMATION, Installed), &[1]),
            Err(STATUS_NOT_SUPPORTED)
        );
    }

    #[test]
    fn clearing_a_delete_is_always_possible() {
        assert_eq!(
            layered_set_information_decision(
                LayeredSetInformation {
                    shadows_installed: true,
                    ..request(FILE_DISPOSITION_INFORMATION, Writable)
                },
                &[0],
            ),
            Ok(Action::Writable)
        );
        assert_eq!(
            layered_set_information_decision(request(FILE_DISPOSITION_INFORMATION, Installed), &[0]),
            Ok(Action::Unchanged)
        );
    }

    #[test]
    fn an_installed_file_accepts_only_a_basic_information_that_changes_nothing() {
        let installed = request(FILE_BASIC_INFORMATION, Installed);
        assert_eq!(
            layered_set_information_decision(installed, &basic(0, 0)),
            Ok(Action::Unchanged)
        );
        assert_eq!(
            layered_set_information_decision(installed, &basic(u64::MAX, 0)),
            Ok(Action::Unchanged)
        );
        assert_eq!(
            layered_set_information_decision(installed, &basic(300, 0)),
            Err(STATUS_NOT_SUPPORTED)
        );
        assert_eq!(
            layered_set_information_decision(
                LayeredSetInformation { is_directory: true, ..installed },
                &basic(0, FILE_ATTRIBUTE_HIDDEN),
            ),
            Err(STATUS_NOT_SUPPORTED)
        );
        // A request that is invalid for the File's kind is invalid before it is unsupported.
        assert_eq!(
            layered_set_information_decision(installed, &basic(0, crate::FILE_ATTRIBUTE_DIRECTORY)),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn an_installed_file_keeps_its_own_position() {
        assert_eq!(
            layered_set_information_decision(
                request(FILE_POSITION_INFORMATION, Installed),
                &0x1234u64.to_le_bytes(),
            ),
            Ok(Action::InstalledPosition(0x1234))
        );
        assert_eq!(
            layered_set_information_decision(
                LayeredSetInformation {
                    is_directory: true,
                    ..request(FILE_POSITION_INFORMATION, Installed)
                },
                &0u64.to_le_bytes(),
            ),
            Err(STATUS_INVALID_PARAMETER)
        );
    }

    #[test]
    fn an_installed_file_cannot_be_resized() {
        for class in [FILE_ALLOCATION_INFORMATION, FILE_END_OF_FILE_INFORMATION] {
            assert_eq!(
                layered_set_information_decision(request(class, Installed), &0u64.to_le_bytes()),
                Err(STATUS_ACCESS_DENIED)
            );
            assert_eq!(
                layered_set_information_decision(
                    LayeredSetInformation { is_directory: true, ..request(class, Installed) },
                    &0u64.to_le_bytes(),
                ),
                Err(STATUS_INVALID_DEVICE_REQUEST)
            );
        }
    }

    #[test]
    fn a_refusal_is_reported_once_and_the_ledger_is_bounded() {
        let mut ledger = RefusalLedger::<2>::default();
        assert!(ledger.first_report(4, STATUS_NOT_SUPPORTED));
        assert!(!ledger.first_report(4, STATUS_NOT_SUPPORTED));
        assert!(ledger.first_report(4, STATUS_ACCESS_DENIED));
        assert!(!ledger.first_report(13, STATUS_NOT_SUPPORTED));
        assert!(!ledger.first_report(4, STATUS_ACCESS_DENIED));
    }
}
