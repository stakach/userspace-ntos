//! Which owner serves an absolute file name on the installed volume.
//!
//! Before the native block handoff the boot loader's synchronous FAT reader serves the
//! installed-volume spellings it can translate (`\??\C:\...`, `\SystemRoot\...`). Once boot
//! storage drains, or the registry journal owns the writable overlay, the registered
//! mounted-volume Device is the only owner of those names.

use alloc::vec::Vec;

use crate::BlockSourceKind;

/// What the Object Manager resolved an absolute file name to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResolvedFileTarget {
    /// No live registered kernel filesystem Device owns the resolved name.
    Unowned,
    /// The empty device-relative FileName: the volume File itself.
    FilesystemVolume,
    /// A named File (including the root `\`) below a registered kernel filesystem Device.
    FilesystemChild,
}

impl ResolvedFileTarget {
    /// Classify an exact Object Manager resolution. A numeric device identity is not authority:
    /// the caller supplies the live registered kernel-filesystem check for that Device.
    pub fn classify<IsKernelFilesystem>(
        resolved: Option<&Result<(u64, Vec<u16>), u32>>,
        is_kernel_filesystem: IsKernelFilesystem,
    ) -> Self
    where
        IsKernelFilesystem: FnOnce(u64) -> bool,
    {
        match resolved {
            Some(Ok((device_id, remaining))) if is_kernel_filesystem(*device_id) => {
                if remaining.is_empty() {
                    Self::FilesystemVolume
                } else {
                    Self::FilesystemChild
                }
            }
            _ => Self::Unowned,
        }
    }
}

/// The routing facts of one absolute file name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AbsoluteFileName {
    pub target: ResolvedFileTarget,
    /// The name uses an installed-volume spelling the boot reader can translate.
    pub installed_volume_spelling: bool,
}

/// After the handoff starts (or while the registry journal owns the overlay), installed-volume
/// names belong to the mounted Device; the boot reader must not observe or mutate them.
pub fn mounted_volume_owns_installed_names(
    block_route: Option<BlockSourceKind>,
    journal_owns_volume: bool,
) -> bool {
    journal_owns_volume
        || matches!(block_route, Some(BlockSourceKind::Draining | BlockSourceKind::Native))
}

/// Whether an absolute CREATE/open or name query enters the registered mounted-volume Device
/// rather than the boot loader's synchronous reader.
///
/// The boot reader can only translate installed-volume spellings, so any other name resolved
/// onto a registered kernel filesystem (`\Device\<volume>\...`) is served by that Device in
/// every phase. An installed spelling moves to the mounted Device at the handoff even when its
/// resolution failed, so the Object Manager's status reaches the caller instead of a FAT miss.
pub fn absolute_file_routes_to_mounted_volume(
    directory_file: bool,
    name: AbsoluteFileName,
    block_route: Option<BlockSourceKind>,
    journal_owns_volume: bool,
) -> bool {
    if directory_file || name.target == ResolvedFileTarget::FilesystemVolume {
        return true;
    }
    if name.installed_volume_spelling {
        return mounted_volume_owns_installed_names(block_route, journal_owns_volume);
    }
    name.target == ResolvedFileTarget::FilesystemChild
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    const MOUNTED: u64 = 41;
    const PHASES: [Option<BlockSourceKind>; 4] = [
        None,
        Some(BlockSourceKind::Boot),
        Some(BlockSourceKind::Draining),
        Some(BlockSourceKind::Native),
    ];

    fn resolved(device_id: u64, remaining: &str) -> Result<(u64, Vec<u16>), u32> {
        Ok((device_id, remaining.encode_utf16().collect()))
    }

    fn registered(device_id: u64) -> bool {
        device_id == MOUNTED
    }

    fn name(target: ResolvedFileTarget, installed_volume_spelling: bool) -> AbsoluteFileName {
        AbsoluteFileName { target, installed_volume_spelling }
    }

    #[test]
    fn classification_requires_exact_resolution_and_registered_filesystem_authority() {
        use ResolvedFileTarget::*;
        assert_eq!(ResolvedFileTarget::classify(Some(&resolved(MOUNTED, "")), registered),
            FilesystemVolume);
        for remaining in [r"\", r"\reactos\system32\autochk.exe"] {
            assert_eq!(ResolvedFileTarget::classify(Some(&resolved(MOUNTED, remaining)),
                registered), FilesystemChild);
        }
        assert_eq!(ResolvedFileTarget::classify(Some(&resolved(MOUNTED + 1, "")), registered),
            Unowned, "a numeric device identity alone is not a filesystem owner");
        assert_eq!(ResolvedFileTarget::classify(Some(&Err(0xC000_0034)), registered), Unowned);
        assert_eq!(ResolvedFileTarget::classify(None, registered), Unowned);
    }

    #[test]
    fn installed_spellings_stay_on_the_boot_reader_until_the_handoff_or_journal() {
        for target in [ResolvedFileTarget::Unowned, ResolvedFileTarget::FilesystemChild] {
            let installed = name(target, true);
            assert!(!absolute_file_routes_to_mounted_volume(false, installed, None, false));
            assert!(!absolute_file_routes_to_mounted_volume(
                false, installed, Some(BlockSourceKind::Boot), false));
            assert!(absolute_file_routes_to_mounted_volume(
                false, installed, Some(BlockSourceKind::Draining), false));
            assert!(absolute_file_routes_to_mounted_volume(
                false, installed, Some(BlockSourceKind::Native), false));
            assert!(absolute_file_routes_to_mounted_volume(
                false, installed, Some(BlockSourceKind::Boot), true),
                "a journal-owned overlay retains the CREATE on the mounted owner");
        }
    }

    #[test]
    fn directory_files_and_the_volume_file_always_use_the_mounted_device() {
        for phase in PHASES {
            for journal in [false, true] {
                assert!(absolute_file_routes_to_mounted_volume(
                    true, name(ResolvedFileTarget::Unowned, false), phase, journal));
                assert!(absolute_file_routes_to_mounted_volume(
                    false, name(ResolvedFileTarget::FilesystemVolume, false), phase, journal));
            }
        }
    }

    #[test]
    fn device_spelled_children_route_to_their_registered_filesystem_in_every_phase() {
        // `\Device\<volume>\reactos\...` has no boot-reader translation. Once the Object
        // Manager resolved it onto a registered kernel filesystem, only that Device can serve it.
        for phase in PHASES {
            for journal in [false, true] {
                assert!(absolute_file_routes_to_mounted_volume(
                    false, name(ResolvedFileTarget::FilesystemChild, false), phase, journal),
                    "device-spelled child must enter the mounted Device: {phase:?} {journal}");
            }
        }
    }

    #[test]
    fn names_outside_every_filesystem_never_enter_the_mounted_device() {
        for phase in PHASES {
            for journal in [false, true] {
                assert!(!absolute_file_routes_to_mounted_volume(
                    false, name(ResolvedFileTarget::Unowned, false), phase, journal));
            }
        }
    }
}
