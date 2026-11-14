//! Rename policy across the installed (immutable) and writable layers of one volume.
//!
//! The writable layer owns every namespace mutation. The installed layer can only be shadowed,
//! never edited, so a rename is decided here before the writable filesystem moves an entry.

use crate::{
    LayeredDirectoryOpenDecision, FILE_DOES_NOT_EXIST, FILE_EXISTS, STATUS_ACCESS_DENIED,
    STATUS_INVALID_PARAMETER, STATUS_NOT_SUPPORTED, STATUS_OBJECT_NAME_COLLISION,
    STATUS_OBJECT_PATH_NOT_FOUND,
};

/// Split a canonical volume-relative name into the directory that holds its final component and
/// that component. The volume root has no containing directory, as in FASTFAT's target open.
pub fn rename_target_parent(relative: &[u8]) -> Result<(&[u8], &[u8]), u32> {
    if relative.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(match relative.iter().rposition(|byte| *byte == b'\\') {
        Some(separator) => (&relative[..separator], &relative[separator + 1..]),
        None => (&[], relative),
    })
}

/// The UTF-16 form of [`rename_target_parent`], for the caller's exact spelling of the name.
pub fn rename_target_parent_units(name: &[u16]) -> Result<(&[u16], &[u16]), u32> {
    const SEPARATOR: u16 = b'\\' as u16;
    let name = name.strip_prefix(&[SEPARATOR]).unwrap_or(name);
    let name = name.strip_suffix(&[SEPARATOR]).unwrap_or(name);
    if name.is_empty() {
        return Err(STATUS_INVALID_PARAMETER);
    }
    Ok(match name.iter().rposition(|unit| *unit == SEPARATOR) {
        Some(separator) => (&name[..separator], &name[separator + 1..]),
        None => (&[], name),
    })
}

/// Result of an `SL_OPEN_TARGET_DIRECTORY` CREATE: which layer backs the opened parent, and the
/// `IoStatus.Information` that tells the I/O Manager whether the final component exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TargetDirectoryOpen {
    pub backing: LayeredDirectoryOpenDecision,
    pub information: u32,
}

/// Open the directory that holds a rename or link target. Each parent argument is
/// `Some(is_directory)` for an entry in that layer; the writable entry shadows the installed one.
/// A missing final component is reported, never failed: only the parent has to exist.
pub fn layered_target_directory_open(
    installed_parent: Option<bool>,
    overlay_parent: Option<bool>,
    installed_target: bool,
    overlay_target: bool,
) -> Result<TargetDirectoryOpen, u32> {
    let backing = match (overlay_parent, installed_parent) {
        (Some(true), _) => LayeredDirectoryOpenDecision::Overlay,
        (None, Some(true)) => LayeredDirectoryOpenDecision::Installed,
        // A missing parent and a parent that is a file both leave the path unresolved.
        _ => return Err(STATUS_OBJECT_PATH_NOT_FOUND),
    };
    Ok(TargetDirectoryOpen {
        backing,
        information: if installed_target || overlay_target {
            FILE_EXISTS
        } else {
            FILE_DOES_NOT_EXIST
        },
    })
}

/// The installed-layer facts a rename needs. The writable filesystem decides everything about
/// its own entries, including a writable target that shadows an installed one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayeredRename {
    /// The source File is backed by a writable entry.
    pub source_in_overlay: bool,
    /// An installed entry also exists under the source's current name.
    pub source_shadows_installed: bool,
    pub source_is_directory: bool,
    /// `Some(is_directory)` when an installed entry holds the target name and no writable entry
    /// shadows it.
    pub installed_target: Option<bool>,
    /// That installed target currently has an open File.
    pub installed_target_open: bool,
    pub replace_if_exists: bool,
}

/// Decide a rename against the installed layer. Moving a name away from an installed entry would
/// need a whiteout to keep it hidden; without one the old name would reappear, so it is refused
/// rather than reported as moved. Target statuses match the writable filesystem's own.
pub fn layered_rename_decision(rename: LayeredRename) -> Result<(), u32> {
    if !rename.source_in_overlay || rename.source_shadows_installed {
        return Err(STATUS_NOT_SUPPORTED);
    }
    let Some(target_is_directory) = rename.installed_target else {
        return Ok(());
    };
    if !rename.replace_if_exists {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    if rename.source_is_directory || target_is_directory || rename.installed_target_open {
        return Err(STATUS_ACCESS_DENIED);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn overlay_file() -> LayeredRename {
        LayeredRename {
            source_in_overlay: true,
            source_shadows_installed: false,
            source_is_directory: false,
            installed_target: None,
            installed_target_open: false,
            replace_if_exists: false,
        }
    }

    #[test]
    fn target_name_splits_into_holding_directory_and_final_component() {
        assert_eq!(
            rename_target_parent(b"users\\default\\ntuser.bak"),
            Ok((b"users\\default".as_slice(), b"ntuser.bak".as_slice()))
        );
        assert_eq!(
            rename_target_parent(b"bootstat.bak"),
            Ok((b"".as_slice(), b"bootstat.bak".as_slice()))
        );
        assert_eq!(rename_target_parent(b""), Err(STATUS_INVALID_PARAMETER));

        let wide = |text: &str| text.encode_utf16().collect::<alloc::vec::Vec<u16>>();
        let name = wide("\\Users\\Default\\NTUSER.bak");
        let (parent, leaf) = rename_target_parent_units(&name).unwrap();
        assert_eq!((parent, leaf), (&wide("Users\\Default")[..], &wide("NTUSER.bak")[..]));
        let root_level = wide("\\NTUSER.bak");
        assert_eq!(
            rename_target_parent_units(&root_level),
            Ok((&[][..], &wide("NTUSER.bak")[..]))
        );
        assert_eq!(rename_target_parent_units(&wide("\\")), Err(STATUS_INVALID_PARAMETER));
    }

    #[test]
    fn target_directory_open_never_fails_for_a_missing_final_component() {
        assert_eq!(
            layered_target_directory_open(Some(true), Some(true), false, false),
            Ok(TargetDirectoryOpen {
                backing: LayeredDirectoryOpenDecision::Overlay,
                information: FILE_DOES_NOT_EXIST,
            })
        );
        assert_eq!(
            layered_target_directory_open(Some(true), None, false, false),
            Ok(TargetDirectoryOpen {
                backing: LayeredDirectoryOpenDecision::Installed,
                information: FILE_DOES_NOT_EXIST,
            })
        );
    }

    #[test]
    fn target_directory_open_reports_an_existing_final_component_in_either_layer() {
        for (installed, overlay) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                layered_target_directory_open(None, Some(true), installed, overlay)
                    .map(|open| open.information),
                Ok(FILE_EXISTS)
            );
        }
    }

    #[test]
    fn target_directory_open_requires_a_directory_parent() {
        assert_eq!(
            layered_target_directory_open(None, None, false, false),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        assert_eq!(
            layered_target_directory_open(Some(false), None, false, false),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
        // A writable file shadows an installed directory of the same name.
        assert_eq!(
            layered_target_directory_open(Some(true), Some(false), false, false),
            Err(STATUS_OBJECT_PATH_NOT_FOUND)
        );
    }

    #[test]
    fn writable_source_renames_onto_a_name_the_installed_layer_does_not_hold() {
        assert_eq!(layered_rename_decision(overlay_file()), Ok(()));
        assert_eq!(
            layered_rename_decision(LayeredRename { replace_if_exists: true, ..overlay_file() }),
            Ok(())
        );
    }

    #[test]
    fn installed_target_collides_without_replace_and_is_shadowed_with_it() {
        let onto_installed = LayeredRename { installed_target: Some(false), ..overlay_file() };
        assert_eq!(layered_rename_decision(onto_installed), Err(STATUS_OBJECT_NAME_COLLISION));
        assert_eq!(
            layered_rename_decision(LayeredRename { replace_if_exists: true, ..onto_installed }),
            Ok(())
        );
    }

    #[test]
    fn installed_target_that_is_open_or_a_directory_is_not_replaced() {
        let replace = LayeredRename {
            installed_target: Some(false),
            replace_if_exists: true,
            ..overlay_file()
        };
        assert_eq!(
            layered_rename_decision(LayeredRename { installed_target_open: true, ..replace }),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            layered_rename_decision(LayeredRename { installed_target: Some(true), ..replace }),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            layered_rename_decision(LayeredRename { source_is_directory: true, ..replace }),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    #[test]
    fn a_name_held_by_the_installed_layer_cannot_be_moved_away() {
        assert_eq!(
            layered_rename_decision(LayeredRename { source_in_overlay: false, ..overlay_file() }),
            Err(STATUS_NOT_SUPPORTED)
        );
        assert_eq!(
            layered_rename_decision(LayeredRename {
                source_shadows_installed: true,
                replace_if_exists: true,
                ..overlay_file()
            }),
            Err(STATUS_NOT_SUPPORTED)
        );
    }
}
