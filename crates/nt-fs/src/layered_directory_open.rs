//! Directory source selection in the installed-plus-writable namespace.

use crate::{
    FILE_CREATE, FILE_DELETE_ON_CLOSE, FILE_DIRECTORY_FILE, FILE_NON_DIRECTORY_FILE,
    FILE_OPEN, FILE_OPEN_IF, FILE_VALID_OPTION_FLAGS, STATUS_CANNOT_DELETE,
    STATUS_FILE_IS_A_DIRECTORY, STATUS_INVALID_PARAMETER, STATUS_NOT_A_DIRECTORY,
    STATUS_OBJECT_NAME_COLLISION, STATUS_OBJECT_NAME_NOT_FOUND,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LayeredDirectoryOpenDecision {
    Installed,
    Overlay,
    CreateOverlay,
}

/// Select the directory backing without creating a node or publishing an open. An upper entry
/// shadows the lower entry even when their types differ. Access and sharing remain enforced by
/// the selected filesystem; callers first validate the complete CREATE parameter contract.
pub fn layered_directory_open_decision(
    installed: Option<bool>,
    overlay: Option<bool>,
    disposition: u32,
    options: u32,
    is_root: bool,
) -> Result<LayeredDirectoryOpenDecision, u32> {
    if !matches!(disposition, FILE_CREATE | FILE_OPEN | FILE_OPEN_IF)
        || options & !FILE_VALID_OPTION_FLAGS != 0
        || options & (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE)
            == (FILE_DIRECTORY_FILE | FILE_NON_DIRECTORY_FILE)
    {
        return Err(STATUS_INVALID_PARAMETER);
    }
    if options & FILE_NON_DIRECTORY_FILE != 0 {
        return Err(STATUS_FILE_IS_A_DIRECTORY);
    }
    if overlay.or(installed) == Some(false) {
        return Err(STATUS_NOT_A_DIRECTORY);
    }
    if is_root && options & FILE_DELETE_ON_CLOSE != 0 {
        return Err(STATUS_CANNOT_DELETE);
    }
    if overlay.or(installed).is_none() {
        return match disposition {
            FILE_OPEN => Err(STATUS_OBJECT_NAME_NOT_FOUND),
            _ => Ok(LayeredDirectoryOpenDecision::CreateOverlay),
        };
    }
    if disposition == FILE_CREATE {
        return Err(STATUS_OBJECT_NAME_COLLISION);
    }
    Ok(if overlay.is_some() {
        LayeredDirectoryOpenDecision::Overlay
    } else {
        LayeredDirectoryOpenDecision::Installed
    })
}
