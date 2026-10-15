//! Fallible storage admission for a captured complete file image.

use alloc::vec::Vec;

use crate::PeError;

/// Admit complete EOF-sized storage before reading, without publishing uncaptured bytes or
/// changing the captured prefix. Subsequent chunks reuse the admitted capacity.
pub fn reserve_file_snapshot_capacity(bytes: &mut Vec<u8>, file_size: usize) -> Result<(), PeError> {
    let remaining = file_size.checked_sub(bytes.len()).ok_or(PeError::BadImageSize)?;
    bytes.try_reserve_exact(remaining).map_err(|_| PeError::InsufficientResources)
}
