//! ReactOS amd64 WindowProc callback header and appended lParam byte-span contract.

use crate::{checked_payload_length, ValidationError};
use core::ops::Range;

const ARGUMENT_BYTES: usize = 0x40;
const LPARAM_BUFFER_SIZE_OFFSET: usize = 0x30;

/// `-1` carries scalar lParam; nonnegative sizes carry exactly that many appended bytes.
/// A zero-sized blob still has a valid target at the end of the copied header.
pub fn windowproc_lparam_span(payload: &[u8]) -> Result<Option<Range<usize>>, ValidationError> {
    checked_payload_length(payload.len())?;
    if payload.len() < ARGUMENT_BYTES {
        return Err(ValidationError::Length);
    }
    let size = i32::from_le_bytes(payload[LPARAM_BUFFER_SIZE_OFFSET..LPARAM_BUFFER_SIZE_OFFSET + 4]
        .try_into().unwrap());
    if size == -1 {
        return if payload.len() == ARGUMENT_BYTES {
            Ok(None)
        } else {
            Err(ValidationError::Length)
        };
    }
    let size = usize::try_from(size).map_err(|_| ValidationError::Length)?;
    let end = ARGUMENT_BYTES.checked_add(size).ok_or(ValidationError::Length)?;
    if end != payload.len() {
        return Err(ValidationError::Length);
    }
    Ok(Some(ARGUMENT_BYTES..end))
}
