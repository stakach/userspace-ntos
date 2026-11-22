//! Registry symbolic link rules shared by every registry store, as ReactOS `CmpGetSymbolicLink`
//! and `CmpParseKey` apply them: a link key names its target in `SymbolicLinkValue`, a REG_LINK
//! value holding an absolute `\\REGISTRY\\...` path without a terminating NUL.

use crate::RegistryValueType;
use alloc::string::String;

/// The value that holds a link key's target.
pub const SYMBOLIC_LINK_VALUE: &str = "SymbolicLinkValue";

/// ObpLookupObjectName's reparse bound; exceeding it fails the open as a missing name.
pub const MAX_REPARSE: usize = 30;

/// Why a link key names no usable target. NtOpenKey reports every case as
/// STATUS_OBJECT_NAME_NOT_FOUND.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SymbolicLinkError {
    /// `SymbolicLinkValue` is absent or not REG_LINK.
    NoTarget,
    /// The target is empty, not UTF-16, contains NUL, or is not an absolute path.
    InvalidTarget,
    /// Target plus remaining path exceeds a UNICODE_STRING (0xFFFF bytes).
    TooLong,
    Capacity,
}

/// CmpGetSymbolicLink's checks on a `SymbolicLinkValue` of type `value_type` holding `bytes`.
pub fn parse_symbolic_link_value(
    value_type: u32,
    bytes: &[u8],
) -> Result<String, SymbolicLinkError> {
    if value_type != RegistryValueType::Link as u32 {
        return Err(SymbolicLinkError::NoTarget);
    }
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(SymbolicLinkError::InvalidTarget);
    }
    if bytes.len() > u16::MAX as usize {
        return Err(SymbolicLinkError::TooLong);
    }
    let mut target = String::new();
    target
        .try_reserve_exact(bytes.len())
        .map_err(|_| SymbolicLinkError::Capacity)?;
    for character in char::decode_utf16(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
    ) {
        match character {
            Ok('\0') | Err(_) => return Err(SymbolicLinkError::InvalidTarget),
            Ok(character) => target.push(character),
        }
    }
    if !target.starts_with('\\') {
        return Err(SymbolicLinkError::InvalidTarget);
    }
    Ok(target)
}

/// Append the components of `rest` to a link target, bounded as a UNICODE_STRING.
pub fn reparse_with_rest<'a>(
    mut target: String,
    rest: impl Iterator<Item = &'a str>,
) -> Result<String, SymbolicLinkError> {
    for part in rest {
        target.push('\\');
        target.push_str(part);
    }
    if target.encode_utf16().count() * 2 > u16::MAX as usize {
        return Err(SymbolicLinkError::TooLong);
    }
    Ok(target)
}
