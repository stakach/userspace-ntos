//! The name handed to the registered WindowStation parse procedure when a Desktop is opened.
//!
//! ReactOS `ObOpenObjectByName` reaches a Desktop only through the WindowStation's
//! `ParseProcedure` (`ExpWinStaObjectParse` -> win32k `IntWinStaObjectParse` ->
//! `IntDesktopObjectParse`), which receives the name left after the WindowStation. The parse
//! routine strips one leading separator, rejects any further one and compares the rest with
//! each desktop's `szDesktopName`.

use core::ops::Range;
use nt_status::NtStatus;

const SEPARATOR: u16 = b'\\' as u16;
pub const STATUS_OBJECT_PATH_SYNTAX_BAD: NtStatus = NtStatus(0xC000_003Bu32 as i32);

/// The RemainingName range within the caller's ObjectName.
///
/// With a WindowStation `RootDirectory`, `ObpLookupObjectName` passes the whole relative name
/// (a leading separator is a syntax error for a rooted lookup). Without one the adapter has
/// already resolved the WindowStation; the remaining name begins at the separator before the
/// final component, exactly as the namespace walk would leave it.
pub fn desktop_remaining_name(name: &[u16], rooted: bool) -> Result<Range<usize>, NtStatus> {
    if rooted {
        if name.first() == Some(&SEPARATOR) {
            return Err(STATUS_OBJECT_PATH_SYNTAX_BAD);
        }
        return Ok(0..name.len());
    }
    match name.iter().rposition(|&unit| unit == SEPARATOR) {
        Some(separator) => Ok(separator..name.len()),
        None => Err(STATUS_OBJECT_PATH_SYNTAX_BAD),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(value: &str) -> alloc::vec::Vec<u16> {
        value.encode_utf16().collect()
    }

    #[test]
    fn rooted_desktop_names_reach_the_parse_procedure_whole() {
        let name = wide("Default");
        assert_eq!(desktop_remaining_name(&name, true), Ok(0..7));
        // IntWinStaObjectParse, not the adapter, rejects an embedded separator.
        let nested = wide("a\\b");
        assert_eq!(desktop_remaining_name(&nested, true), Ok(0..3));
        assert_eq!(desktop_remaining_name(&[], true), Ok(0..0));
        assert_eq!(
            desktop_remaining_name(&wide("\\Default"), true),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
    }

    #[test]
    fn absolute_desktop_names_leave_the_separator_after_the_window_station() {
        let name = wide("\\Windows\\WindowStations\\WinSta0\\Winlogon");
        assert_eq!(desktop_remaining_name(&name, false), Ok(31..name.len()));
        assert_eq!(
            desktop_remaining_name(&wide("Default"), false),
            Err(STATUS_OBJECT_PATH_SYNTAX_BAD)
        );
    }
}
