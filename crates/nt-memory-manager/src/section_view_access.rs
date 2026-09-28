//! Access and protection admission for a data-section view.

use nt_types::AccessMode;

use crate::{
    PAGE_NOACCESS, PAGE_READONLY, PAGE_READWRITE, PAGE_WRITECOPY, STATUS_INVALID_PAGE_PROTECTION,
};

const PAGE_EXECUTE: u32 = 0x10;
const PAGE_EXECUTE_READ: u32 = 0x20;
const PAGE_EXECUTE_READWRITE: u32 = 0x40;
const PAGE_EXECUTE_WRITECOPY: u32 = 0x80;

pub const SECTION_QUERY: u32 = 0x0001;
pub const SECTION_MAP_WRITE: u32 = 0x0002;
pub const SECTION_MAP_READ: u32 = 0x0004;
pub const SECTION_MAP_EXECUTE: u32 = 0x0008;
pub const STATUS_SECTION_PROTECTION: u32 = 0xc000_004e;
const STATUS_ACCESS_DENIED: u32 = 0xc000_0022;
const PAGE_MODIFIERS: u32 = 0x700;
const PAGE_NOCACHE: u32 = 0x200;
const PAGE_WRITECOMBINE: u32 = 0x400;
const GENERIC_READ: u32 = 0x8000_0000;
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_EXECUTE: u32 = 0x2000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

fn base(protection: u32) -> Result<u32, u32> {
    if protection & !(0xff | PAGE_MODIFIERS) != 0 {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    let base = protection & 0xff;
    if !matches!(
        base,
        PAGE_NOACCESS
            | PAGE_READONLY
            | PAGE_READWRITE
            | PAGE_WRITECOPY
            | PAGE_EXECUTE
            | PAGE_EXECUTE_READ
            | PAGE_EXECUTE_READWRITE
            | PAGE_EXECUTE_WRITECOPY
    ) || (base == PAGE_NOACCESS && protection & PAGE_MODIFIERS != 0)
        || (protection & (PAGE_NOCACHE | PAGE_WRITECOMBINE)) == (PAGE_NOCACHE | PAGE_WRITECOMBINE)
    {
        return Err(STATUS_INVALID_PAGE_PROTECTION);
    }
    Ok(base)
}

/// ReactOS `MmMakeSectionAccess`: copy-on-write needs read, not shared-write access.
pub fn required_section_map_access(protection: u32) -> Result<u32, u32> {
    Ok(match base(protection)? {
        PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY => SECTION_MAP_READ,
        PAGE_READWRITE => SECTION_MAP_WRITE,
        PAGE_EXECUTE => SECTION_MAP_EXECUTE,
        PAGE_EXECUTE_READ | PAGE_EXECUTE_WRITECOPY => SECTION_MAP_EXECUTE | SECTION_MAP_READ,
        PAGE_EXECUTE_READWRITE => SECTION_MAP_EXECUTE | SECTION_MAP_WRITE,
        _ => unreachable!(),
    })
}

fn compatible(section: u32, view: u32) -> bool {
    match section {
        PAGE_NOACCESS => view == PAGE_NOACCESS,
        PAGE_READONLY | PAGE_WRITECOPY => {
            matches!(view, PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY)
        }
        PAGE_READWRITE => {
            matches!(
                view,
                PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_READWRITE
            )
        }
        PAGE_EXECUTE => matches!(view, PAGE_NOACCESS | PAGE_EXECUTE),
        PAGE_EXECUTE_READ => matches!(
            view,
            PAGE_NOACCESS | PAGE_READONLY | PAGE_WRITECOPY | PAGE_EXECUTE | PAGE_EXECUTE_READ
        ),
        PAGE_EXECUTE_READWRITE => true,
        PAGE_EXECUTE_WRITECOPY => matches!(
            view,
            PAGE_NOACCESS
                | PAGE_READONLY
                | PAGE_WRITECOPY
                | PAGE_EXECUTE
                | PAGE_EXECUTE_READ
                | PAGE_EXECUTE_WRITECOPY
        ),
        _ => false,
    }
}

fn expanded_grant(granted: u32) -> u32 {
    let mut expanded = granted;
    if granted & GENERIC_ALL != 0 {
        expanded |= SECTION_QUERY | SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE;
    }
    if granted & GENERIC_READ != 0 {
        expanded |= SECTION_QUERY | SECTION_MAP_READ;
    }
    if granted & GENERIC_WRITE != 0 {
        expanded |= SECTION_MAP_WRITE;
    }
    if granted & GENERIC_EXECUTE != 0 {
        expanded |= SECTION_MAP_EXECUTE;
    }
    expanded
}

pub fn check_section_query_access(granted: u32, mode: AccessMode) -> Result<(), u32> {
    if mode == AccessMode::KernelMode || expanded_grant(granted) & SECTION_QUERY != 0 {
        Ok(())
    } else {
        Err(STATUS_ACCESS_DENIED)
    }
}

/// Validate geometry independently of caller mode; only the handle grant is mode-dependent.
pub fn check_section_view_access(
    section_protection: u32,
    view_protection: u32,
    granted: u32,
    mode: AccessMode,
) -> Result<(), u32> {
    let required = required_section_map_access(view_protection)?;
    if mode == AccessMode::UserMode && expanded_grant(granted) & required != required {
        return Err(STATUS_ACCESS_DENIED);
    }
    if !compatible(base(section_protection)?, base(view_protection)?) {
        return Err(STATUS_SECTION_PROTECTION);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protection_selects_exact_map_rights() {
        let cases = [
            (PAGE_NOACCESS, SECTION_MAP_READ),
            (PAGE_READONLY, SECTION_MAP_READ),
            (PAGE_READWRITE, SECTION_MAP_WRITE),
            (PAGE_WRITECOPY, SECTION_MAP_READ),
            (PAGE_EXECUTE, SECTION_MAP_EXECUTE),
            (PAGE_EXECUTE_READ, SECTION_MAP_EXECUTE | SECTION_MAP_READ),
            (
                PAGE_EXECUTE_READWRITE,
                SECTION_MAP_EXECUTE | SECTION_MAP_WRITE,
            ),
            (
                PAGE_EXECUTE_WRITECOPY,
                SECTION_MAP_EXECUTE | SECTION_MAP_READ,
            ),
        ];
        for (protection, required) in cases {
            assert_eq!(required_section_map_access(protection), Ok(required));
            if protection != PAGE_NOACCESS {
                assert_eq!(
                    required_section_map_access(protection | 0x100),
                    Ok(required)
                );
            }
        }
        for invalid in [0, 3, 0x10000, PAGE_NOACCESS | 0x100, PAGE_READONLY | 0x600] {
            assert_eq!(
                required_section_map_access(invalid),
                Err(STATUS_INVALID_PAGE_PROTECTION)
            );
        }
    }

    #[test]
    fn user_grant_is_protection_specific_and_kernel_bypasses_it() {
        assert_eq!(
            check_section_view_access(
                PAGE_READONLY,
                PAGE_WRITECOPY,
                SECTION_MAP_READ,
                AccessMode::UserMode
            ),
            Ok(())
        );
        assert_eq!(
            check_section_view_access(
                PAGE_READWRITE,
                PAGE_READWRITE,
                SECTION_MAP_READ,
                AccessMode::UserMode
            ),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            check_section_view_access(
                PAGE_READWRITE,
                PAGE_READWRITE,
                SECTION_MAP_WRITE,
                AccessMode::UserMode
            ),
            Ok(())
        );
        assert_eq!(
            check_section_view_access(
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READ,
                SECTION_MAP_READ,
                AccessMode::UserMode
            ),
            Err(STATUS_ACCESS_DENIED)
        );
        assert_eq!(
            check_section_view_access(
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READ,
                GENERIC_READ | GENERIC_EXECUTE,
                AccessMode::UserMode
            ),
            Ok(())
        );
        assert_eq!(
            check_section_view_access(
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READ,
                0,
                AccessMode::KernelMode
            ),
            Ok(())
        );
        assert_eq!(
            check_section_query_access(GENERIC_READ, AccessMode::UserMode),
            Ok(())
        );
        assert_eq!(
            check_section_query_access(SECTION_MAP_READ, AccessMode::UserMode),
            Err(STATUS_ACCESS_DENIED)
        );
    }

    #[test]
    fn incompatible_view_is_rejected_before_access() {
        assert_eq!(
            check_section_view_access(PAGE_READONLY, PAGE_READWRITE, 0, AccessMode::KernelMode),
            Err(STATUS_SECTION_PROTECTION)
        );
        assert_eq!(
            check_section_view_access(
                PAGE_EXECUTE_READ,
                PAGE_EXECUTE_READWRITE,
                SECTION_MAP_EXECUTE | SECTION_MAP_WRITE,
                AccessMode::UserMode
            ),
            Err(STATUS_SECTION_PROTECTION)
        );
        assert_eq!(
            check_section_view_access(
                PAGE_READWRITE,
                PAGE_EXECUTE_READ,
                SECTION_MAP_EXECUTE | SECTION_MAP_READ,
                AccessMode::UserMode
            ),
            Err(STATUS_SECTION_PROTECTION)
        );
    }
}
