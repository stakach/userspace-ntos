//! Registry symbolic link keys, as ReactOS `CmpGetSymbolicLink` and `CmpParseKey` treat them: a
//! `KeyKind::SymbolicLink` key names its target in `SymbolicLinkValue`, a REG_LINK value holding
//! an absolute `\REGISTRY\...` path without a terminating NUL. Opening a path through such a key
//! continues at the target, unless the link is the final component and the open asked for the
//! link itself (OBJ_OPENLINK).

use crate::{CellId, Hive, KeyKind, RegistryValueType};
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

/// The absolute target path `key` links to.
pub fn symbolic_link_target(hive: &Hive, key: CellId) -> Result<String, SymbolicLinkError> {
    let (kind, bytes) = hive
        .query_value(key, SYMBOLIC_LINK_VALUE)
        .ok_or(SymbolicLinkError::NoTarget)?;
    if kind != RegistryValueType::Link {
        return Err(SymbolicLinkError::NoTarget);
    }
    if bytes.is_empty() || bytes.len() % 2 != 0 {
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
        bytes.chunks_exact(2).map(|unit| u16::from_le_bytes([unit[0], unit[1]])),
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

/// What a path walk through one hive found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkWalk {
    /// The key at the full path.
    Found(CellId),
    /// A link key was crossed: continue the open at this absolute path (target plus the
    /// components after the link).
    Reparse(String),
    /// A component is absent.
    NotFound,
}

/// Walk `relative` (backslash-separated, from the hive root) one component at a time, stopping
/// at the first link key that must be followed. A link as the last component is returned
/// itself when `open_link` is set.
pub fn walk_following_links(
    hive: &Hive,
    relative: &str,
    open_link: bool,
) -> Result<LinkWalk, SymbolicLinkError> {
    walk_following_links_from(hive, hive.root(), relative, open_link)
}

/// As [`walk_following_links`], starting at `start` (an opened key) instead of the root. The start
/// key itself is never followed: it was already opened.
pub fn walk_following_links_from(
    hive: &Hive,
    start: CellId,
    relative: &str,
    open_link: bool,
) -> Result<LinkWalk, SymbolicLinkError> {
    let mut key = start;
    let mut components = relative.split('\\').filter(|part| !part.is_empty()).peekable();
    while let Some(part) = components.next() {
        let Some(child) = hive.open_subkey(key, part) else {
            return Ok(LinkWalk::NotFound);
        };
        let last = components.peek().is_none();
        if hive.key_kind(child) == Some(KeyKind::SymbolicLink) && !(last && open_link) {
            let mut target = symbolic_link_target(hive, child)?;
            for rest in components {
                target.push('\\');
                target.push_str(rest);
            }
            if target.encode_utf16().count() * 2 > u16::MAX as usize {
                return Err(SymbolicLinkError::TooLong);
            }
            return Ok(LinkWalk::Reparse(target));
        }
        key = child;
    }
    Ok(LinkWalk::Found(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::HiveKind;
    use alloc::vec::Vec;

    const TARGET: &str = r"\REGISTRY\MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Print\Printers";

    fn link_data(target: &str) -> Vec<u8> {
        target.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn hive_with_link(value: Option<(RegistryValueType, Vec<u8>)>) -> (Hive, CellId) {
        let mut hive = Hive::new(HiveKind::System);
        let print = hive.create_key(r"ControlSet001\Control\Print");
        let mut tx = hive.begin_transaction();
        let link = tx
            .try_create_child_of_kind(print, "Printers".into(), None, alloc::vec![1], true,
                KeyKind::SymbolicLink)
            .unwrap();
        if let Some((kind, data)) = value {
            assert!(tx.set_value(link, SYMBOLIC_LINK_VALUE, kind, data));
        }
        tx.commit();
        (hive, link)
    }

    #[test]
    fn a_path_through_a_link_reparses_to_its_target_and_the_rest() {
        let (hive, link) = hive_with_link(Some((RegistryValueType::Link, link_data(TARGET))));
        let path = r"ControlSet001\Control\Print\Printers";
        assert_eq!(walk_following_links(&hive, path, false), Ok(LinkWalk::Reparse(TARGET.into())));
        assert_eq!(
            walk_following_links(&hive, &alloc::format!(r"{path}\HP\Settings"), false),
            Ok(LinkWalk::Reparse(alloc::format!(r"{TARGET}\HP\Settings")))
        );
        // OBJ_OPENLINK opens the final link itself, but never a link in the middle.
        assert_eq!(walk_following_links(&hive, path, true), Ok(LinkWalk::Found(link)));
        assert_eq!(
            walk_following_links(&hive, &alloc::format!(r"{path}\HP"), true),
            Ok(LinkWalk::Reparse(alloc::format!(r"{TARGET}\HP")))
        );
        assert_eq!(walk_following_links(&hive, r"ControlSet001\Missing", false), Ok(LinkWalk::NotFound));
    }

    #[test]
    fn a_link_without_a_valid_target_is_not_followed() {
        let (hive, _) = hive_with_link(None);
        let path = r"ControlSet001\Control\Print\Printers";
        assert_eq!(walk_following_links(&hive, path, false), Err(SymbolicLinkError::NoTarget));
        let (hive, _) = hive_with_link(Some((RegistryValueType::Sz, link_data(TARGET))));
        assert_eq!(walk_following_links(&hive, path, false), Err(SymbolicLinkError::NoTarget));
        let (hive, _) = hive_with_link(Some((RegistryValueType::Link, link_data("relative\\path"))));
        assert_eq!(walk_following_links(&hive, path, false), Err(SymbolicLinkError::InvalidTarget));
        let (hive, _) = hive_with_link(Some((RegistryValueType::Link, link_data("\\a\0"))));
        assert_eq!(walk_following_links(&hive, path, false), Err(SymbolicLinkError::InvalidTarget));
    }
}
