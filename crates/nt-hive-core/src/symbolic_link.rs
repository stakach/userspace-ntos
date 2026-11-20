//! Registry symbolic link keys, as ReactOS `CmpGetSymbolicLink` and `CmpParseKey` treat them: a
//! `KeyKind::SymbolicLink` key names its target in `SymbolicLinkValue`, a REG_LINK value holding
//! an absolute `\REGISTRY\...` path without a terminating NUL. Opening a path through such a key
//! continues at the target, unless the link is the final component and the open asked for the
//! link itself (OBJ_OPENLINK).

use crate::{CellId, Hive, KeyKind};
use alloc::string::String;
pub use nt_config_manager::symbolic_link::{
    parse_symbolic_link_value, reparse_with_rest, SymbolicLinkError, MAX_REPARSE, SYMBOLIC_LINK_VALUE,
};

/// The absolute target path `key` links to.
pub fn symbolic_link_target(hive: &Hive, key: CellId) -> Result<String, SymbolicLinkError> {
    let (kind, bytes) = hive
        .query_value(key, SYMBOLIC_LINK_VALUE)
        .ok_or(SymbolicLinkError::NoTarget)?;
    parse_symbolic_link_value(kind as u32, bytes)
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
            let target = symbolic_link_target(hive, child)?;
            return reparse_with_rest(target, components).map(LinkWalk::Reparse);
        }
        key = child;
    }
    Ok(LinkWalk::Found(key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HiveKind, RegistryValueType};
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

    #[test]
    fn overlay_links_reparse_like_hive_links() {
        let mut overlay = crate::RegistryOverlay::new();
        let link = r"\registry\machine\software\link";
        assert_eq!(overlay.link_reparse(link, false), None, "no links: no checks");
        let index = overlay
            .create_secured_owned_of_kind(link.into(), true, None, alloc::vec![1], true)
            .unwrap();
        assert!(overlay.is_symbolic_link(index));
        assert_eq!(overlay.link_reparse(link, false), Some(Err(SymbolicLinkError::NoTarget)));
        assert!(overlay.set_value(index, SYMBOLIC_LINK_VALUE, RegistryValueType::Link as u32,
            &link_data(TARGET)));
        assert_eq!(overlay.link_reparse(link, false), Some(Ok(TARGET.into())));
        assert_eq!(overlay.link_reparse(&alloc::format!(r"{link}\a\b"), false),
            Some(Ok(alloc::format!(r"{TARGET}\a\b"))));
        assert_eq!(overlay.link_reparse(link, true), None, "OBJ_OPENLINK opens the link itself");
        assert_eq!(overlay.link_reparse(r"\registry\machine\software\other", false), None);
        assert_eq!(
            overlay.create_secured_owned(alloc::format!(r"{link}\child"), true, None, alloc::vec![1]),
            Err(0xC000_0022),
            "a link key has no children"
        );
    }

    #[test]
    fn a_mutable_hive_resolves_through_its_links() {
        let mut hive = Hive::new(HiveKind::Software);
        let parent = hive.create_key("Print");
        let mut tx = hive.begin_transaction();
        let link = tx
            .try_create_child_of_kind(parent, "Printers".into(), None, alloc::vec![1], false,
                KeyKind::SymbolicLink)
            .unwrap();
        assert!(tx.set_value(link, SYMBOLIC_LINK_VALUE, RegistryValueType::Link, link_data(TARGET)));
        tx.commit();
        let mut set = crate::MutableHiveSet::new();
        let id: crate::HiveId = 7;
        set.mount(r"\Registry\Machine\SOFTWARE", id, hive).unwrap();
        let path = r"\Registry\Machine\SOFTWARE\Print\Printers";
        assert_eq!(set.resolve_key_following(path, false), Ok(Some(Err(TARGET.into()))));
        assert_eq!(set.resolve_key_following(path, true),
            Ok(Some(Ok(crate::ResolvedHiveKey { hive: id, key: link }))));
        assert_eq!(set.resolve_key_following(r"\Registry\Machine\SOFTWARE\None", false), Ok(None));
    }
}
