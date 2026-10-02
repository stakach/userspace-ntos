//! Boot-established hardware-profile alias, distinct from the mutable selector value.

use crate::{CurrentControlSet, Hive, HiveKind, KeyKind, RegistryValueType, SYSTEM_HIVE_PATH};
use alloc::string::String;
use core::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareProfileError {
    WrongHiveKind,
    ConfigKeyMissing,
    SelectorMissing,
    SelectorInvalid,
    TargetMissing,
    OrdinaryCurrent,
    LinkInvalid,
    LinkCycle,
    CrossHiveTarget,
    Capacity,
}

/// Captured while publishing a SYSTEM mount. Ordinary CurrentConfig writes do not move this
/// alias. An imported ordinary Current key is not an alias; an actual link retains its REG_LINK
/// target. The captured physical source prevents later Select edits from redirecting either form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareProfileAlias {
    source_control_set: String,
    mode: CapturedMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum CapturedMode {
    Ordinary,
    BootVirtual(Result<String, HardwareProfileError>),
    SymbolicLink(Result<String, HardwareProfileError>),
}

impl HardwareProfileAlias {
    pub fn capture(
        hive: &Hive,
        control_set: &CurrentControlSet,
    ) -> Result<Self, HardwareProfileError> {
        if hive.kind != HiveKind::System {
            return Err(HardwareProfileError::WrongHiveKind);
        }
        let source_control_set = concat(control_set.as_str(), "", "")?;
        let current_path = concat(&source_control_set, r"\Hardware Profiles\Current", "")?;
        let mode = match hive.open_key(&current_path) {
            Some(key) if hive.key_kind(key) == Some(KeyKind::Ordinary) => CapturedMode::Ordinary,
            Some(key) => CapturedMode::SymbolicLink(capture_link(hive, key, &source_control_set)),
            None => CapturedMode::BootVirtual(Self::select(hive, &source_control_set)),
        };
        if matches!(&mode,
            CapturedMode::BootVirtual(Err(HardwareProfileError::Capacity))
            | CapturedMode::SymbolicLink(Err(HardwareProfileError::Capacity))) {
            return Err(HardwareProfileError::Capacity);
        }
        Ok(Self {
            source_control_set,
            mode,
        })
    }

    fn select(hive: &Hive, control_set: &str) -> Result<String, HardwareProfileError> {
        if hive.kind != HiveKind::System {
            return Err(HardwareProfileError::WrongHiveKind);
        }
        let config_path = concat(control_set, r"\Control\IDConfigDB", "")?;
        let key = hive
            .open_key(&config_path)
            .ok_or(HardwareProfileError::ConfigKeyMissing)?;
        let (kind, bytes) = hive
            .query_value(key, "CurrentConfig")
            .ok_or(HardwareProfileError::SelectorMissing)?;
        let bytes: [u8; 4] = bytes
            .try_into()
            .map_err(|_| HardwareProfileError::SelectorInvalid)?;
        if kind != RegistryValueType::Dword {
            return Err(HardwareProfileError::SelectorInvalid);
        }
        let mut name = String::new();
        name.try_reserve_exact(10)
            .map_err(|_| HardwareProfileError::Capacity)?;
        write!(&mut name, "{:04}", u32::from_le_bytes(bytes)).expect("reserved decimal u32");
        let target_path = concat(control_set, r"\Hardware Profiles\", &name)?;
        hive.open_key(&target_path)
            .ok_or(HardwareProfileError::TargetMissing)?;
        Ok(name)
    }

    /// Virtual aliases return their numeric profile name; actual links return the retained
    /// SYSTEM-relative target. Ordinary Current keys have no alias selection.
    pub fn selection(&self) -> Result<&str, HardwareProfileError> {
        match &self.mode {
            CapturedMode::Ordinary => Err(HardwareProfileError::OrdinaryCurrent),
            CapturedMode::BootVirtual(target) | CapturedMode::SymbolicLink(target) =>
                target.as_deref().map_err(|error| *error),
        }
    }

    /// Rewrite only the captured physical alias. The caller first resolves CurrentControlSet
    /// and normalizes separators. This operation is atomic on error, including allocation failure.
    /// The target need not still exist: key lookup owns that decision after alias resolution.
    pub fn resolve_relative_path(&self, path: &mut String) -> Result<(), HardwareProfileError> {
        let mut parts = path.split('\\');
        let Some(control_set) = parts.next() else {
            return Ok(());
        };
        let Some(profiles) = parts.next() else {
            return Ok(());
        };
        let Some(current) = parts.next() else {
            return Ok(());
        };
        if !control_set.eq_ignore_ascii_case(&self.source_control_set)
            || !profiles.eq_ignore_ascii_case("Hardware Profiles")
            || !current.eq_ignore_ascii_case("Current")
        {
            return Ok(());
        }
        if self.mode == CapturedMode::Ordinary {
            return Ok(());
        }
        let start = control_set.len() + 1 + profiles.len() + 1;
        let end = start + current.len();
        let target = self.selection()?;
        let start = match &self.mode {
            CapturedMode::SymbolicLink(_) => 0,
            _ => start,
        };
        path.try_reserve(target.len().saturating_sub(end - start))
            .map_err(|_| HardwareProfileError::Capacity)?;
        path.replace_range(start..end, target);
        Ok(())
    }
}

fn capture_link(hive: &Hive, key: crate::CellId, control_set: &str)
    -> Result<String, HardwareProfileError>
{
    let (kind, bytes) = hive.query_value(key, "SymbolicLinkValue")
        .ok_or(HardwareProfileError::LinkInvalid)?;
    if kind != RegistryValueType::Link || bytes.is_empty() || bytes.len() % 2 != 0
        || bytes.len() > u16::MAX as usize - 2 {
        return Err(HardwareProfileError::LinkInvalid);
    }
    let mut target = String::new();
    target.try_reserve_exact(bytes.len().checked_mul(2)
        .ok_or(HardwareProfileError::Capacity)?)
        .map_err(|_| HardwareProfileError::Capacity)?;
    for character in char::decode_utf16(bytes.chunks_exact(2)
        .map(|unit| u16::from_le_bytes([unit[0], unit[1]]))) {
        let character = character.map_err(|_| HardwareProfileError::LinkInvalid)?;
        if character == '\0' { return Err(HardwareProfileError::LinkInvalid); }
        target.push(character);
    }
    if !target.starts_with('\\') { return Err(HardwareProfileError::LinkInvalid); }
    let prefix = target.get(..SYSTEM_HIVE_PATH.len())
        .ok_or(HardwareProfileError::CrossHiveTarget)?;
    if !prefix.eq_ignore_ascii_case(SYSTEM_HIVE_PATH) {
        return Err(HardwareProfileError::CrossHiveTarget);
    }
    if target.len() == SYSTEM_HIVE_PATH.len() {
        return Err(HardwareProfileError::LinkInvalid);
    }
    if !target[SYSTEM_HIVE_PATH.len()..].starts_with('\\') {
        return Err(HardwareProfileError::CrossHiveTarget);
    }
    let relative = &target[SYSTEM_HIVE_PATH.len() + 1..];
    if relative.is_empty() || relative.split('\\').any(str::is_empty) {
        return Err(HardwareProfileError::LinkInvalid);
    }
    let (first, suffix) = relative.split_once('\\').unwrap_or((relative, ""));
    let target = if first.eq_ignore_ascii_case("CurrentControlSet") {
        concat(control_set, if suffix.is_empty() { "" } else { "\\" }, suffix)
    } else {
        concat(relative, "", "")
    }?;
    let mut parts = target.split('\\');
    if parts.next().is_some_and(|part| part.eq_ignore_ascii_case(control_set))
        && parts.next().is_some_and(|part| part.eq_ignore_ascii_case("Hardware Profiles"))
        && parts.next().is_some_and(|part| part.eq_ignore_ascii_case("Current")) {
        return Err(HardwareProfileError::LinkCycle);
    }
    let mut key = hive.root();
    for part in target.split('\\') {
        let Some(child) = hive.open_subkey(key, part) else { break; };
        if hive.key_kind(child) == Some(KeyKind::SymbolicLink) {
            return Err(HardwareProfileError::LinkInvalid);
        }
        key = child;
    }
    Ok(target)
}

fn concat(first: &str, second: &str, third: &str) -> Result<String, HardwareProfileError> {
    let capacity = first
        .len()
        .checked_add(second.len())
        .and_then(|len| len.checked_add(third.len()))
        .ok_or(HardwareProfileError::Capacity)?;
    let mut value = String::new();
    value
        .try_reserve_exact(capacity)
        .map_err(|_| HardwareProfileError::Capacity)?;
    value.push_str(first);
    value.push_str(second);
    value.push_str(third);
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::format;

    fn link(hive: &mut Hive, target: &str) -> crate::CellId {
        let current = hive.create_key(r"ControlSet001\Hardware Profiles\Current");
        assert!(hive.set_key_kind(current, KeyKind::SymbolicLink));
        let bytes = target.encode_utf16().flat_map(u16::to_le_bytes).collect();
        assert!(hive.set_value(current, "SymbolicLinkValue", RegistryValueType::Link, bytes));
        current
    }

    #[test]
    fn wrong_hive_kind_is_rejected_before_current_classification() {
        let (mut hive, control_set) = fixture(1);
        for kind in [KeyKind::Ordinary, KeyKind::SymbolicLink] {
            let current = hive.create_key(r"ControlSet001\Hardware Profiles\Current");
            hive.set_key_kind(current, kind);
            hive.kind = HiveKind::Software;
            assert_eq!(HardwareProfileAlias::capture(&hive, &control_set),
                Err(HardwareProfileError::WrongHiveKind));
        }
    }

    #[test]
    fn actual_link_to_self_or_descendant_is_never_opened_as_an_ordinary_body() {
        for target in [
            r"\Registry\Machine\System\ControlSet001\Hardware Profiles\Current",
            r"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\Current\Child",
            r"\registry\machine\system\controlset001\hardware profiles\CURRENT\Nested",
        ] {
            let (mut hive, control_set) = fixture(1);
            link(&mut hive, target);
            let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
            let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\Child");
            let before = path.clone();
            assert_eq!(alias.resolve_relative_path(&mut path), Err(HardwareProfileError::LinkCycle));
            assert_eq!(path, before);
        }
    }

    #[test]
    fn unsupported_same_hive_root_link_is_not_misclassified_as_cross_hive() {
        let (mut hive, control_set) = fixture(1);
        link(&mut hive, SYSTEM_HIVE_PATH);
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        assert_eq!(alias.selection(), Err(HardwareProfileError::LinkInvalid));
    }

    #[test]
    fn existing_symbolic_target_or_prefix_is_not_opened_as_a_literal_body() {
        for suffix in ["", r"\MissingChild"] {
            let (mut hive, control_set) = fixture(1);
            let other = hive.create_key(r"ControlSet001\OtherLink");
            hive.set_key_kind(other, KeyKind::SymbolicLink);
            let target = format!(r"\Registry\Machine\System\ControlSet001\OtherLink{suffix}");
            link(&mut hive, &target);
            let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
            let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\Child");
            let before = path.clone();
            assert_eq!(alias.resolve_relative_path(&mut path), Err(HardwareProfileError::LinkInvalid));
            assert_eq!(path, before);
        }
    }

    #[test]
    fn ordinary_current_is_not_shadowed_by_a_selector_or_link_named_value() {
        for selector in [None, Some(1), Some(999)] {
            let (mut hive, control_set) = fixture(1);
            let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
            hive.delete_value(config, "CurrentConfig");
            if let Some(selector) = selector { hive.set_dword(config, "CurrentConfig", selector); }
            let current = hive.create_key(r"ControlSet001\Hardware Profiles\Current");
            hive.create_key(r"ControlSet001\Hardware Profiles\Current\System");
            hive.set_value(current, "SymbolicLinkValue", RegistryValueType::Link,
                alloc::vec![1, 0]);
            let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
            let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\System");
            alias.resolve_relative_path(&mut path).unwrap();
            assert_eq!(path, r"ControlSet001\Hardware Profiles\Current\System");
            assert_eq!(alias.selection(), Err(HardwareProfileError::OrdinaryCurrent));
        }
    }

    #[test]
    fn actual_link_captures_bytes_not_selector_and_preserves_suffix() {
        let (mut hive, control_set) = fixture(1);
        let current = link(&mut hive,
            r"\Registry\Machine\System\CurrentControlSet\Hardware Profiles\0007");
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
        hive.set_dword(config, "CurrentConfig", 9);
        hive.set_value(current, "SymbolicLinkValue", RegistryValueType::Link, alloc::vec![0]);
        let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\System\CurrentControlSet");
        alias.resolve_relative_path(&mut path).unwrap();
        assert_eq!(path, r"ControlSet001\Hardware Profiles\0007\System\CurrentControlSet");
    }

    #[test]
    fn actual_link_can_target_another_same_hive_tree_without_target_creation() {
        let (mut hive, control_set) = fixture(1);
        link(&mut hive, r"\Registry\Machine\System\ControlSet002\Other");
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\Child");
        alias.resolve_relative_path(&mut path).unwrap();
        assert_eq!(path, r"ControlSet002\Other\Child");
        assert!(hive.open_key(&path).is_none());
    }

    #[test]
    fn malformed_actual_links_never_fall_back_to_valid_selector() {
        for bytes in [alloc::vec![], alloc::vec![1], alloc::vec![0, 0], alloc::vec![0, 0xd8]] {
            let (mut hive, control_set) = fixture(1);
            let current = link(&mut hive, r"\Registry\Machine\System\ControlSet001");
            hive.set_value(current, "SymbolicLinkValue", RegistryValueType::Link, bytes);
            let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
            let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\Child");
            let before = path.clone();
            assert_eq!(alias.resolve_relative_path(&mut path), Err(HardwareProfileError::LinkInvalid));
            assert_eq!(path, before);
        }
        let (mut hive, control_set) = fixture(1);
        let current = link(&mut hive, r"\Registry\Machine\System\ControlSet001");
        hive.delete_value(current, "SymbolicLinkValue");
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        assert_eq!(alias.selection(), Err(HardwareProfileError::LinkInvalid));
        hive.set_value(current, "SymbolicLinkValue", RegistryValueType::Sz,
            r"\Registry\Machine\System\ControlSet001".encode_utf16()
                .flat_map(u16::to_le_bytes).collect());
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        assert_eq!(alias.selection(), Err(HardwareProfileError::LinkInvalid));
    }

    #[test]
    fn cross_hive_actual_link_is_explicitly_refused_without_path_mutation() {
        let (mut hive, control_set) = fixture(1);
        link(&mut hive, r"\Registry\Machine\Software\Elsewhere");
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\Child");
        let before = path.clone();
        assert_eq!(alias.resolve_relative_path(&mut path), Err(HardwareProfileError::CrossHiveTarget));
        assert_eq!(path, before);
    }

    fn fixture(number: u32) -> (Hive, CurrentControlSet) {
        let mut hive = Hive::new(HiveKind::System);
        let select = hive.create_key("Select");
        hive.set_dword(select, "Current", 1);
        hive.create_key("ControlSet001");
        let config = hive.create_key(r"ControlSet001\Control\IDConfigDB");
        hive.set_dword(config, "CurrentConfig", number);
        hive.create_key(&format!(r"ControlSet001\Hardware Profiles\{number:04}"));
        let control_set = hive.current_control_set().unwrap();
        (hive, control_set)
    }

    #[test]
    fn captured_target_uses_minimum_width_without_a_default_or_numeric_cap() {
        for (number, name) in [
            (0, "0000"),
            (7, "0007"),
            (12345, "12345"),
            (u32::MAX, "4294967295"),
        ] {
            let (hive, control_set) = fixture(number);
            let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
            assert_eq!(alias.selection(), Ok(name));
            let mut path = String::from(r"controlset001\HARDWARE PROFILES\current\Enum\PCI");
            alias.resolve_relative_path(&mut path).unwrap();
            assert_eq!(
                path,
                format!(r"controlset001\HARDWARE PROFILES\{name}\Enum\PCI")
            );
        }
    }

    #[test]
    fn exact_source_boundary_only() {
        let (hive, control_set) = fixture(3);
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        for path in [
            r"ControlSet002\Hardware Profiles\Current\Enum",
            r"ControlSet001\Control\Hardware Profiles\Current",
            r"ControlSet001\Hardware Profiles\CurrentExtra",
            r"ControlSet001\Hardware Profiles\0003\Current",
            r"ControlSet001\Hardware Profiles",
            r"Other\ControlSet001\Hardware Profiles\Current",
        ] {
            let mut resolved = String::from(path);
            alias.resolve_relative_path(&mut resolved).unwrap();
            assert_eq!(resolved, path);
        }
    }

    #[test]
    fn selector_edits_and_target_deletion_do_not_move_captured_alias() {
        let (mut hive, control_set) = fixture(3);
        let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
        let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
        hive.set_dword(config, "CurrentConfig", 9);
        hive.create_key(r"ControlSet001\Hardware Profiles\0009");
        let target = hive
            .open_key(r"ControlSet001\Hardware Profiles\0003")
            .unwrap();
        hive.delete_key(target).unwrap();
        let mut path = String::from(r"ControlSet001\Hardware Profiles\Current");
        alias.resolve_relative_path(&mut path).unwrap();
        assert_eq!(path, r"ControlSet001\Hardware Profiles\0003");
        assert!(hive.open_key(&path).is_none());
        assert_eq!(
            HardwareProfileAlias::capture(&hive, &control_set)
                .unwrap()
                .selection(),
            Ok("0009")
        );
    }

    #[test]
    fn malformed_or_missing_selection_is_retained_without_affecting_other_paths() {
        for (kind, bytes) in [
            (RegistryValueType::Sz, alloc::vec![1, 0, 0, 0]),
            (RegistryValueType::Dword, alloc::vec![1, 0, 0]),
            (RegistryValueType::Dword, alloc::vec![1, 0, 0, 0, 0]),
        ] {
            let (mut hive, control_set) = fixture(1);
            let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
            hive.set_value(config, "CurrentConfig", kind, bytes);
            let alias = HardwareProfileAlias::capture(&hive, &control_set).unwrap();
            let mut path = String::from(r"ControlSet001\Hardware Profiles\Current\Enum");
            let before = path.clone();
            assert_eq!(
                alias.resolve_relative_path(&mut path),
                Err(HardwareProfileError::SelectorInvalid)
            );
            assert_eq!(path, before);
            let mut ordinary = String::from(r"ControlSet001\Services");
            assert_eq!(alias.resolve_relative_path(&mut ordinary), Ok(()));
        }
        let (mut hive, control_set) = fixture(1);
        let config = hive.open_key(r"ControlSet001\Control\IDConfigDB").unwrap();
        hive.delete_value(config, "CurrentConfig");
        assert_eq!(
            HardwareProfileAlias::capture(&hive, &control_set)
                .unwrap()
                .selection(),
            Err(HardwareProfileError::SelectorMissing)
        );
        hive.delete_key(config).unwrap();
        assert_eq!(
            HardwareProfileAlias::capture(&hive, &control_set)
                .unwrap()
                .selection(),
            Err(HardwareProfileError::ConfigKeyMissing)
        );
        let (mut hive, control_set) = fixture(1);
        let target = hive
            .open_key(r"ControlSet001\Hardware Profiles\0001")
            .unwrap();
        hive.delete_key(target).unwrap();
        assert_eq!(
            HardwareProfileAlias::capture(&hive, &control_set)
                .unwrap()
                .selection(),
            Err(HardwareProfileError::TargetMissing)
        );
    }
}
