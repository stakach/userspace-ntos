//! Boot-established hardware-profile alias, distinct from the mutable selector value.

use crate::{CurrentControlSet, Hive, HiveKind, RegistryValueType};
use alloc::string::String;
use core::fmt::Write;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HardwareProfileError {
    WrongHiveKind,
    ConfigKeyMissing,
    SelectorMissing,
    SelectorInvalid,
    TargetMissing,
    Capacity,
}

/// Captured while publishing a SYSTEM mount. Ordinary CurrentConfig writes do not move this
/// alias. Its physical source includes the original control set, so subsequent Select edits
/// cannot accidentally move it into another tree. Missing selection is retained, not defaulted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HardwareProfileAlias {
    source_control_set: String,
    target: Result<String, HardwareProfileError>,
}

impl HardwareProfileAlias {
    pub fn capture(
        hive: &Hive,
        control_set: &CurrentControlSet,
    ) -> Result<Self, HardwareProfileError> {
        let source_control_set = concat(control_set.as_str(), "", "")?;
        let target = Self::select(hive, &source_control_set);
        if target == Err(HardwareProfileError::Capacity) {
            return Err(HardwareProfileError::Capacity);
        }
        Ok(Self {
            source_control_set,
            target,
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

    pub fn selection(&self) -> Result<&str, HardwareProfileError> {
        self.target.as_deref().map_err(|error| *error)
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
        let start = control_set.len() + 1 + profiles.len() + 1;
        let end = start + current.len();
        let target = self.selection()?;
        path.try_reserve(target.len().saturating_sub(current.len()))
            .map_err(|_| HardwareProfileError::Capacity)?;
        path.replace_range(start..end, target);
        Ok(())
    }
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
