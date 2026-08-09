//! ReactOS registry registrations that setup normally materializes into HKCR.
//!
//! The LiveCD image we boot is intentionally sparse: some COM class registrations that ReactOS
//! explorer expects are not present in the staged SOFTWARE hive. Keep the materialization here pure
//! and host-testable so the executive consumes ReactOS registration data instead of embedding COM
//! string assembly in the syscall handler.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use crate::{canon_path, MutableHiveSet, RegistryOverlay, RegistryValueType};

pub const REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU: u64 = 1 << 0;
pub const REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE: u64 = 1 << 1;

pub const CLSID_START_MENU: &str = "{4622AD11-FF23-11D0-8D34-00A0C90F2719}";
pub const CLSID_REBAR_BAND_SITE: &str = "{ECD4FC4D-521C-11D0-B792-00A0C90312E1}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactOsComClassRegistrationScript {
    pub clsid: &'static str,
    pub module: &'static str,
    pub source_path: &'static str,
    pub rgs: &'static str,
    pub mask_bit: u64,
}

/// COM classes explorer reaches through `base/shell/explorer/rshell.cpp` when `rshell.dll` is not
/// present beside the shell image. The source strings are the modules' own ATL/Wine `.rgs`
/// registration resources; `%MODULE%` is the setup-time module substitution.
pub const REACTOS_EXPLORER_SHELL_COM_REGISTRATION_SCRIPTS: &[ReactOsComClassRegistrationScript] = &[
    ReactOsComClassRegistrationScript {
        clsid: CLSID_START_MENU,
        module: "shell32.dll",
        source_path: "references/reactos/dll/win32/shell32/res/rgs/startmenu.rgs",
        rgs: include_str!("../../../references/reactos/dll/win32/shell32/res/rgs/startmenu.rgs"),
        mask_bit: REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU,
    },
    ReactOsComClassRegistrationScript {
        clsid: CLSID_REBAR_BAND_SITE,
        module: "browseui.dll",
        source_path: "references/reactos/dll/win32/browseui/res/rebarbandsite.rgs",
        rgs: include_str!("../../../references/reactos/dll/win32/browseui/res/rebarbandsite.rgs"),
        mask_bit: REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE,
    },
];

pub fn utf16le_sz(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for unit in s.encode_utf16() {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn class_key(classes_root: &str, clsid: &str) -> String {
    let root = classes_root.trim_end_matches('\\');
    format!(r"{}\CLSID\{}", root, clsid)
}

fn join_key_path(parent: &str, child: &str) -> String {
    let root = parent.trim_end_matches('\\');
    if root.is_empty() {
        canon_path(child)
    } else {
        canon_path(&format!(r"{}\{}", root, child))
    }
}

fn strip_line_comment(line: &str) -> &str {
    line.split_once("//").map_or(line, |(head, _)| head)
}

fn take_rgs_name(input: &str) -> Option<(&str, &str)> {
    let s = input.trim_start();
    let mut chars = s.char_indices();
    let (_, first) = chars.next()?;
    if first == '\'' {
        let end = s[1..].find('\'')? + 2;
        return Some((&s[1..end - 1], &s[end..]));
    }
    if first == '{' {
        let end = s.find('}')? + 1;
        return Some((&s[..end], &s[end..]));
    }

    let end = s
        .char_indices()
        .find_map(|(i, c)| (c.is_whitespace() || c == '=').then_some(i))
        .unwrap_or(s.len());
    (end != 0).then_some((&s[..end], &s[end..]))
}

fn parse_rgs_reg_sz(rest: &str, module: &str) -> Option<Vec<u8>> {
    let (_, after_equals) = rest.split_once('=')?;
    let after_equals = after_equals.trim_start();
    let after_type = after_equals.strip_prefix('s')?.trim_start();
    let value = after_type.strip_prefix('\'')?;
    let end = value.find('\'')?;
    let value = value[..end].replace("%MODULE%", module);
    Some(utf16le_sz(&value))
}

trait RgsSeedTarget {
    fn create_key(&mut self, path: &str) -> bool;
    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool;
    fn has_value(&self, path: &str, name: &str) -> bool;
}

struct OverlayRgsSeedTarget<'a> {
    overlay: &'a mut RegistryOverlay,
}

impl RgsSeedTarget for OverlayRgsSeedTarget<'_> {
    fn create_key(&mut self, path: &str) -> bool {
        self.overlay.create(&canon_path(path));
        true
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        let (index, _) = self.overlay.create(&canon_path(path));
        self.overlay
            .set_value(index, name, value_type as u32, &data)
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        self.overlay
            .find(&canon_path(path))
            .is_some_and(|index| self.overlay.value(index, name).is_some())
    }
}

struct MutableHiveRgsSeedTarget<'a> {
    hives: &'a mut MutableHiveSet,
}

impl RgsSeedTarget for MutableHiveRgsSeedTarget<'_> {
    fn create_key(&mut self, path: &str) -> bool {
        self.hives.create_key(&canon_path(path)).is_some()
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        let Some(key) = self.hives.create_key(&canon_path(path)) else {
            return false;
        };
        self.hives.set_value(key, name, value_type, data)
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        self.hives
            .resolve_key(&canon_path(path))
            .and_then(|key| self.hives.query_value(key, name))
            .is_some()
    }
}

fn seed_key_line<T: RgsSeedTarget>(
    target: &mut T,
    current: &str,
    line: &str,
    module: &str,
) -> Option<String> {
    let (name, rest) = take_rgs_name(line)?;
    let path = join_key_path(current, name);
    if !target.create_key(&path) {
        return None;
    }
    if let Some(data) = parse_rgs_reg_sz(rest, module) {
        target.set_value(&path, "", RegistryValueType::Sz, data);
    }
    Some(path)
}

fn seed_rgs_script<T: RgsSeedTarget>(
    target: &mut T,
    classes_root: &str,
    module: &str,
    rgs: &str,
) -> bool {
    let classes_root = canon_path(classes_root);
    let mut stack = Vec::<String>::new();
    let mut pending_key: Option<String> = None;
    let mut wrote_anything = false;

    for raw_line in rgs.lines() {
        let line = strip_line_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        match line {
            "{" => {
                let path = pending_key
                    .take()
                    .unwrap_or_else(|| stack.last().cloned().unwrap_or_default());
                if !path.is_empty() {
                    wrote_anything |= target.create_key(&path);
                }
                stack.push(path);
            }
            "}" => {
                stack.pop();
            }
            "HKCR" => {
                pending_key = Some(classes_root.clone());
            }
            _ => {
                let current = stack.last().map(String::as_str).unwrap_or("");
                if let Some(rest) = line.strip_prefix("NoRemove ") {
                    pending_key = seed_key_line(target, current, rest, module);
                    wrote_anything |= pending_key.is_some();
                } else if let Some(rest) = line.strip_prefix("ForceRemove ") {
                    pending_key = seed_key_line(target, current, rest, module);
                    wrote_anything |= pending_key.is_some();
                } else if let Some(rest) = line.strip_prefix("val ") {
                    if let Some((name, value_rest)) = take_rgs_name(rest) {
                        if target.create_key(current) {
                            if let Some(data) = parse_rgs_reg_sz(value_rest, module) {
                                wrote_anything |=
                                    target.set_value(current, name, RegistryValueType::Sz, data);
                            }
                        }
                    }
                } else {
                    pending_key = seed_key_line(target, current, line, module);
                    wrote_anything |= pending_key.is_some();
                }
            }
        }
    }

    wrote_anything
}

fn rgs_script_materialized_expected_class<T: RgsSeedTarget>(
    target: &T,
    classes_root: &str,
    clsid: &str,
) -> bool {
    let class_path = class_key(classes_root, clsid);
    let inproc_path = format!(r"{}\InprocServer32", class_key(classes_root, clsid));
    target.has_value(&class_path, "")
        && target.has_value(&inproc_path, "")
        && target.has_value(&inproc_path, "ThreadingModel")
}

fn seed_reactos_explorer_shell_com_classes_into<T: RgsSeedTarget>(
    target: &mut T,
    classes_root: &str,
) -> u64 {
    let mut mask = 0;
    for script in REACTOS_EXPLORER_SHELL_COM_REGISTRATION_SCRIPTS {
        if seed_rgs_script(target, classes_root, script.module, script.rgs)
            && rgs_script_materialized_expected_class(target, classes_root, script.clsid)
        {
            mask |= script.mask_bit;
        }
    }
    mask
}

/// Seed explorer's shell COM classes under `classes_root` (normally
/// `\Registry\Machine\Software\Classes`) into the volatile overlay.
///
/// Returns the ORed class mask for every class written. The operation is idempotent: existing
/// overlay keys are opened and their values are replaced with values parsed from ReactOS `.rgs`
/// registration resources.
pub fn seed_reactos_explorer_shell_com_classes(
    overlay: &mut RegistryOverlay,
    classes_root: &str,
) -> u64 {
    seed_reactos_explorer_shell_com_classes_into(
        &mut OverlayRgsSeedTarget { overlay },
        classes_root,
    )
}

/// Seed explorer's shell COM classes under `classes_root` into mounted mutable hives.
///
/// Unlike the overlay entry point, this is for persistent SOFTWARE/HKCR setup state. If
/// `classes_root` is not owned by a mounted hive, no class is reported as materialized.
pub fn seed_reactos_explorer_shell_com_classes_in_mutable_hives(
    hives: &mut MutableHiveSet,
    classes_root: &str,
) -> u64 {
    seed_reactos_explorer_shell_com_classes_into(
        &mut MutableHiveRgsSeedTarget { hives },
        classes_root,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Hive, HiveKind, MutableHiveSet};

    fn value_bytes<'a>(overlay: &'a RegistryOverlay, key: &str, value: &str) -> (u32, &'a [u8]) {
        let idx = overlay.find(&canon_path(key)).expect("seeded key");
        overlay.value(idx, value).expect("seeded value")
    }

    fn hive_value_bytes<'a>(
        hives: &'a MutableHiveSet,
        key: &str,
        value: &str,
    ) -> (RegistryValueType, &'a [u8]) {
        let key = hives.resolve_key(key).expect("seeded hive key");
        hives.query_value(key, value).expect("seeded hive value")
    }

    #[test]
    fn utf16le_sz_is_nul_terminated() {
        assert_eq!(utf16le_sz("A"), alloc::vec![0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn rgs_subset_parser_materializes_hkcr_keys_and_values() {
        let mut overlay = RegistryOverlay::new();
        assert!(seed_rgs_script(
            &mut OverlayRgsSeedTarget {
                overlay: &mut overlay,
            },
            r"\Registry\Machine\Software\Classes",
            "sample.dll",
            r"
                HKCR
                {
                    NoRemove CLSID
                    {
                        ForceRemove {11111111-2222-3333-4444-555555555555} = s 'Sample Class'
                        {
                            InprocServer32 = s '%MODULE%'
                            {
                                val ThreadingModel = s 'Apartment'
                            }
                        }
                    }
                }
            ",
        ));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("Sample Class"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{11111111-2222-3333-4444-555555555555}\InprocServer32",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("sample.dll"));
    }

    #[test]
    fn seeds_explorer_shell_com_classes_from_reactos_rgs() {
        let mut overlay = RegistryOverlay::new();
        let mask = seed_reactos_explorer_shell_com_classes(
            &mut overlay,
            r"\Registry\Machine\Software\Classes",
        );
        assert_eq!(
            mask,
            REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU
                | REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE
        );

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{4622ad11-ff23-11d0-8d34-00a0c90f2719}",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("Start Menu"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{4622AD11-FF23-11D0-8D34-00A0C90F2719}\InprocServer32",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("shell32.dll"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{ECD4FC4D-521C-11D0-B792-00A0C90312E1}\InprocServer32",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("browseui.dll"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{ECD4FC4D-521C-11D0-B792-00A0C90312E1}",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("Shell Rebar BandSite"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\registry\machine\software\classes\clsid\{ecd4fc4d-521c-11d0-b792-00a0c90312e1}\inprocserver32",
            "threadingmodel",
        );
        assert_eq!(ty, RegistryValueType::Sz as u32);
        assert_eq!(data, utf16le_sz("Apartment"));
    }

    #[test]
    fn seeds_explorer_shell_com_classes_into_mutable_software_hive() {
        let mut hives = MutableHiveSet::new();
        hives.mount(
            r"\Registry\Machine\Software",
            2,
            Hive::new(HiveKind::Software),
        );

        let mask = seed_reactos_explorer_shell_com_classes_in_mutable_hives(
            &mut hives,
            r"\Registry\Machine\Software\Classes",
        );
        assert_eq!(
            mask,
            REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU
                | REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE
        );

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\Machine\Software\Classes\CLSID\{4622ad11-ff23-11d0-8d34-00a0c90f2719}",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("Start Menu"));

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\Machine\Software\Classes\CLSID\{4622AD11-FF23-11D0-8D34-00A0C90F2719}\InprocServer32",
            "",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("shell32.dll"));

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\registry\machine\software\classes\clsid\{ecd4fc4d-521c-11d0-b792-00a0c90312e1}\inprocserver32",
            "threadingmodel",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("Apartment"));

        let first_cell_count = hives.hive(2).expect("software hive").cell_count();
        let second_mask = seed_reactos_explorer_shell_com_classes_in_mutable_hives(
            &mut hives,
            r"\Registry\Machine\Software\Classes",
        );
        assert_eq!(second_mask, mask);
        assert_eq!(
            hives.hive(2).expect("software hive").cell_count(),
            first_cell_count
        );
    }

    #[test]
    fn seeding_is_idempotent() {
        let mut overlay = RegistryOverlay::new();
        seed_reactos_explorer_shell_com_classes(
            &mut overlay,
            r"\Registry\Machine\Software\Classes",
        );
        let first_len = overlay.len();
        seed_reactos_explorer_shell_com_classes(
            &mut overlay,
            r"\Registry\Machine\Software\Classes",
        );
        assert_eq!(overlay.len(), first_len);
    }
}
