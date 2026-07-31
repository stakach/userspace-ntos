//! ReactOS registry registrations that setup normally materializes into HKCR.
//!
//! The LiveCD image we boot is intentionally sparse: some COM class registrations that ReactOS
//! explorer expects are not present in the staged SOFTWARE hive. Keep the data here pure and
//! host-testable so the executive can seed its volatile registry overlay without embedding string
//! assembly in the syscall handler.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use crate::{canon_path, RegistryOverlay};

const REG_SZ: u32 = 1;

pub const REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU: u64 = 1 << 0;
pub const REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE: u64 = 1 << 1;

pub const CLSID_START_MENU: &str = "{4622AD11-FF23-11D0-8D34-00A0C90F2719}";
pub const CLSID_REBAR_BAND_SITE: &str = "{ECD4FC4D-521C-11D0-B792-00A0C90312E1}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactOsComClassRegistration {
    pub clsid: &'static str,
    pub description: &'static str,
    pub module: &'static str,
    pub threading_model: &'static str,
    pub mask_bit: u64,
}

/// COM classes explorer reaches through `base/shell/explorer/rshell.cpp` when `rshell.dll` is not
/// present beside the shell image.
pub const REACTOS_EXPLORER_SHELL_COM_CLASSES: &[ReactOsComClassRegistration] = &[
    ReactOsComClassRegistration {
        clsid: CLSID_START_MENU,
        description: "Start Menu",
        module: "shell32.dll",
        threading_model: "Apartment",
        mask_bit: REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU,
    },
    ReactOsComClassRegistration {
        clsid: CLSID_REBAR_BAND_SITE,
        description: "Shell Rebar BandSite",
        module: "browseui.dll",
        threading_model: "Apartment",
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

/// Seed explorer's shell COM classes under `classes_root` (normally
/// `\Registry\Machine\Software\Classes`) into the volatile overlay.
///
/// Returns the ORed class mask for every class written. The operation is idempotent: existing
/// overlay keys are opened and their values are replaced with the ReactOS registration values.
pub fn seed_reactos_explorer_shell_com_classes(
    overlay: &mut RegistryOverlay,
    classes_root: &str,
) -> u64 {
    let mut mask = 0;
    for reg in REACTOS_EXPLORER_SHELL_COM_CLASSES {
        let class_path = class_key(classes_root, reg.clsid);
        let class_canon = canon_path(&class_path);
        let (class_index, _) = overlay.create(&class_canon);
        let description = utf16le_sz(reg.description);
        overlay.set_value(class_index, "", REG_SZ, &description);

        let inproc_path = format!(r"{}\InprocServer32", class_path);
        let inproc_canon = canon_path(&inproc_path);
        let (inproc_index, _) = overlay.create(&inproc_canon);
        let module = utf16le_sz(reg.module);
        let threading_model = utf16le_sz(reg.threading_model);
        overlay.set_value(inproc_index, "", REG_SZ, &module);
        overlay.set_value(inproc_index, "ThreadingModel", REG_SZ, &threading_model);
        mask |= reg.mask_bit;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    fn value_bytes<'a>(overlay: &'a RegistryOverlay, key: &str, value: &str) -> (u32, &'a [u8]) {
        let idx = overlay.find(&canon_path(key)).expect("seeded key");
        overlay.value(idx, value).expect("seeded value")
    }

    #[test]
    fn utf16le_sz_is_nul_terminated() {
        assert_eq!(utf16le_sz("A"), alloc::vec![0x41, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn seeds_explorer_shell_com_classes() {
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
        assert_eq!(ty, REG_SZ);
        assert_eq!(data, utf16le_sz("Start Menu"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{4622AD11-FF23-11D0-8D34-00A0C90F2719}\InprocServer32",
            "",
        );
        assert_eq!(ty, REG_SZ);
        assert_eq!(data, utf16le_sz("shell32.dll"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\Registry\Machine\Software\Classes\CLSID\{ECD4FC4D-521C-11D0-B792-00A0C90312E1}\InprocServer32",
            "",
        );
        assert_eq!(ty, REG_SZ);
        assert_eq!(data, utf16le_sz("browseui.dll"));

        let (ty, data) = value_bytes(
            &overlay,
            r"\registry\machine\software\classes\clsid\{ecd4fc4d-521c-11d0-b792-00a0c90312e1}\inprocserver32",
            "threadingmodel",
        );
        assert_eq!(ty, REG_SZ);
        assert_eq!(data, utf16le_sz("Apartment"));
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
