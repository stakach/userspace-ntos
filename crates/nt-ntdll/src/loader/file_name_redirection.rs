//! Which image file a requested DLL name loads, and which loaded module already is that image.
//!
//! ReactOS `LdrpApplyFileNameRedirection` (`dll/ntdll/rtl/libsupp.c`) rewrites a requested name
//! before the loader looks for a loaded module or opens a file: an api-set contract becomes its
//! host DLL in System32, and otherwise an activation-context DLL redirection becomes the full
//! path of the side-by-side copy. `LdrpCheckForLoadedDll` (`dll/ntdll/ldr/ldrutils.c`) then
//! matches a redirected name by full path and any other name by base name, so two images with
//! the same base name (System32 `comctl32.dll` and the WinSxS 6.0 copy) are different modules.

use super::api_set::{resolve_api_set, ApiSetEntry, ApiSetHost};

pub const STATUS_INVALID_PARAMETER: u32 = 0xc000_000d;
pub const STATUS_NAME_TOO_LONG: u32 = 0xc000_0106;
pub const STATUS_DLL_NOT_FOUND: u32 = 0xc000_0135;

/// Longest module key: a base name without its `.dll` suffix.
pub const KEY_CAPACITY: usize = 64;
/// Longest name or path handed to the file open.
pub const OPEN_CAPACITY: usize = 160;

/// How a loaded module is recognised as the image a name refers to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModuleIdentity {
    /// An unredirected name: the first loaded module with this base name.
    BaseName,
    /// Redirected into System32: the module with this base name that was loaded from there.
    System32,
    /// Redirected elsewhere: the module loaded from exactly this path.
    Path,
}

/// A DLL name as the loader uses it: lowercase ASCII, with the module key split from the name
/// that is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadName {
    key: [u8; KEY_CAPACITY],
    key_len: usize,
    open: [u8; OPEN_CAPACITY],
    open_len: usize,
    identity: ModuleIdentity,
}

fn leaf(name: &[u8]) -> &[u8] {
    let start = name
        .iter()
        .rposition(|byte| matches!(byte, b'\\' | b'/'))
        .map_or(0, |index| index + 1);
    &name[start..]
}

fn stem(leaf: &[u8]) -> &[u8] {
    leaf.strip_suffix(b".dll").unwrap_or(leaf)
}

impl LoadName {
    /// The caller's spelling, from a counted string or an import descriptor. Forward slashes
    /// become backslashes and ASCII letters are folded, as the module table expects.
    pub fn from_requested(units: impl IntoIterator<Item = u16>) -> Result<Self, u32> {
        let mut open = [0u8; OPEN_CAPACITY];
        let mut open_len = 0;
        for unit in units {
            if unit > 0x7f {
                return Err(STATUS_INVALID_PARAMETER);
            }
            if open_len == OPEN_CAPACITY {
                return Err(STATUS_NAME_TOO_LONG);
            }
            let byte = (unit as u8).to_ascii_lowercase();
            open[open_len] = if byte == b'/' { b'\\' } else { byte };
            open_len += 1;
        }
        Self::from_open(open, open_len, ModuleIdentity::BaseName)
    }

    fn from_open(
        open: [u8; OPEN_CAPACITY],
        open_len: usize,
        identity: ModuleIdentity,
    ) -> Result<Self, u32> {
        let stem = stem(leaf(&open[..open_len]));
        if stem.is_empty() {
            return Err(STATUS_INVALID_PARAMETER);
        }
        if stem.len() > KEY_CAPACITY {
            return Err(STATUS_NAME_TOO_LONG);
        }
        let mut key = [0u8; KEY_CAPACITY];
        key[..stem.len()].copy_from_slice(stem);
        Ok(Self {
            key,
            key_len: stem.len(),
            open,
            open_len,
            identity,
        })
    }

    /// Lowercase base name without a trailing `.dll`.
    pub fn key(&self) -> &[u8] {
        &self.key[..self.key_len]
    }

    /// The name or path to open.
    pub fn open_name(&self) -> &[u8] {
        &self.open[..self.open_len]
    }

    pub fn identity(&self) -> ModuleIdentity {
        self.identity
    }

    /// The path that identifies the module once loaded; empty for a System32 image.
    pub fn module_path(&self) -> &[u8] {
        match self.identity {
            ModuleIdentity::Path => self.open_name(),
            ModuleIdentity::BaseName | ModuleIdentity::System32 => &[],
        }
    }

    /// First step of `LdrpApplyFileNameRedirection`: a contract of `table` that is active for
    /// `versions` is replaced by its host DLL in System32. Returns whether the name was a
    /// resolved contract.
    pub fn apply_api_set(&mut self, table: &[ApiSetEntry], versions: u8) -> Result<bool, u32> {
        let host = match resolve_api_set(table, self.open_name(), versions) {
            ApiSetHost::NotAContract => return Ok(false),
            // ReactOS composes `System32\` plus the empty host and fails to load it.
            ApiSetHost::Unhosted => return Err(STATUS_DLL_NOT_FOUND),
            ApiSetHost::Host(host) => host.as_bytes(),
        };
        let mut open = [0u8; OPEN_CAPACITY];
        if host.len() > OPEN_CAPACITY {
            return Err(STATUS_NAME_TOO_LONG);
        }
        open[..host.len()].copy_from_slice(host);
        *self = Self::from_open(open, host.len(), ModuleIdentity::System32)?;
        Ok(true)
    }

    /// Second step: the activation context redirected the name to `path` (a DOS path).
    pub fn apply_redirected_path(&mut self, path: &[u16], system_root: &[u16]) -> Result<(), u32> {
        let redirected = Self::from_requested(path.iter().copied())?;
        let full = redirected.open_name();
        let leaf_start = full.len() - leaf(full).len();
        *self = if directory_is_system32(&full[..leaf_start], system_root) {
            let mut open = [0u8; OPEN_CAPACITY];
            let leaf = &full[leaf_start..];
            open[..leaf.len()].copy_from_slice(leaf);
            Self::from_open(open, leaf.len(), ModuleIdentity::System32)?
        } else {
            Self {
                identity: ModuleIdentity::Path,
                ..redirected
            }
        };
        Ok(())
    }

    /// Whether a loaded module, recorded under `key` and loaded from `path` (empty for System32),
    /// is the image this name refers to.
    pub fn is_loaded_module(&self, key: &[u8], path: &[u8]) -> bool {
        match self.identity {
            ModuleIdentity::BaseName => key == self.key(),
            ModuleIdentity::System32 => key == self.key() && path.is_empty(),
            ModuleIdentity::Path => path == self.open_name(),
        }
    }
}

/// `directory` is lowercase with a trailing separator; `system_root` is as the system reports it.
fn directory_is_system32(directory: &[u8], system_root: &[u16]) -> bool {
    let mut root_len = system_root.len();
    while root_len != 0 && matches!(system_root[root_len - 1], 0x5c | 0x2f) {
        root_len -= 1;
    }
    const SYSTEM32: &[u8] = b"\\system32\\";
    directory.len() == root_len + SYSTEM32.len()
        && directory[root_len..] == *SYSTEM32
        && directory[..root_len]
            .iter()
            .zip(&system_root[..root_len])
            .all(|(&byte, &unit)| unit < 0x80 && (unit as u8).to_ascii_lowercase() == byte)
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use super::*;
    use crate::loader::api_set::{APISET_WIN10, RELEASE_ROWS};
    use crate::rtl::activation_dependency::{
        resolve_activation_dependencies, ActivationManifestCatalog, ActivationManifestSource,
        ActivationResolverLimits, AssemblyRequest,
    };
    use crate::rtl::activation_redirection::compose_redirected_path;
    use crate::rtl::activation_section::{
        build_dll_redirection_section_for_assemblies, build_window_class_redirection_section,
        decode_dll_redirection, find_dll_redirection, find_window_class_redirection,
        DllRedirectAssembly, WindowClassAssembly,
    };
    use crate::NtStatus;

    fn wide(value: &str) -> Vec<u16> {
        value.encode_utf16().collect()
    }

    fn requested(name: &str) -> LoadName {
        LoadName::from_requested(name.encode_utf16()).unwrap()
    }

    /// The manifest embedded in the released `explorer.exe` (resource 1).
    const EXPLORER_MANIFEST: &[u8] = br#"<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
<assemblyIdentity
    version="1.0.0.0"
    processorArchitecture="*"
    name="ReactOS.Explorer"
    type="win32"
/>
<description>This is ReactOS Explorer</description>
<dependency>
    <dependentAssembly>
        <assemblyIdentity
            type="win32"
            name="Microsoft.Windows.Common-Controls"
            version="6.0.0.0"
            processorArchitecture="*"
            publicKeyToken="6595b64144ccf1df"
            language="*"
        />
    </dependentAssembly>
</dependency>
<application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
        <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
        <dpiAwareness xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">system</dpiAwareness>
    </windowsSettings>
</application>
</assembly>
"#;
    /// `WinSxS\manifests\amd64_microsoft.windows.common-controls_..._6.0.2600.2982_none_deadbeef.manifest`.
    const COMMON_CONTROLS_600: &[u8] = include_bytes!(
        "../../../../references/reactos/dll/win32/comctl32/amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef.manifest"
    );
    const ASSEMBLY: &str =
        "amd64_microsoft.windows.common-controls_6595b64144ccf1df_6.0.2600.2982_none_deadbeef";
    const SYSTEM_ROOT: &str = "C:\\Windows";

    struct WinSxs;

    impl ActivationManifestCatalog for WinSxs {
        fn resolve(
            &mut self,
            request: &AssemblyRequest,
        ) -> Result<Option<ActivationManifestSource>, NtStatus> {
            let name = request.identity.name.as_deref().unwrap_or(&[]);
            Ok((name == wide("Microsoft.Windows.Common-Controls")).then(|| {
                ActivationManifestSource {
                    source: wide(&alloc::format!(
                        "{SYSTEM_ROOT}\\WinSxS\\manifests\\{ASSEMBLY}.manifest"
                    )),
                    manifest_path: wide(&alloc::format!(
                        "{SYSTEM_ROOT}\\WinSxS\\manifests\\{ASSEMBLY}.manifest"
                    )),
                    assembly_directory: wide(ASSEMBLY),
                    manifest: COMMON_CONTROLS_600.to_vec(),
                    shared: true,
                }
            }))
        }
    }

    /// Explorer's process activation context, as far as DLL and window-class redirection go:
    /// the path `comctl32.dll` is redirected to, and the module the class `Static` names.
    fn explorer_redirections() -> (Vec<u16>, Vec<u16>, Vec<u16>) {
        let resolved = resolve_activation_dependencies(
            ActivationManifestSource {
                source: wide("C:\\Windows\\explorer.exe"),
                manifest_path: wide("C:\\Windows\\explorer.exe"),
                assembly_directory: Vec::new(),
                manifest: EXPLORER_MANIFEST.to_vec(),
                shared: false,
            },
            Some(&wide("amd64")),
            ActivationResolverLimits::default(),
            &mut WinSxs,
        )
        .unwrap();
        assert_eq!(resolved.assemblies.len(), 2);

        let dll_assemblies: Vec<_> = resolved
            .assemblies
            .iter()
            .map(|assembly| DllRedirectAssembly {
                redirects: &assembly.details.root.dll_redirects,
            })
            .collect();
        let dll_section = build_dll_redirection_section_for_assemblies(&dll_assemblies).unwrap();
        let lookup = wide("comctl32.dll");
        let found = find_dll_redirection(&dll_section, &lookup).unwrap().unwrap();
        let assembly = &resolved.assemblies[found.assembly_roster_index as usize - 1];
        let path = compose_redirected_path(
            &decode_dll_redirection(&dll_section, found).unwrap(),
            &assembly.source.manifest_path,
            &assembly.source.assembly_directory,
            &wide(SYSTEM_ROOT),
            &lookup,
        )
        .unwrap();

        let class_assemblies: Vec<_> = resolved
            .assemblies
            .iter()
            .map(|assembly| WindowClassAssembly {
                version: assembly.details.root.assembly_identity.version,
                files: &assembly.details.root.dll_redirects,
                classes: &assembly.details.window_classes,
            })
            .collect();
        let class_section = build_window_class_redirection_section(&class_assemblies).unwrap();
        let class = find_window_class_redirection(&class_section, 2, &wide("Static"))
            .unwrap()
            .unwrap();
        // user32 `ClassNameToVersion`: versioned name at data + name_offset, module at
        // section base + module_offset.
        let units = |offset: usize, bytes: usize| -> Vec<u16> {
            class_section[offset..offset + bytes]
                .chunks_exact(2)
                .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
                .collect()
        };
        let data = class.data_offset as usize;
        let field = |index: usize| {
            u32::from_le_bytes(class_section[data + index..data + index + 4].try_into().unwrap())
                as usize
        };
        let versioned = units(data + field(12), field(8));
        let module = units(field(20), field(16));
        (path, versioned, module)
    }

    #[test]
    fn explorer_comctl32_is_the_side_by_side_copy_not_the_loaded_system32_one() {
        let (path, versioned, module) = explorer_redirections();
        assert_eq!(versioned, wide("6.0.2600.2982!Static"));
        assert_eq!(module, wide("comctl32.dll"));
        assert_eq!(
            path,
            wide(&alloc::format!("{SYSTEM_ROOT}\\winsxs\\{ASSEMBLY}\\comctl32.dll"))
        );

        // user32 `VersionRegisterClass` calls `LoadLibraryW(module)` under that context.
        let mut name = LoadName::from_requested(module.iter().copied()).unwrap();
        assert!(!name.apply_api_set(RELEASE_ROWS, APISET_WIN10).unwrap());
        name.apply_redirected_path(&path, &wide(SYSTEM_ROOT)).unwrap();
        assert_eq!(name.identity(), ModuleIdentity::Path);
        assert_eq!(name.key(), b"comctl32");
        let side_by_side =
            alloc::format!("c:\\windows\\winsxs\\{ASSEMBLY}\\comctl32.dll").into_bytes();
        assert_eq!(name.open_name(), side_by_side);
        assert_eq!(name.module_path(), side_by_side);

        // The System32 copy (5.82, no versioned classes) is a different module.
        assert!(!name.is_loaded_module(b"comctl32", b""));
        assert!(name.is_loaded_module(b"comctl32", &side_by_side));
        // Without a redirection the name is the first module with that base name.
        let plain = requested("comctl32.dll");
        assert_eq!(plain.identity(), ModuleIdentity::BaseName);
        assert!(plain.is_loaded_module(b"comctl32", b""));
        assert!(plain.is_loaded_module(b"comctl32", &side_by_side));
    }

    #[test]
    fn redirection_into_system32_names_the_system32_module() {
        let mut name = requested("comctl32.dll");
        name.apply_redirected_path(&wide("C:\\Windows\\System32\\comctl32.dll"), &wide("c:\\windows\\"))
            .unwrap();
        assert_eq!(name.identity(), ModuleIdentity::System32);
        assert_eq!(name.open_name(), b"comctl32.dll");
        assert!(name.module_path().is_empty());
        assert!(name.is_loaded_module(b"comctl32", b""));
        assert!(!name.is_loaded_module(b"comctl32", b"c:\\windows\\winsxs\\x\\comctl32.dll"));

        let mut other = requested("comctl32.dll");
        other
            .apply_redirected_path(&wide("C:\\Windows\\System32x\\comctl32.dll"), &wide("C:\\Windows"))
            .unwrap();
        assert_eq!(other.identity(), ModuleIdentity::Path);
    }

    #[test]
    fn api_set_contracts_load_their_host_from_system32() {
        // dwm.exe's import descriptor.
        let mut dwm = requested("api-ms-win-composition-windowmanager-l1-1-0.dll");
        assert!(dwm.apply_api_set(RELEASE_ROWS, APISET_WIN10).unwrap());
        assert_eq!(dwm.key(), b"udwm");
        assert_eq!(dwm.open_name(), b"udwm.dll");
        assert_eq!(dwm.identity(), ModuleIdentity::System32);

        // `LoadLibraryExW(L"api-ms-win-core-localization-l1-2-1", ...)`: 35 characters, no
        // extension. It used to be refused with STATUS_INVALID_PARAMETER for its length.
        let mut localization = requested("api-ms-win-core-localization-l1-2-1");
        assert!(localization.apply_api_set(RELEASE_ROWS, APISET_WIN10).unwrap());
        assert_eq!(localization.key(), b"kernel32");
        assert!(localization.is_loaded_module(b"kernel32", b""));

        let mut synch = requested("API-MS-Win-Core-Synch-L1-2-0");
        assert!(synch.apply_api_set(RELEASE_ROWS, APISET_WIN10).unwrap());
        assert_eq!(synch.open_name(), b"kernelbase.dll");
    }

    #[test]
    fn names_that_are_not_active_contracts_are_left_alone() {
        for name in [
            "kernel32.dll",
            "api-ms-win-no-such-contract-l1-1-0.dll",
            "c:\\dir\\api-ms-win-core-synch-l1-2-0.dll",
            "apisetschema.dll",
        ] {
            let mut load = requested(name);
            let before = load;
            assert!(!load.apply_api_set(RELEASE_ROWS, APISET_WIN10).unwrap(), "{name}");
            assert_eq!(load, before);
        }
        // A contract with no host in this release cannot be loaded.
        let mut unhosted = requested("ext-ms-win-ntos-ksr-l1-1-5.dll");
        assert_eq!(unhosted.apply_api_set(RELEASE_ROWS, APISET_WIN10), Err(STATUS_DLL_NOT_FOUND));
    }

    #[test]
    fn requested_names_keep_paths_and_report_their_real_limit() {
        let path = requested("C:/Windows/System32/wbem/WmiSvc.DLL");
        assert_eq!(path.open_name(), b"c:\\windows\\system32\\wbem\\wmisvc.dll");
        assert_eq!(path.key(), b"wmisvc");
        assert_eq!(requested("winspool.drv").key(), b"winspool.drv");
        assert_eq!(requested("kernel32").key(), b"kernel32");

        assert_eq!(LoadName::from_requested([]), Err(STATUS_INVALID_PARAMETER));
        assert_eq!(
            LoadName::from_requested("dir\\".encode_utf16()),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            LoadName::from_requested([0x4e2d, b'.' as u16]),
            Err(STATUS_INVALID_PARAMETER)
        );
        assert_eq!(
            LoadName::from_requested(vec![b'a' as u16; KEY_CAPACITY + 1]),
            Err(STATUS_NAME_TOO_LONG)
        );
        assert_eq!(
            LoadName::from_requested(vec![b'a' as u16; OPEN_CAPACITY + 1]),
            Err(STATUS_NAME_TOO_LONG)
        );
        assert_eq!(
            LoadName::from_requested(vec![b'a' as u16; KEY_CAPACITY]).unwrap().key().len(),
            KEY_CAPACITY
        );
    }
}
