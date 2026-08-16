//! ReactOS registry registrations that setup normally materializes into HKCR.
//!
//! The LiveCD image we boot is intentionally sparse: some COM class registrations that ReactOS
//! explorer expects are not present in the staged SOFTWARE hive. Keep the materialization here pure
//! and host-testable so the executive consumes ReactOS registration data instead of embedding COM
//! string assembly in the syscall handler.

extern crate alloc;

use alloc::{format, string::String, vec::Vec};

use crate::{canon_path, MutableHiveSet, RegistryOverlay, RegistryValueType};
use nt_config_manager::{
    CONTROL_CLASS_PATH, SERVICES_PATH, SERVICE_BOOT_START, SERVICE_KERNEL_DRIVER,
    SERVICE_SYSTEM_START,
};

pub const REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_START_MENU: u64 = 1 << 0;
pub const REACTOS_EXPLORER_SHELL_COM_CLASS_MASK_REBAR_BAND_SITE: u64 = 1 << 1;

pub const CLSID_START_MENU: &str = "{4622AD11-FF23-11D0-8D34-00A0C90F2719}";
pub const CLSID_REBAR_BAND_SITE: &str = "{ECD4FC4D-521C-11D0-B792-00A0C90312E1}";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactOsPrintEnvironmentRegistration {
    pub environment: &'static str,
    pub directory: &'static str,
    pub print_processor: &'static str,
    pub processor_driver: &'static str,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReactOsPrintSetupSeedStats {
    pub root_values: u32,
    pub environment_values: u32,
    pub print_processor_values: u32,
    pub monitor_values: u32,
}

impl ReactOsPrintSetupSeedStats {
    pub fn total_values(self) -> u32 {
        self.root_values
            + self.environment_values
            + self.print_processor_values
            + self.monitor_values
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ReactOsKernelDriverServiceRegistration {
    service_name: &'static str,
    image_path: &'static str,
    start_type: u32,
    error_control: u32,
    group: &'static str,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReactOsNetworkSetupSeedStats {
    pub ndis_service_values: u32,
    pub tcpip_service_values: u32,
    pub tcpip_parameter_values: u32,
    pub tcpip_linkage_values: u32,
    pub tcpip_interface_values: u32,
    pub network_adapter_class_values: u32,
    pub network_connection_values: u32,
    pub afd_service_values: u32,
}

impl ReactOsNetworkSetupSeedStats {
    pub fn total_values(self) -> u32 {
        self.ndis_service_values
            + self.tcpip_service_values
            + self.tcpip_parameter_values
            + self.tcpip_linkage_values
            + self.tcpip_interface_values
            + self.network_adapter_class_values
            + self.network_connection_values
            + self.afd_service_values
    }
}

const NET_CLASS_GUID: &str = "{4D36E972-E325-11CE-BFC1-08002BE10318}";
const TCPIP_LINKAGE_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Linkage";
const TCPIP_INTERFACES_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
const CONTROL_NETWORK_NET_CLASS_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}";

/// ReactOS `boot/bootdata/hivesys.inf` print setup registrations.
///
/// The base `AddReg` block always creates the x86 environment, while `AddReg.NTamd64` creates the
/// native x64 environment. Hosted x64 `localspl.dll` asks for `"Windows x64"` from
/// `win32ss/printing/include/prtprocenv.h`, so the setup materialization must expose that section.
pub const REACTOS_PRINT_ENVIRONMENTS: &[ReactOsPrintEnvironmentRegistration] = &[
    ReactOsPrintEnvironmentRegistration {
        environment: "Windows NT x86",
        directory: "W32X86",
        print_processor: "winprint",
        processor_driver: "winprint.dll",
    },
    ReactOsPrintEnvironmentRegistration {
        environment: "Windows x64",
        directory: "x64",
        print_processor: "winprint",
        processor_driver: "winprint.dll",
    },
];

/// ReactOS network driver setup registrations.
///
/// `Ndis` comes from `boot/bootdata/hivesys.inf`, `Tcpip` comes from
/// `media/inf/nettcpip.inf`, and `Afd` comes from `drivers/network/afd/afd_reg.inf`.
const REACTOS_NETWORK_DRIVER_SERVICES: &[ReactOsKernelDriverServiceRegistration] = &[
    ReactOsKernelDriverServiceRegistration {
        service_name: "Ndis",
        image_path: r"system32\drivers\ndis.sys",
        start_type: SERVICE_BOOT_START,
        error_control: 1,
        group: "NDIS Wrapper",
    },
    ReactOsKernelDriverServiceRegistration {
        service_name: "Tcpip",
        image_path: r"system32\drivers\tcpip.sys",
        start_type: SERVICE_SYSTEM_START,
        error_control: 1,
        group: "PNP_TDI",
    },
    ReactOsKernelDriverServiceRegistration {
        service_name: "Afd",
        image_path: r"system32\drivers\afd.sys",
        start_type: SERVICE_SYSTEM_START,
        error_control: 1,
        group: "TDI",
    },
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReactOsProfileShellFolder {
    pub value_name: &'static str,
    pub path: &'static str,
    pub shell_folder: bool,
    pub user_shell_folder: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ReactOsProfileShellFolderSeedStats {
    pub shell_folder_values: u32,
    pub user_shell_folder_values: u32,
}

impl ReactOsProfileShellFolderSeedStats {
    pub fn total_values(self) -> u32 {
        self.shell_folder_values + self.user_shell_folder_values
    }
}

/// ReactOS `dll/win32/userenv/setup.c` `UserShellFolders`. The resource-backed localized names
/// fall back to these literal paths, which match the LiveCD profile tree staged for this bring-up.
pub const REACTOS_USER_PROFILE_SHELL_FOLDERS: &[ReactOsProfileShellFolder] = &[
    ReactOsProfileShellFolder {
        value_name: "AppData",
        path: "Application Data",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Desktop",
        path: "Desktop",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Favorites",
        path: "Favorites",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Personal",
        path: "My Documents",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "NetHood",
        path: "NetHood",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "PrintHood",
        path: "PrintHood",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Recent",
        path: "Recent",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "SendTo",
        path: "SendTo",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Templates",
        path: "Templates",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Start Menu",
        path: "Start Menu",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Programs",
        path: r"Start Menu\Programs",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Startup",
        path: r"Start Menu\Programs\Startup",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Local Settings",
        path: "Local Settings",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Local AppData",
        path: r"Local Settings\Application Data",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Temp",
        path: r"Local Settings\Temp",
        shell_folder: false,
        user_shell_folder: false,
    },
    ReactOsProfileShellFolder {
        value_name: "Cache",
        path: r"Local Settings\Temporary Internet Files",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "History",
        path: r"Local Settings\History",
        shell_folder: true,
        user_shell_folder: true,
    },
    ReactOsProfileShellFolder {
        value_name: "Cookies",
        path: "Cookies",
        shell_folder: true,
        user_shell_folder: true,
    },
];

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
    let mut out = Vec::with_capacity((s.encode_utf16().count() + 1) * 2);
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

fn join_registry_profile_path(profile_root: &str, child: &str) -> String {
    let root = profile_root.trim_end_matches('\\');
    if root.is_empty() {
        String::from(child)
    } else if child.is_empty() {
        String::from(root)
    } else {
        format!(r"{}\{}", root, child)
    }
}

fn dword_bytes(value: u32) -> Vec<u8> {
    value.to_le_bytes().to_vec()
}

fn set_setup_dword<T: ReactOsSetupSeedTarget>(
    target: &mut T,
    path: &str,
    name: &str,
    value: u32,
) -> bool {
    target.set_value(path, name, RegistryValueType::Dword, dword_bytes(value))
}

fn set_setup_sz<T: ReactOsSetupSeedTarget>(
    target: &mut T,
    path: &str,
    name: &str,
    value: &str,
) -> bool {
    target.set_value(path, name, RegistryValueType::Sz, utf16le_sz(value))
}

fn set_setup_expand_sz<T: ReactOsSetupSeedTarget>(
    target: &mut T,
    path: &str,
    name: &str,
    value: &str,
) -> bool {
    target.set_value(path, name, RegistryValueType::ExpandSz, utf16le_sz(value))
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
    let value = &value[..end];
    if value.contains("%MODULE%") {
        Some(utf16le_sz(&value.replace("%MODULE%", module)))
    } else {
        Some(utf16le_sz(value))
    }
}

/// Destination for ReactOS setup registry materialization.
///
/// The parser and setup tables in this module are pure data/logic; callers decide whether writes
/// land in the volatile overlay, a host-test mutable hive set, or the executive's journal-backed
/// Configuration Manager provider.
pub trait ReactOsSetupSeedTarget {
    fn create_key(&mut self, path: &str) -> bool;
    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool;
    fn has_value(&self, path: &str, name: &str) -> bool;
    fn value_matches(
        &self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> bool;
}

struct OverlayRgsSeedTarget<'a> {
    overlay: &'a mut RegistryOverlay,
}

impl ReactOsSetupSeedTarget for OverlayRgsSeedTarget<'_> {
    fn create_key(&mut self, path: &str) -> bool {
        self.overlay.create(path);
        true
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        if self.value_matches(path, name, value_type, &data) {
            return false;
        }
        let (index, _) = self.overlay.create(path);
        self.overlay
            .set_value(index, name, value_type as u32, &data)
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        self.overlay
            .find(path)
            .is_some_and(|index| self.overlay.value(index, name).is_some())
    }

    fn value_matches(
        &self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> bool {
        self.overlay.find(path).is_some_and(|index| {
            self.overlay
                .value(index, name)
                .is_some_and(|(ty, existing)| ty == value_type as u32 && existing == data)
        })
    }
}

struct MutableHiveRgsSeedTarget<'a> {
    hives: &'a mut MutableHiveSet,
}

impl ReactOsSetupSeedTarget for MutableHiveRgsSeedTarget<'_> {
    fn create_key(&mut self, path: &str) -> bool {
        self.hives.create_key(path).is_some()
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        if self.value_matches(path, name, value_type, &data) {
            return false;
        }
        let Some(key) = self.hives.create_key(path) else {
            return false;
        };
        self.hives.set_value(key, name, value_type, data)
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        self.hives
            .resolve_key(path)
            .and_then(|key| self.hives.query_value(key, name))
            .is_some()
    }

    fn value_matches(
        &self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> bool {
        self.hives
            .resolve_key(path)
            .and_then(|key| self.hives.query_value(key, name))
            .is_some_and(|(ty, existing)| ty == value_type && existing == data)
    }
}

struct ConfigManagerSetupSeedTarget<'a> {
    cm: &'a mut nt_config_manager::ConfigManager,
}

impl ReactOsSetupSeedTarget for ConfigManagerSetupSeedTarget<'_> {
    fn create_key(&mut self, path: &str) -> bool {
        self.cm.registry_mut().create_key(path);
        true
    }

    fn set_value(
        &mut self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        if self.value_matches(path, name, value_type, &data) {
            return false;
        }
        let key = self.cm.registry_mut().create_key(path);
        self.cm
            .registry_mut()
            .set_value(key, name, value_type, data)
    }

    fn has_value(&self, path: &str, name: &str) -> bool {
        self.cm
            .registry()
            .open_key(path)
            .is_some_and(|key| self.cm.registry().query_value(key, name).is_some())
    }

    fn value_matches(
        &self,
        path: &str,
        name: &str,
        value_type: RegistryValueType,
        data: &[u8],
    ) -> bool {
        self.cm
            .registry()
            .open_key(path)
            .and_then(|key| self.cm.registry().query_value(key, name))
            .is_some_and(|existing| existing.value_type == value_type && existing.data == data)
    }
}

fn seed_key_line<T: ReactOsSetupSeedTarget>(
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

fn seed_rgs_script<T: ReactOsSetupSeedTarget>(
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

fn rgs_script_materialized_expected_class<T: ReactOsSetupSeedTarget>(
    target: &T,
    classes_root: &str,
    clsid: &str,
) -> bool {
    let class_path = canon_path(&class_key(classes_root, clsid));
    let inproc_path = join_key_path(&class_path, "InprocServer32");
    target.has_value(&class_path, "")
        && target.has_value(&inproc_path, "")
        && target.has_value(&inproc_path, "ThreadingModel")
}

pub fn seed_reactos_explorer_shell_com_classes_into_target<T: ReactOsSetupSeedTarget>(
    target: &mut T,
    classes_root: &str,
) -> u64 {
    let mut mask = 0;
    for script in REACTOS_EXPLORER_SHELL_COM_REGISTRATION_SCRIPTS {
        let _ = seed_rgs_script(target, classes_root, script.module, script.rgs);
        if rgs_script_materialized_expected_class(target, classes_root, script.clsid) {
            mask |= script.mask_bit;
        }
    }
    mask
}

pub fn seed_reactos_user_profile_shell_folders_into_target<T: ReactOsSetupSeedTarget>(
    target: &mut T,
    user_hive_root: &str,
    profile_path: &str,
    user_shell_profile_root: &str,
) -> ReactOsProfileShellFolderSeedStats {
    let shell_key = join_key_path(
        user_hive_root,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
    );
    let user_shell_key = join_key_path(
        user_hive_root,
        r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
    );
    if !target.create_key(&shell_key) || !target.create_key(&user_shell_key) {
        return ReactOsProfileShellFolderSeedStats::default();
    }

    let mut stats = ReactOsProfileShellFolderSeedStats::default();
    for folder in REACTOS_USER_PROFILE_SHELL_FOLDERS {
        if folder.shell_folder {
            let path = join_registry_profile_path(profile_path, folder.path);
            if target.set_value(
                &shell_key,
                folder.value_name,
                RegistryValueType::Sz,
                utf16le_sz(&path),
            ) {
                stats.shell_folder_values += 1;
            }
        }
        if folder.user_shell_folder {
            let path = join_registry_profile_path(user_shell_profile_root, folder.path);
            if target.set_value(
                &user_shell_key,
                folder.value_name,
                RegistryValueType::ExpandSz,
                utf16le_sz(&path),
            ) {
                stats.user_shell_folder_values += 1;
            }
        }
    }
    stats
}

fn seed_reactos_network_driver_service_into_target<T: ReactOsSetupSeedTarget>(
    target: &mut T,
    service: &ReactOsKernelDriverServiceRegistration,
) -> u32 {
    let service_key = join_key_path(
        r"\Registry\Machine\System\CurrentControlSet\Services",
        service.service_name,
    );
    if !target.create_key(&service_key) {
        return 0;
    }

    let mut changed = 0u32;
    if set_setup_dword(&mut *target, &service_key, "Type", SERVICE_KERNEL_DRIVER) {
        changed += 1;
    }
    if set_setup_dword(&mut *target, &service_key, "Start", service.start_type) {
        changed += 1;
    }
    if set_setup_dword(
        &mut *target,
        &service_key,
        "ErrorControl",
        service.error_control,
    ) {
        changed += 1;
    }
    if set_setup_expand_sz(&mut *target, &service_key, "ImagePath", service.image_path) {
        changed += 1;
    }
    if set_setup_sz(&mut *target, &service_key, "Group", service.group) {
        changed += 1;
    }
    changed
}

/// Seed ReactOS network service metadata from setup INF sources into a SYSTEM hive.
///
/// This materializes installed-boot registry state only. Driver selection, dependency loading,
/// system-thread startup, and device binding still flow through Config Manager and I/O Manager
/// mechanisms.
pub fn seed_reactos_network_setup_into_target<T: ReactOsSetupSeedTarget>(
    target: &mut T,
) -> ReactOsNetworkSetupSeedStats {
    const TCPIP_PARAMETERS: &str =
        r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters";

    let mut stats = ReactOsNetworkSetupSeedStats::default();
    for service in REACTOS_NETWORK_DRIVER_SERVICES {
        let changed = seed_reactos_network_driver_service_into_target(target, service);
        match service.service_name {
            "Ndis" => stats.ndis_service_values = changed,
            "Tcpip" => stats.tcpip_service_values = changed,
            "Afd" => stats.afd_service_values = changed,
            _ => {}
        }
    }

    if target.create_key(TCPIP_PARAMETERS) {
        if set_setup_expand_sz(
            &mut *target,
            TCPIP_PARAMETERS,
            "DataBasePath",
            r"%SystemRoot%\System32\drivers\etc",
        ) {
            stats.tcpip_parameter_values += 1;
        }
        for (name, value) in [
            ("Domain", ""),
            ("Hostname", "ROSHost"),
            ("NameServer", ""),
            ("SearchList", ""),
        ] {
            if set_setup_sz(&mut *target, TCPIP_PARAMETERS, name, value) {
                stats.tcpip_parameter_values += 1;
            }
        }
        for (name, value) in [
            ("ForwardBroadcasts", 0),
            ("IPEnableRouter", 0),
            ("EnableSecurityFilters", 0),
        ] {
            if set_setup_dword(&mut *target, TCPIP_PARAMETERS, name, value) {
                stats.tcpip_parameter_values += 1;
            }
        }
    }

    for path in [
        r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Adapters",
        r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces",
        r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes",
    ] {
        target.create_key(path);
    }

    stats
}

#[derive(Clone, Debug)]
struct ReactOsNetworkAdapterBinding {
    instance_id: String,
    class_key_path: String,
    linkage_key_path: String,
    interface_name: String,
    device_name: String,
    tcpip_export_name: String,
    driver_desc: String,
    component_id: String,
}

fn driver_key_is_net_class(driver_key: &str) -> bool {
    let guid = driver_key.split('\\').next().unwrap_or(driver_key);
    guid.eq_ignore_ascii_case(NET_CLASS_GUID)
}

fn service_is_net_class(service: &nt_config_manager::ServiceMetadata) -> bool {
    service
        .class_guid
        .as_deref()
        .is_some_and(|guid| guid.eq_ignore_ascii_case(NET_CLASS_GUID))
}

fn devnode_is_network_adapter(
    service: &nt_config_manager::ServiceMetadata,
    devnode: &nt_config_manager::DevnodeRecord,
) -> bool {
    service_is_net_class(service)
        || devnode
            .driver_key
            .as_deref()
            .is_some_and(driver_key_is_net_class)
}

fn registry_component_token(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_uppercase());
        } else if ch == '_' || ch == '-' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        String::from("NET")
    } else {
        out
    }
}

fn driver_key_leaf(driver_key: &str) -> &str {
    driver_key.rsplit('\\').next().unwrap_or(driver_key)
}

fn instance_component_id(instance_id: &str) -> String {
    instance_id
        .rsplit_once('\\')
        .map(|(component, _)| component)
        .unwrap_or(instance_id)
        .into()
}

fn strip_device_prefix(value: &str) -> Option<&str> {
    value
        .strip_prefix(r"\Device\")
        .or_else(|| value.strip_prefix(r"\device\"))
}

fn existing_string_value(
    cm: &nt_config_manager::ConfigManager,
    path: &str,
    name: &str,
) -> Option<String> {
    let key = cm.registry().open_key(path)?;
    cm.registry().query_string(key, name)
}

fn network_interface_name_for_binding(
    cm: &nt_config_manager::ConfigManager,
    service: &nt_config_manager::ServiceMetadata,
    class_key_path: &str,
    linkage_key_path: &str,
    driver_key: &str,
) -> String {
    if let Some(value) = existing_string_value(cm, class_key_path, "NetCfgInstanceId") {
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(value) = existing_string_value(cm, linkage_key_path, "RootDevice") {
        if !value.is_empty() {
            return value;
        }
    }
    if let Some(value) = existing_string_value(cm, linkage_key_path, "Export") {
        if let Some(suffix) = strip_device_prefix(&value) {
            if !suffix.is_empty() {
                return suffix.into();
            }
        }
    }

    format!(
        "{}_{}",
        registry_component_token(&service.name),
        registry_component_token(driver_key_leaf(driver_key))
    )
}

fn network_driver_desc_for_binding(
    cm: &nt_config_manager::ConfigManager,
    service: &nt_config_manager::ServiceMetadata,
    class_key_path: &str,
) -> String {
    existing_string_value(cm, class_key_path, "DriverDesc")
        .or_else(|| service.display_name.clone())
        .unwrap_or_else(|| service.name.clone())
}

fn collect_reactos_network_adapter_bindings(
    cm: &nt_config_manager::ConfigManager,
) -> Vec<ReactOsNetworkAdapterBinding> {
    let mut out = Vec::new();
    for binding in cm
        .boot_system_pnp_driver_bindings()
        .into_iter()
        .chain(cm.demand_start_pnp_driver_bindings())
    {
        for devnode in binding.devnodes {
            if !devnode_is_network_adapter(&binding.service, &devnode) {
                continue;
            }
            let Some(driver_key) = devnode.driver_key.as_deref() else {
                continue;
            };
            let class_key_path = join_key_path(CONTROL_CLASS_PATH, driver_key);
            let linkage_key_path = join_key_path(&class_key_path, "Linkage");
            let interface_name = network_interface_name_for_binding(
                cm,
                &binding.service,
                &class_key_path,
                &linkage_key_path,
                driver_key,
            );
            if interface_name.is_empty()
                || out.iter().any(|existing: &ReactOsNetworkAdapterBinding| {
                    existing
                        .interface_name
                        .eq_ignore_ascii_case(&interface_name)
                })
            {
                continue;
            }
            let device_name = format!(r"\Device\{}", interface_name);
            let tcpip_export_name = format!(r"\Device\Tcpip_{}", interface_name);
            let driver_desc =
                network_driver_desc_for_binding(cm, &binding.service, &class_key_path);
            out.push(ReactOsNetworkAdapterBinding {
                instance_id: devnode.instance_id.clone(),
                class_key_path,
                linkage_key_path,
                interface_name,
                device_name,
                tcpip_export_name,
                driver_desc,
                component_id: instance_component_id(&devnode.instance_id),
            });
        }
    }
    out
}

fn set_cm_value_if_missing(
    cm: &mut nt_config_manager::ConfigManager,
    path: &str,
    name: &str,
    value_type: RegistryValueType,
    data: Vec<u8>,
) -> bool {
    let key = cm.registry_mut().create_key(path);
    if cm.registry().query_value(key, name).is_some() {
        return false;
    }
    cm.registry_mut().set_value(key, name, value_type, data)
}

fn set_cm_sz_if_missing(
    cm: &mut nt_config_manager::ConfigManager,
    path: &str,
    name: &str,
    value: &str,
) -> bool {
    set_cm_value_if_missing(cm, path, name, RegistryValueType::Sz, utf16le_sz(value))
}

fn set_cm_dword_if_missing(
    cm: &mut nt_config_manager::ConfigManager,
    path: &str,
    name: &str,
    value: u32,
) -> bool {
    set_cm_value_if_missing(
        cm,
        path,
        name,
        RegistryValueType::Dword,
        value.to_le_bytes().to_vec(),
    )
}

fn set_cm_multi_sz_if_missing(
    cm: &mut nt_config_manager::ConfigManager,
    path: &str,
    name: &str,
    values: &[&str],
) -> bool {
    set_cm_value_if_missing(
        cm,
        path,
        name,
        RegistryValueType::MultiSz,
        nt_config_manager::encode_multi_sz(values),
    )
}

fn append_cm_multi_sz_values(
    cm: &mut nt_config_manager::ConfigManager,
    path: &str,
    name: &str,
    values: &[String],
) -> bool {
    if values.is_empty() {
        return false;
    }
    let key = cm.registry_mut().create_key(path);
    let existing_value = cm.registry().query_value(key, name);
    if existing_value.is_some()
        && existing_value
            .and_then(|value| value.as_multi_string())
            .is_none()
    {
        return false;
    }
    let mut merged = cm
        .registry()
        .query_multi_string(key, name)
        .unwrap_or_default();
    let mut changed = existing_value.is_none();
    for value in values {
        if !merged
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(value))
        {
            merged.push(value.clone());
            changed = true;
        }
    }
    if !changed {
        return false;
    }
    let refs: Vec<&str> = merged.iter().map(|value| value.as_str()).collect();
    cm.registry_mut().set_value(
        key,
        name,
        RegistryValueType::MultiSz,
        nt_config_manager::encode_multi_sz(&refs),
    )
}

fn network_connection_name(index: usize) -> String {
    if index == 0 {
        String::from("Local Area Connection")
    } else {
        format!("Local Area Connection {}", index + 1)
    }
}

fn adapter_protocol_tcpip_parameters_path(interface_name: &str) -> String {
    join_key_path(
        &join_key_path(&join_key_path(SERVICES_PATH, interface_name), "Parameters"),
        "Tcpip",
    )
}

fn seed_reactos_network_bindings_in_config_manager(
    cm: &mut nt_config_manager::ConfigManager,
    stats: &mut ReactOsNetworkSetupSeedStats,
) {
    let adapters = collect_reactos_network_adapter_bindings(cm);
    if adapters.is_empty() {
        return;
    }

    let device_names: Vec<String> = adapters
        .iter()
        .map(|adapter| adapter.device_name.clone())
        .collect();
    let tcpip_export_names: Vec<String> = adapters
        .iter()
        .map(|adapter| adapter.tcpip_export_name.clone())
        .collect();
    let route_names: Vec<String> = adapters
        .iter()
        .map(|adapter| adapter.interface_name.clone())
        .collect();

    if append_cm_multi_sz_values(cm, TCPIP_LINKAGE_PATH, "Bind", &device_names) {
        stats.tcpip_linkage_values += 1;
    }
    if append_cm_multi_sz_values(cm, TCPIP_LINKAGE_PATH, "Export", &tcpip_export_names) {
        stats.tcpip_linkage_values += 1;
    }
    if append_cm_multi_sz_values(cm, TCPIP_LINKAGE_PATH, "Route", &route_names) {
        stats.tcpip_linkage_values += 1;
    }

    if set_cm_sz_if_missing(cm, CONTROL_NETWORK_NET_CLASS_PATH, "", "Network Adapters") {
        stats.network_connection_values += 1;
    }
    if set_cm_sz_if_missing(cm, CONTROL_NETWORK_NET_CLASS_PATH, "Class", "Net") {
        stats.network_connection_values += 1;
    }

    for (index, adapter) in adapters.iter().enumerate() {
        cm.registry_mut().create_key(&adapter.class_key_path);
        if set_cm_sz_if_missing(
            cm,
            &adapter.class_key_path,
            "NetCfgInstanceId",
            &adapter.interface_name,
        ) {
            stats.network_adapter_class_values += 1;
        }
        if set_cm_sz_if_missing(
            cm,
            &adapter.class_key_path,
            "DriverDesc",
            &adapter.driver_desc,
        ) {
            stats.network_adapter_class_values += 1;
        }
        if set_cm_sz_if_missing(
            cm,
            &adapter.class_key_path,
            "ComponentId",
            &adapter.component_id,
        ) {
            stats.network_adapter_class_values += 1;
        }
        if set_cm_sz_if_missing(
            cm,
            &adapter.linkage_key_path,
            "Export",
            &adapter.device_name,
        ) {
            stats.network_adapter_class_values += 1;
        }
        if set_cm_sz_if_missing(
            cm,
            &adapter.linkage_key_path,
            "RootDevice",
            &adapter.interface_name,
        ) {
            stats.network_adapter_class_values += 1;
        }
        if set_cm_sz_if_missing(cm, &adapter.linkage_key_path, "UpperBind", "Tcpip") {
            stats.network_adapter_class_values += 1;
        }

        let interface_path = join_key_path(TCPIP_INTERFACES_PATH, &adapter.interface_name);
        if set_cm_multi_sz_if_missing(cm, &interface_path, "DefaultGateway", &["0.0.0.0"]) {
            stats.tcpip_interface_values += 1;
        }
        if set_cm_multi_sz_if_missing(cm, &interface_path, "IPAddress", &["0.0.0.0"]) {
            stats.tcpip_interface_values += 1;
        }
        if set_cm_multi_sz_if_missing(cm, &interface_path, "SubnetMask", &["0.0.0.0"]) {
            stats.tcpip_interface_values += 1;
        }
        if set_cm_dword_if_missing(cm, &interface_path, "EnableDHCP", 1) {
            stats.tcpip_interface_values += 1;
        }
        if set_cm_dword_if_missing(cm, &interface_path, "InterfaceMetric", 0) {
            stats.tcpip_interface_values += 1;
        }

        cm.registry_mut()
            .create_key(&adapter_protocol_tcpip_parameters_path(
                &adapter.interface_name,
            ));

        let connection_path = join_key_path(
            &join_key_path(CONTROL_NETWORK_NET_CLASS_PATH, &adapter.interface_name),
            "Connection",
        );
        if set_cm_sz_if_missing(
            cm,
            &connection_path,
            "Name",
            &network_connection_name(index),
        ) {
            stats.network_connection_values += 1;
        }
        if set_cm_sz_if_missing(cm, &connection_path, "PnpInstanceID", &adapter.instance_id) {
            stats.network_connection_values += 1;
        }
        if set_cm_dword_if_missing(cm, &connection_path, "ShowIcon", 1) {
            stats.network_connection_values += 1;
        }
    }
}

pub fn seed_reactos_print_setup_into_target<T: ReactOsSetupSeedTarget>(
    target: &mut T,
) -> ReactOsPrintSetupSeedStats {
    const PRINT_ROOT: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Print";
    const ENV_ROOT: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Print\Environments";
    const MONITORS_ROOT: &str =
        r"\Registry\Machine\System\CurrentControlSet\Control\Print\Monitors";
    const PROVIDERS_ROOT: &str =
        r"\Registry\Machine\System\CurrentControlSet\Control\Print\Providers";
    const LOCAL_PORT_MONITOR: &str =
        r"\Registry\Machine\System\CurrentControlSet\Control\Print\Monitors\Local Port";

    let mut stats = ReactOsPrintSetupSeedStats::default();
    if !target.create_key(PRINT_ROOT) {
        return stats;
    }

    for (name, value) in [
        ("BeepEnabled", 0u32),
        ("MajorVersion", 2),
        ("MinorVersion", 0),
        ("PortThreadPriority", 0),
        ("PriorityClass", 0),
        ("SchedulerThreadPriority", 0),
    ] {
        if target.set_value(
            PRINT_ROOT,
            name,
            RegistryValueType::Dword,
            value.to_le_bytes().to_vec(),
        ) {
            stats.root_values += 1;
        }
    }

    if !target.create_key(ENV_ROOT) {
        return stats;
    }
    for environment in REACTOS_PRINT_ENVIRONMENTS {
        let environment_key = join_key_path(ENV_ROOT, environment.environment);
        if !target.create_key(&environment_key) {
            continue;
        }
        if target.set_value(
            &environment_key,
            "Directory",
            RegistryValueType::Sz,
            utf16le_sz(environment.directory),
        ) {
            stats.environment_values += 1;
        }

        let processors_key = join_key_path(&environment_key, "Print Processors");
        if !target.create_key(&processors_key) {
            continue;
        }
        let processor_key = join_key_path(&processors_key, environment.print_processor);
        if !target.create_key(&processor_key) {
            continue;
        }
        if target.set_value(
            &processor_key,
            "Driver",
            RegistryValueType::Sz,
            utf16le_sz(environment.processor_driver),
        ) {
            stats.print_processor_values += 1;
        }
    }

    if target.create_key(MONITORS_ROOT)
        && target.create_key(LOCAL_PORT_MONITOR)
        && target.set_value(
            LOCAL_PORT_MONITOR,
            "Driver",
            RegistryValueType::Sz,
            utf16le_sz("localmon.dll"),
        )
    {
        stats.monitor_values += 1;
    }
    target.create_key(PROVIDERS_ROOT);

    stats
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
    seed_reactos_explorer_shell_com_classes_into_target(
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
    seed_reactos_explorer_shell_com_classes_into_target(
        &mut MutableHiveRgsSeedTarget { hives },
        classes_root,
    )
}

/// Seed the ReactOS setup user-profile shell-folder values into a mounted user hive.
///
/// `user_hive_root` is normally `\Registry\User\.Default` during setup. The `Shell Folders` values
/// get absolute profile paths, while `User Shell Folders` keep the expandable profile root, matching
/// `dll/win32/userenv/setup.c`.
pub fn seed_reactos_user_profile_shell_folders_in_mutable_hives(
    hives: &mut MutableHiveSet,
    user_hive_root: &str,
    profile_path: &str,
    user_shell_profile_root: &str,
) -> ReactOsProfileShellFolderSeedStats {
    seed_reactos_user_profile_shell_folders_into_target(
        &mut MutableHiveRgsSeedTarget { hives },
        user_hive_root,
        profile_path,
        user_shell_profile_root,
    )
}

/// Seed the default-user hive exactly where ReactOS setup's standard-profile pass writes it.
pub fn seed_reactos_default_user_shell_folders_in_mutable_hives(
    hives: &mut MutableHiveSet,
    default_user_profile_path: &str,
) -> ReactOsProfileShellFolderSeedStats {
    seed_reactos_user_profile_shell_folders_in_mutable_hives(
        hives,
        r"\Registry\User\.Default",
        default_user_profile_path,
        "%USERPROFILE%",
    )
}

/// Seed ReactOS network setup keys from setup INF sources into the mounted SYSTEM hive.
///
/// This keeps TCPIP/AFD activation data in the same registry authority used by Config Manager
/// rather than synthesizing key-open success in the executive.
pub fn seed_reactos_network_setup_in_mutable_hives(
    hives: &mut MutableHiveSet,
) -> ReactOsNetworkSetupSeedStats {
    seed_reactos_network_setup_into_target(&mut MutableHiveRgsSeedTarget { hives })
}

/// Seed ReactOS network setup keys into a Config Manager registry view.
///
/// This is the launch-planner companion to [`seed_reactos_network_setup_in_mutable_hives`]: it
/// keeps boot/system driver selection on Config Manager metadata while using the same setup source
/// records that live registry callers see through the mounted mutable SYSTEM hive.
pub fn seed_reactos_network_setup_in_config_manager(
    cm: &mut nt_config_manager::ConfigManager,
) -> ReactOsNetworkSetupSeedStats {
    let mut stats =
        seed_reactos_network_setup_into_target(&mut ConfigManagerSetupSeedTarget { cm });
    seed_reactos_network_bindings_in_config_manager(cm, &mut stats);
    stats
}

/// Seed ReactOS print setup keys from `boot/bootdata/hivesys.inf` into the mounted SYSTEM hive.
///
/// This materializes setup-owned registry data. Print provider initialization still uses ordinary
/// registry opens/enumeration and ordinary DLL loading; this function only fills the installed-boot
/// configuration that a LiveCD-derived hive can be missing for the hosted architecture.
pub fn seed_reactos_print_setup_in_mutable_hives(
    hives: &mut MutableHiveSet,
) -> ReactOsPrintSetupSeedStats {
    seed_reactos_print_setup_into_target(&mut MutableHiveRgsSeedTarget { hives })
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

    fn hive_dword(hives: &MutableHiveSet, key: &str, value: &str) -> u32 {
        let key = hives.resolve_key(key).expect("seeded hive key");
        hives
            .hive(key.hive)
            .expect("backing hive")
            .query_dword(key.key, value)
            .expect("seeded dword value")
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
        assert!(hives.clear_hive_dirty(2));
        let second_mask = seed_reactos_explorer_shell_com_classes_in_mutable_hives(
            &mut hives,
            r"\Registry\Machine\Software\Classes",
        );
        assert_eq!(second_mask, mask);
        assert_eq!(
            hives.hive(2).expect("software hive").cell_count(),
            first_cell_count
        );
        assert_eq!(hives.hive(2).expect("software hive").dirty_count(), 0);
    }

    #[test]
    fn seeds_default_user_shell_folders_into_mutable_user_hive() {
        let mut hives = MutableHiveSet::new();
        hives.mount(r"\Registry\User\.Default", 5, Hive::new(HiveKind::Default));

        let stats = seed_reactos_default_user_shell_folders_in_mutable_hives(
            &mut hives,
            r"C:\Profiles\Default User",
        );
        assert_eq!(stats.shell_folder_values, 17);
        assert_eq!(stats.user_shell_folder_values, 17);

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\User\.Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            "AppData",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(
            data,
            utf16le_sz(r"C:\Profiles\Default User\Application Data")
        );

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\User\.Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
            "AppData",
        );
        assert_eq!(ty, RegistryValueType::ExpandSz);
        assert_eq!(data, utf16le_sz(r"%USERPROFILE%\Application Data"));

        let shell_key = hives
            .resolve_key(
                r"\Registry\User\.Default\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders",
            )
            .expect("shell folders key");
        assert!(hives.query_value(shell_key, "Temp").is_none());

        let first_cell_count = hives.hive(5).expect("default hive").cell_count();
        assert!(hives.clear_hive_dirty(5));
        let second_stats = seed_reactos_default_user_shell_folders_in_mutable_hives(
            &mut hives,
            r"C:\Profiles\Default User",
        );
        assert_eq!(second_stats, ReactOsProfileShellFolderSeedStats::default());
        assert_eq!(
            hives.hive(5).expect("default hive").cell_count(),
            first_cell_count
        );
        assert_eq!(hives.hive(5).expect("default hive").dirty_count(), 0);
    }

    #[test]
    fn seeds_reactos_print_setup_into_mutable_system_hive() {
        let mut hives = MutableHiveSet::new();
        hives.mount(r"\Registry\Machine\System", 1, Hive::new(HiveKind::System));

        let stats = seed_reactos_print_setup_in_mutable_hives(&mut hives);
        assert_eq!(
            stats,
            ReactOsPrintSetupSeedStats {
                root_values: 6,
                environment_values: 2,
                print_processor_values: 2,
                monitor_values: 1,
            }
        );

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\Machine\System\CurrentControlSet\Control\Print\Environments\Windows x64",
            "Directory",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("x64"));

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\Machine\System\CurrentControlSet\Control\Print\Environments\Windows x64\Print Processors\winprint",
            "Driver",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("winprint.dll"));

        let (ty, data) = hive_value_bytes(
            &hives,
            r"\Registry\Machine\System\CurrentControlSet\Control\Print\Monitors\Local Port",
            "Driver",
        );
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("localmon.dll"));

        let first_cell_count = hives.hive(1).expect("system hive").cell_count();
        assert!(hives.clear_hive_dirty(1));
        let second_stats = seed_reactos_print_setup_in_mutable_hives(&mut hives);
        assert_eq!(second_stats, ReactOsPrintSetupSeedStats::default());
        assert_eq!(
            hives.hive(1).expect("system hive").cell_count(),
            first_cell_count
        );
        assert_eq!(hives.hive(1).expect("system hive").dirty_count(), 0);
    }

    #[test]
    fn seeds_reactos_network_setup_into_mutable_system_hive() {
        let mut hives = MutableHiveSet::new();
        hives.mount(r"\Registry\Machine\System", 1, Hive::new(HiveKind::System));

        let stats = seed_reactos_network_setup_in_mutable_hives(&mut hives);
        assert_eq!(
            stats,
            ReactOsNetworkSetupSeedStats {
                ndis_service_values: 5,
                tcpip_service_values: 5,
                tcpip_parameter_values: 8,
                tcpip_linkage_values: 0,
                tcpip_interface_values: 0,
                network_adapter_class_values: 0,
                network_connection_values: 0,
                afd_service_values: 5,
            }
        );
        assert_eq!(stats.total_values(), 23);

        let ndis = r"\Registry\Machine\System\CurrentControlSet\Services\Ndis";
        assert_eq!(
            hive_dword(&hives, ndis, "Type"),
            nt_config_manager::SERVICE_KERNEL_DRIVER
        );
        assert_eq!(
            hive_dword(&hives, ndis, "Start"),
            nt_config_manager::SERVICE_BOOT_START
        );
        let (ty, data) = hive_value_bytes(&hives, ndis, "ImagePath");
        assert_eq!(ty, RegistryValueType::ExpandSz);
        assert_eq!(data, utf16le_sz(r"system32\drivers\ndis.sys"));
        let (ty, data) = hive_value_bytes(&hives, ndis, "Group");
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("NDIS Wrapper"));

        let tcpip = r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip";
        assert_eq!(
            hive_dword(&hives, tcpip, "Type"),
            nt_config_manager::SERVICE_KERNEL_DRIVER
        );
        assert_eq!(
            hive_dword(&hives, tcpip, "Start"),
            nt_config_manager::SERVICE_SYSTEM_START
        );
        let (ty, data) = hive_value_bytes(&hives, tcpip, "Group");
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("PNP_TDI"));

        let tcpip_parameters =
            r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters";
        let (ty, data) = hive_value_bytes(&hives, tcpip_parameters, "DataBasePath");
        assert_eq!(ty, RegistryValueType::ExpandSz);
        assert_eq!(data, utf16le_sz(r"%SystemRoot%\System32\drivers\etc"));
        let (ty, data) = hive_value_bytes(&hives, tcpip_parameters, "Hostname");
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("ROSHost"));
        assert_eq!(hive_dword(&hives, tcpip_parameters, "IPEnableRouter"), 0);
        assert!(hives
            .resolve_key(
                r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Adapters"
            )
            .is_some());
        assert!(hives
            .resolve_key(
                r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\Interfaces"
            )
            .is_some());
        assert!(hives
            .resolve_key(
                r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters\PersistentRoutes"
            )
            .is_some());

        let afd = r"\Registry\Machine\System\CurrentControlSet\Services\Afd";
        assert_eq!(
            hive_dword(&hives, afd, "Type"),
            nt_config_manager::SERVICE_KERNEL_DRIVER
        );
        assert_eq!(
            hive_dword(&hives, afd, "Start"),
            nt_config_manager::SERVICE_SYSTEM_START
        );
        let (ty, data) = hive_value_bytes(&hives, afd, "ImagePath");
        assert_eq!(ty, RegistryValueType::ExpandSz);
        assert_eq!(data, utf16le_sz(r"system32\drivers\afd.sys"));
        let (ty, data) = hive_value_bytes(&hives, afd, "Group");
        assert_eq!(ty, RegistryValueType::Sz);
        assert_eq!(data, utf16le_sz("TDI"));

        let first_cell_count = hives.hive(1).expect("system hive").cell_count();
        assert!(hives.clear_hive_dirty(1));
        let second_stats = seed_reactos_network_setup_in_mutable_hives(&mut hives);
        assert_eq!(second_stats, ReactOsNetworkSetupSeedStats::default());
        assert_eq!(
            hives.hive(1).expect("system hive").cell_count(),
            first_cell_count
        );
        assert_eq!(hives.hive(1).expect("system hive").dirty_count(), 0);
    }

    #[test]
    fn seeds_reactos_network_setup_into_config_manager() {
        let mut cm = nt_config_manager::ConfigManager::new();
        let stats = seed_reactos_network_setup_in_config_manager(&mut cm);
        assert_eq!(
            stats,
            ReactOsNetworkSetupSeedStats {
                ndis_service_values: 5,
                tcpip_service_values: 5,
                tcpip_parameter_values: 8,
                tcpip_linkage_values: 0,
                tcpip_interface_values: 0,
                network_adapter_class_values: 0,
                network_connection_values: 0,
                afd_service_values: 5,
            }
        );

        let tcpip = cm
            .registry()
            .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip")
            .expect("Tcpip service");
        assert_eq!(
            cm.registry().query_dword(tcpip, "Start"),
            Some(nt_config_manager::SERVICE_SYSTEM_START)
        );
        let tcpip_parameters = cm
            .registry()
            .open_key(r"\Registry\Machine\System\CurrentControlSet\Services\Tcpip\Parameters")
            .expect("Tcpip Parameters");
        assert_eq!(
            cm.registry()
                .query_string(tcpip_parameters, "Hostname")
                .as_deref(),
            Some("ROSHost")
        );

        let legacy: Vec<alloc::string::String> = cm
            .boot_system_legacy_driver_candidates()
            .into_iter()
            .map(|service| service.name.to_ascii_lowercase())
            .collect();
        assert_eq!(
            legacy,
            alloc::vec![
                alloc::string::String::from("ndis"),
                alloc::string::String::from("tcpip"),
                alloc::string::String::from("afd")
            ]
        );
        let second_stats = seed_reactos_network_setup_in_config_manager(&mut cm);
        assert_eq!(second_stats, ReactOsNetworkSetupSeedStats::default());
    }

    #[test]
    fn seeds_reactos_network_bindings_for_multiple_config_manager_nics() {
        let mut cm = nt_config_manager::ConfigManager::new();
        cm.register_typed_service(
            "E1000",
            r"system32\drivers\e1000.sys",
            nt_config_manager::SERVICE_KERNEL_DRIVER,
            Some("Net"),
            Some(NET_CLASS_GUID),
            nt_config_manager::SERVICE_SYSTEM_START,
            1,
        );

        for (slot, instance) in [
            ("0000", r"PCI\VEN_8086&DEV_100E\3&11583659&0&18"),
            ("0001", r"PCI\VEN_8086&DEV_100E\3&11583659&0&19"),
        ] {
            let key = cm.registry_mut().create_key(&format!(
                r"\Registry\Machine\System\CurrentControlSet\Enum\{}",
                instance
            ));
            cm.registry_mut().set_string(key, "Service", "E1000");
            cm.registry_mut()
                .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
            cm.registry_mut()
                .set_string(key, "Driver", &format!(r"{}\{}", NET_CLASS_GUID, slot));
            cm.registry_mut().set_value(
                key,
                "HardwareID",
                RegistryValueType::MultiSz,
                nt_config_manager::encode_multi_sz(&[r"PCI\VEN_8086&DEV_100E"]),
            );
            cm.registry_mut().set_value(
                key,
                "CompatibleIDs",
                RegistryValueType::MultiSz,
                nt_config_manager::encode_multi_sz(&[r"PCI\CC_020000", r"PCI\CC_0200"]),
            );
        }
        assert_eq!(cm.index_registry_devnodes(), 2);

        let stats = seed_reactos_network_setup_in_config_manager(&mut cm);
        assert_eq!(
            stats,
            ReactOsNetworkSetupSeedStats {
                ndis_service_values: 5,
                tcpip_service_values: 5,
                tcpip_parameter_values: 8,
                tcpip_linkage_values: 3,
                tcpip_interface_values: 10,
                network_adapter_class_values: 12,
                network_connection_values: 8,
                afd_service_values: 5,
            }
        );
        assert_eq!(stats.total_values(), 56);

        let tcpip_linkage = cm
            .registry()
            .open_key(TCPIP_LINKAGE_PATH)
            .expect("Tcpip Linkage");
        assert_eq!(
            cm.registry().query_multi_string(tcpip_linkage, "Bind"),
            Some(alloc::vec![
                alloc::string::String::from(r"\Device\E1000_0000"),
                alloc::string::String::from(r"\Device\E1000_0001")
            ])
        );
        assert_eq!(
            cm.registry().query_multi_string(tcpip_linkage, "Export"),
            Some(alloc::vec![
                alloc::string::String::from(r"\Device\Tcpip_E1000_0000"),
                alloc::string::String::from(r"\Device\Tcpip_E1000_0001")
            ])
        );
        assert_eq!(
            cm.registry().query_multi_string(tcpip_linkage, "Route"),
            Some(alloc::vec![
                alloc::string::String::from("E1000_0000"),
                alloc::string::String::from("E1000_0001")
            ])
        );

        for slot in ["0000", "0001"] {
            let interface = format!("E1000_{}", slot);
            let expected_export = format!(r"\Device\{}", interface);
            let linkage_path = format!(
                r"\Registry\Machine\System\CurrentControlSet\Control\Class\{}\{}\Linkage",
                NET_CLASS_GUID, slot
            );
            let linkage = cm
                .registry()
                .open_key(&linkage_path)
                .expect("adapter linkage");
            assert_eq!(
                cm.registry().query_string(linkage, "Export").as_deref(),
                Some(expected_export.as_str())
            );
            assert_eq!(
                cm.registry().query_string(linkage, "RootDevice").as_deref(),
                Some(interface.as_str())
            );
            assert_eq!(
                cm.registry().query_string(linkage, "UpperBind").as_deref(),
                Some("Tcpip")
            );

            let interface_key = cm
                .registry()
                .open_key(&join_key_path(TCPIP_INTERFACES_PATH, &interface))
                .expect("TCPIP interface");
            assert_eq!(
                cm.registry().query_multi_string(interface_key, "IPAddress"),
                Some(alloc::vec![alloc::string::String::from("0.0.0.0")])
            );
            assert_eq!(
                cm.registry().query_dword(interface_key, "EnableDHCP"),
                Some(1)
            );
            assert_eq!(
                cm.registry().query_dword(interface_key, "InterfaceMetric"),
                Some(0)
            );
        }

        let connection = cm
            .registry()
            .open_key(
                r"\Registry\Machine\System\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\E1000_0001\Connection",
            )
            .expect("second connection");
        assert_eq!(
            cm.registry().query_string(connection, "Name").as_deref(),
            Some("Local Area Connection 2")
        );

        let second_stats = seed_reactos_network_setup_in_config_manager(&mut cm);
        assert_eq!(second_stats, ReactOsNetworkSetupSeedStats::default());
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
