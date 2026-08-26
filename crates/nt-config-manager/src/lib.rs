//! # `nt-config-manager` — the Configuration Manager registry authority
//!
//! The canonical configuration state the rest of the NT personality consults (spec: NT
//! Configuration Manager Service): a registry key/value tree ([`registry`]) plus the higher-
//! level records layered on it — driver **service** records (a `Services\<Name>` key + a
//! `Parameters` subkey), **devnode** records (an `Enum\<InstanceId>` key), and device
//! **interface** records (a `Control\DeviceClasses\<Guid>` registration + a symbolic link).
//!
//! A driver reads its configuration via `Zw*`/`WdfRegistry*` (which the Driver Host bridges
//! to [`Registry`]); the PnP Manager enumerates devnodes; the Object/I/O Managers materialize
//! interface links. This crate owns metadata only — no handles, IRPs, or driver pointers.
//! `no_std` + `alloc`, no raw pointers.

#![no_std]

extern crate alloc;

mod property;
mod registry;

use alloc::string::String;
use alloc::vec::Vec;
use core::cmp::Ordering;

pub use property::{
    device_property, devprop_type, DevPropKey, DevicePropertySource, PropertyBag, PropertyValue,
};
pub use registry::{
    encode_multi_sz, encode_sz, Registry, RegistryKeyId, RegistryValue, RegistryValueType,
};

/// The NT root-bus pseudo-devnode exposed through user-mode PnP relations.
pub const PNP_ROOT_DEVICE_INSTANCE: &str = r"HTREE\ROOT\0";

/// User-mode PnP dynamic property ordinals (`PNP_PROPERTY_*`, NDK `cmtypes.h`).
pub mod pnp_property {
    pub const PHYSICAL_DEVICE_OBJECT_NAME: u32 = 1;
    pub const ENUMERATOR_NAME: u32 = 9;
}

/// User-mode PnP relation ordinals (`PNP_GET_*_DEVICE`, NDK `cmtypes.h`).
pub mod pnp_relation {
    pub const PARENT: u32 = 1;
    pub const CHILD: u32 = 2;
    pub const SIBLING: u32 = 3;
}

pub const SERVICES_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
pub const ENUM_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Enum";
pub const DEVICE_CLASSES_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Control\DeviceClasses";
pub const CONTROL_CLASS_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Class";
pub const CONTROL_NETWORK_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Control\Network";
pub const SERVICE_GROUP_ORDER_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Control\ServiceGroupOrder";
pub const NETWORK_WRAPPER_LOAD_ORDER_GROUP: &str = "NDIS Wrapper";
pub const NETWORK_PNP_TRANSPORT_LOAD_ORDER_GROUP: &str = "PNP_TDI";
pub const NETWORK_TRANSPORT_LOAD_ORDER_GROUP: &str = "TDI";

pub const SERVICE_KERNEL_DRIVER: u32 = 0x0000_0001;
pub const SERVICE_FILE_SYSTEM_DRIVER: u32 = 0x0000_0002;
pub const SERVICE_ADAPTER: u32 = 0x0000_0004;
pub const SERVICE_RECOGNIZER_DRIVER: u32 = 0x0000_0008;
pub const SERVICE_WIN32_OWN_PROCESS: u32 = 0x0000_0010;
pub const SERVICE_WIN32_SHARE_PROCESS: u32 = 0x0000_0020;
pub const SERVICE_INTERACTIVE_PROCESS: u32 = 0x0000_0100;

pub const SERVICE_DRIVER_TYPE_MASK: u32 = SERVICE_KERNEL_DRIVER
    | SERVICE_FILE_SYSTEM_DRIVER
    | SERVICE_ADAPTER
    | SERVICE_RECOGNIZER_DRIVER;
pub const SERVICE_WIN32_TYPE_MASK: u32 = SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS;

pub const SERVICE_BOOT_START: u32 = 0;
pub const SERVICE_SYSTEM_START: u32 = 1;
pub const SERVICE_AUTO_START: u32 = 2;
pub const SERVICE_DEMAND_START: u32 = 3;
pub const SERVICE_DISABLED: u32 = 4;

pub type ServiceId = u64;
pub type DevnodeId = u64;
pub type InterfaceId = u64;

/// A driver service record (spec §9.1).
#[derive(Clone, Debug)]
pub struct ServiceRecord {
    pub id: ServiceId,
    pub name: String,
    pub image_path: String,
    pub service_key: RegistryKeyId,
    pub parameters_key: RegistryKeyId,
    pub class: Option<String>,
    pub class_guid: Option<String>,
    pub start_type: u32,
    pub error_control: u32,
}

/// The kernel launch class implied by a driver service's `Type` bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DriverServiceClass {
    Device,
    FileSystem,
}

/// Win32 service process model encoded in a service's `Type` bits.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Win32ServiceProcessKind {
    Own,
    Shared,
}

/// Registry-selected process creation metadata for a Win32 service.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Win32ServiceLaunchSpec {
    pub service_name: String,
    pub service_key: RegistryKeyId,
    pub image_path: String,
    pub process_kind: Win32ServiceProcessKind,
    pub interactive: bool,
    pub account_name: Option<String>,
    pub display_name: Option<String>,
    pub dependencies: Vec<String>,
}

/// Generic process-creation input derived from a Win32 service `ImagePath`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Win32ServiceProcessLaunch {
    pub service_name: String,
    pub service_key: RegistryKeyId,
    pub executable_path: String,
    pub nt_image_path: String,
    pub command_line: String,
    pub process_kind: Win32ServiceProcessKind,
    pub interactive: bool,
    pub account_name: Option<String>,
    pub display_name: Option<String>,
    pub dependencies: Vec<String>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Win32ServiceProcessLaunchError {
    EmptyImagePath,
    UnterminatedQuote,
    UnsupportedImagePath,
}

/// Registry-selected driver load metadata for `NtLoadDriver`/SCM driver starts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DriverServiceLaunchSpec {
    pub service_name: String,
    pub service_key: RegistryKeyId,
    pub image_path: String,
    pub driver_object_path: String,
    pub class: DriverServiceClass,
    pub start_type: u32,
    pub error_control: Option<u32>,
    pub load_order_group: Option<String>,
    pub class_guid: Option<String>,
    pub tag: Option<u32>,
}

/// One live driver-service selection together with every registry-bound devnode.
///
/// This is the semantic Configuration Manager result consumed by `NtLoadDriver` and the PnP
/// device-action owner. The registry remains authoritative; callers obtain this through
/// [`ConfigManager::driver_service_binding`], which refreshes the Enum index before selection.
#[derive(Clone, Debug)]
pub struct DriverServiceBinding {
    pub service: DriverServiceLaunchSpec,
    pub devnodes: Vec<DevnodeRecord>,
}

/// The start action implied by a service key's `Type` metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ServiceStartSpec {
    Driver(DriverServiceLaunchSpec),
    Win32(Win32ServiceLaunchSpec),
}

pub fn driver_service_class_from_type(service_type: u32) -> Option<DriverServiceClass> {
    if service_type & (SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER) != 0 {
        Some(DriverServiceClass::FileSystem)
    } else if service_type & SERVICE_DRIVER_TYPE_MASK != 0 {
        Some(DriverServiceClass::Device)
    } else {
        None
    }
}

fn strip_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    (value.len() >= prefix.len() && value[..prefix.len()].eq_ignore_ascii_case(prefix))
        .then_some(&value[prefix.len()..])
}

fn strip_rooted_ascii_prefix<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let suffix = strip_ascii_prefix(value, prefix)?;
    (suffix.is_empty() || path_starts_with_sep(suffix)).then_some(suffix)
}

fn path_starts_with_sep(value: &str) -> bool {
    value
        .as_bytes()
        .first()
        .is_some_and(|b| *b == b'\\' || *b == b'/')
}

fn push_backslash_path(out: &mut String, value: &str) {
    for ch in value.chars() {
        out.push(if ch == '/' { '\\' } else { ch });
    }
}

fn system_root_nt_path_from_suffix(suffix: &str) -> String {
    let mut out = String::from(r"\SystemRoot");
    let suffix = suffix.trim_start();
    if suffix.is_empty() {
        return out;
    }
    if path_starts_with_sep(suffix) {
        push_backslash_path(&mut out, suffix);
    } else {
        out.push('\\');
        push_backslash_path(&mut out, suffix);
    }
    out
}

fn normalize_win32_service_executable_path(
    executable_path: &str,
) -> Result<String, Win32ServiceProcessLaunchError> {
    let path = executable_path.trim();
    if path.is_empty() {
        return Err(Win32ServiceProcessLaunchError::EmptyImagePath);
    }

    if let Some(suffix) = strip_rooted_ascii_prefix(path, "%SystemRoot%") {
        return Ok(system_root_nt_path_from_suffix(suffix));
    }
    if let Some(suffix) = strip_rooted_ascii_prefix(path, r"\SystemRoot") {
        return Ok(system_root_nt_path_from_suffix(suffix));
    }
    if strip_ascii_prefix(path, r"system32\").is_some()
        || strip_ascii_prefix(path, "system32/").is_some()
    {
        return Ok(system_root_nt_path_from_suffix(path));
    }

    for prefix in [
        r"\??\C:\ReactOS\",
        r"\??\C:\Windows\",
        r"C:\ReactOS\",
        r"C:\Windows\",
    ] {
        if let Some(suffix) = strip_ascii_prefix(path, prefix) {
            return Ok(system_root_nt_path_from_suffix(suffix));
        }
    }

    Err(Win32ServiceProcessLaunchError::UnsupportedImagePath)
}

fn split_win32_service_image_path(
    image_path: &str,
) -> Result<(&str, &str), Win32ServiceProcessLaunchError> {
    let command_line = image_path.trim();
    if command_line.is_empty() {
        return Err(Win32ServiceProcessLaunchError::EmptyImagePath);
    }
    if let Some(rest) = command_line.strip_prefix('"') {
        let end = rest
            .find('"')
            .ok_or(Win32ServiceProcessLaunchError::UnterminatedQuote)?;
        let executable = &rest[..end];
        if executable.trim().is_empty() {
            return Err(Win32ServiceProcessLaunchError::EmptyImagePath);
        }
        return Ok((executable, command_line));
    }
    let end = command_line
        .char_indices()
        .find(|(_, ch)| ch.is_whitespace())
        .map(|(idx, _)| idx)
        .unwrap_or(command_line.len());
    Ok((&command_line[..end], command_line))
}

impl Win32ServiceLaunchSpec {
    pub fn process_launch(
        &self,
    ) -> Result<Win32ServiceProcessLaunch, Win32ServiceProcessLaunchError> {
        let (executable_path, command_line) = split_win32_service_image_path(&self.image_path)?;
        let nt_image_path = normalize_win32_service_executable_path(executable_path)?;
        Ok(Win32ServiceProcessLaunch {
            service_name: self.service_name.clone(),
            service_key: self.service_key,
            executable_path: executable_path.into(),
            nt_image_path,
            command_line: command_line.into(),
            process_kind: self.process_kind,
            interactive: self.interactive,
            account_name: self.account_name.clone(),
            display_name: self.display_name.clone(),
            dependencies: self.dependencies.clone(),
        })
    }
}

/// Typed view of a `Services\<Name>` key.
///
/// This is read from the registry tree instead of the in-memory service index so imported hives
/// and runtime registry mutations remain authoritative.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceMetadata {
    pub name: String,
    pub service_key: RegistryKeyId,
    pub parameters_key: Option<RegistryKeyId>,
    pub image_path: Option<String>,
    pub service_type: Option<u32>,
    pub start_type: Option<u32>,
    pub error_control: Option<u32>,
    pub load_order_group: Option<String>,
    pub class_guid: Option<String>,
    pub tag: Option<u32>,
    pub dependencies: Vec<String>,
    pub display_name: Option<String>,
    pub object_name: Option<String>,
}

/// The service-key fields that determine SCM database enumeration order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceDatabaseOrderEntry {
    pub name: String,
    pub service_type: Option<u32>,
    pub start_type: Option<u32>,
    pub load_order_group: Option<String>,
    pub tag: Option<u32>,
}

#[derive(Clone, Debug)]
pub struct PnpDriverBinding {
    pub service: ServiceMetadata,
    pub devnodes: Vec<DevnodeRecord>,
}

/// Parse a textual GUID (`{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}` or without punctuation) into the
/// in-memory Windows `GUID` byte layout (`Data1/2/3` little-endian, `Data4` byte-order stable).
pub fn guid_text_to_memory_bytes(guid: &str) -> Option<[u8; 16]> {
    fn hex(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let mut text = [0u8; 16];
    let mut high: Option<u8> = None;
    let mut n = 0usize;
    for b in guid.bytes() {
        if matches!(b, b'{' | b'}' | b'-') {
            continue;
        }
        let digit = hex(b)?;
        if let Some(h) = high.take() {
            if n >= text.len() {
                return None;
            }
            text[n] = (h << 4) | digit;
            n += 1;
        } else {
            high = Some(digit);
        }
    }
    if high.is_some() || n != text.len() {
        return None;
    }
    Some([
        text[3], text[2], text[1], text[0], text[5], text[4], text[7], text[6], text[8], text[9],
        text[10], text[11], text[12], text[13], text[14], text[15],
    ])
}

pub fn guid_text_eq_memory(guid: &str, memory: &[u8; 16]) -> bool {
    guid_text_to_memory_bytes(guid).is_some_and(|parsed| &parsed == memory)
}

impl ServiceMetadata {
    pub fn is_driver(&self) -> bool {
        self.driver_service_class().is_some()
    }

    pub fn is_win32_service(&self) -> bool {
        self.service_type
            .is_some_and(|ty| ty & SERVICE_WIN32_TYPE_MASK != 0)
    }

    pub fn is_disabled(&self) -> bool {
        self.start_type == Some(SERVICE_DISABLED)
    }

    pub fn has_launch_image(&self) -> bool {
        self.image_path.as_ref().is_some_and(|p| !p.is_empty())
    }

    pub fn win32_process_kind(&self) -> Option<Win32ServiceProcessKind> {
        win32_service_process_kind_from_type(self.service_type?)
    }

    pub fn win32_launch_spec(&self) -> Option<Win32ServiceLaunchSpec> {
        if self.is_disabled() {
            return None;
        }
        let process_kind = self.win32_process_kind()?;
        let image_path = self.image_path.as_deref().filter(|path| !path.is_empty())?;
        Some(Win32ServiceLaunchSpec {
            service_name: self.name.clone(),
            service_key: self.service_key,
            image_path: image_path.into(),
            process_kind,
            interactive: self
                .service_type
                .is_some_and(|ty| ty & SERVICE_INTERACTIVE_PROCESS != 0),
            account_name: self.object_name.clone(),
            display_name: self.display_name.clone(),
            dependencies: self.dependencies.clone(),
        })
    }

    pub fn driver_launch_spec(&self) -> Option<DriverServiceLaunchSpec> {
        if self.is_disabled() {
            return None;
        }
        let service_type = self.service_type?;
        if service_type & SERVICE_WIN32_TYPE_MASK != 0 {
            return None;
        }
        let class = self.driver_service_class()?;
        let image_path = self.image_path.as_deref().filter(|path| !path.is_empty())?;
        Some(DriverServiceLaunchSpec {
            service_name: self.name.clone(),
            service_key: self.service_key,
            image_path: image_path.into(),
            driver_object_path: self.driver_object_path()?,
            class,
            start_type: self.start_type?,
            error_control: self.error_control,
            load_order_group: self.load_order_group.clone(),
            class_guid: self.class_guid.clone(),
            tag: self.tag,
        })
    }

    pub fn start_spec(&self) -> Option<ServiceStartSpec> {
        let service_type = self.service_type?;
        let is_driver = service_type & SERVICE_DRIVER_TYPE_MASK != 0;
        let is_win32 = service_type & SERVICE_WIN32_TYPE_MASK != 0;
        match (is_driver, is_win32) {
            (true, false) => self.driver_launch_spec().map(ServiceStartSpec::Driver),
            (false, true) => self.win32_launch_spec().map(ServiceStartSpec::Win32),
            _ => None,
        }
    }

    pub fn driver_service_class(&self) -> Option<DriverServiceClass> {
        driver_service_class_from_type(self.service_type?)
    }

    /// Driver object path implied by this service key.
    ///
    /// This mirrors the NT I/O manager's service-key rule: a driver service's `ObjectName`, when
    /// present, names the driver object directly; otherwise filesystem and recognizer drivers live
    /// under `\FileSystem`, and kernel/device drivers live under `\Driver`.
    pub fn driver_object_path(&self) -> Option<String> {
        let class = self.driver_service_class()?;
        if let Some(object_name) = self.object_name.as_deref().filter(|name| !name.is_empty()) {
            return Some(object_name.into());
        }

        let mut path = match class {
            DriverServiceClass::FileSystem => String::from(r"\FileSystem\"),
            DriverServiceClass::Device => String::from(r"\Driver\"),
        };
        path.push_str(&self.name);
        Some(path)
    }
}

impl From<&ServiceMetadata> for ServiceDatabaseOrderEntry {
    fn from(service: &ServiceMetadata) -> Self {
        Self {
            name: service.name.clone(),
            service_type: service.service_type,
            start_type: service.start_type,
            load_order_group: service.load_order_group.clone(),
            tag: service.tag,
        }
    }
}

pub fn win32_service_process_kind_from_type(service_type: u32) -> Option<Win32ServiceProcessKind> {
    if service_type & SERVICE_DRIVER_TYPE_MASK != 0 {
        return None;
    }
    let owns_process = service_type & SERVICE_WIN32_OWN_PROCESS != 0;
    let shares_process = service_type & SERVICE_WIN32_SHARE_PROCESS != 0;
    match (owns_process, shares_process) {
        (true, false) => Some(Win32ServiceProcessKind::Own),
        (false, true) => Some(Win32ServiceProcessKind::Shared),
        _ => None,
    }
}

/// A device node (devnode) record (spec §10.1).
#[derive(Clone, Debug)]
pub struct DevnodeRecord {
    pub id: DevnodeId,
    pub instance_id: String,
    pub service: Option<String>,
    pub pdo_name: Option<String>,
    pub driver_key: Option<String>,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub enum_key: RegistryKeyId,
    /// PnP properties attached to this devnode (spec §11.5).
    pub properties: PropertyBag,
}

/// A device interface record (spec §11.1).
#[derive(Clone, Debug)]
pub struct InterfaceRecord {
    pub id: InterfaceId,
    pub devnode: DevnodeId,
    pub guid: String,
    pub reference: String,
    pub enabled: bool,
    pub symbolic_link: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum InterfaceRegistrationError {
    UnknownDevnode,
    InvalidGuid,
    InvalidReference,
}

/// The Configuration Manager: the registry + the service/devnode/interface indices.
pub struct ConfigManager {
    registry: Registry,
    services: Vec<ServiceRecord>,
    devnodes: Vec<DevnodeRecord>,
    interfaces: Vec<InterfaceRecord>,
    next_id: u64,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            registry: Registry::new(),
            services: Vec::new(),
            devnodes: Vec::new(),
            interfaces: Vec::new(),
            next_id: 1,
        }
    }

    fn alloc_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// The underlying registry (drivers read/write it via `Zw*`/`WdfRegistry*`).
    pub fn registry(&self) -> &Registry {
        &self.registry
    }
    pub fn registry_mut(&mut self) -> &mut Registry {
        &mut self.registry
    }

    // --- services (spec §9) ---------------------------------------------------

    /// Register a driver service: create `Services\<Name>` + a `Parameters` subkey, and
    /// stamp the standard values (`ImagePath`, `Type`, `Start`, `ErrorControl`). Returns the
    /// service id; re-registering the same name updates it.
    #[allow(clippy::too_many_arguments)]
    pub fn register_service(
        &mut self,
        name: &str,
        image_path: &str,
        class: Option<&str>,
        class_guid: Option<&str>,
        start_type: u32,
        error_control: u32,
    ) -> ServiceId {
        self.register_typed_service(
            name,
            image_path,
            SERVICE_KERNEL_DRIVER,
            class,
            class_guid,
            start_type,
            error_control,
        )
    }

    /// Register a service with an explicit NT `Type` value.
    #[allow(clippy::too_many_arguments)]
    pub fn register_typed_service(
        &mut self,
        name: &str,
        image_path: &str,
        service_type: u32,
        class: Option<&str>,
        class_guid: Option<&str>,
        start_type: u32,
        error_control: u32,
    ) -> ServiceId {
        let service_key = self.registry.create_key(&service_path(name));
        let parameters_key = self.registry.create_subkey(service_key, "Parameters");
        self.registry
            .set_string(service_key, "ImagePath", image_path);
        self.registry.set_dword(service_key, "Type", service_type);
        self.registry.set_dword(service_key, "Start", start_type);
        self.registry
            .set_dword(service_key, "ErrorControl", error_control);
        if let Some(c) = class {
            self.registry.set_string(service_key, "Class", c);
        }
        if let Some(g) = class_guid {
            self.registry.set_string(service_key, "ClassGUID", g);
        }
        let id = self.alloc_id();
        // Replace any prior record of the same name.
        self.services.retain(|s| !s.name.eq_ignore_ascii_case(name));
        self.services.push(ServiceRecord {
            id,
            name: name.into(),
            image_path: image_path.into(),
            service_key,
            parameters_key,
            class: class.map(Into::into),
            class_guid: class_guid.map(Into::into),
            start_type,
            error_control,
        });
        id
    }

    pub fn service(&self, name: &str) -> Option<&ServiceRecord> {
        self.services
            .iter()
            .find(|s| s.name.eq_ignore_ascii_case(name))
    }
    /// The `DriverEntry` `RegistryPath` for a service (spec §9.3) — case-preserved.
    pub fn service_key_path(&self, name: &str) -> Option<String> {
        self.service(name).map(|s| service_path(&s.name))
    }
    /// The `Parameters` subkey a driver reads its config from.
    pub fn service_parameters_key(&self, name: &str) -> Option<RegistryKeyId> {
        self.service(name).map(|s| s.parameters_key)
    }
    /// Seed a value under a service's `Parameters` key (fixture loading, spec §7.6).
    pub fn set_service_parameter(
        &mut self,
        name: &str,
        value_name: &str,
        value_type: RegistryValueType,
        data: Vec<u8>,
    ) -> bool {
        let Some(key) = self.service_parameters_key(name) else {
            return false;
        };
        self.registry.set_value(key, value_name, value_type, data)
    }

    /// Read a typed service view from the live registry tree.
    pub fn service_metadata(&self, name: &str) -> Option<ServiceMetadata> {
        let service_key = self.registry.open_key(&service_path(name))?;
        let name = self
            .registry
            .key_path(service_key)
            .and_then(|p| p.rsplit('\\').next().map(String::from))
            .unwrap_or_else(|| name.into());
        Some(self.service_metadata_from_key(&name, service_key))
    }

    /// Enumerate typed service views from `CurrentControlSet\Services`.
    pub fn service_metadata_list(&self) -> Vec<ServiceMetadata> {
        let Some(services_key) = self.registry.open_key(SERVICES_PATH) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for name in self.registry.enum_subkeys(services_key) {
            if let Some(service_key) = self.registry.open_subkey(services_key, &name) {
                out.push(self.service_metadata_from_key(&name, service_key));
            }
        }
        sort_service_metadata(&mut out);
        out
    }

    /// Service subkey names in the stable order exposed to SCM database builders.
    pub fn service_database_ordered_names(&self) -> Vec<String> {
        let mut entries: Vec<ServiceDatabaseOrderEntry> = self
            .service_metadata_list()
            .iter()
            .map(ServiceDatabaseOrderEntry::from)
            .collect();
        let group_order = self.service_group_order();
        sort_service_database_order_entries(&mut entries, &group_order);
        entries.into_iter().map(|entry| entry.name).collect()
    }

    /// Generic service selection from registry metadata. Callers own policy; this only filters on
    /// explicit `Start` values, explicit `Type` bits, and a non-empty `ImagePath`.
    pub fn service_candidates_by_start_and_type(
        &self,
        start_types: &[u32],
        type_mask: u32,
    ) -> Vec<ServiceMetadata> {
        self.service_metadata_by_start_ordered(start_types)
            .into_iter()
            .filter(|s| {
                s.has_launch_image() && s.service_type.is_some_and(|ty| ty & type_mask != 0)
            })
            .collect()
    }

    /// Registry-declared drivers eligible for kernel boot/system driver bring-up.
    pub fn boot_system_driver_candidates(&self) -> Vec<ServiceMetadata> {
        let mut out = self.service_candidates_by_start_and_type(
            &[SERVICE_BOOT_START, SERVICE_SYSTEM_START],
            SERVICE_DRIVER_TYPE_MASK,
        );
        let group_order = self.service_group_order();
        sort_service_metadata_with_group_order(&mut out, &group_order);
        out
    }

    /// Boot/system device-class drivers selected by service metadata and bound to at least one
    /// imported `Enum` devnode.
    pub fn boot_system_pnp_driver_candidates(&self) -> Vec<ServiceMetadata> {
        self.boot_system_pnp_driver_bindings()
            .into_iter()
            .map(|binding| binding.service)
            .collect()
    }

    /// Whether a boot/system driver service is a hosted legacy network-stack driver.
    ///
    /// The hosted boot-driver path can start PnP-bound device drivers from imported `Enum`
    /// devnodes. The only no-devnode device drivers admitted here are the registry-declared NT5
    /// network wrapper/transport groups; unrelated legacy boot drivers such as boot-bus extenders,
    /// WDF framework loaders, debug/SAC services, and storage class drivers need their own kernel
    /// mechanisms before they enter this path.
    pub fn is_boot_system_legacy_driver(&self, service: &ServiceMetadata) -> bool {
        service.has_launch_image()
            && service.driver_service_class() == Some(DriverServiceClass::Device)
            && service
                .start_type
                .is_some_and(|start| start == SERVICE_BOOT_START || start == SERVICE_SYSTEM_START)
            && service.load_order_group.as_deref().is_some_and(|group| {
                group.eq_ignore_ascii_case(NETWORK_WRAPPER_LOAD_ORDER_GROUP)
                    || group.eq_ignore_ascii_case(NETWORK_PNP_TRANSPORT_LOAD_ORDER_GROUP)
                    || group.eq_ignore_ascii_case(NETWORK_TRANSPORT_LOAD_ORDER_GROUP)
            })
            && !self.service_has_devnodes(&service.name)
    }

    /// Boot/system no-devnode network wrapper/transport drivers selected by service metadata.
    pub fn boot_system_legacy_driver_candidates(&self) -> Vec<ServiceMetadata> {
        self.boot_system_driver_candidates()
            .into_iter()
            .filter(|service| self.is_boot_system_legacy_driver(service))
            .collect()
    }

    fn pnp_driver_bindings_by_start(&self, start_types: &[u32]) -> Vec<PnpDriverBinding> {
        self.service_candidates_by_start_and_type(start_types, SERVICE_DRIVER_TYPE_MASK)
            .into_iter()
            .filter_map(|service| {
                if service.driver_service_class() != Some(DriverServiceClass::Device) {
                    return None;
                }
                let devnodes: Vec<DevnodeRecord> = self
                    .devnodes_for_service(&service.name)
                    .into_iter()
                    .cloned()
                    .collect();
                if devnodes.is_empty() {
                    None
                } else {
                    Some(PnpDriverBinding { service, devnodes })
                }
            })
            .collect()
    }

    /// Boot/system device-class driver bindings: selected service metadata plus the imported
    /// `Enum` devnodes that bind to each service.
    pub fn boot_system_pnp_driver_bindings(&self) -> Vec<PnpDriverBinding> {
        self.pnp_driver_bindings_by_start(&[SERVICE_BOOT_START, SERVICE_SYSTEM_START])
    }

    /// Demand-start device-class driver bindings selected by installed `Enum` devnodes.
    pub fn demand_start_pnp_driver_bindings(&self) -> Vec<PnpDriverBinding> {
        self.pnp_driver_bindings_by_start(&[SERVICE_DEMAND_START])
    }

    /// Demand-start device-class drivers selected by installed `Enum` devnodes.
    pub fn demand_start_pnp_driver_candidates(&self) -> Vec<ServiceMetadata> {
        self.demand_start_pnp_driver_bindings()
            .into_iter()
            .map(|binding| binding.service)
            .collect()
    }

    /// Registry-declared Win32 services that SCM should auto-start after it owns policy.
    pub fn auto_start_win32_service_candidates(&self) -> Vec<ServiceMetadata> {
        self.service_candidates_by_start_and_type(&[SERVICE_AUTO_START], SERVICE_WIN32_TYPE_MASK)
    }

    pub fn auto_start_win32_service_launch_specs(&self) -> Vec<Win32ServiceLaunchSpec> {
        self.win32_service_launch_specs_by_start(&[SERVICE_AUTO_START])
    }

    pub fn auto_start_win32_service_process_launches(&self) -> Vec<Win32ServiceProcessLaunch> {
        self.win32_service_process_launches_by_start(&[SERVICE_AUTO_START])
    }

    /// Registry-declared Win32 services that SCM may demand-start.
    pub fn demand_start_win32_service_candidates(&self) -> Vec<ServiceMetadata> {
        self.service_candidates_by_start_and_type(&[SERVICE_DEMAND_START], SERVICE_WIN32_TYPE_MASK)
    }

    pub fn demand_start_win32_service_launch_specs(&self) -> Vec<Win32ServiceLaunchSpec> {
        self.win32_service_launch_specs_by_start(&[SERVICE_DEMAND_START])
    }

    pub fn demand_start_win32_service_process_launches(&self) -> Vec<Win32ServiceProcessLaunch> {
        self.win32_service_process_launches_by_start(&[SERVICE_DEMAND_START])
    }

    pub fn service_start_spec(&self, name: &str) -> Option<ServiceStartSpec> {
        self.service_metadata(name)?.start_spec()
    }

    pub fn service_start_specs_by_start(&self, start_types: &[u32]) -> Vec<ServiceStartSpec> {
        self.service_metadata_by_start_ordered(start_types)
            .into_iter()
            .filter_map(|service| service.start_spec())
            .collect()
    }

    /// Registry-declared Win32 service process creation metadata for SCM-owned launch decisions.
    pub fn win32_service_launch_specs_by_start(
        &self,
        start_types: &[u32],
    ) -> Vec<Win32ServiceLaunchSpec> {
        self.service_metadata_by_start_ordered(start_types)
            .into_iter()
            .filter_map(|service| service.win32_launch_spec())
            .collect()
    }

    /// Generic process-creation inputs for registry-declared Win32 service starts.
    pub fn win32_service_process_launches_by_start(
        &self,
        start_types: &[u32],
    ) -> Vec<Win32ServiceProcessLaunch> {
        self.win32_service_launch_specs_by_start(start_types)
            .into_iter()
            .filter_map(|spec| spec.process_launch().ok())
            .collect()
    }

    pub fn driver_service_launch_specs_by_start(
        &self,
        start_types: &[u32],
    ) -> Vec<DriverServiceLaunchSpec> {
        self.service_metadata_by_start_ordered(start_types)
            .into_iter()
            .filter_map(|service| service.driver_launch_spec())
            .collect()
    }

    /// Registry-declared drivers that SCM or `NtLoadDriver` may demand-start.
    pub fn demand_start_driver_candidates(&self) -> Vec<ServiceMetadata> {
        self.service_candidates_by_start_and_type(&[SERVICE_DEMAND_START], SERVICE_DRIVER_TYPE_MASK)
    }

    pub fn demand_start_driver_launch_specs(&self) -> Vec<DriverServiceLaunchSpec> {
        self.driver_service_launch_specs_by_start(&[SERVICE_DEMAND_START])
    }

    /// The `Control\ServiceGroupOrder\List` load-order group sequence.
    pub fn service_group_order(&self) -> Vec<String> {
        let Some(key) = self.registry.open_key(SERVICE_GROUP_ORDER_PATH) else {
            return Vec::new();
        };
        self.registry
            .query_multi_string(key, "List")
            .unwrap_or_default()
    }

    fn service_metadata_by_start_ordered(&self, start_types: &[u32]) -> Vec<ServiceMetadata> {
        let mut out: Vec<ServiceMetadata> = self
            .service_metadata_list()
            .into_iter()
            .filter(|service| {
                service
                    .start_type
                    .is_some_and(|start| start_types.contains(&start))
            })
            .collect();
        let group_order = self.service_group_order();
        sort_service_metadata_with_group_order(&mut out, &group_order);
        out
    }

    fn service_metadata_from_key(&self, name: &str, service_key: RegistryKeyId) -> ServiceMetadata {
        ServiceMetadata {
            name: name.into(),
            service_key,
            parameters_key: self.registry.open_subkey(service_key, "Parameters"),
            image_path: self.registry.query_string(service_key, "ImagePath"),
            service_type: self.registry.query_dword(service_key, "Type"),
            start_type: self.registry.query_dword(service_key, "Start"),
            error_control: self.registry.query_dword(service_key, "ErrorControl"),
            load_order_group: self.registry.query_string(service_key, "Group"),
            class_guid: self.registry.query_string(service_key, "ClassGUID"),
            tag: self.registry.query_dword(service_key, "Tag"),
            dependencies: self
                .registry
                .query_multi_string(service_key, "DependOnService")
                .unwrap_or_default(),
            display_name: self.registry.query_string(service_key, "DisplayName"),
            object_name: self.registry.query_string(service_key, "ObjectName"),
        }
    }

    /// Set a DWORD on a service's own key (e.g. `Start`, `CrashCount`) — used by the
    /// driver supervisor to record a crash-looping driver's disabled state where a
    /// user-mode tool (or the PnP manager) can read + act on it. Creates the service
    /// key if it doesn't exist yet.
    pub fn set_service_dword(&mut self, service: &str, value_name: &str, value: u32) {
        let key = self.registry.create_key(&service_path(service));
        self.registry.set_dword(key, value_name, value);
    }

    /// Read a DWORD from a service's own key (creates the key if absent → `None`).
    pub fn service_dword(&mut self, service: &str, value_name: &str) -> Option<u32> {
        let key = self.registry.create_key(&service_path(service));
        self.registry.query_dword(key, value_name)
    }

    // --- devnodes (spec §10) --------------------------------------------------

    /// Register a devnode: create `Enum\<InstanceId>` + stamp the standard values, link it to
    /// its service. Returns the devnode id.
    pub fn register_devnode(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_name: Option<&str>,
        hardware_ids: &[&str],
        compatible_ids: &[&str],
    ) -> DevnodeId {
        let enum_key = self.registry.create_key(&devnode_path(instance_id));
        if let Some(s) = service {
            self.registry.set_string(enum_key, "Service", s);
        }
        if let Some(p) = pdo_name {
            self.registry.set_string(enum_key, "PdoName", p);
        }
        if !hardware_ids.is_empty() {
            self.registry.set_value(
                enum_key,
                "HardwareID",
                RegistryValueType::MultiSz,
                encode_multi_sz(hardware_ids),
            );
        }
        if !compatible_ids.is_empty() {
            self.registry.set_value(
                enum_key,
                "CompatibleIDs",
                RegistryValueType::MultiSz,
                encode_multi_sz(compatible_ids),
            );
        }
        self.refresh_registry_devnode_key(instance_id, enum_key)
            .expect("newly registered devnode metadata was not indexable")
    }

    /// Index one already-existing `Enum\<InstanceId>` key as a devnode record.
    ///
    /// This is the import path for boot hives: the registry tree remains authoritative and the
    /// devnode table becomes a searchable metadata index over it.
    pub fn index_registry_devnode(&mut self, instance_id: &str) -> Option<DevnodeId> {
        if let Some(id) = self.devnode(instance_id).map(|d| d.id) {
            return Some(id);
        }
        let enum_key = self.registry.open_key(&devnode_path(instance_id))?;
        self.index_registry_devnode_key(instance_id, enum_key)
    }

    /// Recursively index all devnode-shaped keys under
    /// `\Registry\Machine\System\CurrentControlSet\Enum`.
    pub fn index_registry_devnodes(&mut self) -> usize {
        let Some(enum_root) = self.registry.open_key(ENUM_PATH) else {
            return 0;
        };
        self.index_registry_devnodes_from_key(enum_root, String::new())
    }

    /// Refresh the complete semantic devnode index from the current registry tree.
    ///
    /// Existing devnode identities and property bags are retained when their instance still
    /// exists, while registry fields are replaced atomically from the current Enum key. Records
    /// whose keys were deleted or no longer contain devnode metadata are removed together with
    /// interfaces that referenced them.
    pub fn refresh_registry_devnodes(&mut self) -> usize {
        let Some(enum_root) = self.registry.open_key(ENUM_PATH) else {
            self.devnodes.clear();
            self.interfaces.clear();
            return 0;
        };
        let mut keys = Vec::new();
        self.collect_registry_devnode_keys(enum_root, String::new(), &mut keys);
        let mut live_instances = Vec::new();
        for (instance_id, enum_key) in keys {
            if self
                .refresh_registry_devnode_key(&instance_id, enum_key)
                .is_some()
            {
                live_instances.push(instance_id);
            }
        }
        let mut retained_instances: Vec<String> = Vec::new();
        self.devnodes.retain(|devnode| {
            let live = live_instances
                .iter()
                .any(|instance| instance.eq_ignore_ascii_case(&devnode.instance_id));
            let duplicate = retained_instances
                .iter()
                .any(|instance| instance.eq_ignore_ascii_case(&devnode.instance_id));
            if live && !duplicate {
                retained_instances.push(devnode.instance_id.clone());
                true
            } else {
                false
            }
        });
        let live_ids: Vec<DevnodeId> = self.devnodes.iter().map(|devnode| devnode.id).collect();
        self.interfaces
            .retain(|interface| live_ids.contains(&interface.devnode));
        self.devnodes.len()
    }

    fn collect_registry_devnode_keys(
        &self,
        key: RegistryKeyId,
        instance_id: String,
        out: &mut Vec<(String, RegistryKeyId)>,
    ) {
        if !instance_id.is_empty() {
            out.push((instance_id.clone(), key));
        }
        for child_name in self.registry.enum_subkeys(key) {
            let Some(child_key) = self.registry.open_subkey(key, &child_name) else {
                continue;
            };
            let child_instance = if instance_id.is_empty() {
                child_name
            } else {
                let mut child_instance = instance_id.clone();
                child_instance.push('\\');
                child_instance.push_str(&child_name);
                child_instance
            };
            self.collect_registry_devnode_keys(child_key, child_instance, out);
        }
    }

    fn refresh_registry_devnode_key(
        &mut self,
        instance_id: &str,
        enum_key: RegistryKeyId,
    ) -> Option<DevnodeId> {
        let service = self.registry.query_string(enum_key, "Service");
        let pdo_name = self.registry.query_string(enum_key, "PdoName");
        let driver_key = self.registry.query_string(enum_key, "Driver");
        let hardware_ids = self
            .registry
            .query_multi_string(enum_key, "HardwareID")
            .unwrap_or_default();
        let compatible_ids = self
            .registry
            .query_multi_string(enum_key, "CompatibleIDs")
            .unwrap_or_default();
        if service.is_none()
            && pdo_name.is_none()
            && driver_key.is_none()
            && hardware_ids.is_empty()
            && compatible_ids.is_empty()
        {
            return None;
        }

        if let Some(existing) = self
            .devnodes
            .iter_mut()
            .find(|devnode| devnode.instance_id.eq_ignore_ascii_case(instance_id))
        {
            existing.instance_id = instance_id.into();
            existing.service = service;
            existing.pdo_name = pdo_name;
            existing.driver_key = driver_key;
            existing.hardware_ids = hardware_ids;
            existing.compatible_ids = compatible_ids;
            existing.enum_key = enum_key;
            return Some(existing.id);
        }

        let id = self.alloc_id();
        self.devnodes.push(DevnodeRecord {
            id,
            instance_id: instance_id.into(),
            service,
            pdo_name,
            driver_key,
            hardware_ids,
            compatible_ids,
            enum_key,
            properties: PropertyBag::default(),
        });
        Some(id)
    }

    fn index_registry_devnodes_from_key(
        &mut self,
        key: RegistryKeyId,
        instance_id: String,
    ) -> usize {
        let mut count = 0usize;
        if !instance_id.is_empty() && self.index_registry_devnode_key(&instance_id, key).is_some() {
            count += 1;
        }

        let child_names = self.registry.enum_subkeys(key);
        for child_name in child_names {
            let Some(child_key) = self.registry.open_subkey(key, &child_name) else {
                continue;
            };
            let child_instance = if instance_id.is_empty() {
                child_name
            } else {
                let mut child_instance = instance_id.clone();
                child_instance.push('\\');
                child_instance.push_str(&child_name);
                child_instance
            };
            count += self.index_registry_devnodes_from_key(child_key, child_instance);
        }
        count
    }

    fn index_registry_devnode_key(
        &mut self,
        instance_id: &str,
        enum_key: RegistryKeyId,
    ) -> Option<DevnodeId> {
        if self.devnode(instance_id).is_some() {
            return None;
        }
        let service = self.registry.query_string(enum_key, "Service");
        let pdo_name = self.registry.query_string(enum_key, "PdoName");
        let driver_key = self.registry.query_string(enum_key, "Driver");
        let hardware_ids = self
            .registry
            .query_multi_string(enum_key, "HardwareID")
            .unwrap_or_default();
        let compatible_ids = self
            .registry
            .query_multi_string(enum_key, "CompatibleIDs")
            .unwrap_or_default();
        if service.is_none()
            && pdo_name.is_none()
            && driver_key.is_none()
            && hardware_ids.is_empty()
            && compatible_ids.is_empty()
        {
            return None;
        }

        let id = self.alloc_id();
        self.devnodes.push(DevnodeRecord {
            id,
            instance_id: instance_id.into(),
            service,
            pdo_name,
            driver_key,
            hardware_ids,
            compatible_ids,
            enum_key,
            properties: PropertyBag::default(),
        });
        Some(id)
    }

    /// Resolve one driver service and its complete current Enum binding from the live registry.
    pub fn driver_service_binding(&mut self, service_name: &str) -> Option<DriverServiceBinding> {
        self.refresh_registry_devnodes();
        let ServiceStartSpec::Driver(service) = self.service_start_spec(service_name)? else {
            return None;
        };
        let devnodes = self
            .devnodes_for_service(&service.service_name)
            .into_iter()
            .cloned()
            .collect();
        Some(DriverServiceBinding { service, devnodes })
    }

    fn devnode_mut(&mut self, id: DevnodeId) -> Option<&mut DevnodeRecord> {
        self.devnodes.iter_mut().find(|d| d.id == id)
    }
    fn devnode_by_id(&self, id: DevnodeId) -> Option<&DevnodeRecord> {
        self.devnodes.iter().find(|d| d.id == id)
    }
    /// The `Enum\<InstanceId>` registry key of a devnode (`WdfDeviceOpenRegistryKey(DEVICE)`).
    pub fn devnode_enum_key(&self, id: DevnodeId) -> Option<RegistryKeyId> {
        self.devnode_by_id(id).map(|d| d.enum_key)
    }

    /// The `Service` value of a devnode — the driver service the PnP Manager binds to it.
    pub fn devnode_service(&self, id: DevnodeId) -> Option<&str> {
        self.devnode_by_id(id).and_then(|d| d.service.as_deref())
    }

    /// A devnode's `HardwareID` list (the `BusQueryHardwareIDs` answer).
    pub fn devnode_hardware_ids(&self, id: DevnodeId) -> Option<&[String]> {
        self.devnode_by_id(id).map(|d| d.hardware_ids.as_slice())
    }

    // --- PnP properties (spec §11) --------------------------------------------

    /// `WdfDeviceAssignProperty` / `IoSetDevicePropertyData` — set a `DEVPROPKEY` property.
    pub fn assign_devprop(
        &mut self,
        devnode: DevnodeId,
        key: DevPropKey,
        value: PropertyValue,
    ) -> bool {
        match self.devnode_mut(devnode) {
            Some(d) => {
                d.properties.set_devprop(key, value);
                true
            }
            None => false,
        }
    }
    /// `WdfDeviceQueryProperty` / `IoGetDevicePropertyData`.
    pub fn query_devprop(&self, devnode: DevnodeId, key: &DevPropKey) -> Option<&PropertyValue> {
        self.devnode_by_id(devnode)?.properties.get_devprop(key)
    }
    /// Set a legacy `DEVICE_REGISTRY_PROPERTY` (e.g. `FriendlyName`).
    pub fn set_legacy_property(
        &mut self,
        devnode: DevnodeId,
        property: u32,
        value: PropertyValue,
    ) -> bool {
        match self.devnode_mut(devnode) {
            Some(d) => {
                d.properties.set_legacy(property, value);
                true
            }
            None => false,
        }
    }
    /// `IoGetDeviceProperty` — read a legacy `DEVICE_REGISTRY_PROPERTY`.
    pub fn query_legacy_property(
        &self,
        devnode: DevnodeId,
        property: u32,
    ) -> Option<&PropertyValue> {
        self.devnode_by_id(devnode)?.properties.get_legacy(property)
    }

    /// Resolve one legacy `IoGetDeviceProperty` value by stable instance path. Imported Enum keys
    /// are indexed on demand. Bus and resource properties intentionally remain owned by the PnP
    /// and resource managers rather than being synthesized from registry metadata.
    pub fn device_property_bytes(&mut self, instance_id: &str, property: u32) -> Option<Vec<u8>> {
        if device_property::source(property) != DevicePropertySource::Configuration {
            return None;
        }
        let devnode_id = self
            .devnode(instance_id)
            .map(|devnode| devnode.id)
            .or_else(|| self.index_registry_devnode(instance_id))?;
        let devnode = self.devnode_by_id(devnode_id)?;
        let enum_key = devnode.enum_key;
        match property {
            device_property::PHYSICAL_DEVICE_OBJECT_NAME => {
                devnode.pdo_name.as_deref().map(encode_sz)
            }
            device_property::ENUMERATOR_NAME => instance_id
                .split_once('\\')
                .map(|(enumerator, _)| enumerator)
                .filter(|enumerator| !enumerator.is_empty())
                .map(encode_sz),
            _ => {
                if let Some(value) = devnode.properties.get_legacy(property) {
                    return valid_legacy_override(property, value).then(|| value.data.clone());
                }
                match property {
                    device_property::DEVICE_DESCRIPTION => {
                        self.registry_property_bytes(enum_key, "DeviceDesc", RegistryValueType::Sz)
                    }
                    device_property::HARDWARE_ID => self.registry_property_bytes(
                        enum_key,
                        "HardwareID",
                        RegistryValueType::MultiSz,
                    ),
                    device_property::COMPATIBLE_IDS => self.registry_property_bytes(
                        enum_key,
                        "CompatibleIDs",
                        RegistryValueType::MultiSz,
                    ),
                    device_property::BOOT_CONFIGURATION => self
                        .registry
                        .open_subkey(enum_key, "LogConf")
                        .and_then(|key| {
                            self.registry_property_bytes(
                                key,
                                "BootConfig",
                                RegistryValueType::ResourceList,
                            )
                        }),
                    device_property::CLASS_NAME => {
                        self.registry_property_bytes(enum_key, "Class", RegistryValueType::Sz)
                    }
                    device_property::CLASS_GUID => {
                        self.registry_property_bytes(enum_key, "ClassGUID", RegistryValueType::Sz)
                    }
                    device_property::DRIVER_KEY_NAME => {
                        self.registry_property_bytes(enum_key, "Driver", RegistryValueType::Sz)
                    }
                    device_property::MANUFACTURER => {
                        self.registry_property_bytes(enum_key, "Mfg", RegistryValueType::Sz)
                    }
                    device_property::FRIENDLY_NAME => self.registry_property_bytes(
                        enum_key,
                        "FriendlyName",
                        RegistryValueType::Sz,
                    ),
                    device_property::LOCATION_INFORMATION => self.registry_property_bytes(
                        enum_key,
                        "LocationInformation",
                        RegistryValueType::Sz,
                    ),
                    device_property::UI_NUMBER => {
                        self.registry_property_bytes(enum_key, "UINumber", RegistryValueType::Dword)
                    }
                    device_property::INSTALL_STATE => {
                        let flags = match self.registry.query_value(enum_key, "ConfigFlags") {
                            None => 0,
                            Some(value)
                                if value.value_type == RegistryValueType::Dword
                                    && valid_registry_property_data(value) =>
                            {
                                u32::from_le_bytes([
                                    value.data[0],
                                    value.data[1],
                                    value.data[2],
                                    value.data[3],
                                ])
                            }
                            Some(_) => return None,
                        };
                        let state = if flags & 0x40 != 0 {
                            2u32
                        } else if flags & 0x20 != 0 {
                            1u32
                        } else {
                            0u32
                        };
                        Some(state.to_le_bytes().to_vec())
                    }
                    device_property::CONTAINER_ID => {
                        self.registry_property_bytes(enum_key, "ContainerID", RegistryValueType::Sz)
                    }
                    _ => None,
                }
            }
        }
    }

    fn registry_property_bytes(
        &self,
        key: RegistryKeyId,
        value_name: &str,
        expected_type: RegistryValueType,
    ) -> Option<Vec<u8>> {
        let value = self.registry.query_value(key, value_name)?;
        (value.value_type == expected_type && valid_registry_property_data(value))
            .then(|| value.data.clone())
    }

    pub fn devnode(&self, instance_id: &str) -> Option<&DevnodeRecord> {
        self.devnodes
            .iter()
            .find(|d| d.instance_id.eq_ignore_ascii_case(instance_id))
    }
    /// Devnodes bound to a service (the PnP Manager's enumeration input, spec §10.3).
    pub fn devnodes_for_service(&self, service: &str) -> Vec<&DevnodeRecord> {
        self.devnodes
            .iter()
            .filter(|d| {
                d.service
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(service))
            })
            .collect()
    }
    pub fn service_has_devnodes(&self, service: &str) -> bool {
        self.devnodes.iter().any(|d| {
            d.service
                .as_deref()
                .is_some_and(|s| s.eq_ignore_ascii_case(service))
        })
    }
    pub fn linkage_export_for_driver_key(&self, driver_key: &str) -> Option<String> {
        if driver_key.is_empty() {
            return None;
        }
        let mut path = String::from(CONTROL_CLASS_PATH);
        path.push('\\');
        path.push_str(driver_key);
        path.push_str("\\Linkage");
        let key = self.registry.open_key(&path)?;
        self.registry.query_string(key, "Export")
    }
    pub fn devnode_linkage_export(&self, devnode: &DevnodeRecord) -> Option<String> {
        self.linkage_export_for_driver_key(devnode.driver_key.as_deref()?)
    }
    pub fn devnode_count(&self) -> usize {
        self.devnodes.len()
    }

    // --- device interfaces (spec §11) -----------------------------------------

    /// `IoRegisterDeviceInterface` — register an interface for a devnode under a class GUID +
    /// build its symbolic link. Returns the interface id.
    pub fn register_interface(
        &mut self,
        devnode: DevnodeId,
        guid: &str,
        reference: &str,
        enabled_on_start: bool,
    ) -> Result<InterfaceId, InterfaceRegistrationError> {
        let instance = self
            .devnodes
            .iter()
            .find(|record| record.id == devnode)
            .map(|record| record.instance_id.clone())
            .ok_or(InterfaceRegistrationError::UnknownDevnode)?;
        if guid_text_to_memory_bytes(guid).is_none() {
            return Err(InterfaceRegistrationError::InvalidGuid);
        }
        if reference.contains(['\\', '/']) {
            return Err(InterfaceRegistrationError::InvalidReference);
        }
        if let Some(existing) = self.interfaces.iter().find(|interface| {
            interface.devnode == devnode
                && interface.guid.eq_ignore_ascii_case(guid)
                && interface.reference.eq_ignore_ascii_case(reference)
        }) {
            return Ok(existing.id);
        }
        let symbolic_link = build_symbolic_link(guid, &instance, reference);
        materialize_interface_registry(
            &mut self.registry,
            guid,
            &instance,
            reference,
            &symbolic_link,
            enabled_on_start,
        );
        let id = self.alloc_id();
        self.interfaces.push(InterfaceRecord {
            id,
            devnode,
            guid: guid.into(),
            reference: reference.into(),
            enabled: enabled_on_start,
            symbolic_link,
        });
        Ok(id)
    }

    /// `IoSetDeviceInterfaceState` — enable/disable an interface (spec §11.3).
    pub fn set_interface_state(&mut self, id: InterfaceId, enabled: bool) -> bool {
        let Some(index) = self
            .interfaces
            .iter()
            .position(|interface| interface.id == id)
        else {
            return false;
        };
        self.set_interface_state_at(index, enabled);
        true
    }
    pub fn interface(&self, id: InterfaceId) -> Option<&InterfaceRecord> {
        self.interfaces.iter().find(|i| i.id == id)
    }
    pub fn interface_by_symbolic_link(&self, symbolic_link: &str) -> Option<&InterfaceRecord> {
        self.interfaces
            .iter()
            .find(|interface| interface.symbolic_link.eq_ignore_ascii_case(symbolic_link))
    }
    pub fn set_interface_state_by_symbolic_link(
        &mut self,
        symbolic_link: &str,
        enabled: bool,
    ) -> bool {
        let Some(index) = self
            .interfaces
            .iter()
            .position(|interface| interface.symbolic_link.eq_ignore_ascii_case(symbolic_link))
        else {
            return false;
        };
        self.set_interface_state_at(index, enabled);
        true
    }

    fn set_interface_state_at(&mut self, index: usize, enabled: bool) {
        let interface = &self.interfaces[index];
        let Some(instance) = self
            .devnodes
            .iter()
            .find(|devnode| devnode.id == interface.devnode)
            .map(|devnode| devnode.instance_id.as_str())
        else {
            return;
        };
        materialize_interface_linked_state(
            &mut self.registry,
            &interface.guid,
            instance,
            &interface.reference,
            enabled,
        );
        self.interfaces[index].enabled = enabled;
    }

    // --- iteration (for persistence snapshots, spec §9) -----------------------

    pub fn services(&self) -> &[ServiceRecord] {
        &self.services
    }
    pub fn devnodes(&self) -> &[DevnodeRecord] {
        &self.devnodes
    }
    pub fn interfaces(&self) -> &[InterfaceRecord] {
        &self.interfaces
    }
    /// Enumerate interfaces by class GUID, optionally only enabled ones (spec §11, §18.3).
    pub fn interfaces_by_guid(&self, guid: &str, enabled_only: bool) -> Vec<&InterfaceRecord> {
        self.interfaces
            .iter()
            .filter(|i| i.guid.eq_ignore_ascii_case(guid) && (!enabled_only || i.enabled))
            .collect()
    }

    /// Does user-mode PnP know this device instance? The CM device set includes the NT root-bus
    /// pseudo-devnode plus every indexed `Enum\<InstanceId>` devnode.
    pub fn pnp_device_exists(&self, instance_id: &str) -> bool {
        instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE)
            || self.devnode(instance_id).is_some()
    }

    /// The root-bus tree depth projected to user-mode PnP. Current CM metadata models each indexed
    /// devnode as a direct child of `HTREE\ROOT\0`.
    pub fn pnp_device_depth(&self, instance_id: &str) -> Option<u32> {
        if instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE) {
            Some(0)
        } else {
            self.devnode(instance_id).map(|_| 1)
        }
    }

    /// Resolve a parent/child/sibling relation in the CM-backed root-bus tree.
    pub fn pnp_related_device(&self, instance_id: &str, relation: u32) -> Option<String> {
        match relation {
            pnp_relation::PARENT => (!instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE)
                && self.devnode(instance_id).is_some())
            .then(|| PNP_ROOT_DEVICE_INSTANCE.into()),
            pnp_relation::CHILD => {
                if instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE) {
                    self.devnodes
                        .first()
                        .map(|devnode| devnode.instance_id.clone())
                } else {
                    None
                }
            }
            pnp_relation::SIBLING => {
                if instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE) {
                    return None;
                }
                let pos = self
                    .devnodes
                    .iter()
                    .position(|devnode| devnode.instance_id.eq_ignore_ascii_case(instance_id))?;
                self.devnodes
                    .get(pos.saturating_add(1))
                    .map(|devnode| devnode.instance_id.clone())
            }
            _ => None,
        }
    }

    /// Bus relations for the current CM root-bus model. Non-bus relation types currently have no
    /// CM-backed edges, so callers receive an empty list after the device identity is validated.
    pub fn pnp_bus_relation_instances(&self, instance_id: &str) -> Option<Vec<String>> {
        if !self.pnp_device_exists(instance_id) {
            return None;
        }
        if instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE) {
            Some(
                self.devnodes
                    .iter()
                    .map(|devnode| devnode.instance_id.clone())
                    .collect(),
            )
        } else {
            Some(Vec::new())
        }
    }

    /// Enabled interface symbolic links matching a Windows in-memory GUID. A root instance queries
    /// all matching interfaces; a concrete devnode filters to interfaces registered to that devnode.
    pub fn pnp_enabled_interface_links_by_guid_bytes(
        &self,
        guid: &[u8; 16],
        instance_id: &str,
    ) -> Option<Vec<String>> {
        if !self.pnp_device_exists(instance_id) {
            return None;
        }
        let devnode_filter = if instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE) {
            None
        } else {
            Some(self.devnode(instance_id)?.id)
        };
        Some(
            self.interfaces
                .iter()
                .filter(|interface| {
                    interface.enabled
                        && guid_text_eq_memory(&interface.guid, guid)
                        && devnode_filter.is_none_or(|id| interface.devnode == id)
                })
                .map(|interface| interface.symbolic_link.clone())
                .collect(),
        )
    }

    /// Dynamic properties served by the kernel PnP manager rather than raw enum-key registry values.
    pub fn pnp_dynamic_property_bytes(&self, instance_id: &str, property: u32) -> Option<Vec<u8>> {
        if instance_id.eq_ignore_ascii_case(PNP_ROOT_DEVICE_INSTANCE) {
            return match property {
                pnp_property::ENUMERATOR_NAME => Some(encode_sz("HTREE")),
                _ => None,
            };
        }
        let devnode = self.devnode(instance_id)?;
        match property {
            pnp_property::PHYSICAL_DEVICE_OBJECT_NAME => devnode.pdo_name.as_deref().map(encode_sz),
            pnp_property::ENUMERATOR_NAME => {
                let enumerator = instance_id.split('\\').next().unwrap_or("");
                (!enumerator.is_empty()).then(|| encode_sz(enumerator))
            }
            _ => None,
        }
    }
}

fn valid_utf16_sz(data: &[u8]) -> bool {
    data.len() >= 2 && data.len() % 2 == 0 && data[data.len() - 2..] == [0, 0]
}

fn valid_utf16_multi_sz(data: &[u8]) -> bool {
    data.len() >= 4 && data.len() % 2 == 0 && data[data.len() - 4..] == [0, 0, 0, 0]
}

fn valid_registry_property_data(value: &RegistryValue) -> bool {
    match value.value_type {
        RegistryValueType::Sz => valid_utf16_sz(&value.data),
        RegistryValueType::MultiSz => valid_utf16_multi_sz(&value.data),
        RegistryValueType::Dword => value.data.len() == 4,
        RegistryValueType::ResourceList => true,
        _ => false,
    }
}

fn valid_legacy_override(property: u32, value: &PropertyValue) -> bool {
    match property {
        device_property::DEVICE_DESCRIPTION
        | device_property::CLASS_NAME
        | device_property::CLASS_GUID
        | device_property::DRIVER_KEY_NAME
        | device_property::MANUFACTURER
        | device_property::FRIENDLY_NAME
        | device_property::LOCATION_INFORMATION
        | device_property::CONTAINER_ID => {
            value.prop_type == devprop_type::STRING && valid_utf16_sz(&value.data)
        }
        device_property::HARDWARE_ID | device_property::COMPATIBLE_IDS => {
            value.prop_type == devprop_type::STRING_LIST && valid_utf16_multi_sz(&value.data)
        }
        device_property::BOOT_CONFIGURATION => value.prop_type == devprop_type::BINARY,
        device_property::UI_NUMBER => {
            value.prop_type == devprop_type::UINT32 && value.data.len() == 4
        }
        device_property::INSTALL_STATE => {
            value.prop_type == devprop_type::UINT32
                && value.data.len() == 4
                && value.as_uint32().is_some_and(|state| state <= 3)
        }
        _ => false,
    }
}

fn service_path(name: &str) -> String {
    let mut p = String::from(SERVICES_PATH);
    p.push('\\');
    p.push_str(name);
    p
}
fn devnode_path(instance_id: &str) -> String {
    let mut p = String::from(ENUM_PATH);
    p.push('\\');
    p.push_str(instance_id);
    p
}
fn device_class_path(guid: &str) -> String {
    let mut p = String::from(DEVICE_CLASSES_PATH);
    p.push('\\');
    p.push_str(guid);
    p
}

fn mangled_device_instance(instance: &str) -> String {
    instance
        .chars()
        .map(|c| if c == '\\' { '#' } else { c })
        .collect()
}

fn interface_registry_path(guid: &str, instance: &str) -> String {
    let mut path = device_class_path(guid);
    path.push_str(r"\##?#");
    path.push_str(&mangled_device_instance(instance));
    path.push('#');
    path.push_str(guid);
    path
}

fn interface_reference_registry_path(guid: &str, instance: &str, reference: &str) -> String {
    let mut path = interface_registry_path(guid, instance);
    path.push_str(r"\#");
    path.push_str(reference);
    path
}

fn materialize_interface_linked_state(
    registry: &mut Registry,
    guid: &str,
    instance: &str,
    reference: &str,
    enabled: bool,
) {
    let mut control_path = interface_reference_registry_path(guid, instance, reference);
    control_path.push_str(r"\Control");
    if enabled {
        let control = registry.create_key(&control_path);
        registry.set_volatile(control, true);
        registry.set_dword(control, "Linked", 1);
    } else if let Some(control) = registry.open_key(&control_path) {
        registry.delete_key(control, true);
    }
}

fn materialize_interface_registry(
    registry: &mut Registry,
    guid: &str,
    instance: &str,
    reference: &str,
    symbolic_link: &str,
    enabled: bool,
) {
    registry.create_key(&device_class_path(guid));
    let interface = registry.create_key(&interface_registry_path(guid, instance));
    registry.set_string(interface, "DeviceInstance", instance);
    let reference_key = registry.create_key(&interface_reference_registry_path(
        guid, instance, reference,
    ));
    let mut registry_link = String::from(symbolic_link);
    registry_link.replace_range(1..2, "\\");
    registry.set_string(reference_key, "SymbolicLink", &registry_link);
    materialize_interface_linked_state(registry, guid, instance, reference, enabled);
}

/// The device-interface symbolic link name: `\??\<mangled-instance>#{GUID}\reference`.
fn build_symbolic_link(guid: &str, instance: &str, reference: &str) -> String {
    let mut s = String::from(r"\??\");
    s.push_str(&mangled_device_instance(instance));
    s.push('#');
    s.push_str(guid);
    if !reference.is_empty() {
        s.push('\\');
        s.push_str(reference);
    }
    s
}

fn sort_service_metadata(services: &mut [ServiceMetadata]) {
    services.sort_by(|a, b| {
        service_order_cmp(
            &a.name,
            a.service_type,
            a.start_type,
            a.load_order_group.as_deref(),
            a.tag,
            &b.name,
            b.service_type,
            b.start_type,
            b.load_order_group.as_deref(),
            b.tag,
            &[],
        )
    });
}

fn sort_service_metadata_with_group_order(
    services: &mut [ServiceMetadata],
    group_order: &[String],
) {
    services.sort_by(|a, b| {
        service_order_cmp(
            &a.name,
            a.service_type,
            a.start_type,
            a.load_order_group.as_deref(),
            a.tag,
            &b.name,
            b.service_type,
            b.start_type,
            b.load_order_group.as_deref(),
            b.tag,
            group_order,
        )
    });
}

pub fn sort_service_database_order_entries(
    entries: &mut [ServiceDatabaseOrderEntry],
    group_order: &[String],
) {
    entries.sort_by(|a, b| {
        service_order_cmp(
            &a.name,
            a.service_type,
            a.start_type,
            a.load_order_group.as_deref(),
            a.tag,
            &b.name,
            b.service_type,
            b.start_type,
            b.load_order_group.as_deref(),
            b.tag,
            group_order,
        )
    });
}

#[allow(clippy::too_many_arguments)]
fn service_order_cmp(
    a_name: &str,
    a_type: Option<u32>,
    a_start: Option<u32>,
    a_group: Option<&str>,
    a_tag: Option<u32>,
    b_name: &str,
    b_type: Option<u32>,
    b_start: Option<u32>,
    b_group: Option<&str>,
    b_tag: Option<u32>,
    group_order: &[String],
) -> Ordering {
    service_start_rank(a_start)
        .cmp(&service_start_rank(b_start))
        .then_with(|| {
            group_order_rank(a_group, group_order).cmp(&group_order_rank(b_group, group_order))
        })
        .then_with(|| optional_ascii_case_insensitive_cmp(a_group, b_group))
        .then_with(|| service_process_rank(a_type).cmp(&service_process_rank(b_type)))
        .then_with(|| service_tag_rank(a_tag).cmp(&service_tag_rank(b_tag)))
        .then_with(|| ascii_case_insensitive_cmp(a_name, b_name))
}

fn service_start_rank(start: Option<u32>) -> u32 {
    start.unwrap_or(u32::MAX)
}

fn service_tag_rank(tag: Option<u32>) -> u32 {
    tag.unwrap_or(u32::MAX)
}

fn service_process_rank(service_type: Option<u32>) -> u8 {
    match service_type.and_then(win32_service_process_kind_from_type) {
        Some(Win32ServiceProcessKind::Own) => 0,
        Some(Win32ServiceProcessKind::Shared) => 1,
        None => 2,
    }
}

fn optional_ascii_case_insensitive_cmp(a: Option<&str>, b: Option<&str>) -> Ordering {
    match (a, b) {
        (Some(a), Some(b)) => ascii_case_insensitive_cmp(a, b),
        (Some(_), None) => Ordering::Less,
        (None, Some(_)) => Ordering::Greater,
        (None, None) => Ordering::Equal,
    }
}

fn ascii_case_insensitive_cmp(a: &str, b: &str) -> Ordering {
    a.to_ascii_lowercase()
        .cmp(&b.to_ascii_lowercase())
        .then_with(|| a.cmp(b))
}

fn group_order_rank(group: Option<&str>, group_order: &[String]) -> usize {
    match group {
        Some(group) => group_order
            .iter()
            .position(|candidate| candidate.eq_ignore_ascii_case(group))
            .unwrap_or(group_order.len()),
        None => group_order.len().saturating_add(1),
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

    use super::*;

    #[test]
    fn root_keys_exist() {
        let cm = ConfigManager::new();
        assert!(cm.registry().open_key(SERVICES_PATH).is_some());
        assert!(cm.registry().open_key(DEVICE_CLASSES_PATH).is_some());
        // Case-insensitive path open.
        assert!(cm
            .registry()
            .open_key(r"\registry\machine\system\currentcontrolset\services")
            .is_some());
    }

    #[test]
    fn service_registration_and_parameters() {
        let mut cm = ConfigManager::new();
        cm.register_service(
            "KmdfInterfaceRegistryTest",
            "KmdfInterfaceRegistryTest.sys",
            Some("System"),
            Some("{4d36e97d-e325-11ce-bfc1-08002be10318}"),
            3,
            1,
        );
        // The service key + standard values exist.
        let key = cm
            .registry()
            .open_key(
                r"\Registry\Machine\System\CurrentControlSet\Services\KmdfInterfaceRegistryTest",
            )
            .unwrap();
        assert_eq!(
            cm.registry().query_dword(key, "Type"),
            Some(SERVICE_KERNEL_DRIVER)
        );
        assert_eq!(cm.registry().query_dword(key, "Start"), Some(3));
        assert_eq!(
            cm.registry().query_string(key, "ImagePath").as_deref(),
            Some("KmdfInterfaceRegistryTest.sys")
        );
        // Fixture Parameters: Answer=42, Greeting="hello registry".
        cm.set_service_parameter(
            "KmdfInterfaceRegistryTest",
            "Answer",
            RegistryValueType::Dword,
            42u32.to_le_bytes().to_vec(),
        );
        cm.set_service_parameter(
            "KmdfInterfaceRegistryTest",
            "Greeting",
            RegistryValueType::Sz,
            encode_sz("hello registry"),
        );
        let params = cm
            .service_parameters_key("KmdfInterfaceRegistryTest")
            .unwrap();
        assert_eq!(cm.registry().query_dword(params, "Answer"), Some(42));
        assert_eq!(
            cm.registry().query_string(params, "greeting").as_deref(),
            Some("hello registry")
        );
        // DriverEntry RegistryPath.
        assert_eq!(
            cm.service_key_path("kmdfinterfaceregistrytest").as_deref(),
            Some(r"\Registry\Machine\System\CurrentControlSet\Services\KmdfInterfaceRegistryTest")
        );
    }

    #[test]
    fn service_metadata_reads_registry_values() {
        let mut cm = ConfigManager::new();
        let key = cm
            .registry_mut()
            .create_key(r"\Registry\Machine\System\CurrentControlSet\Services\RpcSs");
        cm.registry_mut().set_string(
            key,
            "ImagePath",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
        );
        cm.registry_mut()
            .set_dword(key, "Type", SERVICE_WIN32_SHARE_PROCESS);
        cm.registry_mut()
            .set_dword(key, "Start", SERVICE_AUTO_START);
        cm.registry_mut().set_dword(key, "ErrorControl", 1);
        cm.registry_mut().set_string(key, "Group", "Network");
        cm.registry_mut()
            .set_string(key, "ClassGUID", "{4D36E972-E325-11CE-BFC1-08002BE10318}");
        cm.registry_mut().set_dword(key, "Tag", 7);
        cm.registry_mut()
            .set_string(key, "DisplayName", "Remote Procedure Call");
        cm.registry_mut()
            .set_string(key, "ObjectName", "LocalSystem");
        cm.registry_mut().set_value(
            key,
            "DependOnService",
            RegistryValueType::MultiSz,
            encode_multi_sz(&["DcomLaunch", "RpcEptMapper"]),
        );
        let params = cm.registry_mut().create_subkey(key, "Parameters");

        let svc = cm.service_metadata("rpcss").unwrap();
        assert_eq!(svc.name, "RpcSs");
        assert_eq!(svc.service_key, key);
        assert_eq!(svc.parameters_key, Some(params));
        assert_eq!(svc.service_type, Some(SERVICE_WIN32_SHARE_PROCESS));
        assert_eq!(svc.start_type, Some(SERVICE_AUTO_START));
        assert_eq!(svc.error_control, Some(1));
        assert_eq!(svc.load_order_group.as_deref(), Some("Network"));
        assert_eq!(
            svc.class_guid.as_deref(),
            Some("{4D36E972-E325-11CE-BFC1-08002BE10318}")
        );
        assert_eq!(svc.tag, Some(7));
        assert_eq!(svc.display_name.as_deref(), Some("Remote Procedure Call"));
        assert_eq!(svc.object_name.as_deref(), Some("LocalSystem"));
        assert_eq!(
            svc.dependencies,
            alloc::vec![String::from("DcomLaunch"), String::from("RpcEptMapper")]
        );
        assert!(svc.is_win32_service());
        assert!(!svc.is_driver());
        assert_eq!(svc.driver_service_class(), None);
        assert_eq!(svc.driver_object_path(), None);
        assert!(svc.has_launch_image());
    }

    #[test]
    fn service_candidates_are_selected_from_registry_metadata() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "RpcSs",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "Npfs",
            r"system32\drivers\npfs.sys",
            SERVICE_FILE_SYSTEM_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        cm.register_typed_service(
            "PlugPlay",
            r"%SystemRoot%\system32\services.exe",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        cm.register_typed_service(
            "E1000",
            r"system32\drivers\e1000.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        cm.register_typed_service(
            "DisabledSvc",
            r"%SystemRoot%\system32\disabled.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_DISABLED,
            1,
        );
        let malformed = cm
            .registry_mut()
            .create_key(r"\Registry\Machine\System\CurrentControlSet\Services\NoImage");
        cm.registry_mut()
            .set_dword(malformed, "Type", SERVICE_WIN32_OWN_PROCESS);
        cm.registry_mut()
            .set_dword(malformed, "Start", SERVICE_AUTO_START);

        let auto = cm.auto_start_win32_service_candidates();
        assert_eq!(auto.len(), 1);
        assert_eq!(auto[0].name, "RpcSs");

        let drivers = cm.boot_system_driver_candidates();
        assert_eq!(drivers.len(), 1);
        assert_eq!(drivers[0].name, "Npfs");
        assert_eq!(
            drivers[0].driver_service_class(),
            Some(DriverServiceClass::FileSystem)
        );
        assert_eq!(
            driver_service_class_from_type(SERVICE_KERNEL_DRIVER),
            Some(DriverServiceClass::Device)
        );
        assert_eq!(
            driver_service_class_from_type(SERVICE_RECOGNIZER_DRIVER),
            Some(DriverServiceClass::FileSystem)
        );

        let all_auto = cm.service_candidates_by_start_and_type(
            &[SERVICE_AUTO_START],
            SERVICE_WIN32_TYPE_MASK | SERVICE_DRIVER_TYPE_MASK,
        );
        assert_eq!(all_auto.len(), 1);
        assert_eq!(all_auto[0].name, "RpcSs");

        let demand_win32 = cm.demand_start_win32_service_candidates();
        assert_eq!(demand_win32.len(), 1);
        assert_eq!(demand_win32[0].name, "PlugPlay");

        let demand_drivers = cm.demand_start_driver_candidates();
        assert_eq!(demand_drivers.len(), 1);
        assert_eq!(demand_drivers[0].name, "E1000");
        assert_eq!(
            demand_drivers[0].driver_service_class(),
            Some(DriverServiceClass::Device)
        );
    }

    #[test]
    fn win32_service_launch_specs_follow_registry_metadata() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "RpcSs",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        let rpcss_key = cm.service_metadata("RpcSs").unwrap().service_key;
        cm.registry_mut()
            .set_string(rpcss_key, "ObjectName", "LocalSystem");
        cm.registry_mut()
            .set_string(rpcss_key, "DisplayName", "Remote Procedure Call");
        cm.registry_mut().set_value(
            rpcss_key,
            "DependOnService",
            RegistryValueType::MultiSz,
            encode_multi_sz(&["DcomLaunch", "RpcEptMapper"]),
        );

        cm.register_typed_service(
            "InteractiveOwn",
            r"%SystemRoot%\system32\interactive.exe",
            SERVICE_WIN32_OWN_PROCESS | SERVICE_INTERACTIVE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        let own_key = cm.service_metadata("InteractiveOwn").unwrap().service_key;
        cm.registry_mut()
            .set_string(own_key, "ObjectName", r".\InteractiveUser");

        cm.register_typed_service(
            "DemandOwn",
            r"%SystemRoot%\system32\demand.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        cm.register_typed_service(
            "Driver",
            r"system32\drivers\driver.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "DisabledSvc",
            r"%SystemRoot%\system32\disabled.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_DISABLED,
            1,
        );
        cm.register_typed_service(
            "Malformed",
            r"%SystemRoot%\system32\malformed.exe",
            SERVICE_WIN32_OWN_PROCESS | SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "MixedType",
            r"%SystemRoot%\system32\mixed.exe",
            SERVICE_WIN32_OWN_PROCESS | SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        let no_image = cm
            .registry_mut()
            .create_key(r"\Registry\Machine\System\CurrentControlSet\Services\NoImage");
        cm.registry_mut()
            .set_dword(no_image, "Type", SERVICE_WIN32_OWN_PROCESS);
        cm.registry_mut()
            .set_dword(no_image, "Start", SERVICE_AUTO_START);

        let auto = cm.auto_start_win32_service_launch_specs();
        assert_eq!(auto.len(), 2);
        let interactive = auto
            .iter()
            .find(|spec| spec.service_name == "InteractiveOwn")
            .unwrap();
        assert_eq!(interactive.process_kind, Win32ServiceProcessKind::Own);
        assert!(interactive.interactive);
        assert_eq!(
            interactive.account_name.as_deref(),
            Some(r".\InteractiveUser")
        );

        let rpcss = auto
            .iter()
            .find(|spec| spec.service_name == "RpcSs")
            .unwrap();
        assert_eq!(rpcss.service_key, rpcss_key);
        assert_eq!(rpcss.process_kind, Win32ServiceProcessKind::Shared);
        assert!(!rpcss.interactive);
        assert_eq!(rpcss.account_name.as_deref(), Some("LocalSystem"));
        assert_eq!(rpcss.display_name.as_deref(), Some("Remote Procedure Call"));
        assert_eq!(
            rpcss.dependencies,
            alloc::vec![String::from("DcomLaunch"), String::from("RpcEptMapper")]
        );

        let demand = cm.demand_start_win32_service_launch_specs();
        assert_eq!(demand.len(), 1);
        assert_eq!(demand[0].service_name, "DemandOwn");
        assert_eq!(demand[0].process_kind, Win32ServiceProcessKind::Own);
        assert!(!demand[0].interactive);
    }

    #[test]
    fn win32_auto_start_services_follow_service_group_order() {
        fn set_group(cm: &mut ConfigManager, service: &str, group: &str) {
            let key = cm.service_metadata(service).unwrap().service_key;
            cm.registry_mut().set_string(key, "Group", group);
        }

        let mut cm = ConfigManager::new();
        let group_key = cm.registry_mut().create_key(SERVICE_GROUP_ORDER_PATH);
        cm.registry_mut().set_value(
            group_key,
            "List",
            RegistryValueType::MultiSz,
            encode_multi_sz(&["Event Log", "NetworkProvider"]),
        );
        cm.register_typed_service(
            "Browser",
            r"%SystemRoot%\system32\svchost.exe -k netsvcs",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        set_group(&mut cm, "Browser", "NetworkProvider");
        cm.register_typed_service(
            "NoGroupSvc",
            r"%SystemRoot%\system32\nogroup.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "EventLog",
            r"%SystemRoot%\system32\eventlog.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        set_group(&mut cm, "EventLog", "Event Log");
        cm.register_typed_service(
            "VendorSvc",
            r"%SystemRoot%\system32\vendor.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        set_group(&mut cm, "VendorSvc", "Vendor Group");

        let names: Vec<String> = cm
            .auto_start_win32_service_candidates()
            .into_iter()
            .map(|service| service.name)
            .collect();
        assert_eq!(
            names,
            alloc::vec![
                String::from("EventLog"),
                String::from("Browser"),
                String::from("VendorSvc"),
                String::from("NoGroupSvc")
            ]
        );

        let specs = cm.auto_start_win32_service_launch_specs();
        assert_eq!(specs[0].service_name, "EventLog");
        assert_eq!(specs[0].process_kind, Win32ServiceProcessKind::Own);
        assert_eq!(
            specs[0].process_launch().unwrap().nt_image_path,
            r"\SystemRoot\system32\eventlog.exe"
        );
        assert_eq!(
            cm.service_start_specs_by_start(&[SERVICE_AUTO_START])
                .into_iter()
                .filter_map(|spec| match spec {
                    ServiceStartSpec::Win32(spec) => Some(spec.service_name),
                    ServiceStartSpec::Driver(_) => None,
                })
                .collect::<Vec<_>>(),
            names
        );
    }

    #[test]
    fn service_database_order_uses_typed_service_metadata() {
        fn set_group(cm: &mut ConfigManager, service: &str, group: &str) {
            let key = cm.service_metadata(service).unwrap().service_key;
            cm.registry_mut().set_string(key, "Group", group);
        }

        let mut cm = ConfigManager::new();
        let group_key = cm.registry_mut().create_key(SERVICE_GROUP_ORDER_PATH);
        cm.registry_mut().set_value(
            group_key,
            "List",
            RegistryValueType::MultiSz,
            encode_multi_sz(&["Event Log", "NetworkProvider"]),
        );
        cm.register_typed_service(
            "DcomLaunch",
            r"%SystemRoot%\system32\svchost.exe -k DcomLaunch",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        set_group(&mut cm, "DcomLaunch", "Event log");
        cm.register_typed_service(
            "EventLog",
            r"%SystemRoot%\system32\eventlog.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            0,
        );
        set_group(&mut cm, "EventLog", "Event Log");
        cm.register_typed_service(
            "Browser",
            r"%SystemRoot%\system32\svchost.exe -k netsvcs",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        set_group(&mut cm, "Browser", "NetworkProvider");
        cm.register_typed_service(
            "NoGroupSvc",
            r"%SystemRoot%\system32\nogroup.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );

        assert_eq!(
            cm.registry()
                .enum_subkeys(cm.registry().open_key(SERVICES_PATH).unwrap()),
            alloc::vec![
                String::from("DcomLaunch"),
                String::from("EventLog"),
                String::from("Browser"),
                String::from("NoGroupSvc")
            ]
        );
        assert_eq!(
            cm.service_database_ordered_names(),
            alloc::vec![
                String::from("EventLog"),
                String::from("DcomLaunch"),
                String::from("Browser"),
                String::from("NoGroupSvc")
            ]
        );
    }

    #[test]
    fn win32_service_process_launches_project_generic_create_process_inputs() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "RpcSs",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "QuotedOwn",
            r#""C:\ReactOS\System32\quoted service.exe" -service"#,
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "RelativeOwn",
            r"system32\relative.exe /svc",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "DemandOwn",
            r"\SystemRoot\System32\demand.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        cm.register_typed_service(
            "Unsupported",
            r"\\server\share\unsupported.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "BrokenQuote",
            r#""C:\ReactOS\System32\broken.exe"#,
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "BadRoot",
            r"\SystemRooted\bad.exe",
            SERVICE_WIN32_OWN_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );

        let auto_specs = cm.auto_start_win32_service_launch_specs();
        assert_eq!(auto_specs.len(), 6);
        let auto_launches = cm.auto_start_win32_service_process_launches();
        assert_eq!(auto_launches.len(), 3);

        let rpcss = auto_launches
            .iter()
            .find(|launch| launch.service_name == "RpcSs")
            .unwrap();
        assert_eq!(rpcss.executable_path, r"%SystemRoot%\system32\svchost.exe");
        assert_eq!(rpcss.nt_image_path, r"\SystemRoot\system32\svchost.exe");
        assert_eq!(
            rpcss.command_line,
            r"%SystemRoot%\system32\svchost.exe -k rpcss"
        );
        assert_eq!(rpcss.process_kind, Win32ServiceProcessKind::Shared);

        let quoted = auto_launches
            .iter()
            .find(|launch| launch.service_name == "QuotedOwn")
            .unwrap();
        assert_eq!(
            quoted.executable_path,
            r"C:\ReactOS\System32\quoted service.exe"
        );
        assert_eq!(
            quoted.nt_image_path,
            r"\SystemRoot\System32\quoted service.exe"
        );
        assert_eq!(
            quoted.command_line,
            r#""C:\ReactOS\System32\quoted service.exe" -service"#
        );

        let relative = auto_launches
            .iter()
            .find(|launch| launch.service_name == "RelativeOwn")
            .unwrap();
        assert_eq!(relative.nt_image_path, r"\SystemRoot\system32\relative.exe");
        assert_eq!(relative.command_line, r"system32\relative.exe /svc");

        let demand = cm.demand_start_win32_service_process_launches();
        assert_eq!(demand.len(), 1);
        assert_eq!(demand[0].service_name, "DemandOwn");
        assert_eq!(demand[0].nt_image_path, r"\SystemRoot\System32\demand.exe");

        let broken = auto_specs
            .iter()
            .find(|spec| spec.service_name == "BrokenQuote")
            .unwrap();
        assert_eq!(
            broken.process_launch().unwrap_err(),
            Win32ServiceProcessLaunchError::UnterminatedQuote
        );

        let bad_root = auto_specs
            .iter()
            .find(|spec| spec.service_name == "BadRoot")
            .unwrap();
        assert_eq!(
            bad_root.process_launch().unwrap_err(),
            Win32ServiceProcessLaunchError::UnsupportedImagePath
        );
    }

    #[test]
    fn service_start_specs_route_by_registry_type() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "RpcSs",
            r"%SystemRoot%\system32\svchost.exe -k rpcss",
            SERVICE_WIN32_SHARE_PROCESS,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "E1000",
            r"system32\drivers\e1000.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            Some("{4D36E972-E325-11CE-BFC1-08002BE10318}"),
            SERVICE_DEMAND_START,
            1,
        );
        let e1000_key = cm.service_metadata("E1000").unwrap().service_key;
        cm.registry_mut()
            .set_string(e1000_key, "ObjectName", r"\Driver\IntelE1000");
        cm.registry_mut().set_string(e1000_key, "Group", "NDIS");
        cm.registry_mut().set_dword(e1000_key, "Tag", 3);
        cm.register_typed_service(
            "MixedType",
            r"%SystemRoot%\system32\mixed.exe",
            SERVICE_WIN32_OWN_PROCESS | SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_AUTO_START,
            1,
        );
        cm.register_typed_service(
            "DisabledDriver",
            r"system32\drivers\disabled.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_DISABLED,
            1,
        );

        match cm.service_start_spec("RpcSs").unwrap() {
            ServiceStartSpec::Win32(spec) => {
                assert_eq!(spec.service_name, "RpcSs");
                assert_eq!(spec.process_kind, Win32ServiceProcessKind::Shared);
            }
            ServiceStartSpec::Driver(_) => panic!("RpcSs must route as Win32"),
        }

        match cm.service_start_spec("e1000").unwrap() {
            ServiceStartSpec::Driver(spec) => {
                assert_eq!(spec.service_name, "E1000");
                assert_eq!(spec.service_key, e1000_key);
                assert_eq!(spec.class, DriverServiceClass::Device);
                assert_eq!(spec.start_type, SERVICE_DEMAND_START);
                assert_eq!(spec.error_control, Some(1));
                assert_eq!(spec.load_order_group.as_deref(), Some("NDIS"));
                assert_eq!(
                    spec.class_guid.as_deref(),
                    Some("{4D36E972-E325-11CE-BFC1-08002BE10318}")
                );
                assert_eq!(spec.tag, Some(3));
                assert_eq!(spec.image_path, r"system32\drivers\e1000.sys");
                assert_eq!(spec.driver_object_path, r"\Driver\IntelE1000");
            }
            ServiceStartSpec::Win32(_) => panic!("E1000 must route as a driver"),
        }

        assert_eq!(cm.service_start_spec("MixedType"), None);
        assert_eq!(cm.service_start_spec("DisabledDriver"), None);

        let demand_drivers = cm.demand_start_driver_launch_specs();
        assert_eq!(demand_drivers.len(), 1);
        assert_eq!(demand_drivers[0].service_name, "E1000");

        let auto_specs = cm.service_start_specs_by_start(&[SERVICE_AUTO_START]);
        assert_eq!(auto_specs.len(), 1);
        assert!(matches!(auto_specs[0], ServiceStartSpec::Win32(_)));
    }

    #[test]
    fn driver_object_path_follows_nt_service_key_rules() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "Npfs",
            r"system32\drivers\npfs.sys",
            SERVICE_FILE_SYSTEM_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        cm.register_typed_service(
            "Disk",
            r"system32\drivers\disk.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        cm.register_typed_service(
            "FsRec",
            r"system32\drivers\fs_rec.sys",
            SERVICE_RECOGNIZER_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        cm.register_typed_service(
            "Custom",
            r"system32\drivers\custom.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        let custom_key = cm.service_metadata("Custom").unwrap().service_key;
        cm.registry_mut()
            .set_string(custom_key, "ObjectName", r"\Driver\VendorCustom");

        assert_eq!(
            cm.service_metadata("Npfs")
                .unwrap()
                .driver_object_path()
                .as_deref(),
            Some(r"\FileSystem\Npfs")
        );
        assert_eq!(
            cm.service_metadata("Disk")
                .unwrap()
                .driver_object_path()
                .as_deref(),
            Some(r"\Driver\Disk")
        );
        assert_eq!(
            cm.service_metadata("FsRec")
                .unwrap()
                .driver_object_path()
                .as_deref(),
            Some(r"\FileSystem\FsRec")
        );
        assert_eq!(
            cm.service_metadata("Custom")
                .unwrap()
                .driver_object_path()
                .as_deref(),
            Some(r"\Driver\VendorCustom")
        );
    }

    #[test]
    fn boot_system_driver_candidates_follow_service_group_order() {
        fn set_group_tag(cm: &mut ConfigManager, service: &str, group: Option<&str>, tag: u32) {
            let key = cm.service_metadata(service).unwrap().service_key;
            if let Some(group) = group {
                cm.registry_mut().set_string(key, "Group", group);
            }
            cm.registry_mut().set_dword(key, "Tag", tag);
        }

        let mut cm = ConfigManager::new();
        let group_key = cm.registry_mut().create_key(SERVICE_GROUP_ORDER_PATH);
        cm.registry_mut().set_value(
            group_key,
            "List",
            RegistryValueType::MultiSz,
            encode_multi_sz(&["FSFilter Infrastructure", "File System"]),
        );
        cm.register_typed_service(
            "FileSystemDriver",
            r"system32\drivers\fs.sys",
            SERVICE_FILE_SYSTEM_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        set_group_tag(&mut cm, "FileSystemDriver", Some("File System"), 1);
        cm.register_typed_service(
            "FilterAlpha",
            r"system32\drivers\filter-a.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        set_group_tag(&mut cm, "FilterAlpha", Some("FSFilter Infrastructure"), 20);
        cm.register_typed_service(
            "FilterBeta",
            r"system32\drivers\filter-b.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        set_group_tag(&mut cm, "FilterBeta", Some("FSFilter Infrastructure"), 10);
        cm.register_typed_service(
            "UnknownGroup",
            r"system32\drivers\unknown.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        set_group_tag(&mut cm, "UnknownGroup", Some("Unknown"), 0);
        cm.register_typed_service(
            "BootDevice",
            r"system32\drivers\boot.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );

        assert_eq!(
            cm.service_group_order(),
            alloc::vec![
                String::from("FSFilter Infrastructure"),
                String::from("File System")
            ]
        );
        let names: Vec<String> = cm
            .boot_system_driver_candidates()
            .into_iter()
            .map(|service| service.name)
            .collect();
        assert_eq!(
            names,
            alloc::vec![
                String::from("BootDevice"),
                String::from("FilterBeta"),
                String::from("FilterAlpha"),
                String::from("FileSystemDriver"),
                String::from("UnknownGroup")
            ]
        );
    }

    #[test]
    fn boot_system_pnp_driver_candidates_require_enum_binding() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "BoundDevice",
            r"system32\drivers\bound.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        cm.register_typed_service(
            "UnboundDevice",
            r"system32\drivers\unbound.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        cm.register_typed_service(
            "SecondBoundDevice",
            r"system32\drivers\second.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        cm.register_typed_service(
            "FileSystemDriver",
            r"system32\drivers\fs.sys",
            SERVICE_FILE_SYSTEM_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        cm.register_devnode(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            Some("BoundDevice"),
            Some(r"\Device\NTPNP_PCI0001"),
            &[r"PCI\VEN_8086&DEV_100E"],
            &[],
        );
        cm.register_devnode(
            r"ROOT\SECOND_BOUND_DEVICE\0000",
            Some("SecondBoundDevice"),
            Some(r"\Device\NTPNP_ROOT0002"),
            &[r"ROOT\SECOND_BOUND_DEVICE"],
            &[],
        );

        assert!(cm.service_has_devnodes("bounddevice"));
        assert!(cm.service_has_devnodes("secondbounddevice"));
        assert!(!cm.service_has_devnodes("UnboundDevice"));
        let names: Vec<String> = cm
            .boot_system_pnp_driver_candidates()
            .into_iter()
            .map(|service| service.name)
            .collect();
        assert_eq!(
            names,
            alloc::vec![
                String::from("BoundDevice"),
                String::from("SecondBoundDevice")
            ]
        );
        let bindings = cm.boot_system_pnp_driver_bindings();
        assert_eq!(bindings.len(), 2);
        assert_eq!(bindings[0].service.name, "BoundDevice");
        assert_eq!(bindings[0].devnodes.len(), 1);
        assert_eq!(
            bindings[0].devnodes[0].instance_id,
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18"
        );
        assert_eq!(bindings[1].service.name, "SecondBoundDevice");
        assert_eq!(bindings[1].devnodes.len(), 1);
        assert_eq!(
            bindings[1].devnodes[0].instance_id,
            r"ROOT\SECOND_BOUND_DEVICE\0000"
        );
    }

    #[test]
    fn boot_system_legacy_driver_candidates_exclude_pnp_bindings() {
        let mut cm = ConfigManager::new();
        let group_key = cm.registry_mut().create_key(SERVICE_GROUP_ORDER_PATH);
        cm.registry_mut().set_value(
            group_key,
            "List",
            RegistryValueType::MultiSz,
            encode_multi_sz(&["NDIS Wrapper", "PNP_TDI", "NDIS", "TDI"]),
        );
        cm.register_typed_service(
            "Ndis",
            r"system32\drivers\ndis.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        let ndis_key = cm.service_metadata("Ndis").unwrap().service_key;
        cm.registry_mut()
            .set_string(ndis_key, "Group", "NDIS Wrapper");
        cm.register_typed_service(
            "Tcpip",
            r"system32\drivers\tcpip.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        let tcpip_key = cm.service_metadata("Tcpip").unwrap().service_key;
        cm.registry_mut().set_string(tcpip_key, "Group", "PNP_TDI");
        cm.register_typed_service(
            "E1000",
            r"system32\drivers\e1000.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        let e1000_key = cm.service_metadata("E1000").unwrap().service_key;
        cm.registry_mut().set_string(e1000_key, "Group", "NDIS");
        cm.register_typed_service(
            "Afd",
            r"system32\drivers\afd.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        let afd_key = cm.service_metadata("Afd").unwrap().service_key;
        cm.registry_mut().set_string(afd_key, "Group", "TDI");
        cm.register_typed_service(
            "Npfs",
            r"system32\drivers\npfs.sys",
            SERVICE_FILE_SYSTEM_DRIVER,
            None,
            None,
            SERVICE_SYSTEM_START,
            1,
        );
        cm.register_typed_service(
            "sacdrv",
            r"system32\drivers\sacdrv.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            0,
        );
        let sacdrv_key = cm.service_metadata("sacdrv").unwrap().service_key;
        cm.registry_mut().set_string(sacdrv_key, "Group", "EMS");
        cm.register_typed_service(
            "Wdf01000",
            r"system32\drivers\wdf01000.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        let wdf_key = cm.service_metadata("Wdf01000").unwrap().service_key;
        cm.registry_mut()
            .set_string(wdf_key, "Group", "WdfLoadGroup");
        cm.register_typed_service(
            "acpi",
            r"system32\drivers\acpi.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_BOOT_START,
            1,
        );
        let acpi_key = cm.service_metadata("acpi").unwrap().service_key;
        cm.registry_mut()
            .set_string(acpi_key, "Group", "Boot Bus Extender");
        cm.register_typed_service(
            "Packet",
            r"system32\drivers\packet.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_DISABLED,
            1,
        );
        let packet_key = cm.service_metadata("Packet").unwrap().service_key;
        cm.registry_mut().set_string(packet_key, "Group", "PNP_TDI");
        cm.register_devnode(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            Some("E1000"),
            Some(r"\Device\NTPNP_PCI0001"),
            &[r"PCI\VEN_8086&DEV_100E"],
            &[],
        );

        let names: Vec<String> = cm
            .boot_system_legacy_driver_candidates()
            .into_iter()
            .map(|service| service.name)
            .collect();
        assert_eq!(
            names,
            alloc::vec![
                String::from("Ndis"),
                String::from("Tcpip"),
                String::from("Afd")
            ]
        );
    }

    #[test]
    fn demand_start_pnp_driver_candidates_require_enum_binding() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "BochsMp",
            r"system32\drivers\bochsmp.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            Some("{4D36E968-E325-11CE-BFC1-08002BE10318}"),
            SERVICE_DEMAND_START,
            0,
        );
        cm.register_typed_service(
            "UnboundDemand",
            r"system32\drivers\unbound.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_DEMAND_START,
            0,
        );
        cm.register_devnode(
            r"PCI\VEN_1234&DEV_1111\3&11583659&0&08",
            Some("BochsMp"),
            Some(r"\Device\NTPNP_PCI0002"),
            &[r"PCI\VEN_1234&DEV_1111"],
            &[r"PCI\CC_030000", r"PCI\CC_0300"],
        );

        let names: Vec<String> = cm
            .demand_start_pnp_driver_candidates()
            .into_iter()
            .map(|service| service.name)
            .collect();
        assert_eq!(names, alloc::vec![String::from("BochsMp")]);
        let bindings = cm.demand_start_pnp_driver_bindings();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].service.name, "BochsMp");
        assert_eq!(bindings[0].devnodes.len(), 1);
        assert_eq!(
            bindings[0].devnodes[0].instance_id,
            r"PCI\VEN_1234&DEV_1111\3&11583659&0&08"
        );
    }

    #[test]
    fn live_driver_binding_refreshes_changed_and_deleted_enum_records() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "Pending",
            r"system32\drivers\pending.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            Some("{4D36E97D-E325-11CE-BFC1-08002BE10318}"),
            SERVICE_DEMAND_START,
            1,
        );
        let first = r"ROOT\PENDING\0001";
        let second = r"ROOT\PENDING\0002";
        let first_key = cm.registry_mut().create_key(&devnode_path(first));
        cm.registry_mut()
            .set_string(first_key, "Service", "Pending");
        cm.registry_mut()
            .set_string(first_key, "PdoName", r"\Device\RootPending1");
        cm.registry_mut().set_value(
            first_key,
            "HardwareID",
            RegistryValueType::MultiSz,
            encode_multi_sz(&[r"ROOT\PENDING"]),
        );
        let second_key = cm.registry_mut().create_key(&devnode_path(second));
        cm.registry_mut()
            .set_string(second_key, "Service", "Pending");
        cm.registry_mut()
            .set_string(second_key, "PdoName", r"\Device\RootPending2");

        let initial = cm.driver_service_binding("pending").unwrap();
        assert_eq!(initial.service.service_name, "Pending");
        assert_eq!(initial.devnodes.len(), 2);
        let first_id = initial.devnodes[0].id;
        assert_eq!(
            cm.register_devnode(
                first,
                Some("Pending"),
                Some(r"\Device\RootPending1"),
                &[r"ROOT\PENDING"],
                &[],
            ),
            first_id
        );
        assert_eq!(
            cm.driver_service_binding("Pending").unwrap().devnodes.len(),
            2
        );

        cm.registry_mut()
            .set_string(first_key, "PdoName", r"\Device\RootPendingChanged");
        cm.registry_mut().set_value(
            first_key,
            "CompatibleIDs",
            RegistryValueType::MultiSz,
            encode_multi_sz(&[r"ROOT\PENDING_COMPAT"]),
        );
        assert!(cm.registry_mut().delete_key(second_key, true));

        let refreshed = cm.driver_service_binding("Pending").unwrap();
        assert_eq!(refreshed.devnodes.len(), 1);
        assert_eq!(refreshed.devnodes[0].id, first_id);
        assert_eq!(
            refreshed.devnodes[0].pdo_name.as_deref(),
            Some(r"\Device\RootPendingChanged")
        );
        assert_eq!(
            refreshed.devnodes[0].compatible_ids,
            alloc::vec![String::from(r"ROOT\PENDING_COMPAT")]
        );
    }

    #[test]
    fn driver_writes_seen_by_driver() {
        let mut cm = ConfigManager::new();
        cm.register_service("Svc", "svc.sys", None, None, 3, 1);
        let params = cm.service_parameters_key("Svc").unwrap();
        // A driver assigns a ULONG back (WdfRegistryAssignULong).
        cm.registry_mut().set_dword(params, "SeenByDriver", 1);
        assert_eq!(cm.registry().query_dword(params, "SeenByDriver"), Some(1));
    }

    #[test]
    fn devnode_registration_and_enumeration() {
        let mut cm = ConfigManager::new();
        cm.register_service("KmdfInterfaceRegistryTest", "x.sys", None, None, 3, 1);
        cm.register_devnode(
            r"ROOT\KMDF_INTERFACE_TEST\0000",
            Some("KmdfInterfaceRegistryTest"),
            Some(r"\Device\NTPNP_ROOT_0004"),
            &[r"ROOT\KMDF_INTERFACE_TEST"],
            &[r"ROOT\USERSPLACE_NTOS_INTERFACE_TEST"],
        );
        // The PnP Manager discovers the devnode by service.
        let found = cm.devnodes_for_service("KmdfInterfaceRegistryTest");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].instance_id, r"ROOT\KMDF_INTERFACE_TEST\0000");
        // Its Enum key carries the Service value.
        let key = cm
            .devnode(r"ROOT\KMDF_INTERFACE_TEST\0000")
            .unwrap()
            .enum_key;
        assert_eq!(
            cm.registry().query_string(key, "Service").as_deref(),
            Some("KmdfInterfaceRegistryTest")
        );
        assert_eq!(
            cm.registry().query_multi_string(key, "HardwareID").unwrap(),
            alloc::vec![String::from(r"ROOT\KMDF_INTERFACE_TEST")]
        );
        assert_eq!(
            cm.registry()
                .query_multi_string(key, "CompatibleIDs")
                .unwrap(),
            alloc::vec![String::from(r"ROOT\USERSPLACE_NTOS_INTERFACE_TEST")]
        );
    }

    #[test]
    fn registry_enum_tree_indexes_devnodes_for_service_binding() {
        let mut cm = ConfigManager::new();
        cm.register_typed_service(
            "E1000",
            r"system32\drivers\e1000.sys",
            SERVICE_KERNEL_DRIVER,
            None,
            None,
            SERVICE_DEMAND_START,
            1,
        );
        let key = cm
            .registry_mut()
            .create_key(r"\Registry\Machine\System\CurrentControlSet\Enum\PCI\VEN_8086&DEV_100E\3&11583659&0&18");
        cm.registry_mut().set_string(key, "Service", "E1000");
        cm.registry_mut()
            .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
        cm.registry_mut().set_string(
            key,
            "Driver",
            r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0000",
        );
        cm.registry_mut().set_value(
            key,
            "HardwareID",
            RegistryValueType::MultiSz,
            encode_multi_sz(&[r"PCI\VEN_8086&DEV_100E", r"PCI\VEN_8086"]),
        );
        cm.registry_mut().set_value(
            key,
            "CompatibleIDs",
            RegistryValueType::MultiSz,
            encode_multi_sz(&[r"PCI\CC_020000", r"PCI\CC_0200"]),
        );
        cm.registry_mut().create_key(
            r"\Registry\Machine\System\CurrentControlSet\Enum\PCI\VEN_8086&DEV_100E\Properties",
        );
        let linkage = cm
            .registry_mut()
            .create_key(
                r"\Registry\Machine\System\CurrentControlSet\Control\Class\{4D36E972-E325-11CE-BFC1-08002BE10318}\0000\Linkage",
            );
        cm.registry_mut()
            .set_string(linkage, "Export", r"\Device\E1000_0000");

        assert_eq!(cm.index_registry_devnodes(), 1);
        assert_eq!(cm.index_registry_devnodes(), 0);

        let dn = cm
            .devnode(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18")
            .unwrap();
        let dn_id = dn.id;
        assert_eq!(dn.enum_key, key);
        assert_eq!(dn.service.as_deref(), Some("E1000"));
        assert_eq!(dn.pdo_name.as_deref(), Some(r"\Device\NTPNP_PCI0001"));
        assert_eq!(
            dn.driver_key.as_deref(),
            Some(r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0000")
        );
        assert_eq!(
            dn.hardware_ids,
            alloc::vec![
                String::from(r"PCI\VEN_8086&DEV_100E"),
                String::from(r"PCI\VEN_8086"),
            ]
        );
        assert_eq!(
            dn.compatible_ids,
            alloc::vec![String::from(r"PCI\CC_020000"), String::from(r"PCI\CC_0200"),]
        );
        assert_eq!(cm.devnodes_for_service("e1000").len(), 1);
        assert_eq!(
            cm.devnode_linkage_export(dn).as_deref(),
            Some(r"\Device\E1000_0000")
        );
        assert_eq!(
            cm.index_registry_devnode(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18"),
            Some(dn_id)
        );
    }

    #[test]
    fn pnp_properties() {
        let mut cm = ConfigManager::new();
        let dn = cm.register_devnode(r"ROOT\X\0000", Some("Svc"), None, &[], &[]);
        // Legacy FriendlyName (WdfDeviceAssignProperty / IoGetDeviceProperty).
        cm.set_legacy_property(
            dn,
            device_property::FRIENDLY_NAME,
            PropertyValue::string("userspace-ntos KMDF Interface Registry Test Device"),
        );
        assert_eq!(
            cm.query_legacy_property(dn, device_property::FRIENDLY_NAME)
                .and_then(|v| v.as_string())
                .as_deref(),
            Some("userspace-ntos KMDF Interface Registry Test Device")
        );
        // A custom DEVPROPKEY (uint32).
        let key = DevPropKey {
            fmtid: [0xAB; 16],
            pid: 2,
        };
        cm.assign_devprop(dn, key, PropertyValue::uint32(42));
        assert_eq!(
            cm.query_devprop(dn, &key).and_then(|v| v.as_uint32()),
            Some(42)
        );
        assert!(cm
            .query_devprop(
                dn,
                &DevPropKey {
                    fmtid: [0; 16],
                    pid: 1
                }
            )
            .is_none());
    }

    #[test]
    fn device_interface_register_enable_enumerate() {
        let mut cm = ConfigManager::new();
        let dn = cm.register_devnode(r"ROOT\X\0000", Some("Svc"), None, &[], &[]);
        let guid = "{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0001}";
        let iface = cm.register_interface(dn, guid, "", true).unwrap();
        let rec = cm.interface(iface).unwrap();
        assert!(rec.enabled);
        assert_eq!(rec.symbolic_link, format!(r"\??\ROOT#X#0000#{guid}"));
        assert_eq!(
            cm.register_interface(dn, &guid.to_ascii_lowercase(), "", false),
            Ok(iface)
        );
        assert_eq!(cm.interfaces().len(), 1);
        // Enabled-only enumeration.
        assert_eq!(cm.interfaces_by_guid(guid, true).len(), 1);
        assert!(cm.set_interface_state_by_symbolic_link(
            &format!(r"\??\root#x#0000#{}", guid.to_ascii_lowercase()),
            false
        ));
        assert_eq!(cm.interfaces_by_guid(guid, true).len(), 0);
        assert_eq!(cm.interfaces_by_guid(guid, false).len(), 1);
        let interface_key = format!(
            r"{}\{}\##?#ROOT#X#0000#{}\#",
            DEVICE_CLASSES_PATH, guid, guid
        );
        let key = cm.registry().open_key(&interface_key).unwrap();
        assert_eq!(
            cm.registry().query_string(key, "SymbolicLink").as_deref(),
            Some(format!(r"\\?\ROOT#X#0000#{guid}").as_str())
        );
        assert!(cm
            .registry()
            .open_key(&format!(r"{interface_key}\Control"))
            .is_none());
        assert!(cm.set_interface_state(iface, true));
        let control = cm
            .registry()
            .open_key(&format!(r"{interface_key}\Control"))
            .unwrap();
        assert_eq!(cm.registry().query_dword(control, "Linked"), Some(1));

        let referenced = cm.register_interface(dn, guid, "Port0", false).unwrap();
        assert_eq!(
            cm.interface(referenced).unwrap().symbolic_link,
            format!(r"\??\ROOT#X#0000#{guid}\Port0")
        );
        assert_eq!(
            cm.interface_by_symbolic_link(&format!(r"\??\root#x#0000#{guid}\port0"))
                .map(|interface| interface.id),
            Some(referenced)
        );
        assert_eq!(
            cm.register_interface(u64::MAX, guid, "", false),
            Err(InterfaceRegistrationError::UnknownDevnode)
        );
        assert_eq!(
            cm.register_interface(dn, "not-a-guid", "", false),
            Err(InterfaceRegistrationError::InvalidGuid)
        );
        assert_eq!(
            cm.register_interface(dn, guid, r"bad\reference", false),
            Err(InterfaceRegistrationError::InvalidReference)
        );
    }

    #[test]
    fn legacy_device_property_ordinals_match_nt() {
        assert_eq!(
            [
                device_property::DEVICE_DESCRIPTION,
                device_property::HARDWARE_ID,
                device_property::COMPATIBLE_IDS,
                device_property::BOOT_CONFIGURATION,
                device_property::BOOT_CONFIGURATION_TRANSLATED,
                device_property::CLASS_NAME,
                device_property::CLASS_GUID,
                device_property::DRIVER_KEY_NAME,
                device_property::MANUFACTURER,
                device_property::FRIENDLY_NAME,
                device_property::LOCATION_INFORMATION,
                device_property::PHYSICAL_DEVICE_OBJECT_NAME,
                device_property::BUS_TYPE_GUID,
                device_property::LEGACY_BUS_TYPE,
                device_property::BUS_NUMBER,
                device_property::ENUMERATOR_NAME,
                device_property::ADDRESS,
                device_property::UI_NUMBER,
                device_property::INSTALL_STATE,
                device_property::REMOVAL_POLICY,
                device_property::RESOURCE_REQUIREMENTS,
                device_property::ALLOCATED_RESOURCES,
                device_property::CONTAINER_ID,
            ],
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,]
        );

        for property in [0, 1, 2, 3, 5, 6, 7, 8, 9, 10, 11, 15, 17, 18, 22] {
            assert_eq!(
                device_property::source(property),
                DevicePropertySource::Configuration
            );
        }
        for property in [4, 12, 13, 14, 16, 19, 20, 21] {
            assert_eq!(
                device_property::source(property),
                DevicePropertySource::External
            );
        }
        assert_eq!(device_property::source(23), DevicePropertySource::Invalid);
    }

    #[test]
    fn device_property_query_lazily_indexes_enum_and_preserves_authority() {
        let mut cm = ConfigManager::new();
        let instance = r"PCI\VEN_8086&DEV_100E\3&11583659&0&18";
        let key = cm.registry_mut().create_key(&devnode_path(instance));
        cm.registry_mut().set_string(key, "Service", "E1000");
        cm.registry_mut()
            .set_string(key, "PdoName", r"\Device\NTPNP_PCI0001");
        cm.registry_mut().set_string(
            key,
            "Driver",
            r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0000",
        );
        cm.registry_mut()
            .set_string(key, "DeviceDesc", "Intel Ethernet Controller");
        cm.registry_mut().set_string(key, "Class", "Net");
        cm.registry_mut()
            .set_string(key, "ClassGUID", "{4D36E972-E325-11CE-BFC1-08002BE10318}");
        cm.registry_mut().set_string(key, "Mfg", "Intel");
        cm.registry_mut()
            .set_string(key, "FriendlyName", "Intel Test Adapter");
        cm.registry_mut()
            .set_string(key, "LocationInformation", "PCI bus 0, device 3");
        cm.registry_mut()
            .set_string(key, "ContainerID", "{01234567-89AB-CDEF-0123-456789ABCDEF}");
        cm.registry_mut().set_dword(key, "UINumber", 7);
        cm.registry_mut().set_value(
            key,
            "HardwareID",
            RegistryValueType::MultiSz,
            encode_multi_sz(&[r"PCI\VEN_8086&DEV_100E", r"PCI\VEN_8086"]),
        );
        cm.registry_mut().set_value(
            key,
            "CompatibleIDs",
            RegistryValueType::MultiSz,
            encode_multi_sz(&[r"PCI\VEN_8086&CC_020000"]),
        );
        cm.registry_mut().set_value(
            key,
            "BootConfig",
            RegistryValueType::ResourceList,
            alloc::vec![0xff],
        );
        assert!(cm.devnode(instance).is_none());

        let lower_instance = instance.to_ascii_lowercase();
        assert_eq!(
            cm.device_property_bytes(&lower_instance, device_property::DRIVER_KEY_NAME),
            Some(encode_sz(r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0000"))
        );
        let devnode = cm.devnode(instance).unwrap().id;
        assert_eq!(
            cm.device_property_bytes(instance, device_property::DEVICE_DESCRIPTION),
            Some(encode_sz("Intel Ethernet Controller"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::HARDWARE_ID),
            Some(encode_multi_sz(&[
                r"PCI\VEN_8086&DEV_100E",
                r"PCI\VEN_8086"
            ]))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::COMPATIBLE_IDS),
            Some(encode_multi_sz(&[r"PCI\VEN_8086&CC_020000"]))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::ENUMERATOR_NAME),
            Some(encode_sz("PCI"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::PHYSICAL_DEVICE_OBJECT_NAME),
            Some(encode_sz(r"\Device\NTPNP_PCI0001"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::FRIENDLY_NAME),
            Some(encode_sz("Intel Test Adapter"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::CLASS_NAME),
            Some(encode_sz("Net"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::CLASS_GUID),
            Some(encode_sz("{4D36E972-E325-11CE-BFC1-08002BE10318}"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::MANUFACTURER),
            Some(encode_sz("Intel"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::LOCATION_INFORMATION),
            Some(encode_sz("PCI bus 0, device 3"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::CONTAINER_ID),
            Some(encode_sz("{01234567-89AB-CDEF-0123-456789ABCDEF}"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::UI_NUMBER),
            Some(7u32.to_le_bytes().to_vec())
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::INSTALL_STATE),
            Some(0u32.to_le_bytes().to_vec())
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::BOOT_CONFIGURATION),
            None
        );

        let log_conf = cm.registry_mut().create_subkey(key, "LogConf");
        cm.registry_mut().set_value(
            log_conf,
            "BootConfig",
            RegistryValueType::ResourceList,
            alloc::vec![1, 2, 3, 4],
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::BOOT_CONFIGURATION),
            Some(alloc::vec![1, 2, 3, 4])
        );

        cm.registry_mut().set_string(
            key,
            "Driver",
            r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0001",
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::DRIVER_KEY_NAME),
            Some(encode_sz(r"{4D36E972-E325-11CE-BFC1-08002BE10318}\0001"))
        );
        assert!(cm.registry_mut().delete_value(key, "Driver"));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::DRIVER_KEY_NAME),
            None
        );
        assert!(cm.registry_mut().delete_value(key, "HardwareID"));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::HARDWARE_ID),
            None
        );
        cm.registry_mut()
            .set_string(key, "HardwareID", r"PCI\VEN_8086&DEV_100E");
        assert_eq!(
            cm.device_property_bytes(instance, device_property::HARDWARE_ID),
            None
        );

        cm.registry_mut()
            .set_dword(key, "FriendlyName", 0xfeed_beef);
        assert_eq!(
            cm.device_property_bytes(instance, device_property::FRIENDLY_NAME),
            None
        );
        cm.registry_mut()
            .set_string(key, "FriendlyName", "Registry Adapter");
        assert!(cm.set_legacy_property(
            devnode,
            device_property::FRIENDLY_NAME,
            PropertyValue::uint32(1)
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::FRIENDLY_NAME),
            None
        );
        assert!(cm.set_legacy_property(
            devnode,
            device_property::FRIENDLY_NAME,
            PropertyValue {
                prop_type: devprop_type::STRING,
                data: alloc::vec![b'A', 0],
            }
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::FRIENDLY_NAME),
            None
        );

        assert!(cm.set_legacy_property(
            devnode,
            device_property::FRIENDLY_NAME,
            PropertyValue::string("Override Adapter")
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::FRIENDLY_NAME),
            Some(encode_sz("Override Adapter"))
        );
        assert!(cm.set_legacy_property(
            devnode,
            device_property::PHYSICAL_DEVICE_OBJECT_NAME,
            PropertyValue::string(r"\Device\ForgedPdo")
        ));
        assert!(cm.set_legacy_property(
            devnode,
            device_property::ENUMERATOR_NAME,
            PropertyValue::string("FORGED")
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::PHYSICAL_DEVICE_OBJECT_NAME),
            Some(encode_sz(r"\Device\NTPNP_PCI0001"))
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::ENUMERATOR_NAME),
            Some(encode_sz("PCI"))
        );
        assert!(cm.set_legacy_property(
            devnode,
            device_property::BUS_NUMBER,
            PropertyValue::uint32(42)
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::LEGACY_BUS_TYPE),
            None
        );
        assert_eq!(
            cm.device_property_bytes(instance, device_property::BUS_NUMBER),
            None
        );
        assert_eq!(cm.device_property_bytes(instance, 23), None);

        cm.registry_mut()
            .set_string(key, "ConfigFlags", "not-a-dword");
        assert_eq!(
            cm.device_property_bytes(instance, device_property::INSTALL_STATE),
            None
        );
        cm.registry_mut().set_dword(key, "ConfigFlags", 0x20);
        assert_eq!(
            cm.device_property_bytes(instance, device_property::INSTALL_STATE),
            Some(1u32.to_le_bytes().to_vec())
        );
        cm.registry_mut().set_dword(key, "ConfigFlags", 0x60);
        assert_eq!(
            cm.device_property_bytes(instance, device_property::INSTALL_STATE),
            Some(2u32.to_le_bytes().to_vec())
        );
        assert!(cm.set_legacy_property(
            devnode,
            device_property::INSTALL_STATE,
            PropertyValue::uint32(4)
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::INSTALL_STATE),
            None
        );
        assert!(cm.set_legacy_property(
            devnode,
            device_property::INSTALL_STATE,
            PropertyValue::uint32(3)
        ));
        assert_eq!(
            cm.device_property_bytes(instance, device_property::INSTALL_STATE),
            Some(3u32.to_le_bytes().to_vec())
        );

        let flat_instance = "ROOTONLY";
        let flat_key = cm.registry_mut().create_key(&devnode_path(flat_instance));
        cm.registry_mut()
            .set_string(flat_key, "PdoName", r"\Device\FlatPdo");
        assert_eq!(
            cm.device_property_bytes(flat_instance, device_property::ENUMERATOR_NAME),
            None
        );
        assert_eq!(
            cm.device_property_bytes(r"PCI\MISSING\0000", device_property::CLASS_NAME),
            None
        );
    }

    #[test]
    fn guid_text_to_memory_bytes_accepts_nt_forms() {
        let expected = [
            0x24, 0x0b, 0x7b, 0x9a, 0x57, 0x6e, 0x51, 0x4c, 0xad, 0x3c, 0x6d, 0x9f, 0x5f, 0x0e,
            0x00, 0x01,
        ];
        assert_eq!(
            guid_text_to_memory_bytes("{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0001}"),
            Some(expected)
        );
        assert_eq!(
            guid_text_to_memory_bytes("9a7b0b246e574c51ad3c6d9f5f0e0001"),
            Some(expected)
        );
        assert!(guid_text_to_memory_bytes("not-a-guid").is_none());
    }

    #[test]
    fn pnp_root_bus_tree_projection() {
        let mut cm = ConfigManager::new();
        cm.register_devnode(
            r"ROOT\FIRST\0000",
            Some("First"),
            Some(r"\Device\NTPNP_ROOT0001"),
            &[],
            &[],
        );
        cm.register_devnode(
            r"ROOT\SECOND\0000",
            Some("Second"),
            Some(r"\Device\NTPNP_ROOT0002"),
            &[],
            &[],
        );

        assert!(cm.pnp_device_exists(PNP_ROOT_DEVICE_INSTANCE));
        assert!(cm.pnp_device_exists(r"root\first\0000"));
        assert!(!cm.pnp_device_exists(r"ROOT\MISSING\0000"));
        assert_eq!(cm.pnp_device_depth(PNP_ROOT_DEVICE_INSTANCE), Some(0));
        assert_eq!(cm.pnp_device_depth(r"ROOT\FIRST\0000"), Some(1));
        assert_eq!(
            cm.pnp_related_device(r"ROOT\FIRST\0000", pnp_relation::PARENT)
                .as_deref(),
            Some(PNP_ROOT_DEVICE_INSTANCE)
        );
        assert_eq!(
            cm.pnp_related_device(PNP_ROOT_DEVICE_INSTANCE, pnp_relation::CHILD)
                .as_deref(),
            Some(r"ROOT\FIRST\0000")
        );
        assert_eq!(
            cm.pnp_related_device(r"ROOT\FIRST\0000", pnp_relation::SIBLING)
                .as_deref(),
            Some(r"ROOT\SECOND\0000")
        );
        assert!(cm
            .pnp_related_device(r"ROOT\SECOND\0000", pnp_relation::SIBLING)
            .is_none());
        assert_eq!(
            cm.pnp_bus_relation_instances(PNP_ROOT_DEVICE_INSTANCE)
                .unwrap(),
            alloc::vec![
                String::from(r"ROOT\FIRST\0000"),
                String::from(r"ROOT\SECOND\0000")
            ]
        );
        assert_eq!(
            cm.pnp_bus_relation_instances(r"ROOT\FIRST\0000").unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn pnp_dynamic_properties_and_interface_filtering() {
        let mut cm = ConfigManager::new();
        let dn1 = cm.register_devnode(
            r"ROOT\IFACE\0000",
            Some("Svc"),
            Some(r"\Device\NTPNP_ROOT0001"),
            &[],
            &[],
        );
        let dn2 = cm.register_devnode(
            r"ROOT\IFACE\0001",
            Some("Svc"),
            Some(r"\Device\NTPNP_ROOT0002"),
            &[],
            &[],
        );
        let guid = "{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0001}";
        let guid_bytes = guid_text_to_memory_bytes(guid).unwrap();
        cm.register_interface(dn1, guid, "", true).unwrap();
        let disabled = cm.register_interface(dn2, guid, "disabled", false).unwrap();
        let other = cm
            .register_interface(dn2, "{9A7B0B24-6E57-4C51-AD3C-6D9F5F0E0002}", "", true)
            .unwrap();
        assert!(cm.interface(disabled).is_some());
        assert!(cm.interface(other).is_some());

        assert_eq!(
            cm.pnp_dynamic_property_bytes(
                r"ROOT\IFACE\0000",
                pnp_property::PHYSICAL_DEVICE_OBJECT_NAME
            )
            .as_deref(),
            Some(encode_sz(r"\Device\NTPNP_ROOT0001").as_slice())
        );
        assert_eq!(
            cm.pnp_dynamic_property_bytes(r"ROOT\IFACE\0000", pnp_property::ENUMERATOR_NAME)
                .as_deref(),
            Some(encode_sz("ROOT").as_slice())
        );
        let root_links = cm
            .pnp_enabled_interface_links_by_guid_bytes(&guid_bytes, PNP_ROOT_DEVICE_INSTANCE)
            .unwrap();
        assert_eq!(root_links.len(), 1);
        assert!(root_links[0].contains("ROOT#IFACE#0000"));
        let device_links = cm
            .pnp_enabled_interface_links_by_guid_bytes(&guid_bytes, r"ROOT\IFACE\0000")
            .unwrap();
        assert_eq!(device_links, root_links);
        assert!(cm
            .pnp_enabled_interface_links_by_guid_bytes(&guid_bytes, r"ROOT\MISSING\0000")
            .is_none());
    }
}
