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

pub use property::{device_property, devprop_type, DevPropKey, PropertyBag, PropertyValue};
pub use registry::{
    encode_multi_sz, encode_sz, Registry, RegistryKeyId, RegistryValue, RegistryValueType,
};

pub const SERVICES_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
pub const ENUM_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Enum";
pub const DEVICE_CLASSES_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Control\DeviceClasses";
pub const CONTROL_CLASS_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Control\Class";
pub const SERVICE_GROUP_ORDER_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Control\ServiceGroupOrder";

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

pub fn driver_service_class_from_type(service_type: u32) -> Option<DriverServiceClass> {
    if service_type & (SERVICE_FILE_SYSTEM_DRIVER | SERVICE_RECOGNIZER_DRIVER) != 0 {
        Some(DriverServiceClass::FileSystem)
    } else if service_type & SERVICE_DRIVER_TYPE_MASK != 0 {
        Some(DriverServiceClass::Device)
    } else {
        None
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

#[derive(Clone, Debug)]
pub struct PnpDriverBinding {
    pub service: ServiceMetadata,
    pub devnodes: Vec<DevnodeRecord>,
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

    /// Generic service selection from registry metadata. Callers own policy; this only filters on
    /// explicit `Start` values, explicit `Type` bits, and a non-empty `ImagePath`.
    pub fn service_candidates_by_start_and_type(
        &self,
        start_types: &[u32],
        type_mask: u32,
    ) -> Vec<ServiceMetadata> {
        let mut out: Vec<ServiceMetadata> = self
            .service_metadata_list()
            .into_iter()
            .filter(|s| {
                s.has_launch_image()
                    && s.start_type
                        .is_some_and(|start| start_types.contains(&start))
                    && s.service_type.is_some_and(|ty| ty & type_mask != 0)
            })
            .collect();
        sort_service_metadata(&mut out);
        out
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

    /// Boot/system device-class driver bindings: selected service metadata plus the imported
    /// `Enum` devnodes that bind to each service.
    pub fn boot_system_pnp_driver_bindings(&self) -> Vec<PnpDriverBinding> {
        self.boot_system_driver_candidates()
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

    /// Registry-declared Win32 services that SCM should auto-start after it owns policy.
    pub fn auto_start_win32_service_candidates(&self) -> Vec<ServiceMetadata> {
        self.service_candidates_by_start_and_type(&[SERVICE_AUTO_START], SERVICE_WIN32_TYPE_MASK)
    }

    /// Registry-declared Win32 services that SCM may demand-start.
    pub fn demand_start_win32_service_candidates(&self) -> Vec<ServiceMetadata> {
        self.service_candidates_by_start_and_type(&[SERVICE_DEMAND_START], SERVICE_WIN32_TYPE_MASK)
    }

    /// Registry-declared drivers that SCM or `NtLoadDriver` may demand-start.
    pub fn demand_start_driver_candidates(&self) -> Vec<ServiceMetadata> {
        self.service_candidates_by_start_and_type(&[SERVICE_DEMAND_START], SERVICE_DRIVER_TYPE_MASK)
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
        let id = self.alloc_id();
        self.devnodes.push(DevnodeRecord {
            id,
            instance_id: instance_id.into(),
            service: service.map(Into::into),
            pdo_name: pdo_name.map(Into::into),
            driver_key: None,
            hardware_ids: hardware_ids.iter().map(|s| (*s).into()).collect(),
            compatible_ids: compatible_ids.iter().map(|s| (*s).into()).collect(),
            enum_key,
            properties: PropertyBag::default(),
        });
        id
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
    ) -> InterfaceId {
        // Register under Control\DeviceClasses\<Guid>.
        let class_key = self.registry.create_key(&device_class_path(guid));
        let _ = class_key;
        let instance = self
            .devnodes
            .iter()
            .find(|d| d.id == devnode)
            .map(|d| d.instance_id.clone())
            .unwrap_or_default();
        let symbolic_link = build_symbolic_link(guid, &instance, reference);
        let id = self.alloc_id();
        self.interfaces.push(InterfaceRecord {
            id,
            devnode,
            guid: guid.into(),
            reference: reference.into(),
            enabled: enabled_on_start,
            symbolic_link,
        });
        id
    }

    /// `IoSetDeviceInterfaceState` — enable/disable an interface (spec §11.3).
    pub fn set_interface_state(&mut self, id: InterfaceId, enabled: bool) -> bool {
        if let Some(i) = self.interfaces.iter_mut().find(|i| i.id == id) {
            i.enabled = enabled;
            true
        } else {
            false
        }
    }
    pub fn interface(&self, id: InterfaceId) -> Option<&InterfaceRecord> {
        self.interfaces.iter().find(|i| i.id == id)
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

/// The device-interface symbolic link name (spec §11.2): `\??\<guid>#<instance>#<ref>`.
fn build_symbolic_link(guid: &str, instance: &str, reference: &str) -> String {
    let mut s = String::from(r"\??\");
    // NT mangles the instance's backslashes to '#'.
    let mangled: String = instance
        .chars()
        .map(|c| if c == '\\' { '#' } else { c })
        .collect();
    s.push_str(guid);
    s.push('#');
    s.push_str(&mangled);
    if !reference.is_empty() {
        s.push('#');
        s.push_str(reference);
    }
    s
}

fn sort_service_metadata(services: &mut [ServiceMetadata]) {
    services.sort_by(|a, b| {
        a.start_type
            .cmp(&b.start_type)
            .then_with(|| a.load_order_group.cmp(&b.load_order_group))
            .then_with(|| a.tag.cmp(&b.tag))
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
    });
}

fn sort_service_metadata_with_group_order(
    services: &mut [ServiceMetadata],
    group_order: &[String],
) {
    services.sort_by(|a, b| {
        a.start_type
            .cmp(&b.start_type)
            .then_with(|| {
                group_order_rank(a.load_order_group.as_deref(), group_order).cmp(&group_order_rank(
                    b.load_order_group.as_deref(),
                    group_order,
                ))
            })
            .then_with(|| a.load_order_group.cmp(&b.load_order_group))
            .then_with(|| a.tag.cmp(&b.tag))
            .then_with(|| {
                a.name
                    .to_ascii_lowercase()
                    .cmp(&b.name.to_ascii_lowercase())
            })
    });
}

fn group_order_rank(group: Option<&str>, group_order: &[String]) -> usize {
    group
        .and_then(|group| {
            group_order
                .iter()
                .position(|candidate| candidate.eq_ignore_ascii_case(group))
        })
        .unwrap_or(group_order.len())
}

#[cfg(test)]
mod tests {
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
        let iface = cm.register_interface(dn, guid, "", true);
        let rec = cm.interface(iface).unwrap();
        assert!(rec.enabled);
        assert!(rec.symbolic_link.starts_with(r"\??\"));
        assert!(rec.symbolic_link.contains("ROOT#X#0000"));
        // Enabled-only enumeration.
        assert_eq!(cm.interfaces_by_guid(guid, true).len(), 1);
        cm.set_interface_state(iface, false);
        assert_eq!(cm.interfaces_by_guid(guid, true).len(), 0);
        assert_eq!(cm.interfaces_by_guid(guid, false).len(), 1);
    }
}
