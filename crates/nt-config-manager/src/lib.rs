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

mod registry;

use alloc::string::String;
use alloc::vec::Vec;

pub use registry::{encode_sz, Registry, RegistryKeyId, RegistryValue, RegistryValueType};

pub const SERVICES_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Services";
pub const ENUM_PATH: &str = r"\Registry\Machine\System\CurrentControlSet\Enum";
pub const DEVICE_CLASSES_PATH: &str =
    r"\Registry\Machine\System\CurrentControlSet\Control\DeviceClasses";

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

/// A device node (devnode) record (spec §10.1).
#[derive(Clone, Debug)]
pub struct DevnodeRecord {
    pub id: DevnodeId,
    pub instance_id: String,
    pub service: Option<String>,
    pub pdo_name: Option<String>,
    pub hardware_ids: Vec<String>,
    pub compatible_ids: Vec<String>,
    pub enum_key: RegistryKeyId,
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
        let service_key = self.registry.create_key(&service_path(name));
        let parameters_key = self.registry.create_subkey(service_key, "Parameters");
        self.registry
            .set_string(service_key, "ImagePath", image_path);
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
        let id = self.alloc_id();
        self.devnodes.push(DevnodeRecord {
            id,
            instance_id: instance_id.into(),
            service: service.map(Into::into),
            pdo_name: pdo_name.map(Into::into),
            hardware_ids: hardware_ids.iter().map(|s| (*s).into()).collect(),
            compatible_ids: compatible_ids.iter().map(|s| (*s).into()).collect(),
            enum_key,
        });
        id
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
