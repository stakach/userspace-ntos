//! # `nt-pnp-manager` — the PnP Manager core
//!
//! The devnode table + the v0.1 device-lifecycle state machine (spec: NT PnP
//! Manager, Milestone 12, §8). It validates every state transition, tracks
//! service-bound device identity, PDO/FDO/driver bindings, and raw/translated
//! resource assignment, and rejects stale devnode IDs after removal. `no_std` +
//! `alloc`. It holds no driver pointers — only IDs + resource values (§7.3).

#![no_std]

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::vec::Vec;

pub use nt_pnp_abi::DeviceState;

/// A device's assigned resources (raw == translated for the simulated backend).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ResourceAssignment {
    pub mem_start: u64,
    pub mem_length: u32,
    pub int_vector: u32,
    pub int_level: u32,
    pub int_affinity: u64,
    pub int_latched: bool,
}

/// Resource assignment for devices that do not need hardware resources.
pub const NO_RESOURCES: ResourceAssignment = ResourceAssignment {
    mem_start: 0,
    mem_length: 0,
    int_vector: 0,
    int_level: 0,
    int_affinity: 0,
    int_latched: false,
};

/// Native GUID bytes (`GUID` fields in little-endian memory order) for the buses currently
/// enumerated by the production broker.
pub const GUID_BUS_TYPE_PCI: [u8; 16] = [
    0xb0, 0xdf, 0xeb, 0xc8, 0x10, 0xb5, 0xd0, 0x11, 0x80, 0xe5, 0x00, 0xa0, 0xc9, 0x25, 0x42, 0xe3,
];
pub const GUID_BUS_TYPE_INTERNAL: [u8; 16] = [
    0x73, 0xea, 0x30, 0x15, 0x6b, 0x08, 0xd1, 0x11, 0xa0, 0x9f, 0x00, 0xc0, 0x4f, 0xc3, 0x40, 0xb1,
];

pub const INTERFACE_TYPE_PCI_BUS: u32 = 5;
pub const INTERFACE_TYPE_PNP_BUS: u32 = 15;
pub const DEVICE_ADDRESS_UNAVAILABLE: u32 = u32::MAX;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PnpBusInformation {
    pub bus_type_guid: [u8; 16],
    pub legacy_bus_type: u32,
    pub bus_number: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdoCapabilities {
    pub removable: bool,
    pub eject_supported: bool,
    pub surprise_removal_ok: bool,
    pub address: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum DeviceRemovalPolicy {
    ExpectNoRemoval = 1,
    ExpectOrderlyRemoval = 2,
    ExpectSurpriseRemoval = 3,
}

impl DeviceRemovalPolicy {
    pub fn from_capabilities(capabilities: &PdoCapabilities) -> Self {
        if !capabilities.removable {
            Self::ExpectNoRemoval
        } else if capabilities.eject_supported && !capabilities.surprise_removal_ok {
            Self::ExpectOrderlyRemoval
        } else {
            Self::ExpectSurpriseRemoval
        }
    }
}

/// PnP must distinguish a bus query that has not run from a successful query that returned no
/// descriptors. Both differ from a present native variable-length structure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PropertyBlobState {
    Unqueried,
    KnownNone,
    Present(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PdoProperties {
    pub bus_information: Option<PnpBusInformation>,
    pub capabilities: Option<PdoCapabilities>,
    pub removal_policy: Option<DeviceRemovalPolicy>,
    pub boot_resources_raw: PropertyBlobState,
    pub boot_resources_translated: PropertyBlobState,
    /// Initial requirements returned by the bus before the function stack is built.
    pub resource_requirements: PropertyBlobState,
    /// Requirements after `IRP_MN_FILTER_RESOURCE_REQUIREMENTS` has traversed the function stack.
    pub filtered_resource_requirements: PropertyBlobState,
    pub allocated_resources_raw: PropertyBlobState,
    pub allocated_resources_translated: PropertyBlobState,
}

impl PdoProperties {
    pub fn enumerated(
        bus_information: PnpBusInformation,
        capabilities: PdoCapabilities,
        boot_resources_raw: PropertyBlobState,
        boot_resources_translated: PropertyBlobState,
        resource_requirements: PropertyBlobState,
    ) -> Self {
        let removal_policy = DeviceRemovalPolicy::from_capabilities(&capabilities);
        Self {
            bus_information: Some(bus_information),
            capabilities: Some(capabilities),
            removal_policy: Some(removal_policy),
            boot_resources_raw,
            boot_resources_translated,
            resource_requirements,
            filtered_resource_requirements: PropertyBlobState::Unqueried,
            allocated_resources_raw: PropertyBlobState::Unqueried,
            allocated_resources_translated: PropertyBlobState::Unqueried,
        }
    }

    fn immutable_identity_eq(&self, other: &Self) -> bool {
        self.bus_information == other.bus_information
            && self.capabilities == other.capabilities
            && self.removal_policy == other.removal_policy
            && self.boot_resources_raw == other.boot_resources_raw
            && self.boot_resources_translated == other.boot_resources_translated
            && self.resource_requirements == other.resource_requirements
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnpDevicePropertyValue<'a> {
    Bytes(&'a [u8]),
    U32(u32),
    Guid([u8; 16]),
}

impl PnpDevicePropertyValue<'_> {
    pub fn len(&self) -> usize {
        match self {
            Self::Bytes(bytes) => bytes.len(),
            Self::U32(_) => 4,
            Self::Guid(_) => 16,
        }
    }

    pub fn copy_to(&self, out: &mut [u8]) -> bool {
        if out.len() != self.len() {
            return false;
        }
        match self {
            Self::Bytes(bytes) => out.copy_from_slice(bytes),
            Self::U32(value) => out.copy_from_slice(&value.to_le_bytes()),
            Self::Guid(guid) => out.copy_from_slice(guid),
        }
        true
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PnpPropertyError {
    StalePdo,
    InvalidProperty,
    ObjectNameNotFound,
    DeviceNotReady,
}

/// The MMIO interrupt resource shape used by unit tests.
#[cfg(test)]
const MMIO_INTERRUPT_TEST_RESOURCES: ResourceAssignment = ResourceAssignment {
    mem_start: 0x1000_0000,
    mem_length: 0x1000,
    int_vector: 5,
    int_level: 5,
    int_affinity: 1,
    int_latched: false,
};

/// Why a PnP operation was rejected (spec §8.3, §25).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PnpError {
    /// The requested state transition is not allowed from the current state.
    InvalidTransition,
    /// The devnode ID is unknown or refers to a removed (stale) devnode.
    StaleId,
    InvalidIdentity,
    ConflictingPdo,
    InsufficientResources,
}

struct Devnode {
    id: u64,
    generation: u64,
    instance_id: Option<String>,
    service: Option<String>,
    state: DeviceState,
    pdo_object_id: u64,
    fdo_object_id: u64,
    driver_id: u64,
    resources: ResourceAssignment,
    pdo_properties: Option<PdoProperties>,
}

/// Whether the v0.1 state machine permits `from -> to` (spec §8.2/§8.3). `Failed` is
/// reachable from any active state.
pub fn can_transition(from: DeviceState, to: DeviceState) -> bool {
    use DeviceState::*;
    if to == Failed {
        return from != Removed;
    }
    matches!(
        (from, to),
        (Uninitialized, Enumerated)
            | (Enumerated, DriverLoaded)
            | (DriverLoaded, AddDeviceCalled)
            | (AddDeviceCalled, DeviceStackBuilt)
            | (DeviceStackBuilt, ResourcesAssigned)
            | (ResourcesAssigned, StartIrpSent)
            | (StartIrpSent, Started)
            // Started -> stop / remove paths.
            | (Started, QueryStopPending)
            | (Started, QueryRemovePending)
            | (Started, RemovePending)
            | (QueryStopPending, Stopped)
            | (QueryStopPending, Started) // cancel-stop
            | (Stopped, StartIrpSent) // restart
            | (QueryRemovePending, RemovePending)
            | (QueryRemovePending, Started) // cancel-remove
            | (RemovePending, Removed)
    )
}

/// The PnP Manager: a service-bound devnode table and lifecycle state machine.
#[derive(Default)]
pub struct PnpManager {
    devnodes: Vec<Devnode>,
    next_id: u64,
    next_gen: u64,
}

impl PnpManager {
    pub fn new() -> Self {
        Self {
            next_id: 1,
            next_gen: 1,
            ..Default::default()
        }
    }

    fn find(&self, id: u64) -> Option<&Devnode> {
        self.devnodes.iter().find(|d| d.id == id)
    }
    fn find_mut(&mut self, id: u64) -> Option<&mut Devnode> {
        self.devnodes.iter_mut().find(|d| d.id == id)
    }

    fn push_devnode(
        &mut self,
        instance_id: Option<&str>,
        service: Option<&str>,
        pdo_object_id: u64,
        resources: ResourceAssignment,
    ) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        let generation = self.next_gen;
        self.next_gen += 1;
        self.devnodes.push(Devnode {
            id,
            generation,
            instance_id: instance_id.map(ToString::to_string),
            service: service.map(ToString::to_string),
            state: DeviceState::Enumerated,
            pdo_object_id,
            fdo_object_id: 0,
            driver_id: 0,
            resources,
            pdo_properties: None,
        });
        id
    }

    /// Enumerate a registry/service-bound devnode in state `Enumerated`.
    ///
    /// The Configuration Manager owns `Enum\<InstanceId>` parsing and service binding. The PnP
    /// Manager records the already-resolved identity plus resource assignment and owns only the
    /// lifecycle state.
    pub fn create_service_bound_devnode(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_object_id: u64,
        resources: ResourceAssignment,
    ) -> u64 {
        self.push_devnode(Some(instance_id), service, pdo_object_id, resources)
    }

    /// Enumerate a service-bound devnode with no assigned hardware resources.
    pub fn create_service_bound_devnode_without_resources(
        &mut self,
        instance_id: &str,
        service: Option<&str>,
        pdo_object_id: u64,
    ) -> u64 {
        self.create_service_bound_devnode(instance_id, service, pdo_object_id, NO_RESOURCES)
    }

    /// Publish the immutable bus/capability state owned by one enumerated canonical PDO before a
    /// function driver's `AddDevice` is allowed to run. Re-publication is idempotent only for the
    /// exact same devnode identity and property record.
    pub fn register_enumerated_pdo(
        &mut self,
        instance_id: &str,
        pdo_object_id: u64,
        properties: PdoProperties,
    ) -> Result<u64, PnpError> {
        if instance_id.is_empty() || pdo_object_id == 0 {
            return Err(PnpError::InvalidIdentity);
        }
        if let Some(existing) = self
            .devnodes
            .iter()
            .find(|devnode| devnode.pdo_object_id == pdo_object_id)
        {
            return if existing
                .instance_id
                .as_deref()
                .is_some_and(|value| value.eq_ignore_ascii_case(instance_id))
                && existing
                    .pdo_properties
                    .as_ref()
                    .is_some_and(|current| current.immutable_identity_eq(&properties))
            {
                Ok(existing.id)
            } else {
                Err(PnpError::ConflictingPdo)
            };
        }
        let id = self.next_id;
        let generation = self.next_gen;
        let Some(next_id) = self.next_id.checked_add(1) else {
            return Err(PnpError::InsufficientResources);
        };
        let Some(next_gen) = self.next_gen.checked_add(1) else {
            return Err(PnpError::InsufficientResources);
        };
        self.devnodes
            .try_reserve(1)
            .map_err(|_| PnpError::InsufficientResources)?;
        self.devnodes.push(Devnode {
            id,
            generation,
            instance_id: Some(instance_id.to_string()),
            service: None,
            state: DeviceState::Enumerated,
            pdo_object_id,
            fdo_object_id: 0,
            driver_id: 0,
            resources: NO_RESOURCES,
            pdo_properties: Some(properties),
        });
        self.next_id = next_id;
        self.next_gen = next_gen;
        Ok(id)
    }

    pub fn devnode_for_pdo(&self, pdo_object_id: u64) -> Option<u64> {
        self.devnodes
            .iter()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .map(|devnode| devnode.id)
    }

    pub fn commit_resource_assignment(
        &mut self,
        pdo_object_id: u64,
        raw: Vec<u8>,
        translated: Vec<u8>,
    ) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        let properties = devnode.pdo_properties.as_mut().unwrap();
        properties.allocated_resources_raw = if raw.is_empty() {
            PropertyBlobState::KnownNone
        } else {
            PropertyBlobState::Present(raw)
        };
        properties.allocated_resources_translated = if translated.is_empty() {
            PropertyBlobState::KnownNone
        } else {
            PropertyBlobState::Present(translated)
        };
        Ok(())
    }

    pub fn commit_filtered_resource_requirements(
        &mut self,
        pdo_object_id: u64,
        filtered: Vec<u8>,
    ) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        devnode
            .pdo_properties
            .as_mut()
            .unwrap()
            .filtered_resource_requirements = if filtered.is_empty() {
            PropertyBlobState::KnownNone
        } else {
            PropertyBlobState::Present(filtered)
        };
        Ok(())
    }

    pub fn clear_resource_assignment(&mut self, pdo_object_id: u64) -> Result<(), PnpError> {
        let devnode = self
            .devnodes
            .iter_mut()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpError::StaleId)?;
        let properties = devnode.pdo_properties.as_mut().unwrap();
        properties.allocated_resources_raw = PropertyBlobState::Unqueried;
        properties.allocated_resources_translated = PropertyBlobState::Unqueried;
        properties.filtered_resource_requirements = PropertyBlobState::Unqueried;
        Ok(())
    }

    /// Query one PnP/resource-owned `DEVICE_REGISTRY_PROPERTY` by canonical PDO identity.
    pub fn query_device_property(
        &self,
        pdo_object_id: u64,
        property: u32,
    ) -> Result<PnpDevicePropertyValue<'_>, PnpPropertyError> {
        let devnode = self
            .devnodes
            .iter()
            .find(|devnode| {
                devnode.pdo_object_id == pdo_object_id
                    && devnode.pdo_properties.is_some()
                    && devnode.state != DeviceState::Removed
            })
            .ok_or(PnpPropertyError::StalePdo)?;
        let properties = devnode.pdo_properties.as_ref().unwrap();
        match property {
            4 => property_blob_value(&properties.boot_resources_translated),
            12 => properties
                .bus_information
                .as_ref()
                .map(|bus| PnpDevicePropertyValue::Guid(bus.bus_type_guid))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            13 => properties
                .bus_information
                .as_ref()
                .filter(|bus| bus.legacy_bus_type != u32::MAX)
                .map(|bus| PnpDevicePropertyValue::U32(bus.legacy_bus_type))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            14 => properties
                .bus_information
                .as_ref()
                .filter(|bus| bus.bus_number & 0x8000_0000 == 0)
                .map(|bus| PnpDevicePropertyValue::U32(bus.bus_number))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            16 => properties
                .capabilities
                .as_ref()
                .filter(|capabilities| capabilities.address != DEVICE_ADDRESS_UNAVAILABLE)
                .map(|capabilities| PnpDevicePropertyValue::U32(capabilities.address))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            19 => properties
                .removal_policy
                .map(|policy| PnpDevicePropertyValue::U32(policy as u32))
                .ok_or(PnpPropertyError::ObjectNameNotFound),
            20 => match &properties.filtered_resource_requirements {
                PropertyBlobState::Unqueried => {
                    property_blob_value(&properties.resource_requirements)
                }
                filtered => property_blob_value(filtered),
            },
            21 => property_blob_value(&properties.allocated_resources_raw),
            _ => Err(PnpPropertyError::InvalidProperty),
        }
    }

    pub fn state(&self, id: u64) -> Option<DeviceState> {
        self.find(id).map(|d| d.state)
    }

    pub fn generation(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.generation)
    }

    pub fn instance_id(&self, id: u64) -> Option<&str> {
        self.find(id).and_then(|d| d.instance_id.as_deref())
    }

    pub fn service(&self, id: u64) -> Option<&str> {
        self.find(id).and_then(|d| d.service.as_deref())
    }

    pub fn devnodes_for_service(&self, service: &str) -> Vec<u64> {
        self.devnodes
            .iter()
            .filter(|d| {
                d.service
                    .as_deref()
                    .is_some_and(|s| s.eq_ignore_ascii_case(service))
            })
            .map(|d| d.id)
            .collect()
    }

    pub fn resources(&self, id: u64) -> Option<ResourceAssignment> {
        self.find(id).map(|d| d.resources)
    }

    pub fn pdo(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.pdo_object_id)
    }
    pub fn fdo(&self, id: u64) -> Option<u64> {
        self.find(id).map(|d| d.fdo_object_id)
    }

    pub fn set_fdo(&mut self, id: u64, fdo_object_id: u64) -> Result<(), PnpError> {
        self.find_mut(id).ok_or(PnpError::StaleId)?.fdo_object_id = fdo_object_id;
        Ok(())
    }
    pub fn set_driver(&mut self, id: u64, driver_id: u64) -> Result<(), PnpError> {
        self.find_mut(id).ok_or(PnpError::StaleId)?.driver_id = driver_id;
        Ok(())
    }

    /// Attempt a state transition, validating it against the state machine (spec
    /// §8.3). A devnode already `Removed` is stale.
    pub fn transition(&mut self, id: u64, to: DeviceState) -> Result<(), PnpError> {
        let d = self.find_mut(id).ok_or(PnpError::StaleId)?;
        if d.state == DeviceState::Removed {
            return Err(PnpError::StaleId);
        }
        if !can_transition(d.state, to) {
            return Err(PnpError::InvalidTransition);
        }
        d.state = to;
        Ok(())
    }

    /// True once the device is `Started` — resource mapping / interrupt connect is
    /// allowed only then (spec §15.2).
    pub fn mapping_allowed(&self, id: u64) -> bool {
        self.state(id) == Some(DeviceState::Started)
    }

    /// True if the devnode ID resolves to a device that is not removed.
    pub fn is_live(&self, id: u64) -> bool {
        matches!(self.state(id), Some(s) if s != DeviceState::Removed)
    }
}

fn property_blob_value(
    state: &PropertyBlobState,
) -> Result<PnpDevicePropertyValue<'_>, PnpPropertyError> {
    match state {
        PropertyBlobState::Unqueried => Err(PnpPropertyError::DeviceNotReady),
        PropertyBlobState::KnownNone => Ok(PnpDevicePropertyValue::Bytes(&[])),
        PropertyBlobState::Present(bytes) => Ok(PnpDevicePropertyValue::Bytes(bytes)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use DeviceState::*;

    fn create_mmio_test_devnode(p: &mut PnpManager, pdo_object_id: u64) -> u64 {
        p.create_service_bound_devnode(
            r"ROOT\MMIO_INTERRUPT_TEST\0000",
            Some("MmioInterruptTest"),
            pdo_object_id,
            MMIO_INTERRUPT_TEST_RESOURCES,
        )
    }

    fn pci_properties() -> PdoProperties {
        PdoProperties::enumerated(
            PnpBusInformation {
                bus_type_guid: GUID_BUS_TYPE_PCI,
                legacy_bus_type: INTERFACE_TYPE_PCI_BUS,
                bus_number: 2,
            },
            PdoCapabilities {
                removable: false,
                eject_supported: false,
                surprise_removal_ok: false,
                address: (3 << 16) | 1,
            },
            PropertyBlobState::Present(vec![9, 8]),
            PropertyBlobState::Present(vec![1, 2, 3]),
            PropertyBlobState::KnownNone,
        )
    }

    #[test]
    fn canonical_pdo_properties_exist_before_add_device_and_assignment() {
        let mut p = PnpManager::new();
        let pdo = 0x1234;
        let id = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, pci_properties())
            .unwrap();
        assert_eq!(p.devnode_for_pdo(pdo), Some(id));
        assert_eq!(
            p.query_device_property(pdo, 12),
            Ok(PnpDevicePropertyValue::Guid(GUID_BUS_TYPE_PCI))
        );
        assert_eq!(
            p.query_device_property(pdo, 13),
            Ok(PnpDevicePropertyValue::U32(INTERFACE_TYPE_PCI_BUS))
        );
        assert_eq!(
            p.query_device_property(pdo, 14),
            Ok(PnpDevicePropertyValue::U32(2))
        );
        assert_eq!(
            p.query_device_property(pdo, 16),
            Ok(PnpDevicePropertyValue::U32((3 << 16) | 1))
        );
        assert_eq!(
            p.query_device_property(pdo, 19),
            Ok(PnpDevicePropertyValue::U32(
                DeviceRemovalPolicy::ExpectNoRemoval as u32
            ))
        );
        assert_eq!(
            p.query_device_property(pdo, 4),
            Ok(PnpDevicePropertyValue::Bytes(&[1, 2, 3]))
        );
        assert_eq!(
            p.query_device_property(pdo, 20),
            Ok(PnpDevicePropertyValue::Bytes(&[]))
        );
        p.commit_filtered_resource_requirements(pdo, vec![0x44, 0x55])
            .unwrap();
        assert_eq!(
            p.query_device_property(pdo, 20),
            Ok(PnpDevicePropertyValue::Bytes(&[0x44, 0x55]))
        );
        assert_eq!(
            p.query_device_property(pdo, 21),
            Err(PnpPropertyError::DeviceNotReady)
        );

        p.commit_resource_assignment(pdo, vec![4, 5], vec![6, 7])
            .unwrap();
        assert_eq!(
            p.query_device_property(pdo, 21),
            Ok(PnpDevicePropertyValue::Bytes(&[4, 5]))
        );
        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, pci_properties(),),
            Ok(id)
        );
        assert_eq!(
            p.query_device_property(pdo, 21),
            Ok(PnpDevicePropertyValue::Bytes(&[4, 5]))
        );
        p.clear_resource_assignment(pdo).unwrap();
        assert_eq!(
            p.query_device_property(pdo, 21),
            Err(PnpPropertyError::DeviceNotReady)
        );
    }

    #[test]
    fn canonical_pdo_republication_is_exact_and_removal_policy_is_derived() {
        let mut p = PnpManager::new();
        let pdo = 0x1234;
        let properties = pci_properties();
        let id = p
            .register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, properties.clone())
            .unwrap();
        assert_eq!(
            p.register_enumerated_pdo(r"pci\ven_1234&dev_5678\0001", pdo, properties.clone()),
            Ok(id)
        );
        let mut conflicting = properties;
        conflicting.capabilities.as_mut().unwrap().address = 7;
        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, conflicting),
            Err(PnpError::ConflictingPdo)
        );

        let mut conflicting_raw = pci_properties();
        conflicting_raw.boot_resources_raw = PropertyBlobState::Present(vec![7]);
        assert_eq!(
            p.register_enumerated_pdo(r"PCI\VEN_1234&DEV_5678\0001", pdo, conflicting_raw,),
            Err(PnpError::ConflictingPdo)
        );
        assert_eq!(
            p.register_enumerated_pdo("", 1, pci_properties()),
            Err(PnpError::InvalidIdentity)
        );
        assert_eq!(
            DeviceRemovalPolicy::from_capabilities(&PdoCapabilities {
                removable: true,
                eject_supported: true,
                surprise_removal_ok: false,
                address: 0,
            }),
            DeviceRemovalPolicy::ExpectOrderlyRemoval
        );
        assert_eq!(
            DeviceRemovalPolicy::from_capabilities(&PdoCapabilities {
                removable: true,
                eject_supported: false,
                surprise_removal_ok: true,
                address: 0,
            }),
            DeviceRemovalPolicy::ExpectSurpriseRemoval
        );
    }

    #[test]
    fn service_bound_mmio_devnode_is_enumerated_with_resources() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0xBD0);
        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.pdo(id), Some(0xBD0));
        assert_eq!(p.instance_id(id), Some(r"ROOT\MMIO_INTERRUPT_TEST\0000"));
        assert_eq!(p.service(id), Some("MmioInterruptTest"));
        let r = p.resources(id).unwrap();
        assert_eq!(r.mem_start, 0x1000_0000);
        assert_eq!(r.int_vector, 5);
    }

    #[test]
    fn service_bound_devnode_tracks_registry_identity() {
        let mut p = PnpManager::new();
        let resources = ResourceAssignment {
            mem_start: 0x2000_0000,
            mem_length: 0x2000,
            int_vector: 9,
            int_level: 9,
            int_affinity: 3,
            int_latched: true,
        };

        let id = p.create_service_bound_devnode(
            r"PCI\VEN_8086&DEV_100E\3&11583659&0&18",
            Some("E1000"),
            0x1000,
            resources,
        );

        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(
            p.instance_id(id),
            Some(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18")
        );
        assert_eq!(p.service(id), Some("E1000"));
        assert_eq!(p.pdo(id), Some(0x1000));
        assert_eq!(p.resources(id), Some(resources));
        assert_eq!(p.devnodes_for_service("e1000"), vec![id]);
    }

    #[test]
    fn service_bound_devnode_without_resources_is_enumerated() {
        let mut p = PnpManager::new();
        let id = p.create_service_bound_devnode_without_resources(
            r"ROOT\KMDF_INTERFACE_REGISTRY_TEST\0001",
            Some("KmdfInterfaceRegistryTest"),
            0x3000,
        );

        assert_eq!(p.state(id), Some(Enumerated));
        assert_eq!(p.resources(id), Some(NO_RESOURCES));
        assert_eq!(
            p.devnodes_for_service("KmdfInterfaceRegistryTest"),
            vec![id]
        );
    }

    #[test]
    fn full_start_lifecycle() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
        ] {
            assert_eq!(p.transition(id, s), Ok(()), "to {s:?}");
        }
        assert!(p.mapping_allowed(id));
        assert!(p.is_live(id));
    }

    #[test]
    fn invalid_transitions_rejected() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        // No START before AddDevice.
        assert_eq!(
            p.transition(id, StartIrpSent),
            Err(PnpError::InvalidTransition)
        );
        assert!(!p.mapping_allowed(id)); // not Started
    }

    #[test]
    fn no_duplicate_start() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
        ] {
            p.transition(id, s).unwrap();
        }
        // Started -> StartIrpSent is not allowed (no restart without Stop).
        assert_eq!(
            p.transition(id, StartIrpSent),
            Err(PnpError::InvalidTransition)
        );
    }

    #[test]
    fn remove_then_stale() {
        let mut p = PnpManager::new();
        let id = create_mmio_test_devnode(&mut p, 0);
        for s in [
            DriverLoaded,
            AddDeviceCalled,
            DeviceStackBuilt,
            ResourcesAssigned,
            StartIrpSent,
            Started,
            RemovePending,
            Removed,
        ] {
            p.transition(id, s).unwrap();
        }
        assert_eq!(p.state(id), Some(Removed));
        assert!(!p.is_live(id));
        assert!(!p.mapping_allowed(id));
        // Any further transition on a removed devnode is stale.
        assert_eq!(p.transition(id, Started), Err(PnpError::StaleId));
    }
}
