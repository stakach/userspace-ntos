//! # `nt-root-bus` — the synthetic root/PDO bus
//!
//! In v0.1 the enumerator for the userspace-ntos device tree is a native Rust component, not a
//! loaded `.sys` bus driver. For each root-enumerated devnode the root bus creates a **physical
//! device object** (PDO) and answers the bus queries the PnP Manager issues before a function driver
//! is bound: `IRP_MN_QUERY_ID` (the device / hardware / compatible / instance IDs) and
//! `IRP_MN_QUERY_CAPABILITIES` (a `DEVICE_CAPABILITIES` block).
//!
//! IDs are returned as the wide (UTF-16) buffers a PnP `QUERY_ID` produces: a single
//! NUL-terminated string for `DeviceID`/`InstanceID`, and a double-NUL-terminated `REG_MULTI_SZ`
//! for `HardwareIDs`/`CompatibleIDs`. This crate is pure logic — `no_std + alloc`, no seL4, no raw
//! pointers — so it is unit-tested on the host; the seL4 component maps the wide buffers into the
//! IRP.

#![no_std]

extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use nt_io_abi::DeviceId;

/// The ID class an `IRP_MN_QUERY_ID` requests (`BusQueryId`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BusQueryId {
    /// `BusQueryDeviceID` — the single enumerator-qualified device ID.
    DeviceId,
    /// `BusQueryHardwareIDs` — the `REG_MULTI_SZ` hardware-ID list.
    HardwareIds,
    /// `BusQueryCompatibleIDs` — the `REG_MULTI_SZ` compatible-ID list.
    CompatibleIds,
    /// `BusQueryInstanceID` — the instance ID under the device key.
    InstanceId,
}

/// A subset of `DEVICE_CAPABILITIES` (the fields the PnP Manager consults for a root-enumerated
/// fixture device). `device_state[i]` maps system power state `S(i)` to the deepest supported
/// device power state: `1` = `D0`, `4` = `D3`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceCapabilities {
    /// Structure version (`1` for NT 6.1).
    pub version: u16,
    /// The device supports the D1 / D2 idle states.
    pub device_d1: bool,
    /// The device supports the D2 idle state.
    pub device_d2: bool,
    /// The device can be locked against ejection.
    pub lock_supported: bool,
    /// The device can be software-ejected.
    pub eject_supported: bool,
    /// The device is removable.
    pub removable: bool,
    /// The device exposes a globally unique ID.
    pub unique_id: bool,
    /// The device installs without user prompts.
    pub silent_install: bool,
    /// The device may be opened without a function driver.
    pub raw_device_ok: bool,
    /// The device tolerates surprise removal.
    pub surprise_removal_ok: bool,
    /// Bus-relative address (`0xFFFF_FFFF` = unspecified).
    pub address: u32,
    /// UI slot number (`0xFFFF_FFFF` = unspecified).
    pub ui_number: u32,
    /// `DeviceState[PowerSystemMaximum]`: S0..=S5 → device power state.
    pub device_state: [u32; 6],
}

impl DeviceCapabilities {
    /// The default capabilities of a root-enumerated synthetic device: powered in S0 (`D0`), off in
    /// every sleep/hibernate/shutdown state (`D3`), non-removable, surprise-removal tolerant.
    pub fn root_default() -> Self {
        Self {
            version: 1,
            device_d1: false,
            device_d2: false,
            lock_supported: false,
            eject_supported: false,
            removable: false,
            unique_id: false,
            silent_install: true,
            raw_device_ok: false,
            surprise_removal_ok: true,
            address: 0xFFFF_FFFF,
            ui_number: 0xFFFF_FFFF,
            // S0 -> D0, S1..S5 -> D3.
            device_state: [1, 4, 4, 4, 4, 4],
        }
    }
}

/// A physical device object the root bus created for one devnode.
#[derive(Clone, Debug)]
pub struct Pdo {
    /// The canonical I/O Manager identity of this PDO.
    pub canonical_id: DeviceId,
    /// `BusQueryDeviceID`.
    pub device_id: String,
    /// `BusQueryHardwareIDs`.
    pub hardware_ids: Vec<String>,
    /// `BusQueryCompatibleIDs`.
    pub compatible_ids: Vec<String>,
    /// `BusQueryInstanceID`.
    pub instance_id: String,
    /// `IRP_MN_QUERY_CAPABILITIES`.
    pub capabilities: DeviceCapabilities,
    /// Whether the bus has started this PDO (set by `IRP_MN_START_DEVICE` reaching the bottom of
    /// the device stack, cleared by `IRP_MN_REMOVE_DEVICE`).
    pub started: bool,
}

/// Invalid identity material for a root-bus PDO.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootBusPdoError {
    /// The caller did not supply a canonical PDO identity.
    NullCanonicalDeviceId,
    /// The bus already owns this canonical PDO identity.
    DuplicateCanonicalDeviceId,
    /// `BusQueryDeviceID` would be empty.
    EmptyDeviceId,
    /// `BusQueryInstanceID` would be empty.
    EmptyInstanceId,
    /// `BusQueryHardwareIDs` would be an empty `REG_MULTI_SZ`.
    EmptyHardwareIds,
    /// One hardware-ID entry is empty.
    EmptyHardwareId,
    /// One compatible-ID entry is empty.
    EmptyCompatibleId,
}

/// `NTSTATUS` the PDO's PnP dispatch returns.
const STATUS_SUCCESS: i32 = 0;
const STATUS_NO_SUCH_DEVICE: i32 = 0xC000_000Eu32 as i32;

/// `IRP_MN_START_DEVICE` — the bus PDO's start minor.
pub const IRP_MN_START_DEVICE: u8 = 0x00;
/// `IRP_MN_QUERY_REMOVE_DEVICE` — may the device be removed? (the bus always allows it).
pub const IRP_MN_QUERY_REMOVE_DEVICE: u8 = 0x01;
/// `IRP_MN_REMOVE_DEVICE` — the bus PDO's remove minor.
pub const IRP_MN_REMOVE_DEVICE: u8 = 0x02;
/// `IRP_MN_CANCEL_REMOVE_DEVICE` — a proposed remove was cancelled.
pub const IRP_MN_CANCEL_REMOVE_DEVICE: u8 = 0x03;
/// `IRP_MN_STOP_DEVICE` — quiesce the PDO (a query/cancel-stop precede it).
pub const IRP_MN_STOP_DEVICE: u8 = 0x04;
/// `IRP_MN_QUERY_STOP_DEVICE` — may the device be stopped? (the bus always allows it).
pub const IRP_MN_QUERY_STOP_DEVICE: u8 = 0x05;
/// `IRP_MN_CANCEL_STOP_DEVICE` — a proposed stop was cancelled.
pub const IRP_MN_CANCEL_STOP_DEVICE: u8 = 0x06;
/// `IRP_MN_SURPRISE_REMOVAL` — the device was removed unexpectedly.
pub const IRP_MN_SURPRISE_REMOVAL: u8 = 0x17;

/// The synthetic root bus: a table of PDOs it has enumerated.
#[derive(Default)]
pub struct RootBus {
    pdos: Vec<Pdo>,
}

impl RootBus {
    /// A root bus with no children yet.
    pub fn new() -> Self {
        Self { pdos: Vec::new() }
    }

    /// Validate the identity a real PnP root PDO will publish through `IRP_MN_QUERY_ID`.
    pub fn validate_pdo_identity<H, C>(
        canonical_id: DeviceId,
        device_id: &str,
        hardware_ids: &[H],
        compatible_ids: &[C],
        instance_id: &str,
    ) -> Result<(), RootBusPdoError>
    where
        H: AsRef<str>,
        C: AsRef<str>,
    {
        if canonical_id.is_null() {
            return Err(RootBusPdoError::NullCanonicalDeviceId);
        }
        if device_id.is_empty() {
            return Err(RootBusPdoError::EmptyDeviceId);
        }
        if instance_id.is_empty() {
            return Err(RootBusPdoError::EmptyInstanceId);
        }
        if hardware_ids.is_empty() {
            return Err(RootBusPdoError::EmptyHardwareIds);
        }
        for id in hardware_ids {
            if id.as_ref().is_empty() {
                return Err(RootBusPdoError::EmptyHardwareId);
            }
        }
        for id in compatible_ids {
            if id.as_ref().is_empty() {
                return Err(RootBusPdoError::EmptyCompatibleId);
            }
        }
        Ok(())
    }

    /// Checked variant for real PnP publication. Proof components can still use `create_pdo`
    /// directly when constructing intentionally minimal fixtures.
    pub fn try_create_pdo<H, C>(
        &mut self,
        canonical_id: DeviceId,
        device_id: &str,
        hardware_ids: &[H],
        compatible_ids: &[C],
        instance_id: &str,
    ) -> Result<DeviceId, RootBusPdoError>
    where
        H: AsRef<str>,
        C: AsRef<str>,
    {
        Self::validate_pdo_identity(
            canonical_id,
            device_id,
            hardware_ids,
            compatible_ids,
            instance_id,
        )?;
        if self.pdo(canonical_id).is_some() {
            return Err(RootBusPdoError::DuplicateCanonicalDeviceId);
        }
        self.pdos.push(Pdo {
            canonical_id,
            device_id: device_id.into(),
            hardware_ids: hardware_ids.iter().map(|s| s.as_ref().into()).collect(),
            compatible_ids: compatible_ids.iter().map(|s| s.as_ref().into()).collect(),
            instance_id: instance_id.into(),
            capabilities: DeviceCapabilities::root_default(),
            started: false,
        });
        Ok(canonical_id)
    }

    /// Enumerate a child with a canonical I/O Manager identity and default capabilities.
    pub fn create_pdo<H, C>(
        &mut self,
        canonical_id: DeviceId,
        device_id: &str,
        hardware_ids: &[H],
        compatible_ids: &[C],
        instance_id: &str,
    ) -> Result<DeviceId, RootBusPdoError>
    where
        H: AsRef<str>,
        C: AsRef<str>,
    {
        self.try_create_pdo(
            canonical_id,
            device_id,
            hardware_ids,
            compatible_ids,
            instance_id,
        )
    }

    /// The PDO with `canonical_id`, if the bus enumerated it.
    pub fn pdo(&self, canonical_id: DeviceId) -> Option<&Pdo> {
        self.pdos
            .iter()
            .find(|pdo| pdo.canonical_id == canonical_id)
    }

    /// Remove one exact canonical PDO from the bus.
    pub fn remove_pdo(&mut self, canonical_id: DeviceId) -> bool {
        let Some(index) = self
            .pdos
            .iter()
            .position(|pdo| pdo.canonical_id == canonical_id)
        else {
            return false;
        };
        self.pdos.swap_remove(index);
        true
    }

    /// Number of enumerated children.
    pub fn len(&self) -> usize {
        self.pdos.len()
    }

    /// Whether the bus has enumerated any children.
    pub fn is_empty(&self) -> bool {
        self.pdos.is_empty()
    }

    /// Answer `IRP_MN_QUERY_ID` for a PDO: a wide (UTF-16) buffer. `DeviceId`/`InstanceId` is one
    /// NUL-terminated string; `HardwareIds`/`CompatibleIds` is a double-NUL-terminated multi-SZ.
    /// Returns `None` if the PDO is unknown.
    pub fn query_id(&self, canonical_id: DeviceId, kind: BusQueryId) -> Option<Vec<u16>> {
        let pdo = self.pdo(canonical_id)?;
        Some(match kind {
            BusQueryId::DeviceId => wide_z(&pdo.device_id),
            BusQueryId::InstanceId => wide_z(&pdo.instance_id),
            BusQueryId::HardwareIds => multi_sz(&pdo.hardware_ids),
            BusQueryId::CompatibleIds => multi_sz(&pdo.compatible_ids),
        })
    }

    /// Answer `IRP_MN_QUERY_CAPABILITIES` for a PDO.
    pub fn query_capabilities(&self, canonical_id: DeviceId) -> Option<&DeviceCapabilities> {
        self.pdo(canonical_id).map(|p| &p.capabilities)
    }

    /// Answer `IRP_MN_QUERY_DEVICE_RELATIONS(BusRelations)`: the object IDs of every child PDO the
    /// bus has enumerated — the root of the device tree reporting its children.
    pub fn query_device_relations(&self) -> Vec<DeviceId> {
        self.pdos.iter().map(|p| p.canonical_id).collect()
    }

    /// The PDO's PnP dispatch — the bottom of the device stack. A function driver's framework PnP
    /// handler forwards `IRP_MN_START_DEVICE` / `IRP_MN_REMOVE_DEVICE` down to here; the bus starts
    /// or stops the PDO and completes the IRP. Returns the `NTSTATUS`.
    pub fn dispatch_pnp(&mut self, canonical_id: DeviceId, minor: u8) -> i32 {
        let Some(pdo) = self
            .pdos
            .iter_mut()
            .find(|pdo| pdo.canonical_id == canonical_id)
        else {
            return STATUS_NO_SUCH_DEVICE;
        };
        match minor {
            IRP_MN_START_DEVICE => pdo.started = true,
            // STOP / REMOVE / SURPRISE_REMOVAL all quiesce the PDO; QUERY_STOP + CANCEL_STOP are
            // pure negotiation the bus always allows without changing state.
            IRP_MN_STOP_DEVICE | IRP_MN_REMOVE_DEVICE | IRP_MN_SURPRISE_REMOVAL => {
                pdo.started = false
            }
            // Query/cancel of a proposed stop or remove is pure negotiation the bus always allows.
            IRP_MN_QUERY_STOP_DEVICE
            | IRP_MN_CANCEL_STOP_DEVICE
            | IRP_MN_QUERY_REMOVE_DEVICE
            | IRP_MN_CANCEL_REMOVE_DEVICE => {}
            _ => {}
        }
        STATUS_SUCCESS
    }

    /// Whether the bus has started this PDO.
    pub fn pdo_started(&self, canonical_id: DeviceId) -> bool {
        self.pdo(canonical_id).map(|p| p.started).unwrap_or(false)
    }
}

/// Split an imported `Enum` instance path into the bus-reported `DeviceID` and local
/// `BusQueryInstanceID`.
///
/// For PCI, registry paths look like `PCI\VEN_8086&DEV_100E\3&11583659&0&18`; the bus reports
/// `PCI\VEN_8086&DEV_100E` as the device ID and `3&11583659&0&18` as the instance ID.
pub fn split_enum_instance_path(path: &str) -> (&str, &str) {
    match path.rfind('\\') {
        Some(pos) => (&path[..pos], &path[pos + 1..]),
        None => (path, ""),
    }
}

/// A single NUL-terminated wide string.
fn wide_z(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

/// A `REG_MULTI_SZ`: each entry NUL-terminated, the whole list double-NUL-terminated. An empty list
/// is a single trailing NUL (an empty multi-SZ).
fn multi_sz(items: &[String]) -> Vec<u16> {
    let mut v = Vec::new();
    for item in items {
        v.extend(item.encode_utf16());
        v.push(0);
    }
    v.push(0);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const PRIMARY_PDO: DeviceId = DeviceId::new(1, 1);

    fn bus() -> RootBus {
        let mut b = RootBus::new();
        b.create_pdo(
            PRIMARY_PDO,
            r"ROOT\KMDF_LOADER_COMPAT_TEST",
            &[r"ROOT\KMDF_LOADER_COMPAT_TEST"],
            &[r"ROOT\USERSPACE_NTOS_TEST_DEVICE"],
            "0001",
        )
        .unwrap();
        b
    }

    #[test]
    fn device_id_is_nul_terminated_wide() {
        let b = bus();
        let id = b.query_id(PRIMARY_PDO, BusQueryId::DeviceId).unwrap();
        assert_eq!(*id.last().unwrap(), 0);
        let s = String::from_utf16(&id[..id.len() - 1]).unwrap();
        assert_eq!(s, r"ROOT\KMDF_LOADER_COMPAT_TEST");
    }

    #[test]
    fn hardware_ids_are_double_nul_multi_sz() {
        let b = bus();
        let m = b.query_id(PRIMARY_PDO, BusQueryId::HardwareIds).unwrap();
        // one entry -> "<id>\0\0"
        assert_eq!(m[m.len() - 1], 0);
        assert_eq!(m[m.len() - 2], 0);
        let first: String = String::from_utf16(&m[..m.len() - 2]).unwrap();
        assert_eq!(first, r"ROOT\KMDF_LOADER_COMPAT_TEST");
    }

    #[test]
    fn instance_id_and_caps() {
        let b = bus();
        let inst = b.query_id(PRIMARY_PDO, BusQueryId::InstanceId).unwrap();
        assert_eq!(String::from_utf16(&inst[..inst.len() - 1]).unwrap(), "0001");
        let caps = b.query_capabilities(PRIMARY_PDO).unwrap();
        assert_eq!(caps.version, 1);
        assert_eq!(caps.device_state[0], 1); // S0 -> D0
        assert_eq!(caps.device_state[5], 4); // S5 -> D3
        assert!(caps.surprise_removal_ok);
    }

    #[test]
    fn unknown_pdo_returns_none() {
        let b = bus();
        assert!(b
            .query_id(DeviceId::new(1, 99), BusQueryId::DeviceId)
            .is_none());
        assert!(b.query_capabilities(DeviceId::new(1, 99)).is_none());
    }

    #[test]
    fn bus_relations_lists_all_children() {
        let mut b = RootBus::new();
        let empty: [&str; 0] = [];
        let a = DeviceId::new(1, 1);
        let b_id = DeviceId::new(1, 2);
        let c = DeviceId::new(1, 3);
        b.create_pdo(a, r"ROOT\A", &[r"ROOT\A"], &empty, "0001")
            .unwrap();
        b.create_pdo(b_id, r"ROOT\B", &[r"ROOT\B"], &empty, "0001")
            .unwrap();
        b.create_pdo(c, r"ROOT\C", &[r"ROOT\C"], &empty, "0001")
            .unwrap();
        let rel = b.query_device_relations();
        assert_eq!(rel, alloc::vec![a, b_id, c]);
        assert_eq!(b.len(), 3);
    }

    #[test]
    fn pdo_start_remove_dispatch() {
        let mut b = bus();
        assert!(!b.pdo_started(PRIMARY_PDO));
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_START_DEVICE), 0);
        assert!(b.pdo_started(PRIMARY_PDO));
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_REMOVE_DEVICE), 0);
        assert!(!b.pdo_started(PRIMARY_PDO));
        assert_ne!(b.dispatch_pnp(DeviceId::new(1, 99), IRP_MN_START_DEVICE), 0);
    }

    #[test]
    fn pdo_stop_and_surprise_dispatch() {
        let mut b = bus();
        b.dispatch_pnp(PRIMARY_PDO, IRP_MN_START_DEVICE);
        // query-stop + cancel-stop are pure negotiation: still started.
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_QUERY_STOP_DEVICE), 0);
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_CANCEL_STOP_DEVICE), 0);
        assert!(b.pdo_started(PRIMARY_PDO));
        // stop quiesces; restart resumes.
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_STOP_DEVICE), 0);
        assert!(!b.pdo_started(PRIMARY_PDO));
        b.dispatch_pnp(PRIMARY_PDO, IRP_MN_START_DEVICE);
        assert!(b.pdo_started(PRIMARY_PDO));
        // query-remove + cancel-remove are pure negotiation: still started.
        b.dispatch_pnp(PRIMARY_PDO, IRP_MN_START_DEVICE);
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_QUERY_REMOVE_DEVICE), 0);
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_CANCEL_REMOVE_DEVICE), 0);
        assert!(b.pdo_started(PRIMARY_PDO));
        // surprise removal quiesces.
        assert_eq!(b.dispatch_pnp(PRIMARY_PDO, IRP_MN_SURPRISE_REMOVAL), 0);
        assert!(!b.pdo_started(PRIMARY_PDO));
    }

    #[test]
    fn splits_enum_instance_path_for_bus_query_ids() {
        assert_eq!(
            split_enum_instance_path(r"PCI\VEN_8086&DEV_100E\3&11583659&0&18"),
            (r"PCI\VEN_8086&DEV_100E", r"3&11583659&0&18")
        );
        assert_eq!(
            split_enum_instance_path(r"ROOT\DEVICE\0001"),
            (r"ROOT\DEVICE", "0001")
        );
        assert_eq!(
            split_enum_instance_path("LEGACY_DEVICE"),
            ("LEGACY_DEVICE", "")
        );
    }

    #[test]
    fn checked_pdo_rejects_incomplete_registry_identity() {
        let empty: [&str; 0] = [];
        let mut b = RootBus::new();

        assert_eq!(
            b.try_create_pdo(DeviceId::NULL, r"ROOT\A", &[r"ROOT\A"], &empty, "0001"),
            Err(RootBusPdoError::NullCanonicalDeviceId)
        );
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, "", &[r"ROOT\A"], &empty, "0001"),
            Err(RootBusPdoError::EmptyDeviceId)
        );
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, r"ROOT\A", &[r"ROOT\A"], &empty, ""),
            Err(RootBusPdoError::EmptyInstanceId)
        );
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, r"ROOT\A", &empty, &empty, "0001"),
            Err(RootBusPdoError::EmptyHardwareIds)
        );
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, r"ROOT\A", &[""], &empty, "0001"),
            Err(RootBusPdoError::EmptyHardwareId)
        );
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, r"ROOT\A", &[r"ROOT\A"], &[""], "0001"),
            Err(RootBusPdoError::EmptyCompatibleId)
        );

        assert!(b.is_empty());
    }

    #[test]
    fn checked_pdo_publishes_registry_identity_without_synthesis() {
        let mut b = RootBus::new();
        let empty: [&str; 0] = [];
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, r"ROOT\A", &[r"ROOT\A"], &empty, "0001"),
            Ok(PRIMARY_PDO)
        );
        assert_eq!(b.len(), 1);
        let pdo = b.pdo(PRIMARY_PDO).unwrap();
        assert_eq!(pdo.hardware_ids, alloc::vec![String::from(r"ROOT\A")]);
        assert!(pdo.compatible_ids.is_empty());
        assert_eq!(
            b.try_create_pdo(PRIMARY_PDO, r"ROOT\B", &[r"ROOT\B"], &empty, "0002"),
            Err(RootBusPdoError::DuplicateCanonicalDeviceId)
        );
        assert!(b.remove_pdo(PRIMARY_PDO));
        assert!(!b.remove_pdo(PRIMARY_PDO));
        assert!(b.is_empty());
    }
}
