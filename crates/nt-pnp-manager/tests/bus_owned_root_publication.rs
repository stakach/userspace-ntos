//! The released LiberNT PCI root reports bus routing windows as its current resources.
//! A successful StartDevice may publish that exact assignment without an MMIO mapping lease,
//! but the assignment must still be tied to the started PDO and its checked translation.

use nt_pnp_manager::{
    DeviceState, DevnodeIdentity, PdoProperties, PnpBusInformation, PnpManager, PnpMinor,
    PropertyBlobState, GUID_BUS_TYPE_PCI, INTERFACE_TYPE_PCI_BUS,
};

const ROOT_PDO: u64 = 0x4530;
const ROOT_FDO: u64 = 0x4531;
const START_IRP: u64 = 0x4532;

fn released_root_pair() -> (Vec<u8>, Vec<u8>) {
    let mut lines =
        include_str!("../../nt-cm-resources/src/libernt_pci_root_resources.hex").lines();
    let decode = |hex: &str| {
        hex.as_bytes()
            .chunks_exact(2)
            .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
            .collect::<Vec<_>>()
    };
    let raw = decode(lines.next().unwrap());
    let requirements = decode(lines.next().unwrap());
    assert_eq!((raw.len(), requirements.len()), (480, 296));
    (raw, requirements)
}

fn root_properties(
    boot_raw: PropertyBlobState,
    boot_translated: PropertyBlobState,
    requirements: PropertyBlobState,
    bus_number: u32,
) -> PdoProperties {
    PdoProperties::from_bus_queries(
        Some(PnpBusInformation {
            bus_type_guid: GUID_BUS_TYPE_PCI,
            legacy_bus_type: INTERFACE_TYPE_PCI_BUS,
            bus_number,
        }),
        None,
        boot_raw,
        boot_translated,
        requirements,
    )
}

fn assigned_root(
    properties: PdoProperties,
    filtered: Vec<u8>,
    assigned_raw: Vec<u8>,
    assigned_translated: Vec<u8>,
) -> (PnpManager, DevnodeIdentity) {
    let mut pnp = PnpManager::new();
    pnp.register_enumerated_pdo(r"ACPI\PNP0A08\0", ROOT_PDO, properties)
        .unwrap();
    pnp.commit_device_stack(ROOT_PDO, ROOT_FDO, 0x4533).unwrap();
    let identity = pnp.devnode_identity_for_pdo(ROOT_PDO).unwrap();
    pnp.commit_filtered_resource_requirements(ROOT_PDO, filtered)
        .unwrap();
    pnp.commit_resource_assignment(ROOT_PDO, assigned_raw, assigned_translated)
        .unwrap();
    (pnp, identity)
}

fn start_root(pnp: &mut PnpManager) {
    let token = pnp
        .begin_pnp_dispatch(ROOT_PDO, PnpMinor::StartDevice, START_IRP)
        .unwrap();
    assert_eq!(
        pnp.complete_pnp_dispatch(&token, START_IRP, true).unwrap(),
        DeviceState::Started,
    );
}

#[test]
fn released_libernt_mixed_root_assignment_requires_exact_started_proof() {
    let (raw, requirements) = released_root_pair();
    let translated =
        nt_cm_resources::admit_bus_owned_root_resources(&raw, &requirements, 0).unwrap();
    let (mut pnp, identity) = assigned_root(
        root_properties(
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::Present(requirements.clone()),
            0,
        ),
        requirements,
        raw,
        translated,
    );
    assert!(!pnp.devnode_has_started_bus_number_assignment(identity));
    assert!(!pnp.devnode_has_started_bus_owned_root_assignment(identity));
    let token = pnp.begin_pnp_dispatch(ROOT_PDO, PnpMinor::StartDevice, START_IRP)
        .unwrap();
    assert!(!pnp.devnode_has_started_bus_owned_root_assignment(identity));
    assert_eq!(
        pnp.complete_pnp_dispatch(&token, START_IRP, true).unwrap(),
        DeviceState::Started,
    );
    assert!(pnp.devnode_has_started_bus_owned_root_assignment(identity));
}

#[test]
fn bus_owned_root_proof_rejects_changed_or_incomplete_resource_provenance() {
    let (raw, requirements) = released_root_pair();
    let translated =
        nt_cm_resources::admit_bus_owned_root_resources(&raw, &requirements, 0).unwrap();
    let mut changed_raw = raw.clone();
    changed_raw[44] ^= 1;
    let mut changed_translated = translated.clone();
    changed_translated[44] ^= 1;
    let mut changed_requirements = requirements.clone();
    changed_requirements[80] ^= 1;
    let cases = [
        (
            "filtered requirements differ from the original query",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::Present(requirements.clone()),
            changed_requirements,
            raw.clone(),
            translated.clone(),
            0,
        ),
        (
            "filtered requirements were not retained",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::Present(requirements.clone()),
            Vec::new(),
            raw.clone(),
            translated.clone(),
            0,
        ),
        (
            "bus requirements were not queried",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::KnownNone,
            requirements.clone(),
            raw.clone(),
            translated.clone(),
            0,
        ),
        (
            "boot translation was supplied instead of a checked assignment",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::Present(translated.clone()),
            PropertyBlobState::Present(requirements.clone()),
            requirements.clone(),
            raw.clone(),
            translated.clone(),
            0,
        ),
        (
            "committed raw list differs from the provider list",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::Present(requirements.clone()),
            requirements.clone(),
            changed_raw,
            translated.clone(),
            0,
        ),
        (
            "committed translation differs from checked admission",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::Present(requirements.clone()),
            requirements.clone(),
            raw.clone(),
            changed_translated,
            0,
        ),
        (
            "published bus identity changed",
            PropertyBlobState::Present(raw.clone()),
            PropertyBlobState::KnownNone,
            PropertyBlobState::Present(requirements.clone()),
            requirements.clone(),
            raw.clone(),
            translated.clone(),
            1,
        ),
    ];
    for (
        reason,
        boot_raw,
        boot_translated,
        resource_requirements,
        filtered,
        assigned_raw,
        assigned_translated,
        bus_number,
    ) in cases
    {
        let (mut pnp, identity) = assigned_root(
            root_properties(boot_raw, boot_translated, resource_requirements, bus_number),
            filtered,
            assigned_raw,
            assigned_translated,
        );
        start_root(&mut pnp);
        assert!(
            !pnp.devnode_has_started_bus_owned_root_assignment(identity),
            "{reason}"
        );
    }
}
