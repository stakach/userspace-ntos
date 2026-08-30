//! `pnp` — the executive-side PnP cap-minting BROKER (the MECHANISM half of
//! capability-secure PnP; the POLICY lives in the host-tested `nt-pnp` crate).
//!
//! `nt-pnp` decides *what* a device is granted (enumerate PCI plus registry devnode matching →
//! `CM_RESOURCE_LIST`); this module, running in the trusted root task where the
//! privileged seL4 caps live, performs the grant by MINTING exactly the caps that
//! resource list describes — the device's MMIO BAR frame caps, its IRQ notification,
//! its DMA frame — and by writing the driver-visible `CM_RESOURCE_LIST` into the
//! driver's resource frame. Same policy/mechanism split as `nt-process` (see
//! `project_driver_model.md`, effort 2, and `feedback_implement_kernel_api_for_real`).
//!
//! Scope this increment: enumerate the real PCI bus through `nt-pnp` over the
//! executive's `pci_read32`/`pci_write32` closures, resolve registry-selected devnodes, and build
//! `CM_RESOURCE_LIST` bytes from the enumerated BARs + assigned interrupt vectors. The BAR frame
//! caps + IRQ ntfn + DMA frames are minted by the executive's existing device primitives
//! (`claim_device_pages`, `make_object`, `untyped_retype`) — driven here from the enumerated
//! resource list rather than hand-authored constants.
#![allow(clippy::all)]
use alloc::vec;
use alloc::vec::Vec;

use crate::*;
use nt_pnp::{
    assign_platform_resources, assign_resources, assign_root_bus_resources, assignment_to_cm_list,
    enumerate_hierarchy, pci_boot_resources, pci_resource_requirements,
    platform_resource_requirements, root_bus_resource_requirements, select_resource_assignment,
    PciDevice, PciInterruptAssignment, PlatformResourceProfile, ResourceAssignment, ResourceView,
    RootBusResourceCatalog, RootBusResourceProfile, ASSIGNMENT_CM_LIST_MAX_SIZE,
    INTERFACE_TYPE_PCI_BUS, INTERFACE_TYPE_PNP_BUS, ROOT_DMA_TEST_RESOURCE_PROFILE,
};

static mut ROOT_BUS_RESOURCE_CATALOG: Option<RootBusResourceCatalog> = None;
static mut PCI_CONFIG_IO_CAP: u64 = 0;

#[derive(Copy, Clone)]
pub(crate) struct PciInterruptLineProgramming {
    bus: u8,
    dev: u8,
    func: u8,
    previous_line: u8,
    assigned_line: u8,
}

/// Enumerate the complete configured PCI hierarchy through `nt-pnp` using the executive's
/// port-I/O config access. The walk follows validated PCI-to-PCI bridge bus windows from bus 0.
pub(crate) unsafe fn enumerate_pci_hierarchy(
    pci_io: u64,
) -> Result<alloc::vec::Vec<PciDevice>, nt_pnp::PciTopologyError> {
    PCI_CONFIG_IO_CAP = pci_io;
    enumerate_hierarchy(
        0,
        |bus, dev, func, off| pci_read32(pci_io, bus, dev, func, off),
        |bus, dev, func, off, v| pci_write32(pci_io, bus, dev, func, off, v),
    )
}

/// Program the platform-selected INTx line into PCI configuration space immediately before START.
/// The returned record makes the write transactional with the remaining device-start operation.
pub(crate) unsafe fn program_pci_interrupt_line(
    device: &PciDevice,
    assigned_line: u32,
) -> Result<Option<PciInterruptLineProgramming>, nt_status::NtStatus> {
    if device.irq_pin == 0 {
        return if assigned_line == 0 {
            Ok(None)
        } else {
            Err(nt_status::NtStatus::INVALID_PARAMETER)
        };
    }
    let assigned_line = u8::try_from(assigned_line)
        .ok()
        .filter(|line| *line != u8::MAX)
        .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?;
    if PCI_CONFIG_IO_CAP == 0 {
        print_str(b"[pnp] PCI InterruptLine program rejected: configuration authority absent\n");
        return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
    }
    let interrupt = pci_read32(PCI_CONFIG_IO_CAP, device.bus, device.dev, device.func, 0x3c);
    let previous_line = interrupt as u8;
    if previous_line != device.irq_line {
        print_str(b"[pnp] PCI InterruptLine program rejected: stale snapshot current=");
        print_u64(previous_line as u64);
        print_str(b" enumerated=");
        print_u64(device.irq_line as u64);
        print_str(b" assigned=");
        print_u64(assigned_line as u64);
        print_str(b"\n");
        return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    if previous_line != assigned_line {
        pci_write32(
            PCI_CONFIG_IO_CAP,
            device.bus,
            device.dev,
            device.func,
            0x3c,
            (interrupt & !0xff) | assigned_line as u32,
        );
        if pci_read32(PCI_CONFIG_IO_CAP, device.bus, device.dev, device.func, 0x3c) as u8
            != assigned_line
        {
            print_str(b"[pnp] PCI InterruptLine write did not latch bus=");
            print_u64(device.bus as u64);
            print_str(b" dev=");
            print_u64(device.dev as u64);
            print_str(b" func=");
            print_u64(device.func as u64);
            print_str(b" assigned=");
            print_u64(assigned_line as u64);
            print_str(b"\n");
            pci_write32(
                PCI_CONFIG_IO_CAP,
                device.bus,
                device.dev,
                device.func,
                0x3c,
                interrupt,
            );
            return Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        }
    }
    Ok(Some(PciInterruptLineProgramming {
        bus: device.bus,
        dev: device.dev,
        func: device.func,
        previous_line,
        assigned_line,
    }))
}

pub(crate) unsafe fn restore_pci_interrupt_line(programming: PciInterruptLineProgramming) -> bool {
    if PCI_CONFIG_IO_CAP == 0 || programming.previous_line == programming.assigned_line {
        return PCI_CONFIG_IO_CAP != 0;
    }
    let interrupt = pci_read32(
        PCI_CONFIG_IO_CAP,
        programming.bus,
        programming.dev,
        programming.func,
        0x3c,
    );
    if interrupt as u8 != programming.assigned_line {
        return false;
    }
    pci_write32(
        PCI_CONFIG_IO_CAP,
        programming.bus,
        programming.dev,
        programming.func,
        0x3c,
        (interrupt & !0xff) | programming.previous_line as u32,
    );
    pci_read32(
        PCI_CONFIG_IO_CAP,
        programming.bus,
        programming.dev,
        programming.func,
        0x3c,
    ) as u8
        == programming.previous_line
}

/// The PCI function and raw/translated START resource bytes selected for one registry devnode.
pub(crate) struct DevnodePciResourceGrant {
    pub device: PciDevice,
    pub assignment: ResourceAssignment,
    pub raw_resource_list: Vec<u8>,
    pub translated_resource_list: Vec<u8>,
}

/// Immutable PCI bus publications prepared before the function driver's `AddDevice` runs.
pub(crate) struct DevnodePciBusResources {
    pub device: PciDevice,
    pub resource_requirements: Vec<u8>,
    pub raw_boot_resources: Vec<u8>,
    pub translated_boot_resources: Vec<u8>,
}

/// The root-bus profile and raw/translated START resource bytes selected for one registry devnode.
pub(crate) struct DevnodeRootResourceGrant {
    pub assignment: ResourceAssignment,
    pub resource_requirements: Vec<u8>,
    pub raw_boot_resources: Vec<u8>,
    pub translated_boot_resources: Vec<u8>,
    pub raw_resource_list: Vec<u8>,
    pub translated_resource_list: Vec<u8>,
}

pub(crate) fn root_bus_resource_profile_for_devnode<H, C>(
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
) -> Option<RootBusResourceProfile>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    unsafe {
        root_bus_resource_catalog_mut()?.find_for_devnode(instance_id, hardware_ids, compatible_ids)
    }
}

unsafe fn root_bus_resource_catalog_mut() -> Option<&'static mut RootBusResourceCatalog> {
    let slot = &mut *core::ptr::addr_of_mut!(ROOT_BUS_RESOURCE_CATALOG);
    if slot.is_none() {
        let mut catalog = RootBusResourceCatalog::new();
        if catalog.register(ROOT_DMA_TEST_RESOURCE_PROFILE).is_err() {
            return None;
        }
        *slot = Some(catalog);
    }
    slot.as_mut()
}

#[allow(dead_code)]
pub(crate) fn register_root_bus_resource_profile(profile: RootBusResourceProfile) -> bool {
    unsafe {
        root_bus_resource_catalog_mut()
            .and_then(|catalog| catalog.register(profile).ok())
            .is_some()
    }
}

/// Build the bus-owned BootResources and initial requirements before `AddDevice`.
pub(crate) fn build_devnode_pci_bus_resources(
    device: &PciDevice,
    boot_interrupt: Option<PciInterruptAssignment>,
) -> Option<DevnodePciBusResources> {
    let resource_requirements = pci_resource_requirements(device).ok()??;
    let boot_resources = pci_boot_resources(device, boot_interrupt).ok()??;
    Some(DevnodePciBusResources {
        device: device.clone(),
        resource_requirements,
        raw_boot_resources: boot_resources.raw,
        translated_boot_resources: boot_resources.translated,
    })
}

/// Build the final raw/translated START resources after the function stack has filtered its bus
/// requirements and the platform resource providers have selected a route.
pub(crate) fn build_devnode_pci_resource_grant(
    bus_resources: DevnodePciBusResources,
    interrupt: Option<PciInterruptAssignment>,
    dma_len: u64,
    filtered_resource_requirements: Vec<u8>,
) -> Result<DevnodePciResourceGrant, nt_pnp::ResourceRequirementsError> {
    let available = assign_resources(&bus_resources.device, interrupt, dma_len)?
        .ok_or(nt_pnp::ResourceRequirementsError::UnsatisfiedFilteredRequirements)?;
    let assignment = select_resource_assignment(
        &available,
        &filtered_resource_requirements,
        INTERFACE_TYPE_PCI_BUS,
        bus_resources.device.bus as u32,
        bus_resources.device.slot_number(),
    )?;
    let mut translated_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let n = assignment_to_cm_list(
        &mut translated_resource_list,
        nt_pnp::INTERFACE_TYPE_PCI_BUS,
        bus_resources.device.bus as u32,
        &assignment,
        ResourceView::Translated,
    )
    .map_err(nt_pnp::ResourceRequirementsError::EncodeCm)?;
    translated_resource_list.truncate(n);
    let mut raw_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let raw_len = assignment_to_cm_list(
        &mut raw_resource_list,
        nt_pnp::INTERFACE_TYPE_PCI_BUS,
        bus_resources.device.bus as u32,
        &assignment,
        ResourceView::Raw,
    )
    .map_err(nt_pnp::ResourceRequirementsError::EncodeCm)?;
    raw_resource_list.truncate(raw_len);
    Ok(DevnodePciResourceGrant {
        device: bus_resources.device,
        assignment,
        raw_resource_list,
        translated_resource_list,
    })
}

/// Apply the function stack's returned list to a pre-arbitrated root-bus candidate set and rebuild
/// both START lists from only the admitted descriptors.
pub(crate) fn filter_devnode_root_resource_grant(
    mut grant: DevnodeRootResourceGrant,
    filtered_resource_requirements: Vec<u8>,
) -> Result<DevnodeRootResourceGrant, nt_pnp::ResourceRequirementsError> {
    grant.assignment = select_resource_assignment(
        &grant.assignment,
        &filtered_resource_requirements,
        INTERFACE_TYPE_PNP_BUS,
        0,
        0,
    )?;
    grant.resource_requirements = filtered_resource_requirements;
    let mut translated_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let translated_len = assignment_to_cm_list(
        &mut translated_resource_list,
        INTERFACE_TYPE_PNP_BUS,
        0,
        &grant.assignment,
        ResourceView::Translated,
    )
    .map_err(nt_pnp::ResourceRequirementsError::EncodeCm)?;
    translated_resource_list.truncate(translated_len);
    let mut raw_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let raw_len = assignment_to_cm_list(
        &mut raw_resource_list,
        INTERFACE_TYPE_PNP_BUS,
        0,
        &grant.assignment,
        ResourceView::Raw,
    )
    .map_err(nt_pnp::ResourceRequirementsError::EncodeCm)?;
    raw_resource_list.truncate(raw_len);
    grant.raw_resource_list = raw_resource_list;
    grant.translated_resource_list = translated_resource_list;
    Ok(grant)
}

/// Resolve a registry-selected root-bus devnode against broker-backed resource profiles and build
/// the physical `CM_RESOURCE_LIST` that will be passed to the hosted driver's START IRP.
pub(crate) fn assign_devnode_root_dma_resources<H, C>(
    instance_id: &str,
    hardware_ids: &[H],
    compatible_ids: &[C],
    int_vector: u32,
    int_latched: bool,
    dma_len: u64,
) -> Option<DevnodeRootResourceGrant>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    let profile = root_bus_resource_profile_for_devnode(instance_id, hardware_ids, compatible_ids)?;
    let assignment = assign_root_bus_resources(
        instance_id,
        hardware_ids,
        compatible_ids,
        &profile,
        int_vector,
        int_latched,
        /*affinity=*/ 1,
        dma_len,
    )?;
    let resource_requirements = root_bus_resource_requirements(&profile).ok()?;
    let mut translated_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let n = assignment_to_cm_list(
        &mut translated_resource_list,
        nt_pnp::INTERFACE_TYPE_PNP_BUS,
        0,
        &assignment,
        ResourceView::Translated,
    )
    .ok()?;
    translated_resource_list.truncate(n);
    let mut raw_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let raw_len = assignment_to_cm_list(
        &mut raw_resource_list,
        nt_pnp::INTERFACE_TYPE_PNP_BUS,
        0,
        &assignment,
        ResourceView::Raw,
    )
    .ok()?;
    raw_resource_list.truncate(raw_len);
    Some(DevnodeRootResourceGrant {
        assignment,
        resource_requirements,
        raw_boot_resources: raw_resource_list.clone(),
        translated_boot_resources: translated_resource_list.clone(),
        raw_resource_list,
        translated_resource_list,
    })
}

/// Build boot/requirements/START snapshots for a firmware-derived platform resource profile.
pub(crate) fn build_devnode_platform_resources(
    profile: &PlatformResourceProfile,
) -> Result<DevnodeRootResourceGrant, nt_pnp::ResourceRequirementsError> {
    let assignment = assign_platform_resources(profile)?;
    let resource_requirements = platform_resource_requirements(profile)?;
    let mut translated_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let translated_len = assignment_to_cm_list(
        &mut translated_resource_list,
        INTERFACE_TYPE_PNP_BUS,
        0,
        &assignment,
        ResourceView::Translated,
    )
    .map_err(nt_pnp::ResourceRequirementsError::EncodeCm)?;
    translated_resource_list.truncate(translated_len);
    let mut raw_resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let raw_len = assignment_to_cm_list(
        &mut raw_resource_list,
        INTERFACE_TYPE_PNP_BUS,
        0,
        &assignment,
        ResourceView::Raw,
    )
    .map_err(nt_pnp::ResourceRequirementsError::EncodeCm)?;
    raw_resource_list.truncate(raw_len);
    Ok(DevnodeRootResourceGrant {
        assignment,
        resource_requirements,
        raw_boot_resources: raw_resource_list.clone(),
        translated_boot_resources: translated_resource_list.clone(),
        raw_resource_list,
        translated_resource_list,
    })
}
