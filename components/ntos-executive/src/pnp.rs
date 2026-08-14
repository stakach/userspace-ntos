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
    assign_resources, assign_root_bus_resources, assignment_to_cm_list, enumerate_bus,
    PciDevice, ResourceAssignment, RootBusResourceProfile, ASSIGNMENT_CM_LIST_MAX_SIZE,
    ROOT_DMA_TEST_RESOURCE_PROFILE,
};

static ROOT_BUS_RESOURCE_PROFILES: [RootBusResourceProfile; 1] = [ROOT_DMA_TEST_RESOURCE_PROFILE];

/// Enumerate PCI bus 0 through `nt-pnp` using the executive's port-I/O config access. The reader
/// closures drive `pci_read32`/`pci_write32` (0xCF8/0xCFC via `pci_io`); the writer is used by
/// `nt-pnp`'s BAR size-probe (write-all-ones then restore), so the caps must reach real config
/// space. Returns every enumerated function on bus 0 (vendor/device/class, decoded BAR base+SIZE,
/// IRQ line/pin) — the same bus walk the executive did inline, now the PnP Manager's job.
pub(crate) unsafe fn enumerate_pci_bus0(pci_io: u64) -> alloc::vec::Vec<PciDevice> {
    enumerate_bus(
        0,
        |dev, func, off| pci_read32(pci_io, 0, dev, func, off),
        |dev, func, off, v| pci_write32(pci_io, 0, dev, func, off, v),
    )
}

/// The PCI function and translated START resource bytes selected for one registry devnode.
pub(crate) struct DevnodePciResourceGrant {
    pub device: PciDevice,
    pub assignment: ResourceAssignment,
    pub resource_list: Vec<u8>,
}

/// The root-bus profile and translated START resource bytes selected for one registry devnode.
pub(crate) struct DevnodeRootResourceGrant {
    pub assignment: ResourceAssignment,
    pub resource_list: Vec<u8>,
}

pub(crate) fn root_bus_resource_profile_for_devnode(
    instance_id: &str,
    hardware_ids: &[&str],
    compatible_ids: &[&str],
) -> Option<&'static RootBusResourceProfile> {
    ROOT_BUS_RESOURCE_PROFILES.iter().find(|profile| {
        nt_pnp::devnode_matches_root_bus_profile(instance_id, hardware_ids, compatible_ids, profile)
    })
}

/// Build the physical START resources for an already-selected PCI function.
pub(crate) fn build_devnode_pci_resource_grant(
    device: &PciDevice,
    int_vector: u32,
    int_latched: bool,
    dma_len: u64,
    granted_mmio_len: u32,
) -> Option<DevnodePciResourceGrant> {
    let assignment = assign_resources(
        device,
        int_vector,
        int_latched,
        /*affinity=*/ 1,
        dma_len,
    )?;
    let mmio_len = assignment.mmio_len.min(granted_mmio_len as u64);
    if mmio_len == 0 || mmio_len > u32::MAX as u64 {
        return None;
    }
    let mut resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let n = assignment_to_cm_list(
        &mut resource_list,
        device.bus as u32,
        &assignment,
        assignment.mmio_phys,
        mmio_len as u32,
    )?;
    resource_list.truncate(n);
    Some(DevnodePciResourceGrant {
        device: device.clone(),
        assignment,
        resource_list,
    })
}

/// Resolve a registry-selected root-bus devnode against broker-backed resource profiles and build
/// the physical `CM_RESOURCE_LIST` that will be passed to the hosted driver's START IRP.
pub(crate) fn assign_devnode_root_dma_resources(
    instance_id: &str,
    hardware_ids: &[&str],
    compatible_ids: &[&str],
    int_vector: u32,
    int_latched: bool,
    dma_len: u64,
    granted_mmio_len: u32,
) -> Option<DevnodeRootResourceGrant> {
    let profile = root_bus_resource_profile_for_devnode(instance_id, hardware_ids, compatible_ids)?;
    let assignment = assign_root_bus_resources(
        instance_id,
        hardware_ids,
        compatible_ids,
        profile,
        int_vector,
        int_latched,
        /*affinity=*/ 1,
        dma_len,
    )?;
    let mmio_len = assignment.mmio_len.min(granted_mmio_len as u64);
    if mmio_len == 0 || mmio_len > u32::MAX as u64 {
        return None;
    }
    let mut resource_list = vec![0u8; ASSIGNMENT_CM_LIST_MAX_SIZE];
    let n = assignment_to_cm_list(
        &mut resource_list,
        0,
        &assignment,
        assignment.mmio_phys,
        mmio_len as u32,
    )?;
    resource_list.truncate(n);
    Some(DevnodeRootResourceGrant {
        assignment,
        resource_list,
    })
}
