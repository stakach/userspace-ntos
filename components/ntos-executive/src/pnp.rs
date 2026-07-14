//! `pnp` — the executive-side PnP cap-minting BROKER (the MECHANISM half of
//! capability-secure PnP; the POLICY lives in the host-tested `nt-pnp` crate).
//!
//! `nt-pnp` decides *what* a device is granted (enumerate PCI → bind a driver →
//! `CM_RESOURCE_LIST`); this module, running in the trusted root task where the
//! privileged seL4 caps live, performs the grant by MINTING exactly the caps that
//! resource list describes — the device's MMIO BAR frame caps, its IRQ notification,
//! its DMA frame — and by writing the driver-visible `CM_RESOURCE_LIST` into the
//! driver's resource frame. Same policy/mechanism split as `nt-process` (see
//! `project_driver_model.md`, effort 2, and `feedback_implement_kernel_api_for_real`).
//!
//! Scope this increment: enumerate the real PCI bus through `nt-pnp` over the
//! executive's `pci_read32`/`pci_write32` closures, bind the NIC, and build its
//! `CM_RESOURCE_LIST` from the enumerated BAR + assigned interrupt vector. The BAR
//! frame caps + IRQ ntfn + DMA frame are minted by the executive's existing device
//! primitives (`claim_device_pages`, `make_object`, `untyped_retype`) — driven here
//! from the enumerated resource list rather than hand-authored constants.
#![allow(clippy::all)]
use crate::*;
use nt_pnp::{
    assign_resources, assignment_to_cm_list, enumerate_bus, find_device_for_class, DriverClass,
    PciDevice, ResourceAssignment, MEMORY_INTERRUPT_LIST_SIZE,
};

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

/// The PnP resource assignment + minted caps for one device the broker granted.
pub(crate) struct GrantedDevice {
    /// The bound device (bus/dev/func + decoded BARs/IRQ from enumeration).
    pub device: PciDevice,
    /// The abstract resource assignment (MMIO phys+len, interrupt vector, DMA len).
    pub assignment: ResourceAssignment,
}

/// Bind + assign resources to the network device on bus 0: find the NIC (`nt-pnp` binds the
/// network class to the NIC driver), then assign it its MMIO BAR + the given translated interrupt
/// vector (+ a `dma_len`-byte common buffer). Returns `None` if no bindable NIC is present. This is
/// the PnP arbitration step — the executive then mints the caps `assignment` names.
pub(crate) fn assign_nic(
    devices: &[PciDevice],
    int_vector: u32,
    int_latched: bool,
    dma_len: u64,
) -> Option<GrantedDevice> {
    let nic = find_device_for_class(devices, DriverClass::Network)?;
    let assignment = assign_resources(nic, int_vector, int_latched, /*affinity=*/ 1, dma_len)?;
    Some(GrantedDevice { device: nic.clone(), assignment })
}

/// Write the driver-visible `CM_RESOURCE_LIST` for `assign` into the resource frame at
/// `reslist_va` — the exact bytes a WDK driver reads at `IRP_MN_START_DEVICE`. `mmio_va` is the
/// driver-visible VA of the minted MMIO window (where the BAR frame caps are mapped in the driver's
/// VSpace), `mmio_len` the length exposed to the driver. This is the resource-assignment grant made
/// concrete: the descriptor names the caps the broker minted, at the VAs they are mapped.
pub(crate) unsafe fn write_cm_resource_list(
    reslist_va: u64,
    bus_number: u32,
    assign: &ResourceAssignment,
    mmio_va: u64,
    mmio_len: u32,
) {
    let buf = core::slice::from_raw_parts_mut(reslist_va as *mut u8, MEMORY_INTERRUPT_LIST_SIZE);
    let _ = assignment_to_cm_list(buf, bus_number, assign, mmio_va, mmio_len);
}
