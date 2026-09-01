use crate::*;
use alloc::vec::Vec;
use nt_pnp_context::{
    AddressSlotAllocator, AddressSlotReservation, ContextId, ContextLease, ContextLeaseIdentity,
    ContextRegistry,
};

const HOSTED_RESOURCE_WINDOW_STRIDE: u64 = 0x20_0000;
const HOSTED_RESOURCE_COMPONENT_VA_BASE: u64 = 0x0000_0100_1600_0000;
const HOSTED_RESOURCE_COMPONENT_VA_LIMIT: u64 = crate::allocator::HEAP_BASE as u64;

const _: () = assert!(HOSTED_RESOURCE_COMPONENT_VA_BASE & 0x1F_FFFF == 0);
const _: () = assert!(HOSTED_RESOURCE_COMPONENT_VA_BASE < HOSTED_RESOURCE_COMPONENT_VA_LIMIT);

#[derive(Clone)]
pub(crate) struct HostedPnpPciMemoryDescriptor {
    pub(crate) bar_index: u8,
    pub(crate) phys: u64,
    pub(crate) len: u64,
    pub(crate) frame_base: u64,
    pub(crate) pages: u64,
    pub(crate) map_pages: u64,
    pub(crate) va: u64,
    pub(crate) seed_va: u64,
}

impl HostedPnpPciMemoryDescriptor {
    pub(crate) fn mapped_len(&self) -> u64 {
        self.len.min(self.map_pages.saturating_mul(0x1000))
    }
}

#[derive(Clone)]
pub(crate) struct HostedPnpPciResourceDescriptor {
    pub(crate) bus: u8,
    pub(crate) dev: u8,
    pub(crate) func: u8,
    pub(crate) memory: Vec<HostedPnpPciMemoryDescriptor>,
    pub(crate) dma_frame_base: u64,
    pub(crate) dma_pages: u64,
    pub(crate) dma_va: u64,
    pub(crate) dma_seed_va: u64,
    pub(crate) dma_logical: u64,
    pub(crate) dma_len: u64,
}

impl HostedPnpPciResourceDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        bus: u8,
        dev: u8,
        func: u8,
        memory: Vec<HostedPnpPciMemoryDescriptor>,
        dma_frame_base: u64,
        dma_pages: u64,
        dma_va: u64,
        dma_seed_va: u64,
        dma_logical: u64,
        dma_len: u64,
    ) -> Option<Self> {
        if memory.len() > nt_pnp::PCI_NUM_BARS
            || memory.iter().enumerate().any(|(index, window)| {
                window.bar_index as usize >= nt_pnp::PCI_NUM_BARS
                    || memory[..index]
                        .iter()
                        .any(|previous| previous.bar_index == window.bar_index)
                    || window.phys == 0
                    || window.len == 0
                    || window.frame_base == 0
                    || window.pages == 0
                    || window.map_pages == 0
                    || window.map_pages > window.pages
                    || window.va == 0
                    || window.seed_va == 0
            })
        {
            return None;
        }
        let has_dma = dma_frame_base != 0
            || dma_pages != 0
            || dma_va != 0
            || dma_seed_va != 0
            || dma_logical != 0
            || dma_len != 0;
        if has_dma
            && (dma_frame_base == 0
                || dma_pages == 0
                || dma_va == 0
                || dma_seed_va == 0
                || dma_logical == 0
                || dma_len == 0)
        {
            return None;
        }
        Some(Self {
            bus,
            dev,
            func,
            memory,
            dma_frame_base,
            dma_pages,
            dma_va,
            dma_seed_va,
            dma_logical,
            dma_len,
        })
    }

    pub(crate) fn matches(&self, device: &nt_pnp::PciDevice) -> bool {
        self.bus == device.bus && self.dev == device.dev && self.func == device.func
    }

    pub(crate) fn memory_window(&self, bar_index: u8) -> Option<&HostedPnpPciMemoryDescriptor> {
        self.memory
            .iter()
            .find(|window| window.bar_index == bar_index)
    }

    pub(crate) fn dma_grant_valid(&self) -> bool {
        let has_dma = self.dma_va != 0
            || self.dma_frame_base != 0
            || self.dma_pages != 0
            || self.dma_seed_va != 0
            || self.dma_logical != 0
            || self.dma_len != 0;
        !has_dma
            || (self.dma_va != 0
                && self.dma_frame_base != 0
                && self.dma_pages != 0
                && self.dma_seed_va != 0
                && self.dma_logical != 0
                && self.dma_len != 0)
    }
}

#[derive(Clone)]
pub(crate) struct HostedPnpPlatformMemoryDescriptor {
    pub(crate) resource_index: u8,
    pub(crate) phys: u64,
    pub(crate) len: u64,
    pub(crate) writable: bool,
    pub(crate) frame_base: u64,
    pub(crate) pages: u64,
    pub(crate) va: u64,
    pub(crate) seed_va: u64,
    pub(crate) platform_hpet: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpPlatformPortDescriptor {
    pub(crate) resource_index: u8,
    pub(crate) base: u64,
    pub(crate) len: u32,
    pub(crate) platform_reset: bool,
}

#[derive(Clone)]
pub(crate) struct HostedPnpPlatformResourceDescriptor {
    pub(crate) instance_path: &'static str,
    pub(crate) hardware_id: &'static str,
    pub(crate) compatible_id: &'static str,
    pub(crate) memory: Vec<HostedPnpPlatformMemoryDescriptor>,
    pub(crate) ports: Vec<HostedPnpPlatformPortDescriptor>,
    pub(crate) interrupt_vector: u32,
    pub(crate) interrupt_latched: bool,
    pub(crate) interrupt_shared: bool,
    pub(crate) interrupt_active_low: bool,
}

impl HostedPnpPlatformResourceDescriptor {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        instance_path: &'static str,
        hardware_id: &'static str,
        compatible_id: &'static str,
        memory: Vec<HostedPnpPlatformMemoryDescriptor>,
        ports: Vec<HostedPnpPlatformPortDescriptor>,
        interrupt_vector: u32,
        interrupt_latched: bool,
        interrupt_shared: bool,
        interrupt_active_low: bool,
    ) -> Option<Self> {
        if instance_path.is_empty()
            || hardware_id.is_empty()
            || interrupt_vector == 0
            || memory.len() > driver_launch::SH_RESOURCE_KIND_CAPACITY as usize
            || ports.len() > driver_launch::SH_RESOURCE_KIND_CAPACITY as usize
            || memory.iter().enumerate().any(|(index, resource)| {
                resource.resource_index >= driver_launch::SH_RESOURCE_KIND_CAPACITY
                    || memory[..index]
                        .iter()
                        .any(|previous| previous.resource_index == resource.resource_index)
                    || resource.len == 0
                    || resource.frame_base == 0
                    || resource.pages == 0
                    || resource.va == 0
                    || resource.seed_va == 0
                    || resource.phys.checked_add(resource.len).is_none()
                    || resource.frame_base.checked_add(resource.pages).is_none()
                    || resource.phys & 0xfff != resource.va & 0xfff
                    || resource.phys & 0xfff != resource.seed_va & 0xfff
                    || (resource.phys & 0xfff)
                        .checked_add(resource.len)
                        .is_none_or(|bytes| bytes > resource.pages.saturating_mul(0x1000))
            })
            || ports.iter().enumerate().any(|(index, resource)| {
                resource.resource_index >= driver_launch::SH_RESOURCE_KIND_CAPACITY
                    || ports[..index]
                        .iter()
                        .any(|previous| previous.resource_index == resource.resource_index)
                    || resource.platform_reset
                        && ports[..index]
                            .iter()
                            .any(|previous| previous.platform_reset)
                    || resource.len == 0
                    || resource
                        .base
                        .checked_add(resource.len as u64)
                        .and_then(|end| end.checked_sub(1))
                        .is_none_or(|end| end > u16::MAX as u64)
            })
        {
            return None;
        }
        Some(Self {
            instance_path,
            hardware_id,
            compatible_id,
            memory,
            ports,
            interrupt_vector,
            interrupt_latched,
            interrupt_shared,
            interrupt_active_low,
        })
    }

    pub(crate) fn matches_devnode<H, C>(
        &self,
        instance_path: &str,
        hardware_ids: &[H],
        compatible_ids: &[C],
    ) -> bool
    where
        H: AsRef<str>,
        C: AsRef<str>,
    {
        instance_path.eq_ignore_ascii_case(self.instance_path)
            || hardware_ids
                .iter()
                .any(|id| id.as_ref().eq_ignore_ascii_case(self.hardware_id))
            || compatible_ids
                .iter()
                .any(|id| id.as_ref().eq_ignore_ascii_case(self.compatible_id))
    }
}

pub(crate) struct HostedPnpContextDescription {
    pub(crate) pci_devices: Vec<nt_pnp::PciDevice>,
    pub(crate) pci_windows: Vec<HostedPnpPciResourceDescriptor>,
    pub(crate) platform_windows: Vec<HostedPnpPlatformResourceDescriptor>,
}

impl HostedPnpContextDescription {
    fn new(
        pci_devices: Vec<nt_pnp::PciDevice>,
        pci_windows: Vec<HostedPnpPciResourceDescriptor>,
        platform_windows: Vec<HostedPnpPlatformResourceDescriptor>,
    ) -> Option<Self> {
        if pci_windows.iter().enumerate().any(|(index, window)| {
            pci_windows[..index].iter().any(|previous| {
                previous.bus == window.bus
                    && previous.dev == window.dev
                    && previous.func == window.func
            }) || !pci_devices.iter().any(|device| window.matches(device))
        }) || platform_windows.iter().enumerate().any(|(index, window)| {
            window.instance_path.is_empty()
                || window.hardware_id.is_empty()
                || window.interrupt_vector == 0
                || platform_windows[..index].iter().any(|previous| {
                    previous
                        .instance_path
                        .eq_ignore_ascii_case(window.instance_path)
                })
        }) {
            return None;
        }
        Some(Self {
            pci_devices,
            pci_windows,
            platform_windows,
        })
    }
}

#[derive(Clone, Copy)]
enum HostedPnpVaPool {
    Component,
    RootSeed,
}

struct HostedPnpVaReservation {
    pool: HostedPnpVaPool,
    span: AddressSlotReservation,
}

struct HostedPnpOwnedRootFrame {
    cap: u64,
    mapped: bool,
}

struct HostedPnpOwnedAlias {
    cap: u64,
    mapped: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpOwnerCheckpoint {
    alias_caps: usize,
    root_frames: usize,
    va_reservations: usize,
}

pub(crate) struct HostedPnpContextOwner {
    alias_caps: Vec<HostedPnpOwnedAlias>,
    root_frames: Vec<HostedPnpOwnedRootFrame>,
    va_reservations: Vec<HostedPnpVaReservation>,
}

impl HostedPnpContextOwner {
    pub(crate) const fn new() -> Self {
        Self {
            alias_caps: Vec::new(),
            root_frames: Vec::new(),
            va_reservations: Vec::new(),
        }
    }

    pub(crate) fn checkpoint(&self) -> HostedPnpOwnerCheckpoint {
        HostedPnpOwnerCheckpoint {
            alias_caps: self.alias_caps.len(),
            root_frames: self.root_frames.len(),
            va_reservations: self.va_reservations.len(),
        }
    }

    pub(crate) fn reserve_alias_caps(&mut self, count: usize) -> bool {
        self.alias_caps.try_reserve_exact(count).is_ok()
    }

    pub(crate) fn adopt_alias_cap(&mut self, cap: u64, mapped: bool) {
        debug_assert!(cap != 0);
        debug_assert!(self.alias_caps.len() < self.alias_caps.capacity());
        self.alias_caps.push(HostedPnpOwnedAlias { cap, mapped });
    }

    pub(crate) fn reserve_root_frames(&mut self, count: usize) -> bool {
        self.root_frames.try_reserve_exact(count).is_ok()
    }

    pub(crate) fn adopt_root_frame(&mut self, cap: u64, mapped: bool) {
        debug_assert!(cap != 0);
        debug_assert!(self.root_frames.len() < self.root_frames.capacity());
        self.root_frames
            .push(HostedPnpOwnedRootFrame { cap, mapped });
    }

    pub(crate) unsafe fn rollback_to(&mut self, checkpoint: HostedPnpOwnerCheckpoint) -> bool {
        let mut ok = true;
        while self.alias_caps.len() > checkpoint.alias_caps {
            let mut alias = self.alias_caps.pop().unwrap();
            if alias.mapped {
                if page_unmap_r(alias.cap) != 0 {
                    self.alias_caps.push(alias);
                    ok = false;
                    break;
                }
                alias.mapped = false;
            }
            if cnode_delete_recycle_r(alias.cap) != 0 {
                self.alias_caps.push(alias);
                ok = false;
                break;
            }
        }
        while self.root_frames.len() > checkpoint.root_frames {
            let frame = self.root_frames.pop().unwrap();
            if frame.mapped && page_unmap_r(frame.cap) != 0 {
                self.root_frames.push(frame);
                ok = false;
                break;
            }
            if cnode_delete_recycle_r(frame.cap) != 0 {
                self.root_frames.push(HostedPnpOwnedRootFrame {
                    cap: frame.cap,
                    mapped: false,
                });
                ok = false;
                break;
            }
        }
        while self.va_reservations.len() > checkpoint.va_reservations {
            let reservation = self.va_reservations.pop().unwrap();
            if let Err(reservation) = hosted_pnp_context_authority_mut().release_va(reservation) {
                self.va_reservations.push(reservation);
                ok = false;
                break;
            }
        }
        ok
    }

    unsafe fn retire(mut self) -> Result<(), Self> {
        if self.rollback_to(HostedPnpOwnerCheckpoint {
            alias_caps: 0,
            root_frames: 0,
            va_reservations: 0,
        }) {
            Ok(())
        } else {
            Err(self)
        }
    }
}

struct HostedPnpContextAuthority {
    registry: ContextRegistry<HostedPnpContextDescription, HostedPnpContextOwner>,
    component_slots: AddressSlotAllocator,
    pending_retirements: Vec<HostedPnpContextOwner>,
}

impl HostedPnpContextAuthority {
    const fn new() -> Self {
        Self {
            registry: ContextRegistry::new(),
            component_slots: AddressSlotAllocator::new(
                HOSTED_RESOURCE_COMPONENT_VA_BASE,
                HOSTED_RESOURCE_COMPONENT_VA_LIMIT,
                HOSTED_RESOURCE_WINDOW_STRIDE,
            ),
            pending_retirements: Vec::new(),
        }
    }

    fn release_va(
        &mut self,
        reservation: HostedPnpVaReservation,
    ) -> Result<(), HostedPnpVaReservation> {
        let pool = reservation.pool;
        let result = match pool {
            HostedPnpVaPool::Component => self.component_slots.release(reservation.span),
            HostedPnpVaPool::RootSeed => {
                return unsafe {
                    crate::executive_va::release_executive_device_mapping(reservation.span)
                }
                .map_err(|error| HostedPnpVaReservation {
                    pool,
                    span: error.into_reservation(),
                });
            }
        };
        result.map_err(|error| HostedPnpVaReservation {
            pool,
            span: error.into_reservation(),
        })
    }
}

static mut HOSTED_PNP_CONTEXT_AUTHORITY: HostedPnpContextAuthority =
    HostedPnpContextAuthority::new();

unsafe fn hosted_pnp_context_authority_mut() -> &'static mut HostedPnpContextAuthority {
    &mut *core::ptr::addr_of_mut!(HOSTED_PNP_CONTEXT_AUTHORITY)
}

unsafe fn reserve_hosted_pnp_slots(
    owner: &mut HostedPnpContextOwner,
    pool: HostedPnpVaPool,
    bytes: u64,
) -> Option<u64> {
    owner.va_reservations.try_reserve(1).ok()?;
    let authority = hosted_pnp_context_authority_mut();
    let reservation = match pool {
        HostedPnpVaPool::Component => authority.component_slots.allocate(bytes),
        HostedPnpVaPool::RootSeed => crate::executive_va::reserve_executive_device_mapping(bytes),
    }
    .ok()?;
    let value = reservation.address();
    owner.va_reservations.push(HostedPnpVaReservation {
        pool,
        span: reservation,
    });
    Some(value)
}

pub(crate) unsafe fn reserve_hosted_pnp_component_span(
    owner: &mut HostedPnpContextOwner,
    bytes: u64,
) -> Option<u64> {
    reserve_hosted_pnp_slots(owner, HostedPnpVaPool::Component, bytes)
}

pub(crate) unsafe fn reserve_hosted_pnp_root_seed_span(
    owner: &mut HostedPnpContextOwner,
    bytes: u64,
) -> Option<u64> {
    reserve_hosted_pnp_slots(owner, HostedPnpVaPool::RootSeed, bytes)
}

unsafe fn retain_failed_owner(owner: HostedPnpContextOwner) -> Result<(), nt_status::NtStatus> {
    let authority = hosted_pnp_context_authority_mut();
    authority.pending_retirements.push(owner);
    Err(nt_status::NtStatus::UNSUCCESSFUL)
}

unsafe fn retire_or_retain(owner: HostedPnpContextOwner) -> Result<(), nt_status::NtStatus> {
    match owner.retire() {
        Ok(()) => Ok(()),
        Err(owner) => retain_failed_owner(owner),
    }
}

pub(crate) unsafe fn retire_hosted_pnp_context_owner(
    owner: HostedPnpContextOwner,
) -> Result<(), nt_status::NtStatus> {
    retire_or_retain(owner)
}

pub(crate) unsafe fn retry_hosted_pnp_context_retirements() -> usize {
    let pending_count = hosted_pnp_context_authority_mut().pending_retirements.len();
    let mut failures = Vec::new();
    if failures.try_reserve(pending_count).is_err() {
        return pending_count;
    }
    let mut pending = core::mem::take(&mut hosted_pnp_context_authority_mut().pending_retirements);
    for owner in pending.drain(..) {
        if let Err(owner) = owner.retire() {
            failures.push(owner);
        }
    }
    hosted_pnp_context_authority_mut().pending_retirements = failures;
    hosted_pnp_context_authority_mut().pending_retirements.len()
}

pub(crate) unsafe fn publish_hosted_pnp_resource_context(
    pci_devices: Vec<nt_pnp::PciDevice>,
    pci_windows: Vec<HostedPnpPciResourceDescriptor>,
    platform_windows: Vec<HostedPnpPlatformResourceDescriptor>,
    owner: HostedPnpContextOwner,
) -> Result<ContextId, nt_status::NtStatus> {
    let _ = retry_hosted_pnp_context_retirements();
    hosted_pnp_context_authority_mut()
        .pending_retirements
        .try_reserve(1)
        .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
    let Some(description) =
        HostedPnpContextDescription::new(pci_devices, pci_windows, platform_windows)
    else {
        retire_or_retain(owner)?;
        return Err(nt_status::NtStatus::INVALID_PARAMETER);
    };
    let publication = {
        let authority = hosted_pnp_context_authority_mut();
        authority.registry.publish(description, owner)
    };
    match publication {
        Ok(outcome) => {
            if let Some(owner) = outcome.retired_owner {
                retire_or_retain(owner)?;
            }
            Ok(outcome.context)
        }
        Err(error) => {
            let (_, owner) = error.into_inner();
            retire_or_retain(owner)?;
            Err(nt_status::NtStatus::INSUFFICIENT_RESOURCES)
        }
    }
}

pub(crate) unsafe fn acquire_hosted_pnp_context_lease() -> Result<ContextLease, nt_status::NtStatus>
{
    hosted_pnp_context_authority_mut()
        .registry
        .acquire_active()
        .map_err(|error| match error {
            nt_pnp_context::AcquireError::NoActiveContext => {
                nt_status::NtStatus(0xC000_00A3u32 as i32)
            }
            nt_pnp_context::AcquireError::IdExhausted
            | nt_pnp_context::AcquireError::InsufficientResources => {
                nt_status::NtStatus::INSUFFICIENT_RESOURCES
            }
        })
}

pub(crate) unsafe fn hosted_pnp_context_description<'a>(
    lease: &'a ContextLease,
) -> Result<&'a HostedPnpContextDescription, nt_status::NtStatus> {
    hosted_pnp_context_authority_mut()
        .registry
        .description(lease)
        .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)
}

pub(crate) unsafe fn hosted_pnp_context_lease_is_live(lease: ContextLeaseIdentity) -> bool {
    hosted_pnp_context_authority_mut()
        .registry
        .description_by_identity(lease)
        .is_ok()
}

pub(crate) unsafe fn release_hosted_pnp_context_lease(
    lease: ContextLeaseIdentity,
) -> Result<(), nt_status::NtStatus> {
    let owner = {
        let authority = hosted_pnp_context_authority_mut();
        authority
            .pending_retirements
            .try_reserve(1)
            .map_err(|_| nt_status::NtStatus::INSUFFICIENT_RESOURCES)?;
        authority
            .registry
            .release(lease)
            .map_err(|_| nt_status::NtStatus::INVALID_DEVICE_REQUEST)?
    };
    if let Some(owner) = owner {
        retire_or_retain(owner)?;
    }
    Ok(())
}
