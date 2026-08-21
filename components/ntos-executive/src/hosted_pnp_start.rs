use crate::*;
use alloc::vec::Vec;

static mut HOSTED_PNP_PCI_DEVICES: Option<Vec<nt_pnp::PciDevice>> = None;
static mut HOSTED_PNP_PCI_WINDOWS: Option<Vec<HostedPnpPciResourceWindow>> = None;
static mut HOSTED_PNP_ROOT_WINDOWS: Option<Vec<HostedPnpRootResourceWindow>> = None;

const STATUS_DEVICE_NOT_READY: nt_status::NtStatus = nt_status::NtStatus(0xC000_00A3u32 as i32);
const HOSTED_RESOURCE_WINDOW_STRIDE: u64 = 0x20_0000;
const HOSTED_RESOURCE_COMPONENT_VA_BASE: u64 = 0x0000_0100_1600_0000;
const HOSTED_RESOURCE_COMPONENT_VA_LIMIT: u64 = crate::allocator::HEAP_BASE as u64;
const HOSTED_ROOT_SEED_VA_BASE: u64 = 0x0000_0100_1100_0000;
const HOSTED_ROOT_SEED_VA_LIMIT: u64 = HOSTED_RESOURCE_COMPONENT_VA_BASE;
const HOSTED_ROOT_DMA_LOGICAL_BASE: u64 = 0x0010_0000;

const _: () = assert!(HOSTED_RESOURCE_COMPONENT_VA_BASE & 0x1F_FFFF == 0);
const _: () = assert!(
    HOSTED_RESOURCE_COMPONENT_VA_BASE + HOSTED_RESOURCE_WINDOW_STRIDE
        <= HOSTED_RESOURCE_COMPONENT_VA_LIMIT
);
const _: () = assert!(HOSTED_ROOT_SEED_VA_BASE & 0x1F_FFFF == 0);
const _: () =
    assert!(HOSTED_ROOT_SEED_VA_BASE + HOSTED_RESOURCE_WINDOW_STRIDE <= HOSTED_ROOT_SEED_VA_LIMIT);

#[derive(Default)]
pub(crate) struct HostedPnpResourceVaAllocator {
    component_slots: u64,
    root_seed_slots: u64,
    root_dma_logical_slots: u64,
}

impl HostedPnpResourceVaAllocator {
    pub(crate) fn allocate_component_span(&mut self, bytes: u64) -> Option<u64> {
        let slots = hosted_window_slots_for_bytes(bytes)?;
        let va = hosted_window_span_va(
            HOSTED_RESOURCE_COMPONENT_VA_BASE,
            HOSTED_RESOURCE_COMPONENT_VA_LIMIT,
            self.component_slots,
            slots,
        )?;
        self.component_slots = self.component_slots.checked_add(slots)?;
        Some(va)
    }

    pub(crate) fn allocate_root_seed_window(&mut self) -> Option<u64> {
        let va = hosted_window_slot_va(
            HOSTED_ROOT_SEED_VA_BASE,
            HOSTED_ROOT_SEED_VA_LIMIT,
            self.root_seed_slots,
        )?;
        self.root_seed_slots = self.root_seed_slots.checked_add(1)?;
        Some(va)
    }

    pub(crate) fn allocate_root_seed_span(&mut self, bytes: u64) -> Option<u64> {
        let slots = hosted_window_slots_for_bytes(bytes)?;
        let va = hosted_window_span_va(
            HOSTED_ROOT_SEED_VA_BASE,
            HOSTED_ROOT_SEED_VA_LIMIT,
            self.root_seed_slots,
            slots,
        )?;
        self.root_seed_slots = self.root_seed_slots.checked_add(slots)?;
        Some(va)
    }

    pub(crate) fn allocate_root_dma_logical(&mut self) -> Option<u64> {
        let logical = HOSTED_ROOT_DMA_LOGICAL_BASE.checked_add(
            self.root_dma_logical_slots
                .checked_mul(HOSTED_RESOURCE_WINDOW_STRIDE)?,
        )?;
        self.root_dma_logical_slots = self.root_dma_logical_slots.checked_add(1)?;
        Some(logical)
    }
}

fn hosted_window_slot_va(base: u64, limit: u64, slot: u64) -> Option<u64> {
    let va = base.checked_add(slot.checked_mul(HOSTED_RESOURCE_WINDOW_STRIDE)?)?;
    let end = va.checked_add(HOSTED_RESOURCE_WINDOW_STRIDE)?;
    (end <= limit).then_some(va)
}

fn hosted_window_slots_for_bytes(bytes: u64) -> Option<u64> {
    let bytes = bytes.max(1);
    Some(bytes.checked_add(HOSTED_RESOURCE_WINDOW_STRIDE - 1)? / HOSTED_RESOURCE_WINDOW_STRIDE)
}

fn hosted_window_span_va(base: u64, limit: u64, slot: u64, slots: u64) -> Option<u64> {
    if slots == 0 {
        return None;
    }
    let va = base.checked_add(slot.checked_mul(HOSTED_RESOURCE_WINDOW_STRIDE)?)?;
    let len = slots.checked_mul(HOSTED_RESOURCE_WINDOW_STRIDE)?;
    let end = va.checked_add(len)?;
    (end <= limit).then_some(va)
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpPciResourceWindow {
    pub(crate) bus: u8,
    pub(crate) dev: u8,
    pub(crate) func: u8,
    pub(crate) mmio_phys: u64,
    pub(crate) mmio_frame_base: u64,
    pub(crate) mmio_pages: u64,
    pub(crate) mmio_map_pages: u64,
    pub(crate) mmio_va: u64,
    pub(crate) mmio_seed_va: u64,
    pub(crate) interrupt_vector: u32,
    pub(crate) interrupt_latched: bool,
    pub(crate) dma_frame_base: u64,
    pub(crate) dma_pages: u64,
    pub(crate) dma_va: u64,
    pub(crate) dma_seed_va: u64,
    pub(crate) dma_logical: u64,
    pub(crate) dma_len: u64,
}

impl HostedPnpPciResourceWindow {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        bus: u8,
        dev: u8,
        func: u8,
        mmio_phys: u64,
        mmio_frame_base: u64,
        mmio_pages: u64,
        mmio_map_pages: u64,
        mmio_va: u64,
        mmio_seed_va: u64,
        interrupt_vector: u32,
        interrupt_latched: bool,
        dma_frame_base: u64,
        dma_pages: u64,
        dma_va: u64,
        dma_seed_va: u64,
        dma_logical: u64,
        dma_len: u64,
    ) -> Option<Self> {
        let has_mmio = mmio_phys != 0
            || mmio_frame_base != 0
            || mmio_pages != 0
            || mmio_map_pages != 0
            || mmio_va != 0
            || mmio_seed_va != 0;
        if has_mmio
            && (mmio_phys == 0
                || mmio_frame_base == 0
                || mmio_pages == 0
                || mmio_map_pages == 0
                || mmio_va == 0
                || mmio_seed_va == 0
                || mmio_map_pages > mmio_pages)
        {
            return None;
        }
        let has_dma = dma_frame_base != 0
            || dma_pages != 0
            || dma_va != 0
            || dma_seed_va != 0
            || dma_logical != 0
            || dma_len != 0;
        if (!has_dma && dma_va != 0)
            || (has_dma
                && (dma_frame_base == 0
                    || dma_pages == 0
                    || dma_va == 0
                    || dma_seed_va == 0
                    || dma_logical == 0
                    || dma_len == 0))
        {
            return None;
        }
        Some(Self {
            bus,
            dev,
            func,
            mmio_phys,
            mmio_frame_base,
            mmio_pages,
            mmio_map_pages,
            mmio_va,
            mmio_seed_va,
            interrupt_vector,
            interrupt_latched,
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

    pub(crate) fn granted_mmio_len(&self) -> u32 {
        self.mmio_pages.saturating_mul(0x1000).min(u32::MAX as u64) as u32
    }

    pub(crate) fn mapped_mmio_len(&self) -> u32 {
        self.mmio_map_pages
            .saturating_mul(0x1000)
            .min(u32::MAX as u64) as u32
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

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpRootResourceWindow {
    pub(crate) device_id: &'static str,
    pub(crate) mmio_phys: u64,
    pub(crate) mmio_frame_base: u64,
    pub(crate) mmio_pages: u64,
    pub(crate) mmio_va: u64,
    pub(crate) mmio_seed_va: u64,
    pub(crate) interrupt_vector: u32,
    pub(crate) interrupt_latched: bool,
    pub(crate) dma_frame_base: u64,
    pub(crate) dma_pages: u64,
    pub(crate) dma_va: u64,
    pub(crate) dma_logical: u64,
    pub(crate) dma_len: u64,
}

impl HostedPnpRootResourceWindow {
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        profile: &nt_pnp::RootBusResourceProfile,
        mmio_frame_base: u64,
        mmio_pages: u64,
        mmio_va: u64,
        mmio_seed_va: u64,
        interrupt_vector: u32,
        interrupt_latched: bool,
        dma_frame_base: u64,
        dma_pages: u64,
        dma_va: u64,
        dma_logical: u64,
        dma_len: u64,
    ) -> Option<Self> {
        if mmio_va == 0 || mmio_seed_va == 0 || dma_va == 0 || dma_logical == 0 {
            return None;
        }
        Some(Self {
            device_id: profile.device_id,
            mmio_phys: profile.mmio_phys,
            mmio_frame_base,
            mmio_pages,
            mmio_va,
            mmio_seed_va,
            interrupt_vector,
            interrupt_latched,
            dma_frame_base,
            dma_pages,
            dma_va,
            dma_logical,
            dma_len,
        })
    }

    pub(crate) fn matches_profile(&self, profile: &nt_pnp::RootBusResourceProfile) -> bool {
        self.device_id.eq_ignore_ascii_case(profile.device_id)
    }

    pub(crate) fn granted_mmio_len(&self) -> u32 {
        self.mmio_pages.saturating_mul(0x1000).min(u32::MAX as u64) as u32
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum HostedPnpStartTrace {
    BootService,
    DemandStart,
    HardwareProof,
}

#[derive(Clone, Copy)]
pub(crate) struct HostedPnpStartOptions {
    pub(crate) trace: HostedPnpStartTrace,
    pub(crate) inject_test_interrupt: bool,
}

impl HostedPnpStartOptions {
    pub(crate) const fn boot_service() -> Self {
        Self {
            trace: HostedPnpStartTrace::BootService,
            inject_test_interrupt: false,
        }
    }

    pub(crate) const fn demand_start() -> Self {
        Self {
            trace: HostedPnpStartTrace::DemandStart,
            inject_test_interrupt: false,
        }
    }

    pub(crate) const fn hardware_proof() -> Self {
        Self {
            trace: HostedPnpStartTrace::HardwareProof,
            inject_test_interrupt: true,
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct HostedPnpStartReport {
    pub(crate) driver_ready_for_pnp: bool,
    pub(crate) add_device: bool,
    pub(crate) start_ok: bool,
    pub(crate) resource_granted: bool,
    pub(crate) mmio_mapped: bool,
    pub(crate) interrupt_connected: bool,
    pub(crate) interrupt_delivered: bool,
    pub(crate) interrupt_acknowledged: bool,
    pub(crate) dpc_delivered: bool,
    pub(crate) dma_adapter: bool,
    pub(crate) dma_common: bool,
    pub(crate) dma_packet_descriptors: bool,
    pub(crate) io_port_out32: bool,
    pub(crate) root_started: bool,
    pub(crate) video_route_published: bool,
    pub(crate) attempted: u64,
    pub(crate) add_device_count: u64,
    pub(crate) started: u64,
    pub(crate) resource_granted_count: u64,
    pub(crate) mmio_mapped_count: u64,
    pub(crate) interrupt_connected_count: u64,
    pub(crate) interrupt_delivered_count: u64,
    pub(crate) interrupt_acknowledged_count: u64,
    pub(crate) dpc_delivered_count: u64,
    pub(crate) dma_adapter_count: u64,
    pub(crate) dma_common_count: u64,
    pub(crate) dma_packet_descriptor_count: u64,
    pub(crate) dma_packet_descriptor_common_count: u64,
    pub(crate) dma_packet_descriptor_mapping_count: u64,
    pub(crate) dma_packet_descriptor_completed_mapping_count: u64,
    pub(crate) dma_device_tx_completion_count: u64,
    pub(crate) dma_device_rx_completion_count: u64,
    pub(crate) dma_device_interrupt_cause_count: u64,
    pub(crate) dma_device_model_failure_count: u64,
    pub(crate) dma_tx_window_observation_count: u64,
    pub(crate) dma_tx_window_enabled_count: u64,
    pub(crate) dma_tx_window_ring_ready_count: u64,
    pub(crate) dma_tx_window_posted_count: u64,
    pub(crate) dma_tx_window_idle_count: u64,
    pub(crate) dma_tx_descriptor_candidate_count: u64,
    pub(crate) dma_tx_descriptor_map_candidate_count: u64,
    pub(crate) dma_tx_descriptor_done_seen_count: u64,
    pub(crate) dma_tx_last_candidate_address: u64,
    pub(crate) dma_tx_last_candidate_len: u64,
    pub(crate) dma_tx_last_candidate_status: u64,
    pub(crate) dma_tx_last_head: u64,
    pub(crate) dma_tx_last_tail: u64,
    pub(crate) io_port_out32_count: u64,
    pub(crate) root_started_count: u64,
    pub(crate) video_route_attempted_count: u64,
    pub(crate) video_route_published_count: u64,
    pub(crate) first_error: u32,
}

struct HostedPnpDevnodeStart<'a, H, C> {
    instance_id: &'a str,
    driver_key: Option<&'a str>,
    linkage_export: Option<&'a str>,
    hardware_ids: &'a [H],
    compatible_ids: &'a [C],
}

pub(crate) unsafe fn publish_hosted_pnp_resource_context(
    pci_devices: &[nt_pnp::PciDevice],
    pci_windows: &[HostedPnpPciResourceWindow],
    root_windows: &[HostedPnpRootResourceWindow],
) {
    let new_devices = Vec::from(pci_devices);
    let old = core::ptr::replace(
        core::ptr::addr_of_mut!(HOSTED_PNP_PCI_DEVICES),
        Some(new_devices),
    );
    drop(old);
    let new_windows = Vec::from(pci_windows);
    let old = core::ptr::replace(
        core::ptr::addr_of_mut!(HOSTED_PNP_PCI_WINDOWS),
        Some(new_windows),
    );
    drop(old);
    let new_root_windows = Vec::from(root_windows);
    let old = core::ptr::replace(
        core::ptr::addr_of_mut!(HOSTED_PNP_ROOT_WINDOWS),
        Some(new_root_windows),
    );
    drop(old);
}

pub(crate) unsafe fn start_inline_driver_service_devnodes(
    dc: &driver_launch::DriverComponent,
    spec: &InlineDriverLaunchSpec,
    plan: &InlineDriverLaunchPlan,
    options: HostedPnpStartOptions,
) -> HostedPnpStartReport {
    let mut report = HostedPnpStartReport {
        driver_ready_for_pnp: (dc.verdict & V_ENTERED) != 0
            && (dc.add_device != 0
                || driver_launch::hosted_driver_video_port_initialized(dc.driver_id)),
        ..HostedPnpStartReport::default()
    };
    let class_guid = if spec.class_guid_present {
        Some(spec.class_guid.as_str())
    } else {
        None
    };
    for devnode in plan.devnodes_for(spec) {
        let hardware_refs = plan.hardware_ids_for(devnode);
        let compatible_refs = plan.compatible_ids_for(devnode);
        let driver_key = if devnode.driver_key_present {
            Some(devnode.driver_key.as_str())
        } else {
            None
        };
        let linkage_export = if devnode.linkage_export_present {
            Some(devnode.linkage_export.as_str())
        } else {
            None
        };
        start_one_devnode(
            dc,
            spec.service_name.as_str(),
            class_guid,
            HostedPnpDevnodeStart {
                instance_id: devnode.instance_id.as_str(),
                driver_key,
                linkage_export,
                hardware_ids: hardware_refs,
                compatible_ids: compatible_refs,
            },
            options,
            &mut report,
        );
    }
    report
}

pub(crate) unsafe fn start_owned_driver_service_devnodes(
    dc: &driver_launch::DriverComponent,
    spec: &DriverServiceLaunchSpec,
    options: HostedPnpStartOptions,
) -> Result<HostedPnpStartReport, nt_status::NtStatus> {
    let mut report = HostedPnpStartReport {
        driver_ready_for_pnp: (dc.verdict & V_ENTERED) != 0
            && (dc.add_device != 0
                || driver_launch::hosted_driver_video_port_initialized(dc.driver_id)),
        ..HostedPnpStartReport::default()
    };
    let class_guid = spec.class_guid.as_deref();
    for devnode in &spec.devnodes {
        start_one_devnode(
            dc,
            &spec.service_name,
            class_guid,
            HostedPnpDevnodeStart {
                instance_id: &devnode.instance_id,
                driver_key: devnode.driver_key.as_deref(),
                linkage_export: devnode.linkage_export.as_deref(),
                hardware_ids: &devnode.hardware_ids,
                compatible_ids: &devnode.compatible_ids,
            },
            options,
            &mut report,
        );
    }
    if report.first_error != 0 {
        Err(nt_status::NtStatus(report.first_error as i32))
    } else if report.attempted != report.started {
        Err(nt_status::NtStatus::UNSUCCESSFUL)
    } else {
        Ok(report)
    }
}

unsafe fn start_one_devnode<H, C>(
    dc: &driver_launch::DriverComponent,
    service_name: &str,
    class_guid: Option<&str>,
    devnode: HostedPnpDevnodeStart<'_, H, C>,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) where
    H: AsRef<str>,
    C: AsRef<str>,
{
    report.attempted += 1;
    match driver_launch::call_add_device_for_driver(
        dc.driver_id,
        class_guid,
        devnode.driver_key,
        devnode.linkage_export,
        devnode.instance_id,
        devnode.hardware_ids,
        devnode.compatible_ids,
    ) {
        Ok(device_id) => {
            report.add_device = true;
            report.add_device_count += 1;
            print_add_device_success(options.trace, service_name, devnode.instance_id, device_id);
            let start_status = match grant_current_hosted_devnode_resources(
                device_id,
                devnode.instance_id,
                devnode.hardware_ids,
                devnode.compatible_ids,
            ) {
                Ok(Some(grant)) => {
                    print_hosted_devnode_grant(
                        service_name.as_bytes(),
                        devnode.instance_id.as_bytes(),
                        &grant,
                    );
                    driver_launch::start_hosted_device(device_id, &grant.resource_list)
                }
                Ok(None) => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
                Err(status) => {
                    print_resource_grant_failure(
                        options.trace,
                        service_name,
                        devnode.instance_id,
                        status,
                    );
                    Err(status)
                }
            };
            let start_status_raw = match start_status {
                Ok(()) => {
                    report.start_ok = true;
                    report.started += 1;
                    0
                }
                Err(status) => {
                    remember_error(report, status);
                    status.raw() as u32
                }
            };
            print_start_status(
                options.trace,
                service_name,
                devnode.instance_id,
                start_status_raw,
            );
            if options.inject_test_interrupt && start_status_raw == 0 {
                inject_proof_interrupt(
                    device_id,
                    options.trace,
                    service_name,
                    devnode.instance_id,
                    report,
                );
            }
            collect_hardware_evidence(
                device_id,
                options.trace,
                service_name,
                devnode.instance_id,
                start_status_raw,
                report,
            );
            if start_status_raw == 0 {
                try_publish_hosted_video_route(
                    device_id,
                    service_name,
                    devnode.instance_id,
                    report,
                );
            }
        }
        Err(status) => {
            remember_error(report, status);
            print_add_device_failure(options.trace, service_name, devnode.instance_id, status);
        }
    }
}

unsafe fn grant_current_hosted_devnode_resources<H, C>(
    device_id: u64,
    instance_id: &str,
    hardware_refs: &[H],
    compatible_refs: &[C],
) -> Result<Option<HostedDevnodeGrant>, nt_status::NtStatus>
where
    H: AsRef<str>,
    C: AsRef<str>,
{
    let devices = (*core::ptr::addr_of!(HOSTED_PNP_PCI_DEVICES))
        .as_ref()
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    let pci_windows = (*core::ptr::addr_of!(HOSTED_PNP_PCI_WINDOWS))
        .as_ref()
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    let root_windows = (*core::ptr::addr_of!(HOSTED_PNP_ROOT_WINDOWS))
        .as_ref()
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    grant_hosted_devnode_resources(
        device_id,
        instance_id,
        hardware_refs,
        compatible_refs,
        devices.as_slice(),
        pci_windows.as_slice(),
        root_windows.as_slice(),
    )
}

fn remember_error(report: &mut HostedPnpStartReport, status: nt_status::NtStatus) {
    if report.first_error == 0 {
        report.first_error = status.raw() as u32;
    }
}

fn hosted_display_service_registry_path(service_name: &str) -> Option<Vec<u8>> {
    if service_name.is_empty() || !service_name.as_bytes().iter().all(|byte| byte.is_ascii()) {
        return None;
    }
    let prefix = b"\\Registry\\Machine\\System\\CurrentControlSet\\Services\\";
    let suffix = b"\\Device0";
    let len = prefix
        .len()
        .checked_add(service_name.len())?
        .checked_add(suffix.len())?;
    let mut path = Vec::new();
    path.try_reserve_exact(len).ok()?;
    path.extend_from_slice(prefix);
    path.extend_from_slice(service_name.as_bytes());
    path.extend_from_slice(suffix);
    Some(path)
}

unsafe fn try_publish_hosted_video_route(
    device_id: u64,
    service_name: &str,
    instance_id: &str,
    report: &mut HostedPnpStartReport,
) {
    if !driver_launch::hosted_device_video_port_initialized(device_id) {
        return;
    }
    report.video_route_attempted_count += 1;
    let Some(_route) = driver_launch::hosted_video_route_info(device_id) else {
        remember_error(report, nt_status::NtStatus::INVALID_DEVICE_REQUEST);
        print_hosted_video_route_published(service_name, instance_id, device_id, false);
        return;
    };
    let Some(service_registry_path) = hosted_display_service_registry_path(service_name) else {
        remember_error(report, nt_status::NtStatus::INVALID_PARAMETER);
        print_hosted_video_route_published(service_name, instance_id, device_id, false);
        return;
    };
    let published = crate::video_device::publish_hosted_video_device_route(
        &crate::video_device::HostedVideoDeviceRegistration {
            device_id,
            service_registry_path: service_registry_path.as_slice(),
            allocate_projection: crate::win32k_subsystem::pool_alloc_export,
        },
    );
    report.video_route_published |= published;
    if published {
        report.video_route_published_count += 1;
    } else {
        remember_error(report, nt_status::NtStatus::UNSUCCESSFUL);
    }
    print_hosted_video_route_published(service_name, instance_id, device_id, published);
}

unsafe fn inject_proof_interrupt(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    report: &mut HostedPnpStartReport,
) {
    if let Some(evidence) = driver_launch::hosted_hardware_evidence(device_id) {
        if evidence.interrupt_connected()
            && (evidence.mmio_mapped() || evidence.io_port_out32_serviced())
        {
            let ack_window = root_window_for_evidence(evidence);
            if let Some(window) = ack_window {
                core::ptr::write_volatile(
                    (window.mmio_seed_va + ROOT_DMA_PROOF_INTERRUPT_ACK_OFFSET) as *mut u32,
                    0,
                );
                core::ptr::write_volatile(
                    (window.mmio_seed_va + ROOT_DMA_PROOF_INTERRUPT_STATUS_OFFSET) as *mut u32,
                    1,
                );
            }
            match driver_launch::inject_hosted_device_interrupt(device_id) {
                Ok(delivery) => {
                    let ack = ack_window
                        .map(|window| {
                            core::ptr::read_volatile(
                                (window.mmio_seed_va + ROOT_DMA_PROOF_INTERRUPT_ACK_OFFSET)
                                    as *const u32,
                            )
                        })
                        .unwrap_or(0);
                    if ack_window.is_some() {
                        report.interrupt_acknowledged |= ack == 1;
                        if ack == 1 {
                            report.interrupt_acknowledged_count += 1;
                        }
                    }
                    match driver_launch::redrive_hosted_device_tx_interrupt(device_id) {
                        Ok(_) => {}
                        Err(status) => {
                            print_interrupt_delivery_failure(trace, status);
                            remember_error(report, status);
                        }
                    }
                    print_interrupt_delivery(trace, service_name, instance_id, delivery, ack);
                }
                Err(status) => {
                    print_interrupt_delivery_failure(trace, status);
                    remember_error(report, status);
                }
            }
        }
    }
}

unsafe fn root_window_for_evidence(
    evidence: driver_launch::HostedHardwareEvidence,
) -> Option<HostedPnpRootResourceWindow> {
    (*core::ptr::addr_of!(HOSTED_PNP_ROOT_WINDOWS))
        .as_ref()?
        .iter()
        .copied()
        .find(|window| {
            window.mmio_phys == evidence.resource_mmio_phys
                && window.dma_va == evidence.dma_common_va
                && window.dma_logical == evidence.dma_common_logical
        })
}

fn collect_hardware_evidence(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    report: &mut HostedPnpStartReport,
) {
    if let Err(status) = unsafe { driver_launch::redrive_hosted_device_tx_interrupt(device_id) } {
        remember_error(report, status);
    }
    if let Some(evidence) = driver_launch::hosted_hardware_evidence(device_id) {
        if evidence.resource_granted() {
            report.resource_granted = true;
            report.resource_granted_count += 1;
            report.mmio_mapped |= evidence.mmio_mapped();
            report.interrupt_connected |= evidence.interrupt_connected();
            report.interrupt_delivered |= evidence.interrupt_delivered();
            report.dpc_delivered |= evidence.dpc_delivered();
            report.dma_adapter |= evidence.dma_adapter_created();
            report.dma_common |= evidence.dma_common_allocated();
            report.dma_packet_descriptors |= evidence.dma_packet_descriptors_observed();
            report.io_port_out32 |= evidence.io_port_out32_serviced();
            report.root_started |= evidence.root_pdo_started;
            if evidence.mmio_mapped() {
                report.mmio_mapped_count += 1;
            }
            if evidence.interrupt_connected() {
                report.interrupt_connected_count += 1;
            }
            if evidence.interrupt_delivered() {
                report.interrupt_delivered_count += 1;
            }
            if evidence.dpc_delivered() {
                report.dpc_delivered_count += 1;
            }
            if evidence.dma_adapter_created() {
                report.dma_adapter_count += 1;
            }
            if evidence.dma_common_allocated() {
                report.dma_common_count += 1;
            }
            if evidence.dma_packet_descriptors_observed() {
                report.dma_packet_descriptor_count += 1;
            }
            report.dma_packet_descriptor_common_count = report
                .dma_packet_descriptor_common_count
                .saturating_add(evidence.dma_descriptor_common_buffers);
            report.dma_packet_descriptor_mapping_count = report
                .dma_packet_descriptor_mapping_count
                .saturating_add(evidence.dma_descriptor_transfer_mappings);
            report.dma_packet_descriptor_completed_mapping_count = report
                .dma_packet_descriptor_completed_mapping_count
                .saturating_add(evidence.dma_descriptor_completed_transfer_mappings);
            report.dma_device_tx_completion_count = report
                .dma_device_tx_completion_count
                .saturating_add(evidence.dma_device_tx_completions);
            report.dma_device_rx_completion_count = report
                .dma_device_rx_completion_count
                .saturating_add(evidence.dma_device_rx_completions);
            report.dma_device_interrupt_cause_count = report
                .dma_device_interrupt_cause_count
                .saturating_add(evidence.dma_device_interrupt_causes);
            report.dma_device_model_failure_count = report
                .dma_device_model_failure_count
                .saturating_add(evidence.dma_device_model_failures);
            report.dma_tx_window_observation_count = report
                .dma_tx_window_observation_count
                .saturating_add(evidence.dma_tx_window_observations);
            report.dma_tx_window_enabled_count = report
                .dma_tx_window_enabled_count
                .saturating_add(evidence.dma_tx_window_enabled);
            report.dma_tx_window_ring_ready_count = report
                .dma_tx_window_ring_ready_count
                .saturating_add(evidence.dma_tx_window_ring_ready);
            report.dma_tx_window_posted_count = report
                .dma_tx_window_posted_count
                .saturating_add(evidence.dma_tx_window_posted);
            report.dma_tx_window_idle_count = report
                .dma_tx_window_idle_count
                .saturating_add(evidence.dma_tx_window_idle);
            report.dma_tx_descriptor_candidate_count = report
                .dma_tx_descriptor_candidate_count
                .saturating_add(evidence.dma_tx_descriptor_candidates);
            report.dma_tx_descriptor_map_candidate_count = report
                .dma_tx_descriptor_map_candidate_count
                .saturating_add(evidence.dma_tx_descriptor_map_candidates);
            report.dma_tx_descriptor_done_seen_count = report
                .dma_tx_descriptor_done_seen_count
                .saturating_add(evidence.dma_tx_descriptor_done_seen);
            if evidence.dma_tx_descriptor_candidates != 0
                || evidence.dma_tx_descriptor_done_seen != 0
            {
                report.dma_tx_last_candidate_address = evidence.dma_tx_last_candidate_address;
                report.dma_tx_last_candidate_len = evidence.dma_tx_last_candidate_len;
                report.dma_tx_last_candidate_status = evidence.dma_tx_last_candidate_status;
            }
            if evidence.dma_tx_window_observations != 0 {
                report.dma_tx_last_head = evidence.dma_tx_last_head;
                report.dma_tx_last_tail = evidence.dma_tx_last_tail;
            }
            if evidence.io_port_out32_serviced() {
                report.io_port_out32_count += 1;
            }
            if evidence.root_pdo_started {
                report.root_started_count += 1;
            }
        }
        print_hardware_evidence(trace, service_name, instance_id, start_status_raw, evidence);
    }
}

fn print_add_device_success(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    device_id: u64,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware AddDevice service="
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand AddDevice service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] AddDevice service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" device_id=");
    print_u64(device_id);
    print_str(b"\n");
}

fn print_add_device_failure(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: nt_status::NtStatus,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware AddDevice failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand AddDevice failed status=0x",
        HostedPnpStartTrace::BootService => b"[driver-launch] AddDevice failed status=0x",
    });
    print_hex(status.raw() as u32);
    print_str(b" service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b"\n");
}

fn print_hosted_video_route_published(
    service_name: &str,
    instance_id: &str,
    device_id: u64,
    published: bool,
) {
    print_str(b"[video-device] hosted route service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" device_id=");
    print_u64(device_id);
    print_str(b" published=");
    print_u64(published as u64);
    print_str(b"\n");
}

fn print_resource_grant_failure(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: nt_status::NtStatus,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware resource grant failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => {
            b"[driver-launch] demand resource grant failed status=0x"
        }
        HostedPnpStartTrace::BootService => b"[driver-launch] resource grant failed status=0x",
    });
    print_hex(status.raw() as u32);
    print_str(b" service=");
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b"\n");
}

fn print_start_status(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    status: u32,
) {
    if status == 0 {
        print_str(match trace {
            HostedPnpStartTrace::HardwareProof => {
                b"[driver-launch] generic hardware StartDevice service="
            }
            HostedPnpStartTrace::DemandStart => b"[driver-launch] demand StartDevice service=",
            HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice service=",
        });
    } else {
        print_str(match trace {
            HostedPnpStartTrace::HardwareProof => {
                b"[driver-launch] generic hardware StartDevice failed service="
            }
            HostedPnpStartTrace::DemandStart => {
                b"[driver-launch] demand StartDevice failed service="
            }
            HostedPnpStartTrace::BootService => b"[driver-launch] StartDevice failed service=",
        });
    }
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" status=");
    print_hex(status);
    print_str(b"\n");
}

fn print_interrupt_delivery(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    delivery: driver_launch::HostedInterruptDelivery,
    ack: u32,
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware interrupt delivery service="
        }
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand interrupt delivery service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] interrupt delivery service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" id=");
    print_u64(delivery.interrupt_id);
    print_str(b" vector=");
    print_u64(delivery.vector as u64);
    print_str(b" claimed=");
    print_u64(delivery.claimed as u64);
    print_str(b" ack=");
    print_u64(ack as u64);
    print_str(b"\n");
}

fn print_interrupt_delivery_failure(trace: HostedPnpStartTrace, status: nt_status::NtStatus) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => {
            b"[driver-launch] generic hardware interrupt delivery failed status=0x"
        }
        HostedPnpStartTrace::DemandStart => {
            b"[driver-launch] demand interrupt delivery failed status=0x"
        }
        HostedPnpStartTrace::BootService => b"[driver-launch] interrupt delivery failed status=0x",
    });
    print_hex(status.raw() as u32);
    print_str(b"\n");
}

fn print_hardware_evidence(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    evidence: driver_launch::HostedHardwareEvidence,
) {
    if trace == HostedPnpStartTrace::HardwareProof {
        print_str(b"[driver-launch] generic hardware evidence service=");
        print_str(service_name.as_bytes());
        print_str(b" devnode=");
        print_str(instance_id.as_bytes());
        print_str(b" start=");
        print_hex(start_status_raw);
        print_str(b" mmio=");
        print_u64(evidence.mmio_mapped() as u64);
        print_str(b" irq=");
        print_u64(evidence.interrupt_connected() as u64);
        print_str(b"/");
        print_u64(evidence.interrupt_delivered() as u64);
        print_str(b" dpc=");
        print_u64(evidence.dpc_delivered() as u64);
        print_str(b" dma=");
        print_u64(evidence.dma_adapter_created() as u64);
        print_str(b"/");
        print_u64(evidence.dma_common_allocated() as u64);
        print_str(b" desc=");
        print_u64(evidence.dma_packet_descriptors_observed() as u64);
        print_str(b" txrx=");
        print_u64(evidence.dma_device_tx_completions);
        print_str(b"/");
        print_u64(evidence.dma_device_rx_completions);
        print_str(b" pbrx=");
        print_u64(evidence.dma_device_post_bind_rx_attempts);
        print_str(b"/");
        print_u64(evidence.dma_device_post_bind_rx_deliveries);
        print_str(b"/");
        print_u64(evidence.dma_device_post_bind_rx_failures);
        print_str(b" io=");
        print_u64(evidence.io_port_out32_serviced() as u64);
        print_str(b" video=");
        print_u64(evidence.video_initialized as u64);
        print_str(b"/");
        print_u64(evidence.video_find_adapter_calls);
        print_str(b" root=");
        print_u64(evidence.root_pdo_started as u64);
        print_str(b"\n");
        return;
    }

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"bus");
    print_str(b" start=");
    print_hex(start_status_raw);
    print_str(b" mmio=");
    print_u64(evidence.mmio_mapped() as u64);
    print_str(b" mmio_len=");
    print_u64(evidence.resource_mmio_len);
    print_str(b" mmio_map_len=");
    print_u64(evidence.resource_mmio_map_len);
    print_str(b" root_started=");
    print_u64(evidence.root_pdo_started as u64);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"irq");
    print_str(b" int=");
    print_u64(evidence.interrupt_connected() as u64);
    print_str(b" int_ctx=");
    print_u64((evidence.interrupt_context != 0) as u64);
    print_str(b" int_delivered=");
    print_u64(evidence.interrupt_delivered() as u64);
    print_str(b" int_count=");
    print_u64(evidence.interrupt_deliveries);
    print_str(b" dpc=");
    print_u64(evidence.dpc_delivered() as u64);
    print_str(b" dpc_count=");
    print_u64(evidence.dpc_deliveries);
    print_str(b" dpc_drops=");
    print_u64(evidence.dpc_drops);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"dma");
    print_str(b" dma_adapter=");
    print_u64(evidence.dma_adapter_created() as u64);
    print_str(b" dma_common=");
    print_u64(evidence.dma_common_allocated() as u64);
    print_str(b" dma_len=");
    print_u64(evidence.dma_common_len);
    print_str(b" dma_desc=");
    print_u64(evidence.dma_packet_descriptors_observed() as u64);
    print_str(b" dma_desc_rings=");
    print_u64(evidence.dma_descriptor_rings);
    print_str(b" dma_desc_addr/ok=");
    print_u64(evidence.dma_descriptor_addresses);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_decodable);
    print_str(b" dma_desc_common/map=");
    print_u64(evidence.dma_descriptor_common_buffers);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_transfer_mappings);
    print_str(b" dma_desc_len/done=");
    print_u64(evidence.dma_descriptor_lengths);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_completed);
    print_str(b" dma_desc_done_common/map=");
    print_u64(evidence.dma_descriptor_completed_common_buffers);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_completed_transfer_mappings);
    print_str(b" dma_desc_bad/fail=");
    print_u64(evidence.dma_descriptor_malformed);
    print_str(b"/");
    print_u64(evidence.dma_descriptor_observation_failures);
    print_str(b" dma_dev_tx/rx=");
    print_u64(evidence.dma_device_tx_completions);
    print_str(b"/");
    print_u64(evidence.dma_device_rx_completions);
    print_str(b" dma_dev_cause/fail=");
    print_u64(evidence.dma_device_interrupt_causes);
    print_str(b"/");
    print_u64(evidence.dma_device_model_failures);
    print_str(b" dma_post_bind_rx=");
    print_u64(evidence.dma_device_post_bind_rx_attempts);
    print_str(b"/");
    print_u64(evidence.dma_device_post_bind_rx_deliveries);
    print_str(b"/");
    print_u64(evidence.dma_device_post_bind_rx_failures);
    print_str(b" dma_tx_window=");
    print_u64(evidence.dma_tx_window_observations);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_enabled);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_ring_ready);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_posted);
    print_str(b"/");
    print_u64(evidence.dma_tx_window_idle);
    print_str(b" dma_tx_head/tail=");
    print_u64(evidence.dma_tx_last_head);
    print_str(b"/");
    print_u64(evidence.dma_tx_last_tail);
    print_str(b" dma_tx_candidates/map/done=");
    print_u64(evidence.dma_tx_descriptor_candidates);
    print_str(b"/");
    print_u64(evidence.dma_tx_descriptor_map_candidates);
    print_str(b"/");
    print_u64(evidence.dma_tx_descriptor_done_seen);
    print_str(b" dma_tx_last_desc=0x");
    print_hex(evidence.dma_tx_last_candidate_address as u32);
    print_str(b"/");
    print_u64(evidence.dma_tx_last_candidate_len);
    print_str(b"/0x");
    print_hex(evidence.dma_tx_last_candidate_status as u32);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"io");
    print_str(b" io_out32=");
    print_u64(evidence.io_port_out32_serviced() as u64);
    print_str(b" io_out32_count=");
    print_u64(evidence.io_port_out32_faults);
    print_str(b" io_cap=");
    print_u64(evidence.resource_io_port_cap);
    print_str(b"/");
    print_u64(evidence.resource_io_port_component_cap);
    print_str(b" io_in16=");
    print_u64(evidence.io_port_in16_calls);
    print_str(b"/");
    print_u64(evidence.io_port_in16_failures);
    print_str(b" io_out16=");
    print_u64(evidence.io_port_out16_calls);
    print_str(b"/");
    print_u64(evidence.io_port_out16_failures);
    print_str(b" io16_denied=");
    print_u64(evidence.io_port_in16_denied);
    print_str(b"/");
    print_u64(evidence.io_port_out16_denied);
    print_str(b" io16_last_status=");
    print_u64(evidence.io_port_last_in16_status);
    print_str(b"/");
    print_u64(evidence.io_port_last_out16_status);
    print_str(b" io16_last_port=0x");
    print_hex(evidence.io_port_last_in16_port as u32);
    print_str(b"/0x");
    print_hex(evidence.io_port_last_out16_port as u32);
    print_str(b" io16_last_value=0x");
    print_hex(evidence.io_port_last_in16_value as u32);
    print_str(b"/0x");
    print_hex(evidence.io_port_last_out16_value as u32);
    print_str(b"\n");

    print_hardware_evidence_prefix(trace, service_name, instance_id, b"video");
    print_str(b" video_init=");
    print_u64(evidence.video_initialized as u64);
    print_str(b" video_find=");
    print_u64(evidence.video_find_adapter_calls);
    print_str(b" video_find_status=0x");
    print_hex(evidence.video_find_adapter_status);
    print_str(b" video_again=");
    print_u64(evidence.video_find_adapter_again as u64);
    print_str(b" video_hwinit=");
    print_u64(evidence.video_hw_initialize_calls);
    print_str(b" video_hwinit_ok=");
    print_u64(evidence.video_hw_initialize_ok as u64);
    print_str(b" video_startio=");
    print_u64(evidence.video_hw_start_io_calls);
    print_str(b" video_reg_set=");
    print_u64(evidence.video_registry_set_calls);
    print_str(b"/");
    print_u64(evidence.video_registry_set_bytes);
    print_str(b" video_reg_status=0x");
    print_hex(evidence.video_registry_commit_status as u32);
    print_str(b" video_reg_failures=");
    print_u64(evidence.video_registry_commit_failures);
    print_str(b"\n");
}

fn print_hardware_evidence_prefix(
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    group: &[u8],
) {
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => b"[driver-launch] generic hardware evidence service=",
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand hardware evidence service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] hardware evidence service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" group=");
    print_str(group);
}
