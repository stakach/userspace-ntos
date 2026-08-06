use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use crate::*;

static mut HOSTED_PNP_PCI_DEVICES: Option<Vec<nt_pnp::PciDevice>> = None;
static HOSTED_PNP_NIC_BAR_BASE: AtomicU64 = AtomicU64::new(0);
static HOSTED_PNP_NIC_MMIO: AtomicU64 = AtomicU64::new(0);
static HOSTED_PNP_NIC_DMA_FRAME: AtomicU64 = AtomicU64::new(0);
static mut HOSTED_PNP_ROOT_DMA_MMIO_FRAME: u64 = 0;
static mut HOSTED_PNP_ROOT_DMA_COMMON_FRAME: u64 = 0;

const STATUS_DEVICE_NOT_READY: nt_status::NtStatus = nt_status::NtStatus(0xC000_00A3u32 as i32);

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
    pub(crate) root_started: bool,
    pub(crate) attempted: u64,
    pub(crate) started: u64,
    pub(crate) first_error: u32,
}

struct HostedPnpDevnodeStart<'a> {
    instance_id: &'a str,
    driver_key: Option<&'a str>,
    hardware_ids: &'a [&'a str],
    compatible_ids: &'a [&'a str],
}

pub(crate) unsafe fn publish_hosted_pnp_resource_context(
    pci_devices: &[nt_pnp::PciDevice],
    nic_bar_base: u64,
    nic_mmio: u64,
    nic_dma_frame: u64,
) {
    let new_devices = Vec::from(pci_devices);
    let old = core::ptr::replace(
        core::ptr::addr_of_mut!(HOSTED_PNP_PCI_DEVICES),
        Some(new_devices),
    );
    drop(old);
    HOSTED_PNP_NIC_BAR_BASE.store(nic_bar_base, Ordering::Relaxed);
    HOSTED_PNP_NIC_MMIO.store(nic_mmio, Ordering::Relaxed);
    HOSTED_PNP_NIC_DMA_FRAME.store(nic_dma_frame, Ordering::Relaxed);
}

pub(crate) unsafe fn start_inline_driver_service_devnodes(
    dc: &driver_launch::DriverComponent,
    spec: &InlineDriverLaunchSpec,
    options: HostedPnpStartOptions,
) -> HostedPnpStartReport {
    let mut report = HostedPnpStartReport {
        driver_ready_for_pnp: (dc.verdict & V_ENTERED) != 0 && dc.add_device != 0,
        ..HostedPnpStartReport::default()
    };
    let class_guid = if spec.class_guid_present {
        Some(spec.class_guid.as_str())
    } else {
        None
    };
    for devnode in &spec.devnodes[..spec.devnode_count] {
        let mut hardware_refs = [""; BOOT_DRIVER_ID_MAX];
        let hardware_refs = devnode.hardware_refs(&mut hardware_refs);
        let mut compatible_refs = [""; BOOT_DRIVER_ID_MAX];
        let compatible_refs = devnode.compatible_refs(&mut compatible_refs);
        let driver_key = if devnode.driver_key_present {
            Some(devnode.driver_key.as_str())
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
        driver_ready_for_pnp: (dc.verdict & V_ENTERED) != 0 && dc.add_device != 0,
        ..HostedPnpStartReport::default()
    };
    let class_guid = spec.class_guid.as_deref();
    for devnode in &spec.devnodes {
        let mut hardware_refs = [""; BOOT_DRIVER_ID_MAX];
        let hardware_count =
            copy_service_string_refs(&devnode.hardware_ids, &mut hardware_refs);
        let mut compatible_refs = [""; BOOT_DRIVER_ID_MAX];
        let compatible_count =
            copy_service_string_refs(&devnode.compatible_ids, &mut compatible_refs);
        start_one_devnode(
            dc,
            &spec.service_name,
            class_guid,
            HostedPnpDevnodeStart {
                instance_id: &devnode.instance_id,
                driver_key: devnode.driver_key.as_deref(),
                hardware_ids: &hardware_refs[..hardware_count],
                compatible_ids: &compatible_refs[..compatible_count],
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

fn copy_service_string_refs<'a>(
    src: &'a [alloc::string::String],
    dst: &mut [&'a str; BOOT_DRIVER_ID_MAX],
) -> usize {
    let mut count = 0usize;
    for value in src {
        if count >= dst.len() {
            break;
        }
        dst[count] = value.as_str();
        count += 1;
    }
    count
}

unsafe fn start_one_devnode(
    dc: &driver_launch::DriverComponent,
    service_name: &str,
    class_guid: Option<&str>,
    devnode: HostedPnpDevnodeStart<'_>,
    options: HostedPnpStartOptions,
    report: &mut HostedPnpStartReport,
) {
    report.attempted += 1;
    match driver_launch::call_add_device_for_driver(
        dc.driver_id,
        service_name,
        class_guid,
        devnode.driver_key,
        devnode.instance_id,
        devnode.hardware_ids,
        devnode.compatible_ids,
    ) {
        Ok(device_id) => {
            report.add_device = true;
            print_add_device_success(options.trace, service_name, devnode.instance_id, device_id);
            let start_status = match grant_current_hosted_devnode_resources(
                device_id,
                devnode.instance_id,
                devnode.hardware_ids,
                devnode.compatible_ids,
            ) {
                Ok(Some(grant)) => {
                    print_hosted_devnode_grant(service_name.as_bytes(), devnode.instance_id.as_bytes(), &grant);
                    driver_launch::start_hosted_device(device_id, &grant.resource_list)
                }
                Ok(None) => Err(nt_status::NtStatus::INVALID_DEVICE_REQUEST),
                Err(status) => {
                    print_resource_grant_failure(options.trace, service_name, devnode.instance_id, status);
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
            print_start_status(options.trace, service_name, devnode.instance_id, start_status_raw);
            if options.inject_test_interrupt && start_status_raw == 0 {
                inject_proof_interrupt(device_id, options.trace, service_name, devnode.instance_id, report);
            }
            collect_hardware_evidence(device_id, options.trace, service_name, devnode.instance_id, start_status_raw, report);
        }
        Err(status) => {
            remember_error(report, status);
            print_add_device_failure(options.trace, service_name, devnode.instance_id, status);
        }
    }
}

unsafe fn grant_current_hosted_devnode_resources(
    device_id: u64,
    instance_id: &str,
    hardware_refs: &[&str],
    compatible_refs: &[&str],
) -> Result<Option<HostedDevnodeGrant>, nt_status::NtStatus> {
    let devices = (*core::ptr::addr_of!(HOSTED_PNP_PCI_DEVICES))
        .as_ref()
        .ok_or(STATUS_DEVICE_NOT_READY)?;
    let mut root_dma_mmio_frame =
        core::ptr::read_volatile(core::ptr::addr_of!(HOSTED_PNP_ROOT_DMA_MMIO_FRAME));
    let mut root_dma_common_frame =
        core::ptr::read_volatile(core::ptr::addr_of!(HOSTED_PNP_ROOT_DMA_COMMON_FRAME));
    let result = grant_hosted_devnode_resources(
        device_id,
        instance_id,
        hardware_refs,
        compatible_refs,
        devices.as_slice(),
        HOSTED_PNP_NIC_BAR_BASE.load(Ordering::Relaxed),
        HOSTED_PNP_NIC_MMIO.load(Ordering::Relaxed),
        HOSTED_PNP_NIC_DMA_FRAME.load(Ordering::Relaxed),
        &mut root_dma_mmio_frame,
        &mut root_dma_common_frame,
    );
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!(HOSTED_PNP_ROOT_DMA_MMIO_FRAME),
        root_dma_mmio_frame,
    );
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!(HOSTED_PNP_ROOT_DMA_COMMON_FRAME),
        root_dma_common_frame,
    );
    result
}

fn remember_error(report: &mut HostedPnpStartReport, status: nt_status::NtStatus) {
    if report.first_error == 0 {
        report.first_error = status.raw() as u32;
    }
}

unsafe fn inject_proof_interrupt(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    report: &mut HostedPnpStartReport,
) {
    if let Some(evidence) = driver_launch::hosted_hardware_evidence(device_id) {
        if evidence.mmio_mapped() && evidence.interrupt_connected() {
            core::ptr::write_volatile(
                (ROOT_DMA_PROOF_MMIO_SEED_VADDR + ROOT_DMA_PROOF_INTERRUPT_ACK_OFFSET) as *mut u32,
                0,
            );
            core::ptr::write_volatile(
                (ROOT_DMA_PROOF_MMIO_SEED_VADDR + ROOT_DMA_PROOF_INTERRUPT_STATUS_OFFSET)
                    as *mut u32,
                1,
            );
            match driver_launch::inject_hosted_device_interrupt(device_id) {
                Ok(delivery) => {
                    let ack = core::ptr::read_volatile(
                        (ROOT_DMA_PROOF_MMIO_SEED_VADDR + ROOT_DMA_PROOF_INTERRUPT_ACK_OFFSET)
                            as *const u32,
                    );
                    report.interrupt_acknowledged |= ack == 1;
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

fn collect_hardware_evidence(
    device_id: u64,
    trace: HostedPnpStartTrace,
    service_name: &str,
    instance_id: &str,
    start_status_raw: u32,
    report: &mut HostedPnpStartReport,
) {
    if let Some(evidence) = driver_launch::hosted_hardware_evidence(device_id) {
        if evidence.resource_granted() {
            report.resource_granted = true;
            report.mmio_mapped |= evidence.mmio_mapped();
            report.interrupt_connected |= evidence.interrupt_connected();
            report.interrupt_delivered |= evidence.interrupt_delivered();
            report.dpc_delivered |= evidence.dpc_delivered();
            report.dma_adapter |= evidence.dma_adapter_created();
            report.dma_common |= evidence.dma_common_allocated();
            report.root_started |= evidence.root_pdo_started;
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
        HostedPnpStartTrace::HardwareProof => b"[driver-launch] generic hardware AddDevice service=",
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
    print_str(match trace {
        HostedPnpStartTrace::HardwareProof => b"[driver-launch] generic hardware evidence service=",
        HostedPnpStartTrace::DemandStart => b"[driver-launch] demand hardware evidence service=",
        HostedPnpStartTrace::BootService => b"[driver-launch] hardware evidence service=",
    });
    print_str(service_name.as_bytes());
    print_str(b" devnode=");
    print_str(instance_id.as_bytes());
    print_str(b" start=");
    print_hex(start_status_raw);
    print_str(b" mmio=");
    print_u64(evidence.mmio_mapped() as u64);
    print_str(b" mmio_len=");
    print_u64(evidence.resource_mmio_len);
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
    print_str(b" dma_adapter=");
    print_u64(evidence.dma_adapter_created() as u64);
    print_str(b" dma_common=");
    print_u64(evidence.dma_common_allocated() as u64);
    print_str(b" dma_len=");
    print_u64(evidence.dma_common_len);
    print_str(b" root_started=");
    print_u64(evidence.root_pdo_started as u64);
    print_str(b"\n");
}
