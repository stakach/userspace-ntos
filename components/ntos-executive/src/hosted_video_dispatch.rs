//! Videoport interception with exact provider-entry evidence.

use super::*;

unsafe fn dispatch_video_initialize_for_instance(
    index: usize,
    inst: DriverInstance,
    device_object: u64,
) -> HostedIrpTransportResult {
    if !hosted_instance_video_port_initialized(inst) {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        };
    }
    let Some(window) = ExecVaWindow::try_for_instance(index) else {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        };
    };
    let sh = inst.exec_shared_va;
    write_volatile((sh + SH_ACTIVE_DEVICE_OBJECT) as *mut u64, device_object);
    write_volatile(
        (sh + SH_REQ_MAJOR) as *mut u64,
        FSD_DISPATCH_VIDEO_INITIALIZE,
    );
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FSCTL) as *mut u64, 0);
    write_volatile((sh + SH_REQ_INLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FILEID) as *mut u64, 0);
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        code_va: 0,
        image_frames: 0,
        exec_code_va: window.code_va,
        root_image_rights: 3,
        root_image_map_owner: inst.map_cap_bank.owner,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
        client_generation: 0,
        logical_caller: None,
        kernel_caller: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            io_port_faults: shared_has_port_resources(sh),
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let bugchecks_before = FSD_BUGCHECKS.load(Ordering::Relaxed);
    let pr = hosted_component_pump(&ch);
    let guarded_abort = FSD_BUGCHECKS.load(Ordering::Relaxed) != bugchecks_before;
    if guarded_abort {
        FSD_BUGCHECK_INSTANCE.store(index as u64 + 1, Ordering::Relaxed);
    }
    if !pr.completed || guarded_abort {
        register_instance_ready(index, false);
        return HostedIrpTransportResult::Indeterminate {
            transport_status: nt_status::NtStatus::UNSUCCESSFUL,
        };
    }
    let info = read_volatile((sh + SH_REQ_INFO) as *const u64);
    if pr.status == 0 {
        if let Err(status) = commit_video_registry_parameters_for_instance(inst) {
            return video_transport_return(index, status.raw(), 0);
        }
    }
    video_transport_return(index, pr.status, info)
}

unsafe fn dispatch_video_start_io_for_instance(
    index: usize,
    inst: DriverInstance,
    device_object: u64,
    ioctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> HostedIrpTransportResult {
    if !hosted_instance_video_port_initialized(inst) {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_DEVICE_REQUEST,
        };
    }
    if ioctl > u32::MAX as u64 || in_data.len() > u32::MAX as usize || out.len() > u32::MAX as usize
    {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        };
    }
    let Some(window) = ExecVaWindow::try_for_instance(index) else {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        };
    };
    let sh = inst.exec_shared_va;
    let inlen = in_data.len();
    write_volatile((sh + SH_ACTIVE_DEVICE_OBJECT) as *mut u64, device_object);
    write_volatile((sh + SH_REQ_MAJOR) as *mut u64, FSD_DISPATCH_VIDEO_START_IO);
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FSCTL) as *mut u64, ioctl);
    write_volatile((sh + SH_REQ_INLEN) as *mut u64, inlen as u64);
    write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, out.len() as u64);
    write_volatile((sh + SH_REQ_FILEID) as *mut u64, file_id);
    write_volatile((sh + SH_REQ_CONTROL_ID) as *mut u64, 0);
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        code_va: 0,
        image_frames: 0,
        exec_code_va: window.code_va,
        root_image_rights: 3,
        root_image_map_owner: inst.map_cap_bank.owner,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        client_pi: 0,
        client_generation: 0,
        logical_caller: None,
        kernel_caller: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            io_port_faults: shared_has_port_resources(sh),
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    let Some(transfer_guard) = enter_active_hosted_irp_transfer(sh, 0, in_data, out) else {
        return HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INSUFFICIENT_RESOURCES,
        };
    };
    let bugchecks_before = FSD_BUGCHECKS.load(Ordering::Relaxed);
    let pr = hosted_component_pump(&ch);
    drop(transfer_guard);
    let guarded_abort = FSD_BUGCHECKS.load(Ordering::Relaxed) != bugchecks_before;
    if guarded_abort {
        FSD_BUGCHECK_INSTANCE.store(index as u64 + 1, Ordering::Relaxed);
    }
    if !pr.completed || guarded_abort {
        register_instance_ready(index, false);
        return HostedIrpTransportResult::Indeterminate {
            transport_status: nt_status::NtStatus::UNSUCCESSFUL,
        };
    }
    let info = read_volatile((sh + SH_REQ_INFO) as *const u64);
    video_transport_return(index, pr.status, info)
}

fn video_transport_return(index: usize, status: i32, information: u64) -> HostedIrpTransportResult {
    // The current video miniport request has no durable asynchronous VRP owner.
    // STATUS_PENDING therefore cannot authorize ordinary FSD completion polling.
    if status as u32 == STATUS_PENDING {
        register_instance_ready(index, false);
        HostedIrpTransportResult::Indeterminate {
            transport_status: nt_status::NtStatus::UNSUCCESSFUL,
        }
    } else {
        HostedIrpTransportResult::Returned {
            status: nt_status::NtStatus(status),
            information,
            file_context: 0,
        }
    }
}

pub(super) unsafe fn dispatch_video_irp_for_binding_exact(
    index: usize,
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    major: u64,
    minor: u64,
    fsctl: u64,
    file_id: u64,
    in_data: &[u8],
    out: &mut [u8],
) -> Option<HostedIrpTransportResult> {
    if !hosted_instance_video_port_initialized(inst) {
        return None;
    }
    if major > u8::MAX as u64 {
        return Some(HostedIrpTransportResult::NotDispatched {
            status: nt_status::NtStatus::INVALID_PARAMETER,
        });
    }
    let device_object = binding.device_object;
    let outcome = match major as u8 {
        major::IRP_MJ_CREATE => {
            let result = dispatch_video_initialize_for_instance(index, inst, device_object);
            let initialize_calls =
                read_volatile((inst.exec_shared_va + SH_VIDEO_HW_INITIALIZE_CALLS) as *const u64);
            let initialize_ok =
                read_volatile((inst.exec_shared_va + SH_VIDEO_HW_INITIALIZE_OK) as *const u8);
            let (status, information) = match result {
                HostedIrpTransportResult::Returned {
                    status,
                    information,
                    ..
                } => (status, information),
                HostedIrpTransportResult::NotDispatched { status } => (status, 0),
                HostedIrpTransportResult::Indeterminate { transport_status } => {
                    (transport_status, 0)
                }
            };
            if status.raw() != 0 || initialize_ok == 0 {
                print_str(b"[driver-launch] hosted video Initialize failed device_id=");
                print_u64(binding.device_id);
                print_str(b" status=0x");
                print_hex(status.raw() as u32);
                print_str(b" info=");
                print_u64(information);
                print_str(b" calls=");
                print_u64(initialize_calls);
                print_str(b" ok=");
                print_u64(initialize_ok as u64);
                print_str(b"\n");
            }
            result
        }
        major::IRP_MJ_CLEANUP | major::IRP_MJ_CLOSE => video_transport_return(index, 0, 0),
        major::IRP_MJ_DEVICE_CONTROL | major::IRP_MJ_INTERNAL_DEVICE_CONTROL => {
            dispatch_video_start_io_for_instance(
                index,
                inst,
                device_object,
                fsctl,
                file_id,
                in_data,
                out,
            )
        }
        _ => video_transport_return(index, nt_status::NtStatus::INVALID_DEVICE_REQUEST.raw(), 0),
    };
    let _ = minor;
    Some(outcome)
}
