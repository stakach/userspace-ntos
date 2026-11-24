//! The video-port START intercept's HwFindAdapter dispatch (#420).
//!
//! START runs the miniport's FindAdapter in the hosted provider on the instance's primary lane.
//! A pump that stops before FindAdapter returns, where its caller cannot wait, is kept in
//! `hosted_backend_pumps` and the START IRP answers pending. Meanwhile the adapter's discovery
//! is running in the provider and the instance stays ready. The pump's true return is mapped
//! once (`nt_video_miniport::find_adapter_start`) and published as the IRP's ordinary
//! completion by `hosted_backend_irp_operations`. Only an untrustworthy return quarantines the
//! IRP and retires the instance, whose lane the pump left suspended.

use super::*;
use hosted_backend_pumps::BackendDispatch;
use nt_video_miniport::{find_adapter_start, FindAdapterPump, FindAdapterStart};

/// An unfinished FindAdapter pump and what reading its return needs.
pub(super) struct Kept {
    pump: component_scheduler::HostedPumpRestore,
    index: usize,
    device_id: u64,
    shared_va: u64,
    device_context: DeviceDispatchContextOwner,
}

impl Kept {
    pub(super) fn retryable(&self) -> bool { self.pump.retryable_continuation() }

    /// Resume once from the root boundary. `Err` is a pump that has not returned yet.
    pub(super) unsafe fn resume(self) -> Result<HostedIrpTransportResult, Self> {
        if !self.retryable() { return Err(self); }
        let Self { pump, index, device_id, shared_va, device_context } = self;
        let device_context = match device_context.resume() {
            Ok(owner) => owner,
            Err((status, owner)) => {
                trace(b"context-resume-refused", device_id, status.raw() as u32);
                return Err(Self { pump, index, device_id, shared_va, device_context: owner });
            }
        };
        // Another device may have projected resources onto this instance while FindAdapter
        // waited. Reproject only its retained canonical binding before re-entering the pump.
        let projection = device_context.active_ref()
            .ok_or(nt_status::NtStatus::DEVICE_BUSY)
            .and_then(|context| context.projection_binding(shared_va))
            .and_then(|binding| {
                let inst = instance(index).ok_or(nt_status::NtStatus::DEVICE_NOT_CONNECTED)?;
                if inst.driver_id != binding.driver_id || binding.device_id != device_id {
                    return Err(nt_status::NtStatus::DEVICE_NOT_CONNECTED);
                }
                restore_hosted_device_resource_state(binding, shared_va, inst.cnode, false)
                    .map(|_| ())
            });
        if let Err(status) = projection {
            let device_context = match device_context.suspend() {
                Ok(owner) | Err((_, owner)) => owner,
            };
            trace(b"context-projection-refused", device_id, status.raw() as u32);
            return Err(Self { pump, index, device_id, shared_va, device_context });
        }
        answer(Self {
            pump: component_scheduler::retry_child_work(pump),
            index, device_id, shared_va, device_context,
        })
    }
}

/// Run FindAdapter for the START IRP of `device_id`. Every refusal before the provider is
/// entered is a certain no-entry.
pub(super) unsafe fn dispatch(
    index: usize,
    inst: DriverInstance,
    binding: HostedDeviceBinding,
    caller: nt_process::native_handle::NativeHandleCaller,
) -> BackendDispatch {
    let not_dispatched = |status| BackendDispatch::Returned(
        HostedIrpTransportResult::NotDispatched { status });
    let sh = inst.exec_shared_va;
    let device_id = binding.device_id;
    if !hosted_instance_video_port_initialized(inst) {
        return not_dispatched(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let Some((route_index, route_inst, device_object)) =
        hosted_driver_device_route_by_device_id(device_id)
    else {
        return not_dispatched(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    };
    if route_index != index || route_inst.driver_id != inst.driver_id
        || binding.instance != index || binding.driver_id != inst.driver_id
        || binding.device_object != device_object
    {
        return not_dispatched(nt_status::NtStatus::INVALID_DEVICE_REQUEST);
    }
    let Some(exec_window) = ExecVaWindow::try_for_instance(index) else {
        return not_dispatched(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    };
    // The row that keeps an unfinished pump has capacity before resource projection or
    // provider entry. `reserve_channel` preallocates; it does not claim a row yet.
    if hosted_backend_pumps::reserve_channel().is_err() {
        return not_dispatched(nt_status::NtStatus::INSUFFICIENT_RESOURCES);
    }
    let mut context = match HostedDeviceDispatchContextGuard::enter(index, binding) {
        Ok(context) => context,
        Err(status) => return not_dispatched(status),
    };
    if let Err(status) = context.bind_projection_shared(sh) {
        return not_dispatched(status);
    }
    if let Err(status) = restore_hosted_device_resource_state(binding, sh, inst.cnode, false) {
        return not_dispatched(status);
    }
    let interface_type = read_volatile((sh + SH_RESOURCE_INTERFACE_TYPE) as *const u32);
    let bus_number = read_volatile((sh + SH_RESOURCE_BUS_NUMBER) as *const u32);
    let interrupt_vector = read_volatile((sh + SH_RESOURCE_INTERRUPT_VECTOR) as *const u32);
    let interrupt_mode = if interface_type == HOSTED_INTERFACE_TYPE_PCIBUS {
        VIDEO_INTERRUPT_MODE_LEVEL_SENSITIVE
    } else {
        VIDEO_INTERRUPT_MODE_LATCHED
    };
    let config = VideoPortConfigInfoX64::new_pnp(
        bus_number,
        interface_type,
        interrupt_vector,
        interrupt_vector,
        interrupt_mode,
        0,
        0,
    );
    let mut raw = [0u8; VIDEO_PORT_CONFIG_INFO_X64_SIZE];
    if config.write(&mut raw).is_err() {
        return not_dispatched(nt_status::NtStatus::INVALID_PARAMETER);
    }
    write_volatile((sh + SH_ACTIVE_DEVICE_OBJECT) as *mut u64, device_object);
    for (idx, byte) in raw.iter().enumerate() {
        write_volatile((inst.exec_arg_va + idx as u64) as *mut u8, *byte);
    }
    write_volatile((sh + SH_REQ_MAJOR) as *mut u64, FSD_DISPATCH_VIDEO_FIND_ADAPTER);
    write_volatile((sh + SH_REQ_MINOR) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FSCTL) as *mut u64, 0);
    write_volatile((sh + SH_REQ_INLEN) as *mut u64, VIDEO_PORT_CONFIG_INFO_X64_SIZE as u64);
    write_volatile((sh + SH_REQ_OUTLEN) as *mut u64, 0);
    write_volatile((sh + SH_REQ_FILEID) as *mut u64, 0);
    write_volatile((sh + SH_REQ_STATUS) as *mut i32, 0);
    write_volatile((sh + SH_REQ_INFO) as *mut u64, 0);

    let ch = crate::spawn_hosts::PumpChannel {
        initial_root_dispatch: None,
        fault_ep: inst.fault_ep,
        pml4: inst.pml4,
        physical_domain: instance_domain_identity(inst),
        ingress_route: hosted_ingress_sources::primary_route(index),
        code_va: 0,
        image_frames: 0,
        exec_code_va: exec_window.code_va,
        root_image_rights: 3,
        root_image_map_owner: inst.map_cap_bank.owner,
        shared_va: sh,
        dispatch_label: FSD_DISPATCH_LABEL,
        demand_cap: 256,
        trace_faults: false,
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: inst.tcb,
        reply_cap: inst.reply_cap,
        child_work_capable: false,
        client_pi: 0,
        client_generation: 0,
        logical_caller: None,
        kernel_caller: None,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Irp,
            io_port_faults: shared_has_port_resources(sh),
            // The backend row keeps this pump, so a wait the provider parks inside FindAdapter
            // may leave the root loop running.
            parked_dispatch_yield: true,
            ..crate::spawn_hosts::HostCaps::default()
        },
    };
    // A root caller that may block still waits here for the true result.
    let pump = component_scheduler::service_continuation::settle_for_file_owner(
        component_scheduler::hosted_component_pump_with_caller_retained(&ch, caller));
    match answer(Kept {
        pump, index, device_id, shared_va: sh,
        device_context: DeviceDispatchContextOwner::active(context),
    }) {
        Ok(result) => BackendDispatch::Returned(result),
        Err(kept) => {
            trace(b"pending", device_id, 0);
            BackendDispatch::Pending(hosted_backend_pumps::keep_channel(kept))
        }
    }
}

/// FindAdapter's answer for the START IRP, exactly once per return. `Err` hands back a pump
/// that has not returned yet.
unsafe fn answer(kept: Kept) -> Result<HostedIrpTransportResult, Kept> {
    use component_scheduler::HostedPumpRestore;
    let outcome = match &kept.pump {
        HostedPumpRestore::Restored(pr) | HostedPumpRestore::Unattributed(pr) if pr.completed =>
            FindAdapterPump::Returned {
                dispatch_status: pr.status as u32,
                // Generic IRP pumps mirror dispatch NTSTATUS in `result`. The miniport's
                // independent VP_STATUS is written into this exact retained request bank.
                vp_status: if pr.status < 0 { VP_NO_ERROR } else {
                    read_volatile((kept.shared_va + SH_VIDEO_FIND_ADAPTER_STATUS) as *const u32)
                },
            },
        HostedPumpRestore::Restored(_) | HostedPumpRestore::Unattributed(_) =>
            FindAdapterPump::Uncertain,
        _ => FindAdapterPump::Unfinished,
    };
    let start = find_adapter_start(outcome);
    if start != FindAdapterStart::Pending {
        // Whatever FindAdapter did, the lane may be free once its pump stopped (#427).
        hosted_file_owners::lane_freed();
    }
    match start {
        FindAdapterStart::Pending => {
            let Kept { pump, index, device_id, shared_va, device_context } = kept;
            let device_context = match device_context.suspend() {
                Ok(owner) => owner,
                Err((status, owner)) => {
                    trace(b"context-suspend-refused", device_id, status.raw() as u32);
                    owner
                }
            };
            Err(Kept { pump, index, device_id, shared_va, device_context })
        }
        FindAdapterStart::Quarantined => {
            let Kept { index, device_id, .. } = kept;
            trace(b"quarantined", device_id, 0);
            // The pump left the lane's TCB suspended with its Reply bound: no later dispatch
            // may reply on it.
            register_instance_ready(index, false);
            Ok(HostedIrpTransportResult::Indeterminate {
                transport_status: nt_status::NtStatus::UNSUCCESSFUL,
            })
        }
        FindAdapterStart::Completed(status) => {
            let Kept { device_id, shared_va: sh, .. } = kept;
            if let FindAdapterPump::Returned { vp_status, .. } = outcome {
                let again = read_volatile((sh + SH_VIDEO_FIND_ADAPTER_AGAIN) as *const u8);
                if vp_status != VP_NO_ERROR || again != 0 {
                    print_str(b"[driver-launch] hosted video FindAdapter returned device_id=");
                    print_u64(device_id);
                    print_str(b" status=0x");
                    print_hex(vp_status);
                    print_str(b" calls=");
                    print_u64(read_volatile((sh + SH_VIDEO_FIND_ADAPTER_CALLS) as *const u64));
                    print_str(b" again=");
                    print_u64(again as u64);
                    print_str(b"\n");
                }
            }
            trace(b"returned", device_id, status);
            Ok(HostedIrpTransportResult::Returned {
                status: nt_status::NtStatus(status as i32),
                information: 0,
                file_context: 0,
            })
        }
    }
}

fn trace(stage: &[u8], device_id: u64, status: u32) {
    static TRACED: AtomicU64 = AtomicU64::new(0);
    let n = TRACED.fetch_add(1, Ordering::Relaxed) + 1;
    if n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[video-find-adapter] n=");
    print_u64(n);
    print_str(b" stage=");
    print_str(stage);
    print_str(b" device_id=");
    print_u64(device_id);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}
