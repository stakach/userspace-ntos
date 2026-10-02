//! PoSetPowerState crosses into the executive before resolving or mutating canonical state.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
use nt_io_abi::power_report::{PowerReportReply, PowerReportRequest};

static REPORT_RECEIPTS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

struct ReportTarget {
    device: nt_io_manager::DeviceId,
    domain: HostedDomainIdentity,
    tcb: u64,
}

fn observe_report(target: &ReportTarget, request: PowerReportRequest, previous: u32) {
    let receipt = REPORT_RECEIPTS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if receipt > 8 && receipt % 256 != 0 { return; }
    print_str(b"[power-report] commit #"); print_u64(receipt);
    print_str(b" device="); print_u64(target.device.raw());
    print_str(b" domain="); print_u64(target.domain.domain_id.raw());
    print_str(b" cookie="); print_u64(target.domain.cookie);
    print_str(b" tcb="); print_u64(target.tcb);
    print_str(b" type="); print_u64(request.power_type as u64);
    print_str(b" previous="); print_u64(previous as u64);
    print_str(b" new="); print_u64(request.state as u64);
    print_str(b"\n");
}

pub(super) unsafe fn component_report(device: u64, power_type: u32, state: u32) -> u32 {
    if PowerReportRequest::decode(device, power_type as u64, state as u64).is_err() {
        crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_REPORT_POWER_STATE, device, power_type as u64, state as u64]);
    }
    let (words, status, previous, reserved0, reserved1) = call_on4_raw(
        (FSD_SERVICE_DEVICE_LABEL << 12) | 4,
        HOSTED_DEVICE_OP_REPORT_POWER_STATE, device, power_type as u64, state as u64,
    );
    match PowerReportReply::decode(words, status, previous, [reserved0, reserved1], power_type) {
        Ok(PowerReportReply::Success(previous)) => previous,
        // This ULONG-returning NT API has no error channel. Neither rejection nor an
        // ambiguous acknowledgement can be converted into a fabricated old state or replay.
        _ => crate::provider_bugcheck::report(0xc4, [HOSTED_DEVICE_OP_REPORT_POWER_STATE, device, words, status]),
    }
}

fn resolve_report_target(
    ch: &crate::spawn_hosts::PumpChannel,
    device: u64,
    reply_cap: u64,
    badge: u64,
) -> Result<ReportTarget, nt_status::NtStatus> {
    let (_, inst, device_id) = authenticated_hosted_device(ch, device, reply_cap)?;
    let domain = instance_domain_identity(inst).ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
    let route = unsafe { runtime::channel_route(ch).ok().flatten() }
        .ok_or(nt_status::NtStatus::ACCESS_DENIED)?;
    let source = unsafe { runtime::physical_source(route) }
        .map_err(|_| nt_status::NtStatus::ACCESS_DENIED)?;
    if route.badge() != badge || source.tcb != ch.tcb
        || source.pml4 != inst.pml4 || source.domain != runtime::PhysicalDomain::Hosted(domain)
        || unsafe { runtime::dispatch(route) }.is_err()
    {
        return Err(nt_status::NtStatus::ACCESS_DENIED);
    }
    if io_manager_mut().hosted_power_report_target(domain, device)? != device_id {
        return Err(nt_status::NtStatus::ACCESS_DENIED);
    }
    let _ = unsafe {
        hosted_add_device_rollback::power_report_target(domain, ch, reply_cap, badge, device_id)?
    };
    Ok(ReportTarget { device: device_id, domain, tcb: source.tcb })
}

pub(super) fn service_report(
    ch: &crate::spawn_hosts::PumpChannel,
    device: u64,
    power_type: u64,
    state: u64,
    reply_cap: u64,
    badge: u64,
) -> (i32, u64, u64, u64) {
    let result = (|| -> Result<u32, nt_status::NtStatus> {
        let request = PowerReportRequest::decode(device, power_type, state)
            .map_err(|_| nt_status::NtStatus::INVALID_PARAMETER)?;
        let target = resolve_report_target(ch, request.device, reply_cap, badge)?;
        let previous = match request.power_type {
            nt_power_types::POWER_STATE_TYPE_DEVICE => io_manager_mut().report_device_power_state(
                target.device, nt_power_types::DevicePowerState::from_u32(request.state)
                    .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?,
            ).map(|previous| previous as u32),
            nt_power_types::POWER_STATE_TYPE_SYSTEM => io_manager_mut().report_system_power_state(
                target.device, nt_power_types::SystemPowerState::from_u32(request.state)
                    .ok_or(nt_status::NtStatus::INVALID_PARAMETER)?,
            ).map(|previous| previous as u32),
            _ => Err(nt_status::NtStatus::INVALID_PARAMETER),
        }?;
        observe_report(&target, request, previous);
        Ok(previous)
    })();
    match result {
        Ok(previous) => (STATUS_SUCCESS, previous as u64, 0, 0),
        Err(status) => (status.raw(), 0, 0, 0),
    }
}
