//! Producer routing for allocation retirement; IRQ service never enters the fixed request bank.

use super::*;

pub(super) unsafe fn retire(op: u64, address: u64) -> i32 {
    if let Some((_, identity, _, _, grant)) = hosted_irq_lane_context() {
        let mut arguments = [0; nt_hosted_runtime::HOSTED_IRQ_ARENA_ARGUMENT_CAP];
        arguments[..2].copy_from_slice(&[op, address]);
        let result = hosted_irq_lane_service(nt_hosted_runtime::HostedIrqServiceCommand {
            kind: nt_hosted_runtime::HostedIrqServiceKind::PoolRetirement,
            service_id: FSD_SERVICE_SOURCE_IRP_LABEL,
            target_domain_id: identity.domain_id,
            target_domain_cookie: identity.domain_cookie,
            authority_cookie: 0,
            grant,
            argument_count: 2,
            arguments,
        });
        if result.faulted || result.value_count != 0 {
            hosted_irq_lane_protocol_fault(address);
        }
        return result.status;
    }
    let (label, status, _, _, _) =
        call_on4((FSD_SERVICE_SOURCE_IRP_LABEL << 12) | 4, op, address, 0, 0);
    if label != 0 {
        crate::provider_bugcheck::report(0xc4, [FSD_SERVICE_SOURCE_IRP_LABEL, op, address, status]);
    }
    status as u32 as i32
}
