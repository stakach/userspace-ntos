//! Scalar observations of authenticated Section cleanup; never an admission or ownership source.

use crate::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;

#[derive(Clone, Copy)]
pub(crate) struct RetirementReceipt {
    pub pointer: u64,
    pub native_generation: u64,
    pub view_generation: u64,
    pub provider_domain: u64,
    pub provider_generation: u64,
    pub base: u64,
    pub remaining_references: u64,
}

pub(crate) fn unmap_retired(receipt: Option<RetirementReceipt>) {
    let Some(receipt) = receipt else { return; };
    print_str(b"[kernel-section-unmap-retired] pointer="); print_hex_u64(receipt.pointer);
    print_str(b" native-generation="); print_u64(receipt.native_generation);
    print_str(b" view-generation="); print_u64(receipt.view_generation);
    print_str(b" provider-domain="); print_u64(receipt.provider_domain);
    print_str(b" provider-generation="); print_u64(receipt.provider_generation);
    print_str(b" base="); print_hex_u64(receipt.base);
    print_str(b" remaining-refs="); print_u64(receipt.remaining_references);
    print_str(b"\n");
}

/// Called only after physical ingress authentication and the actual cleanup operation return.
/// A retained caller can be recorded after exit without manufacturing fresh handle authority.
pub(crate) unsafe fn observe_cleanup_result(
    handler: *const ExecNtHandler,
    channel: &spawn_hosts::PumpChannel,
    physical: runtime::PhysicalSource,
    op: u64,
    target: u64,
    result: &Result<u64, u32>,
) {
    let runtime::PhysicalDomain::Provider { domain, .. } = physical.domain else { return; };
    let name: &[u8] = match op {
        nt_io_manager::win32k_mm_section_wire::OP_UNMAP => b"unmap",
        nt_io_manager::win32k_mm_section_wire::OP_DEREFERENCE => b"dereference",
        _ => return,
    };
    let actor = match (channel.logical_caller, channel.kernel_caller) {
        (Some(caller), None) => {
            let current = (*handler).pm.validate_thread_lifetime(caller.thread())
                && (*handler).capture_process_identity(caller.pi()) == Some(caller.process());
            Some((b"logical" as &[u8], caller.thread(), current))
        }
        (None, Some(caller)) => {
            let thread = caller.thread();
            let current = (*handler).pm.validate_thread_lifetime(thread)
                && (*handler).pm.process(thread.process_id()).is_some();
            Some((b"kernel" as &[u8], thread, current))
        }
        _ => None,
    };
    print_str(b"[kernel-section-cleanup-result] op="); print_str(name);
    print_str(b" target="); print_hex_u64(target);
    print_str(b" provider-domain="); print_u64(domain.domain);
    print_str(b" provider-generation="); print_u64(domain.generation);
    print_str(b" caller=");
    if let Some((kind, thread, current)) = actor {
        print_str(kind);
        print_str(b" pid="); print_u64(thread.process_id() as u64);
        print_str(b" tid="); print_u64(u64::from(thread.thread_id()));
        print_str(b" thread-generation="); print_u64(thread.generation());
        print_str(b" canonical-current="); print_u64(u64::from(current));
        print_str(b" process-signaled=");
        if current {
            print_u64(u64::from((*handler).pm.is_process_signaled(thread.process_id())));
        } else { print_str(b"unknown"); }
    } else {
        print_str(b"none canonical-current=0 process-signaled=unknown");
    }
    match result {
        Ok(value) => {
            print_str(b" status="); print_hex(0);
            print_str(b" return-value="); print_u64(*value);
        }
        Err(status) => { print_str(b" status="); print_hex(*status); }
    }
    print_str(b"\n");
}
