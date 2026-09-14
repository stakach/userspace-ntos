//! IRQL follows the exact executing stack activation, never a shared last-writer byte.

use super::*;

pub(super) fn protocol_fault(operation: &[u8]) -> ! {
    print_str(b"[win32k-irql] invalid execution context or IRQL: ");
    print_str(operation);
    print_str(b"\n");
    park()
}

pub(super) extern "win64" fn get_current() -> u8 {
    unsafe {
        let activation = active_provider_stack_event_activation()
            .unwrap_or_else(|| protocol_fault(b"KeGetCurrentIrql"));
        (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
            .as_ref()
            .and_then(|catalog| catalog.current_irql(activation).ok())
            .unwrap_or_else(|| protocol_fault(b"KeGetCurrentIrql"))
    }
}

/// The rewritten CR8 instruction originally defined all of RAX, not merely the KIRQL byte.
pub(super) extern "win64" fn read_cr8() -> u64 {
    u64::from(get_current())
}

pub(super) extern "win64" fn raise(new: u8) -> u8 {
    unsafe {
        let activation = active_provider_stack_event_activation()
            .unwrap_or_else(|| protocol_fault(b"KfRaiseIrql"));
        (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS))
            .as_mut()
            .and_then(|catalog| catalog.raise_irql(activation, new).ok())
            .unwrap_or_else(|| protocol_fault(b"KfRaiseIrql"))
    }
}

pub(super) extern "win64" fn lower(new: u8) {
    unsafe {
        let activation = active_provider_stack_event_activation()
            .unwrap_or_else(|| protocol_fault(b"KeLowerIrql"));
        (&mut *core::ptr::addr_of_mut!(WIN32K_STACK_EVENT_ACTIVATIONS))
            .as_mut()
            .and_then(|catalog| catalog.lower_irql(activation, new).ok())
            .unwrap_or_else(|| protocol_fault(b"KeLowerIrql"));
    }
}

pub(super) extern "win64" fn raise_to_dpc() -> u8 {
    raise(nt_kernel_exec::DISPATCH_LEVEL)
}

pub(super) fn require_wait(timeout: nt_provider_wait::ProviderWaitTimeoutKind) {
    let allowed = unsafe {
        let activation = active_provider_stack_event_activation()
            .unwrap_or_else(|| protocol_fault(b"dispatcher wait"));
        (&*core::ptr::addr_of!(WIN32K_STACK_EVENT_ACTIVATIONS))
            .as_ref()
            .and_then(|catalog| catalog.can_wait(activation, timeout).ok())
            .unwrap_or(false)
    };
    if !allowed {
        protocol_fault(b"dispatcher wait");
    }
}

pub(super) fn require_passive(operation: &[u8]) {
    if get_current() != nt_kernel_exec::PASSIVE_LEVEL {
        protocol_fault(operation);
    }
}
