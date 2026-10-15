//! Snapshot hints are checked against actual TCB VSpace objects before receive-yield effects.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;
type Binding = nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>;

static mut OBSERVER: Option<crate::hosted_process_vspace::VSpaceObserver> = None;

/// Install a read-only reference to the same canonical journal before provider dispatch begins.
pub(crate) unsafe fn install(observer: crate::hosted_process_vspace::VSpaceObserver) {
    assert!((*core::ptr::addr_of!(OBSERVER)).is_none());
    core::ptr::write(core::ptr::addr_of_mut!(OBSERVER), Some(observer));
}

/// Read-only hint while the provider owns the outer mutable executive borrow. The kernel
/// query below supplies physical identity; neither this cap number nor PI is authority.
pub(crate) unsafe fn peek_root(binding: Binding) -> Option<u64> {
    (&*core::ptr::addr_of!(OBSERVER))
        .as_ref()?
        .expected_child_root(binding)
}

pub(crate) unsafe fn validate_pair(
    child_tcb: u64,
    child_root: u64,
    provider_tcb: u64,
    provider_root: u64,
) -> bool {
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    // Both roots are checked against their actual TCB binding. Comparing cptrs would admit
    // two aliases of the same PML4; the kernel compares the referenced physical root objects.
    let child = sel4_rt::vspace_binding::query(child_tcb, child_root, provider_root);
    if child != Ok(sel4_rt::vspace_binding::Binding::MatchesSeparate) {
        return false;
    }
    let provider = sel4_rt::vspace_binding::query(provider_tcb, provider_root, child_root);
    provider == Ok(sel4_rt::vspace_binding::Binding::MatchesSeparate)
}

pub(crate) unsafe fn validate_current(
    handler: &ExecNtHandler,
    binding: Binding,
    observed: runtime::ReceiveChildObservation,
) -> bool {
    if handler.capture_process_identity(binding.pi) != Some(binding.process) {
        return false;
    }
    let Some(child_root) = handler
        .hosted_vspace_observer()
        .expected_child_root(binding)
    else {
        return false;
    };
    validate_pair(
        binding.tcb,
        child_root,
        observed.provider_tcb,
        observed.provider_pml4,
    )
}
