use super::*;
use crate::ps_bootstrap::{PsBootstrapParts, PsBootstrapState};
use nt_types::AccessMode;

fn fixture() -> (PsBootstrapParts, NativeHandleCaller) {
    let mut parts = PsBootstrapState::try_new(0x1000, 0).unwrap().into_parts();
    let pid = parts.pm.create_process("registry-actor", None, None);
    let tid = parts.pm.create_thread(pid, 0x2000, 0, false).unwrap();
    assert!(parts.pm.publish_process_kernel_object(pid, 0x3000));
    assert!(parts.pm.publish_thread_kernel_object(tid, 0x4000));
    let caller = parts
        .pm
        .capture_native_handle_caller(
            parts.pm.thread_lifetime(tid).unwrap(),
            AccessMode::KernelMode,
        )
        .unwrap();
    (parts, caller)
}

fn references(pm: &ProcessManager, caller: NativeHandleCaller) -> (u32, u32) {
    let blockers = pm
        .process_object_delete_blockers(caller.original_thread().process_id())
        .unwrap();
    (
        blockers.process_kernel_pointer_references,
        blockers.thread_kernel_pointer_references,
    )
}

#[test]
fn bootstrap_binds_once_and_rejects_other_physical_identity_or_epoch() {
    let (mut parts, caller) = fixture();
    let mut owners = RegistryCallerOwners::new();
    owners
        .capture(&mut parts.pm, 1u64, None, 0x5000, caller)
        .unwrap();
    assert_eq!(references(&parts.pm, caller), (1, 1));
    assert!(owners.resolve(&parts.pm, 2, 7u64, 0x5000).is_err());
    assert!(owners.resolve(&parts.pm, 1, 7, 0x6000).is_err());
    assert_eq!(owners.resolve(&parts.pm, 1, 7, 0x5000), Ok(caller));
    assert!(owners.resolve(&parts.pm, 1, 8, 0x5000).is_err());
    assert_eq!(owners.retire(&mut parts.pm, 1, 8), Ok(false));
    assert_eq!(references(&parts.pm, caller), (1, 1));
    assert_eq!(owners.retire(&mut parts.pm, 1, 7), Ok(true));
    assert_eq!(owners.retire(&mut parts.pm, 1, 7), Ok(false));
    assert_eq!(references(&parts.pm, caller), (0, 0));
}

#[test]
fn nested_provider_needs_explicit_inheritance_and_has_independent_retirement() {
    let (mut parts, caller) = fixture();
    let mut owners = RegistryCallerOwners::new();
    owners
        .capture(&mut parts.pm, 1u64, Some(7u64), 0x5000, caller)
        .unwrap();
    assert!(owners.resolve(&parts.pm, 2, 8, 0x6000).is_err());
    let inherited = owners.resolve(&parts.pm, 1, 7, 0x5000).unwrap();
    owners
        .capture(&mut parts.pm, 2, Some(8), 0x6000, inherited)
        .unwrap();
    assert_eq!(references(&parts.pm, caller), (2, 2));
    assert!(owners.retire(&mut parts.pm, 2, 8).unwrap());
    assert_eq!(references(&parts.pm, caller), (1, 1));
    assert_eq!(owners.resolve(&parts.pm, 1, 7, 0x5000), Ok(caller));
    assert!(owners.retire(&mut parts.pm, 1, 7).unwrap());
}

#[test]
fn uncertain_job_excludes_replacement_until_exact_completion() {
    let (mut parts, caller) = fixture();
    let mut owners = RegistryCallerOwners::new();
    owners
        .capture(&mut parts.pm, 1u64, Some(7u64), 0x5000, caller)
        .unwrap();
    assert!(owners
        .capture(&mut parts.pm, 1, Some(8), 0x5000, caller)
        .is_err());
    assert_eq!(owners.len(), 1);
    assert_eq!(references(&parts.pm, caller), (1, 1));
    assert!(owners.retire(&mut parts.pm, 1, 7).unwrap());
    owners
        .capture(&mut parts.pm, 1, Some(8), 0x5000, caller)
        .unwrap();
    assert!(owners.retire(&mut parts.pm, 1, 8).unwrap());
}

#[test]
fn foreign_manager_cannot_resolve_or_retire_and_exit_still_allows_cleanup() {
    let (mut parts, caller) = fixture();
    let (mut foreign, _) = fixture();
    let mut owners = RegistryCallerOwners::new();
    owners
        .capture(&mut parts.pm, 1u64, Some(7u64), 0x5000, caller)
        .unwrap();
    assert!(owners.resolve(&foreign.pm, 1, 7, 0x5000).is_err());
    assert!(owners.retire(&mut foreign.pm, 1, 7).is_err());
    assert_eq!(owners.len(), 1);
    parts
        .pm
        .terminate_thread(caller.original_thread().thread_id(), 0)
        .unwrap();
    assert!(owners.resolve(&parts.pm, 1, 7, 0x5000).is_err());
    assert!(owners.retire(&mut parts.pm, 1, 7).unwrap());
    assert!(owners.is_empty());
}

#[test]
fn autonomous_workers_have_distinct_system_threads_and_terminal_reference_owners() {
    let mut parts = PsBootstrapState::try_new(0x1000, 0).unwrap().into_parts();
    let system = parts.pm.initial_system_identity().unwrap();
    assert!(parts.pm.publish_process_kernel_object(system.process_id(), 0x10000));
    let mut callers = Vec::new();
    for body in [0x20000, 0x30000] {
        let tid = parts.pm.create_thread(system.process_id(), 0x40000, 0, true).unwrap();
        assert_ne!(tid, system.thread_id());
        assert!(parts.pm.publish_thread_kernel_object(tid, body));
        let caller = parts.pm.capture_native_handle_caller(
            parts.pm.thread_lifetime(tid).unwrap(), AccessMode::KernelMode,
        ).unwrap();
        callers.push(caller);
    }
    assert_ne!(callers[0].original_thread(), callers[1].original_thread());
    let mut owners = RegistryCallerOwners::new();
    for (route, caller) in callers.iter().copied().enumerate() {
        owners.capture(&mut parts.pm, route, Some(1u64), 0x50000, caller).unwrap();
    }
    parts.pm.terminate_thread(callers[0].original_thread().thread_id(), 0).unwrap();
    assert!(owners.resolve(&parts.pm, 0, 1, 0x50000).is_err());
    assert_eq!(owners.resolve(&parts.pm, 1, 1, 0x50000), Ok(callers[1]));
    assert!(owners.retire(&mut parts.pm, 0, 1).unwrap());
    assert!(!owners.retire(&mut parts.pm, 0, 1).unwrap());
    assert!(parts.pm.validate_initial_system_caller(system));
    assert!(owners.retire(&mut parts.pm, 1, 1).unwrap());
}
