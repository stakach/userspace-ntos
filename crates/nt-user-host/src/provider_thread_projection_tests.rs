use super::*;
use crate::ps_bootstrap::{PsBootstrapParts, PsBootstrapState};

fn fixture() -> (PsBootstrapParts, NativeHandleCaller, ThreadProjection) {
    let mut parts = PsBootstrapState::try_new(0x1000, 0).unwrap().into_parts();
    let pid = parts.pm.create_process("projection", None, None);
    let tid = parts.pm.create_thread(pid, 0x2000, 0, false).unwrap();
    assert!(parts.pm.publish_process_kernel_object(pid, 0x3000));
    assert!(parts.pm.publish_thread_kernel_object(tid, 0x4000));
    let caller = parts.pm.capture_native_handle_caller(parts.pm.thread_lifetime(tid).unwrap(),
        nt_types::AccessMode::KernelMode).unwrap();
    (parts, caller, ThreadProjection { executor: 1, address_space: 2,
        component_kpcr: 0x5000, executive_kpcr: 0x6000, thread_body: 0x4000 })
}

#[test]
fn bootstrap_binds_once_and_only_exact_completion_releases() {
    let (mut parts, caller, projection) = fixture();
    let mut owners = ProjectionOwners::new();
    owners.capture(&mut parts.pm, 1u64, None, caller, projection).unwrap();
    assert!(owners.completing(1, 10u64).is_err());
    owners.bind(&parts.pm, 1, 10, caller, projection).unwrap();
    assert!(owners.bind(&parts.pm, 1, 11, caller, projection).is_err());
    assert!(owners.retire(&mut parts.pm, 1, 11).is_err());
    assert_eq!(owners.completing(1, 10), Ok(Some(projection)));
    owners.retire(&mut parts.pm, 1, 10).unwrap();
    assert!(!owners.contains(1));
    let blockers = parts.pm.process_object_delete_blockers(caller.original_thread().process_id()).unwrap();
    assert_eq!(blockers.thread_kernel_pointer_references, 0);
    assert_eq!(blockers.process_kernel_pointer_references, 0);
}

#[test]
fn uncertain_release_retains_identity_and_excludes_replay() {
    let (mut parts, caller, projection) = fixture();
    let mut owners = ProjectionOwners::new();
    owners.capture(&mut parts.pm, 1u64, Some(10u64), caller, projection).unwrap();
    owners.hold(1, 10).unwrap();
    assert!(owners.completing(1, 10).is_err());
    assert!(owners.begin_restore(&parts.pm, 1, 11).is_err());
    assert_eq!(owners.begin_restore(&parts.pm, 1, 10), Ok(Some(projection)));
    assert!(owners.begin_restore(&parts.pm, 1, 10).is_err());
    assert!(owners.capture(&mut parts.pm, 2, Some(11), caller, projection).is_err());
    assert!(owners.retire(&mut parts.pm, 1, 10).is_err());
    owners.restored(1, 10).unwrap();
    owners.retire(&mut parts.pm, 1, 10).unwrap();
}

#[test]
fn held_parent_allows_exact_nested_projection_on_same_executor() {
    let (mut parts, caller, projection) = fixture();
    let second_tid = parts.pm.create_thread(caller.original_thread().process_id(),
        0x7000, 0, false).unwrap();
    assert!(parts.pm.publish_thread_kernel_object(second_tid, 0x8000));
    let second_caller = parts.pm.capture_native_handle_caller(
        parts.pm.thread_lifetime(second_tid).unwrap(),
        nt_types::AccessMode::KernelMode,
    ).unwrap();
    let second_projection = ThreadProjection { thread_body: 0x8000, ..projection };
    let mut owners = ProjectionOwners::new();
    owners.capture(&mut parts.pm, 1u64, Some(10u64), caller, projection).unwrap();
    assert_eq!(owners.hold(1, 10), Ok(true));
    owners.capture(&mut parts.pm, 1, Some(11), second_caller, second_projection).unwrap();
    assert_eq!(owners.completing(1, 11), Ok(Some(second_projection)));
    owners.retire(&mut parts.pm, 1, 11).unwrap();
    assert_eq!(owners.begin_restore(&parts.pm, 1, 10), Ok(Some(projection)));
    owners.restored(1, 10).unwrap();
    owners.retire(&mut parts.pm, 1, 10).unwrap();
}

#[test]
fn different_executors_cannot_share_a_kpcr_in_one_address_space() {
    let (mut parts, caller, projection) = fixture();
    let mut owners = ProjectionOwners::new();
    owners.capture(&mut parts.pm, 1u64, Some(10u64), caller, projection).unwrap();
    let mut second = projection;
    second.executor = 3;
    second.executive_kpcr = 0x7000;
    assert!(owners.capture(&mut parts.pm, 2, Some(11), caller, second).is_err());
    second.component_kpcr = 0x8000;
    owners.capture(&mut parts.pm, 2, Some(11), caller, second).unwrap();
    owners.hold(1, 10).unwrap();
    assert_eq!(owners.completing(2, 11), Ok(Some(second)));
    owners.retire(&mut parts.pm, 2, 11).unwrap();
    assert!(owners.contains(1));
}

#[test]
fn foreign_manager_and_forged_thread_body_cannot_project() {
    let (mut parts, caller, projection) = fixture();
    let (foreign, _, _) = fixture();
    let mut owners = ProjectionOwners::new();
    let mut forged = projection;
    forged.thread_body += 0x1000;
    assert!(owners.capture(&mut parts.pm, 1u64, Some(10u64), caller, forged).is_err());
    owners.capture(&mut parts.pm, 1, Some(10), caller, projection).unwrap();
    owners.hold(1, 10).unwrap();
    assert!(owners.begin_restore(&foreign.pm, 1, 10).is_err());
    assert_eq!(owners.begin_restore(&parts.pm, 1, 10), Ok(Some(projection)));
}

#[test]
fn confirmed_stop_can_retire_uncertain_projection_but_not_another_executor() {
    let (mut parts, caller, projection) = fixture();
    let (mut foreign, _, _) = fixture();
    let mut owners = ProjectionOwners::new();
    owners.capture(&mut parts.pm, 1u64, Some(10u64), caller, projection).unwrap();
    owners.hold(1, 10).unwrap();
    owners.begin_restore(&parts.pm, 1, 10).unwrap();
    assert!(owners.retire_stopped(&mut parts.pm, 1, 2, projection.address_space).is_err());
    assert!(owners.retire_stopped(&mut foreign.pm, 1, projection.executor, projection.address_space).is_err());
    assert!(owners.contains(1));
    owners.retire_stopped(&mut parts.pm, 1, projection.executor, projection.address_space).unwrap();
    assert!(!owners.contains(1));
}
