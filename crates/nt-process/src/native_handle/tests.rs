use super::*;

fn fixture() -> (
    ProcessManager,
    NativeHandleCaller,
    NativeHandleCaller,
    ProcessId,
    crate::ThreadId,
) {
    let mut pm = ProcessManager::new();
    let system_pid = pm.create_process("kernel", None, None);
    let system_tid = pm.create_thread(system_pid, 0, 0, true).unwrap();
    pm.designate_initial_system(system_pid, system_tid).unwrap();
    assert!(pm.publish_process_kernel_object(system_pid, 0x1000));
    assert!(pm.publish_thread_kernel_object(system_tid, 0x2000));
    let pid = pm.create_process("client", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x3000));
    assert!(pm.publish_thread_kernel_object(tid, 0x4000));
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let user = pm
        .capture_native_handle_caller(lifetime, AccessMode::UserMode)
        .unwrap();
    let kernel = pm
        .capture_native_handle_caller(lifetime, AccessMode::KernelMode)
        .unwrap();
    (pm, user, kernel, pid, tid)
}

fn counts(pm: &ProcessManager, pid: ProcessId, tid: crate::ThreadId) -> (u32, u32) {
    (
        pm.process(pid).unwrap().kernel_pointer_references,
        pm.thread(tid).unwrap().kernel_pointer_references,
    )
}

#[test]
fn strict_native_scope_never_truncates_or_confuses_pseudo_handles() {
    let (pm, user, kernel, pid, _) = fixture();
    assert_eq!(
        pm.decode_native_handle(user, u64::MAX),
        Ok(NativeHandleScope::CurrentProcess)
    );
    assert_eq!(
        pm.decode_native_handle(kernel, u64::MAX - 1),
        Ok(NativeHandleScope::CurrentThread)
    );
    assert_eq!(
        pm.decode_native_handle(kernel, 4),
        Ok(NativeHandleScope::Table {
            owner: pid,
            handle: 4,
            kernel: false,
        })
    );
    let system = pm.initial_system_identity().unwrap().process_id();
    assert_eq!(
        pm.decode_native_handle(kernel, KERNEL_HANDLE_TAG | 4),
        Ok(NativeHandleScope::Table {
            owner: system,
            handle: 4,
            kernel: true
        })
    );
    assert_eq!(
        pm.decode_native_handle(user, KERNEL_HANDLE_TAG | 4),
        Err(STATUS_INVALID_HANDLE)
    );
    for value in [
        0,
        1,
        3,
        0x8000_0004,
        0x1_0000_0004,
        0xffff_fffe_8000_0004,
        KERNEL_HANDLE_TAG,
        KERNEL_HANDLE_TAG | 1,
    ] {
        assert_eq!(
            pm.decode_native_handle(kernel, value),
            Err(STATUS_INVALID_HANDLE),
            "{value:x}"
        );
    }
    for tags in 0..4 {
        assert_eq!(
            pm.decode_native_handle(user, 4 | tags),
            Ok(NativeHandleScope::Table {
                owner: pid,
                handle: 4,
                kernel: false,
            })
        );
        assert_eq!(
            pm.decode_native_handle(kernel, KERNEL_HANDLE_TAG | 4 | tags),
            Ok(NativeHandleScope::Table {
                owner: system,
                handle: 4,
                kernel: true
            })
        );
    }
    assert_eq!(
        pm.decode_native_handle(kernel, u64::MAX - 2),
        Ok(NativeHandleScope::Table {
            owner: system,
            handle: MAX_RAW_HANDLE as Handle,
            kernel: true,
        })
    );
}

#[test]
fn real_user_handles_enforce_type_and_grants_before_reference_acquisition() {
    let (mut pm, user, kernel, pid, tid) = fixture();
    let handle = pm
        .insert_handle(pid, HandleObject::Process(pid), 0x400)
        .unwrap();
    pm.set_handle_flags(
        pid,
        handle,
        HandleFlags {
            inherit: true,
            protect_from_close: true,
        },
    )
    .unwrap();
    assert_eq!(
        pm.reference_native_ps_handle(user, handle.into(), Some(PsHandleType::Thread), 0)
            .unwrap_err(),
        STATUS_OBJECT_TYPE_MISMATCH
    );
    assert_eq!(
        pm.reference_native_ps_handle(user, handle.into(), None, 0x800)
            .unwrap_err(),
        STATUS_ACCESS_DENIED
    );
    assert_eq!(counts(&pm, pid, tid), (0, 0));
    let mut reference = pm
        .reference_native_ps_handle(user, handle.into(), Some(PsHandleType::Process), 0x400)
        .unwrap();
    assert_eq!(reference.body(), 0x3000);
    assert_eq!(
        reference.information(),
        NativeHandleInformation {
            attributes: 3,
            granted_access: Some(0x400)
        }
    );
    assert_eq!(counts(&pm, pid, tid), (1, 0));
    reference.release(&mut pm).unwrap();
    let mut reference = pm
        .reference_native_ps_handle(kernel, handle.into(), None, u32::MAX)
        .unwrap();
    assert_eq!(counts(&pm, pid, tid), (1, 0));
    reference.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, pid, tid), (0, 0));
}

#[test]
fn pseudo_handles_acquire_one_reference_including_real_system_objects() {
    let (mut pm, user, _, pid, tid) = fixture();
    let mut process = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let mut thread = pm
        .reference_native_ps_handle(user, u64::MAX - 1, None, 0)
        .unwrap();
    assert_eq!(counts(&pm, pid, tid), (1, 1));
    process.release(&mut pm).unwrap();
    thread.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, pid, tid), (0, 0));
    let system = pm.initial_system_identity().unwrap();
    let caller = pm
        .capture_native_handle_caller(system.thread(), AccessMode::KernelMode)
        .unwrap();
    let mut reference = pm
        .reference_native_ps_handle(caller, u64::MAX, None, 0)
        .unwrap();
    assert_eq!(reference.body(), 0x1000);
    assert_eq!(counts(&pm, system.process_id(), system.thread_id()), (2, 1));
    reference.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, system.process_id(), system.thread_id()), (1, 1));
}

#[test]
fn caller_exit_rejects_new_work_but_preserves_owned_reference_rollback() {
    let (mut pm, user, _, pid, tid) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    pm.terminate_process(pid, 0).unwrap();
    assert_eq!(pm.decode_native_handle(user, 4), Err(STATUS_INVALID_HANDLE));
    reference.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, pid, tid), (0, 0));
    assert_eq!(reference.release(&mut pm), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn replacement_manager_and_changed_activation_cannot_consume_reference() {
    let (mut first, user, _, pid, tid) = fixture();
    let (mut second, _, _, _, _) = fixture();
    let mut reference = first
        .reference_native_ps_handle(user, u64::MAX - 1, None, 0)
        .unwrap();
    assert_eq!(
        second.decode_native_handle(user, 4),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(reference.release(&mut second), Err(STATUS_INVALID_HANDLE));
    assert!(reference.is_held());
    assert_eq!(counts(&second, pid, tid), (0, 0));
    let generation = first.threads.get_mut(&tid).unwrap().activation_generation;
    first.threads.get_mut(&tid).unwrap().activation_generation += 1;
    assert_eq!(
        first.decode_native_handle(user, 4),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(reference.release(&mut first), Err(STATUS_INVALID_HANDLE));
    assert!(reference.is_held());
    first.threads.get_mut(&tid).unwrap().activation_generation = generation;
    reference.release(&mut first).unwrap();
}

#[test]
fn handle_close_and_manager_move_do_not_invalidate_acquired_reference() {
    let (mut pm, user, _, pid, tid) = fixture();
    let handle = pm.insert_handle(pid, HandleObject::Thread(tid), 0).unwrap();
    let mut reference = pm
        .reference_native_ps_handle(user, handle.into(), None, 0)
        .unwrap();
    pm.close_handle(pid, handle).unwrap();
    let mut moved = alloc::boxed::Box::new(pm);
    assert_eq!(counts(&moved, pid, tid), (0, 1));
    reference.release(&mut moved).unwrap();
    assert_eq!(counts(&moved, pid, tid), (0, 0));
}

#[test]
fn missing_projection_wrong_object_and_overflow_fail_without_partial_references() {
    let (mut pm, user, _, pid, tid) = fixture();
    let event = pm.insert_handle(pid, HandleObject::Opaque(7), 0).unwrap();
    assert_eq!(
        pm.reference_native_ps_handle(user, event.into(), None, 0)
            .unwrap_err(),
        STATUS_OBJECT_TYPE_MISMATCH
    );
    pm.processes.get_mut(&pid).unwrap().kernel_process_object = None;
    assert_eq!(
        pm.reference_native_ps_handle(user, u64::MAX, None, 0)
            .unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    pm.processes.get_mut(&pid).unwrap().kernel_process_object = Some(0x3000);
    pm.processes
        .get_mut(&pid)
        .unwrap()
        .kernel_pointer_references = u32::MAX;
    assert_eq!(
        pm.reference_native_ps_handle(user, u64::MAX, None, 0)
            .unwrap_err(),
        crate::STATUS_INSUFFICIENT_RESOURCES
    );
    assert_eq!(counts(&pm, pid, tid), (u32::MAX, 0));
}

#[test]
fn authorized_kernel_handle_uses_existing_system_table_and_owns_target_lifetime() {
    let (mut pm, user, kernel, pid, tid) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let system = pm.initial_system_identity().unwrap().process_id();
    let before = pm.handle_count(system);
    assert_eq!(
        pm.insert_authorized_native_ps_handle(user, &reference, 0, OBJ_KERNEL_HANDLE),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.insert_authorized_native_ps_handle(kernel, &reference, 0, 0x4000),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.handle_count(system), before);
    let value = pm
        .insert_authorized_native_ps_handle(kernel, &reference, 0x400, OBJ_KERNEL_HANDLE)
        .unwrap();
    let raw = (value & !KERNEL_HANDLE_TAG) as Handle;
    assert_eq!(
        pm.lookup_handle(system, raw),
        Some(HandleObject::Process(pid))
    );
    assert_eq!(pm.handle_count(system), before + 1);
    assert_eq!(pm.handle_reservation_count(system), 0);
    assert_eq!(
        pm.reference_native_ps_handle(user, value, None, 0)
            .unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    let mut second = pm
        .reference_native_ps_handle(kernel, value, Some(PsHandleType::Process), u32::MAX)
        .unwrap();
    assert_eq!(counts(&pm, pid, tid), (2, 0));
    second.release(&mut pm).unwrap();
    reference.release(&mut pm).unwrap();
    pm.terminate_process(pid, 0).unwrap();
    assert!(!pm.process_object_delete_ready(pid));
    pm.close_handle(system, raw).unwrap();
    assert_eq!(pm.handle_count(system), before);
}

#[test]
fn successful_publication_transfers_reference_to_existing_ob_dereference_path() {
    let (mut pm, user, _, pid, tid) = fixture();
    let reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let body = reference.into_body().unwrap();
    assert_eq!(counts(&pm, pid, tid), (1, 0));
    pm.release_kernel_object_pointer(body).unwrap();
    assert_eq!(counts(&pm, pid, tid), (0, 0));
}

#[test]
fn unknown_pseudo_self_grants_never_become_synthetic_access_or_information() {
    let (mut pm, user, kernel, pid, tid) = fixture();
    for value in [u64::MAX, u64::MAX - 1] {
        assert_eq!(
            pm.reference_native_ps_handle(user, value, None, 1)
                .unwrap_err(),
            STATUS_NOT_SUPPORTED
        );
        assert_eq!(counts(&pm, pid, tid), (0, 0));
        let mut reference = pm.reference_native_ps_handle(user, value, None, 0).unwrap();
        assert_eq!(reference.information().granted_access, None);
        reference.release(&mut pm).unwrap();
        let mut reference = pm
            .reference_native_ps_handle(kernel, value, None, u32::MAX)
            .unwrap();
        assert_eq!(reference.information().granted_access, None);
        reference.release(&mut pm).unwrap();
    }
    assert_eq!(counts(&pm, pid, tid), (0, 0));
}

#[test]
fn system_root_teardown_cannot_prevent_exact_reference_cleanup() {
    let (mut pm, user, _, pid, tid) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX - 1, None, 0)
        .unwrap();
    let system = pm.initial_system_identity().unwrap();
    pm.release_initial_system_references(system).unwrap();
    pm.terminate_process(system.process_id(), 0).unwrap();
    assert!(pm
        .delete_process_object_if_unreferenced(system.process_id())
        .is_some());
    assert_eq!(pm.initial_system_identity(), None);
    assert_eq!(pm.decode_native_handle(user, 4), Err(STATUS_INVALID_HANDLE));
    reference.release(&mut pm).unwrap();
    assert!(!reference.is_held());
    assert_eq!(counts(&pm, pid, tid), (0, 0));
}

#[test]
fn prepared_handle_is_invisible_but_keeps_terminated_target_alive_without_pointer_lease() {
    let (mut pm, user, kernel, pid, tid) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let mut publication = pm
        .prepare_authorized_native_ps_handle(kernel, &reference, 0x400, OBJ_KERNEL_HANDLE)
        .unwrap();
    let system = pm.initial_system_identity().unwrap().process_id();
    assert_eq!(pm.handle_count(system), 0);
    assert_eq!(pm.handle_reservation_count(system), 1);
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::Process(pid)),
        1
    );
    assert_eq!(
        pm.reference_native_ps_handle(kernel, publication.value(), None, 0)
            .unwrap_err(),
        STATUS_INVALID_HANDLE
    );
    assert_eq!(pm.take_any_handle(system), None);
    reference.release(&mut pm).unwrap();
    assert_eq!(counts(&pm, pid, tid), (0, 0));
    pm.terminate_process(pid, 0).unwrap();
    assert!(!pm.process_object_delete_ready(pid));
    assert!(pm.delete_process_object_if_unreferenced(pid).is_none());
    let handle = publication.publish(&mut pm).unwrap();
    assert_eq!(
        publication.phase(),
        NativePsHandlePublicationPhase::Published
    );
    assert_eq!(pm.handle_reservation_count(system), 0);
    assert_eq!(
        pm.lookup_handle(system, (handle & !KERNEL_HANDLE_TAG) as Handle),
        Some(HandleObject::Process(pid))
    );
    pm.close_handle(system, (handle & !KERNEL_HANDLE_TAG) as Handle)
        .unwrap();
    assert!(pm.delete_process_object_if_unreferenced(pid).is_some());
}

#[test]
fn terminated_table_owner_requires_abort_and_cannot_be_deleted_while_bound() {
    let (mut pm, user, _, pid, tid) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX - 1, None, 0)
        .unwrap();
    let mut publication = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0, 0)
        .unwrap();
    reference.release(&mut pm).unwrap();
    pm.terminate_process(pid, 0).unwrap();
    assert!(!pm.process_object_delete_ready(pid));
    assert_eq!(
        publication.publish(&mut pm),
        Err(crate::STATUS_PROCESS_IS_TERMINATING)
    );
    assert_eq!(publication.phase(), NativePsHandlePublicationPhase::Bound);
    assert_eq!(pm.handle_reservation_count(pid), 1);
    publication.abort(&mut pm).unwrap();
    assert_eq!(counts(&pm, pid, tid), (0, 0));
    assert_eq!(pm.handle_reservation_count(pid), 0);
    assert!(pm.delete_process_object_if_unreferenced(pid).is_some());
}

#[test]
fn completed_publication_and_abort_cannot_mutate_reused_raw_slot() {
    let (mut pm, user, _, pid, _) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let mut published = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0x400, OBJ_INHERIT)
        .unwrap();
    let handle = published.publish(&mut pm).unwrap();
    assert_eq!(
        pm.handle_flags(pid, handle as Handle).unwrap().inherit,
        true
    );
    pm.close_handle(pid, handle as Handle).unwrap();
    let reused = pm
        .insert_handle(pid, HandleObject::Opaque(900), 0x20)
        .unwrap();
    assert_eq!(u64::from(reused), handle);
    assert_eq!(published.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(published.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(
        pm.lookup_handle(pid, reused),
        Some(HandleObject::Opaque(900))
    );
    let mut aborted = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0, 0)
        .unwrap();
    aborted.abort(&mut pm).unwrap();
    assert_eq!(aborted.phase(), NativePsHandlePublicationPhase::Aborted);
    assert_eq!(aborted.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(aborted.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    reference.release(&mut pm).unwrap();
}

#[test]
fn external_cancellation_and_rebinding_retain_failed_transaction_without_touching_new_owner() {
    let (mut pm, user, _, pid, _) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let mut stale = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0, 0)
        .unwrap();
    pm.cancel_bound_handle(stale.reservation).unwrap();
    let mut current = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0, 0)
        .unwrap();
    assert_eq!(stale.value(), current.value());
    assert_ne!(stale.reservation.generation, current.reservation.generation);
    assert_eq!(stale.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(stale.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(stale.phase(), NativePsHandlePublicationPhase::Bound);
    assert_eq!(pm.handle_reservation_count(pid), 1);
    current.abort(&mut pm).unwrap();
    reference.release(&mut pm).unwrap();
}

#[test]
fn publication_wrong_manager_cannot_consume_colliding_bound_reservation() {
    let (mut first, caller, _, pid, _) = fixture();
    let (mut second, second_caller, _, _, _) = fixture();
    let mut reference = first
        .reference_native_ps_handle(caller, u64::MAX, None, 0)
        .unwrap();
    let mut other_reference = second
        .reference_native_ps_handle(second_caller, u64::MAX, None, 0)
        .unwrap();
    let mut publication = first
        .prepare_authorized_native_ps_handle(caller, &reference, 0, 0)
        .unwrap();
    let mut other_publication = second
        .prepare_authorized_native_ps_handle(second_caller, &other_reference, 0, 0)
        .unwrap();
    assert_eq!(publication.reservation, other_publication.reservation);
    assert_eq!(publication.publish(&mut second), Err(STATUS_INVALID_HANDLE));
    assert_eq!(publication.abort(&mut second), Err(STATUS_INVALID_HANDLE));
    assert_eq!(first.handle_reservation_count(pid), 1);
    assert_eq!(second.handle_reservation_count(pid), 1);
    publication.abort(&mut first).unwrap();
    other_publication.abort(&mut second).unwrap();
    reference.release(&mut first).unwrap();
    other_reference.release(&mut second).unwrap();
}

#[test]
fn bound_attribute_change_is_rejected_before_publication_or_rollback_mutation() {
    let (mut pm, user, _, pid, _) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let mut publication = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0x400, OBJ_INHERIT)
        .unwrap();
    let slot = crate::handle_to_slot(publication.reservation.handle).unwrap();
    if let crate::HandleSlot::Bound { entry, .. } =
        &mut pm.processes.get_mut(&pid).unwrap().handles[slot]
    {
        entry.flags.inherit = false;
    } else {
        panic!("expected bound handle");
    }
    assert_eq!(publication.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(publication.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(publication.phase(), NativePsHandlePublicationPhase::Bound);
    assert_eq!(pm.handle_count(pid), 0);
    if let crate::HandleSlot::Bound { entry, .. } =
        &mut pm.processes.get_mut(&pid).unwrap().handles[slot]
    {
        entry.flags.inherit = true;
    }
    publication.abort(&mut pm).unwrap();
    reference.release(&mut pm).unwrap();
}

#[test]
fn reservation_generation_exhaustion_does_not_allocate_mutate_or_wrap() {
    let (mut pm, user, _, pid, _) = fixture();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::MAX, None, 0)
        .unwrap();
    let capacity = pm.handle_capacity(pid);
    for generation in [0, u64::MAX] {
        pm.processes
            .get_mut(&pid)
            .unwrap()
            .next_handle_reservation_generation = generation;
        assert_eq!(
            pm.prepare_authorized_native_ps_handle(user, &reference, 0, 0)
                .unwrap_err(),
            crate::STATUS_INSUFFICIENT_RESOURCES
        );
        assert_eq!(
            pm.process(pid).unwrap().next_handle_reservation_generation,
            generation
        );
        assert_eq!(pm.handle_reservation_count(pid), 0);
        assert_eq!(pm.handle_capacity(pid), capacity);
    }
    pm.processes
        .get_mut(&pid)
        .unwrap()
        .next_handle_reservation_generation = u64::MAX - 1;
    let mut last = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0, 0)
        .unwrap();
    assert_eq!(last.reservation.generation, u64::MAX - 1);
    last.abort(&mut pm).unwrap();
    assert_eq!(
        pm.try_reserve_handle_slot(pid),
        Err(crate::STATUS_INSUFFICIENT_RESOURCES)
    );
    assert_eq!(
        pm.process(pid).unwrap().next_handle_reservation_generation,
        u64::MAX
    );
    reference.release(&mut pm).unwrap();
}

fn bound_thread_reactivation_regression(terminated: bool) {
    let (mut pm, user, _, pid, _) = fixture();
    let target = pm.create_dormant_thread(pid).unwrap();
    assert!(pm.publish_thread_kernel_object(target, 0x5000));
    let prepare = |pm: &ProcessManager| {
        pm.prepare_thread_activation(target, 0x6000, 0, false, 0x7000, 123, false)
    };
    if terminated {
        let first = prepare(&pm).unwrap();
        pm.commit_thread_activation(first).unwrap();
        pm.terminate_thread(target, 0).unwrap();
        assert!(pm.can_reclaim_thread(target));
    }
    let lifetime = pm.thread_lifetime(target).unwrap();
    let plan_before_binding = prepare(&pm).unwrap();
    let source = pm
        .insert_handle(pid, HandleObject::Thread(target), 0)
        .unwrap();
    let mut reference = pm
        .reference_native_ps_handle(user, u64::from(source), None, 0)
        .unwrap();
    pm.close_handle(pid, source).unwrap();
    let mut publication = pm
        .prepare_authorized_native_ps_handle(user, &reference, 0, 0)
        .unwrap();
    reference.release(&mut pm).unwrap();
    assert_eq!(pm.thread(target).unwrap().kernel_pointer_references, 0);
    assert_eq!(pm.handle_object_count(HandleObject::Thread(target)), 0);
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::Thread(target)),
        1
    );
    assert!(!pm.can_reclaim_thread(target));
    assert_eq!(prepare(&pm), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        pm.commit_thread_activation(plan_before_binding),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(pm.thread_lifetime(target), Some(lifetime));
    assert_eq!(publication.phase(), NativePsHandlePublicationPhase::Bound);
    publication.abort(&mut pm).unwrap();
    if terminated {
        assert!(pm.can_reclaim_thread(target));
    }
    assert!(prepare(&pm).is_ok());
    pm.commit_thread_activation(plan_before_binding).unwrap();
    assert_ne!(pm.thread_lifetime(target), Some(lifetime));
}

#[test]
fn bound_initialized_thread_handle_blocks_new_and_precomputed_activation() {
    bound_thread_reactivation_regression(false);
}

#[test]
fn bound_terminated_thread_handle_blocks_reclaim_and_precomputed_activation() {
    bound_thread_reactivation_regression(true);
}

fn incoming_handle_blocks_creation_abort(thread_target: bool, publish: bool) {
    let (mut pm, caller, _, owner, _) = fixture();
    let pid = pm.create_process("unpublished", None, None);
    let tid = pm.create_thread(pid, 0x8000, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(pid, 0x5000));
    assert!(pm.publish_thread_kernel_object(tid, 0x6000));
    let object = if thread_target {
        HandleObject::Thread(tid)
    } else {
        HandleObject::Process(pid)
    };
    let source = pm.insert_handle(owner, object, 0).unwrap();
    let mut reference = pm
        .reference_native_ps_handle(caller, u64::from(source), None, 0)
        .unwrap();
    pm.close_handle(owner, source).unwrap();
    let mut transaction = pm
        .prepare_authorized_native_ps_handle(caller, &reference, 0, 0)
        .unwrap();
    reference.release(&mut pm).unwrap();
    if publish {
        transaction.publish(&mut pm).unwrap();
    }
    assert_eq!(counts(&pm, pid, tid), (0, 0));
    assert!(pm.abort_process_creation(pid).is_none());
    assert!(pm.process(pid).is_some());
    assert!(pm.thread(tid).is_some());
    if publish {
        pm.close_handle(owner, transaction.value() as Handle)
            .unwrap();
    } else {
        transaction.abort(&mut pm).unwrap();
    }
    assert!(pm.abort_process_creation(pid).is_some());
    assert!(pm.process(pid).is_none());
    assert!(pm.thread(tid).is_none());
}

#[test]
fn incoming_bound_process_and_thread_handles_block_creation_abort() {
    incoming_handle_blocks_creation_abort(false, false);
    incoming_handle_blocks_creation_abort(true, false);
}

#[test]
fn incoming_visible_process_and_thread_handles_block_creation_abort() {
    incoming_handle_blocks_creation_abort(false, true);
    incoming_handle_blocks_creation_abort(true, true);
}

fn exact_creation_handle_activation(terminated: bool) {
    let (mut pm, _, _, pid, main_tid) = fixture();
    let tid = pm.create_dormant_thread(pid).unwrap();
    assert!(pm.publish_thread_kernel_object(tid, 0x5000));
    let prepare = |pm: &ProcessManager| {
        pm.prepare_thread_activation(tid, 0x6000, 0, false, 0x7000, 123, false)
    };
    if terminated {
        let first = prepare(&pm).unwrap();
        pm.commit_thread_activation(first).unwrap();
        pm.terminate_thread(tid, 0).unwrap();
    }
    let plan = prepare(&pm).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let own = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(own, HandleObject::Thread(tid), 0)
        .unwrap();
    assert_eq!(
        pm.commit_thread_activation(plan),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.commit_thread_activation_with_handle(
            plan,
            crate::HandleReservation {
                generation: own.generation + 1,
                ..own
            }
        ),
        Err(STATUS_INVALID_HANDLE)
    );
    let wrong = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(wrong, HandleObject::Thread(main_tid), 0)
        .unwrap();
    assert_eq!(
        pm.commit_thread_activation_with_handle(plan, wrong),
        Err(STATUS_INVALID_HANDLE)
    );
    pm.cancel_bound_handle(wrong).unwrap();
    let extra = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(extra, HandleObject::Thread(tid), 0)
        .unwrap();
    assert_eq!(
        pm.commit_thread_activation_with_handle(plan, own),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.cancel_bound_handle(extra).unwrap();
    let visible = pm.insert_handle(pid, HandleObject::Thread(tid), 0).unwrap();
    assert_eq!(
        pm.commit_thread_activation_with_handle(plan, own),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.close_handle(pid, visible).unwrap();
    let (body, _) = pm.lookup_kernel_thread_by_id(tid).unwrap();
    assert_eq!(
        pm.commit_thread_activation_with_handle(plan, own),
        Err(STATUS_INVALID_PARAMETER)
    );
    pm.release_kernel_object_pointer(body).unwrap();
    assert_eq!(pm.thread_lifetime(tid), Some(lifetime));
    assert_eq!(pm.lookup_handle(pid, own.handle), None);
    pm.commit_thread_activation_with_handle(plan, own).unwrap();
    assert_ne!(pm.thread_lifetime(tid), Some(lifetime));
    assert_eq!(pm.lookup_handle(pid, own.handle), None);
    pm.publish_reserved_handle(own).unwrap();
    assert_eq!(
        pm.lookup_handle(pid, own.handle),
        Some(HandleObject::Thread(tid))
    );
}

#[test]
fn initialized_activation_exempts_only_its_exact_creation_handle() {
    exact_creation_handle_activation(false);
}

#[test]
fn terminated_activation_exempts_only_its_exact_creation_handle() {
    exact_creation_handle_activation(true);
}

#[test]
fn stale_creation_handle_cannot_exempt_a_reused_bound_slot() {
    let (mut pm, _, _, pid, _) = fixture();
    let tid = pm.create_dormant_thread(pid).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x6000, 0, false, 0x7000, 123, false)
        .unwrap();
    let stale = pm.try_reserve_handle_slot(pid).unwrap();
    pm.bind_reserved_handle(stale, HandleObject::Thread(tid), 0)
        .unwrap();
    pm.cancel_bound_handle(stale).unwrap();
    let current = pm.try_reserve_handle_slot(pid).unwrap();
    assert_eq!(stale.handle, current.handle);
    assert_ne!(stale.generation, current.generation);
    pm.bind_reserved_handle(current, HandleObject::Thread(tid), 0)
        .unwrap();
    assert_eq!(
        pm.commit_thread_activation_with_handle(plan, stale),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Initialized);
    pm.commit_thread_activation_with_handle(plan, current)
        .unwrap();
    pm.publish_reserved_handle(current).unwrap();
}

#[test]
fn terminated_creation_handle_owner_cannot_authorize_activation() {
    let (mut pm, _, _, pid, _) = fixture();
    let tid = pm.create_dormant_thread(pid).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x6000, 0, false, 0x7000, 123, false)
        .unwrap();
    let system = pm.initial_system_identity().unwrap().process_id();
    let reservation = pm.try_reserve_handle_slot(system).unwrap();
    pm.bind_reserved_handle(reservation, HandleObject::Thread(tid), 0)
        .unwrap();
    pm.terminate_process(system, 0).unwrap();
    assert_eq!(
        pm.commit_thread_activation_with_handle(plan, reservation),
        Err(crate::STATUS_PROCESS_IS_TERMINATING)
    );
    assert_eq!(pm.thread(tid).unwrap().state, ThreadState::Initialized);
    pm.cancel_bound_handle(reservation).unwrap();
    pm.commit_thread_activation(plan).unwrap();
}
