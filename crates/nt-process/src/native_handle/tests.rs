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
