use super::*;

fn fixture() -> (ProcessManager, NativeHandleCaller, NativeHandleCaller) {
    let mut pm = ProcessManager::new();
    let system = pm.create_process("system", None, None);
    let initial = pm.create_thread(system, 0, 0, true).unwrap();
    pm.designate_initial_system(system, initial).unwrap();
    let pid = pm.create_process("client", None, None);
    let tid = pm.create_thread(pid, 0, 0, false).unwrap();
    let lifetime = pm.thread_lifetime(tid).unwrap();
    let user = pm
        .capture_native_handle_caller(lifetime, AccessMode::UserMode)
        .unwrap();
    let kernel = pm
        .capture_native_handle_caller(lifetime, AccessMode::KernelMode)
        .unwrap();
    (pm, user, kernel)
}

#[test]
fn native_kernel_key_is_invisible_until_publication_and_never_aliases_client_table() {
    let (mut pm, user, kernel) = fixture();
    let mut local = pm.reserve_native_registry_key_handle(user, 0).unwrap();
    local.bind(&mut pm, 11, 1).unwrap();
    let raw = local.publish(&mut pm).unwrap();
    let mut system = pm
        .reserve_native_registry_key_handle(kernel, OBJ_KERNEL_HANDLE | OBJ_INHERIT)
        .unwrap();
    assert_eq!(system.value(), KERNEL_HANDLE_TAG | raw);
    system.bind(&mut pm, 22, 2).unwrap();
    assert_eq!(
        pm.lookup_native_registry_key_handle(kernel, system.value(), 0),
        Err(STATUS_INVALID_HANDLE)
    );
    system.publish(&mut pm).unwrap();
    assert_eq!(
        pm.lookup_native_registry_key_handle(user, system.value(), 0),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.lookup_native_registry_key_handle(kernel, system.value() | 3, 0),
        Ok(22)
    );
    assert_eq!(pm.lookup_native_registry_key_handle(kernel, raw, 0), Ok(11));
    assert!(
        pm.handle_flags(system.process_id(), raw as u32)
            .unwrap()
            .inherit
    );
    assert_eq!(
        pm.close_native_registry_key_handle(kernel, system.value()),
        Ok(22)
    );
    assert_eq!(pm.lookup_native_registry_key_handle(user, raw, 1), Ok(11));
}

#[test]
fn native_key_scope_grants_and_attributes_are_strict() {
    let (mut pm, user, kernel) = fixture();
    assert!(matches!(
        pm.reserve_native_registry_key_handle(user, OBJ_KERNEL_HANDLE),
        Err(crate::STATUS_INVALID_PARAMETER)
    ));
    assert!(matches!(
        pm.reserve_native_registry_key_handle(kernel, 1),
        Err(crate::STATUS_INVALID_PARAMETER)
    ));
    let mut key = pm
        .reserve_native_registry_key_handle(user, OBJ_INHERIT)
        .unwrap();
    key.bind(&mut pm, 33, 1).unwrap();
    let value = key.publish(&mut pm).unwrap();
    assert_eq!(
        pm.lookup_native_registry_key_handle(user, value, 2),
        Err(crate::STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        pm.lookup_native_registry_key_handle(kernel, value, 2),
        Ok(33)
    );
    assert_eq!(
        pm.lookup_native_registry_key_handle(kernel, value | 0x1_0000_0000, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.lookup_native_registry_key_handle(kernel, u64::MAX, 0),
        Err(STATUS_OBJECT_TYPE_MISMATCH)
    );
    let (foreign, _, _) = fixture();
    assert_eq!(
        foreign.lookup_native_registry_key_handle(kernel, value, 0),
        Err(STATUS_INVALID_HANDLE)
    );
}

#[test]
fn native_key_abort_retains_system_target_across_requestor_exit() {
    let (mut pm, _, kernel) = fixture();
    let mut key = pm
        .reserve_native_registry_key_handle(kernel, OBJ_KERNEL_HANDLE)
        .unwrap();
    key.bind(&mut pm, 33, 1).unwrap();
    pm.terminate_process(kernel.effective_process(), 0).unwrap();
    assert_eq!(
        pm.close_native_registry_key_handle(kernel, key.value()),
        Err(NativePsCloseError::Status(STATUS_INVALID_HANDLE))
    );
    assert_eq!(key.abort(&mut pm), Ok(Some(33)));
    assert_eq!(key.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn native_key_operations_never_remove_other_object_types() {
    let (mut pm, user, kernel) = fixture();
    let pid = user.effective_process();
    let handle = pm
        .insert_handle(pid, HandleObject::Process(pid), 1)
        .unwrap();
    assert_eq!(
        pm.lookup_native_registry_key_handle(user, handle as u64, 0),
        Err(STATUS_OBJECT_TYPE_MISMATCH)
    );
    assert_eq!(
        pm.close_native_registry_key_handle(kernel, handle as u64),
        Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH))
    );
    assert_eq!(
        pm.lookup_handle(pid, handle),
        Some(HandleObject::Process(pid))
    );
}

#[test]
fn changed_bound_flags_do_not_authorize_publication_or_cleanup() {
    let (mut pm, _, kernel) = fixture();
    let mut key = pm
        .reserve_native_registry_key_handle(kernel, OBJ_KERNEL_HANDLE)
        .unwrap();
    key.bind(&mut pm, 55, 1).unwrap();
    let slot = crate::handle_to_slot(key.reservation.handle).unwrap();
    let HandleSlot::Bound { entry, .. } =
        &mut pm.processes.get_mut(&key.process_id()).unwrap().handles[slot]
    else {
        unreachable!()
    };
    entry.flags.inherit = true;
    assert_eq!(key.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(key.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(55)),
        1
    );
}

#[test]
fn native_key_protected_close_preserves_entry_for_both_modes() {
    let (mut pm, user, kernel) = fixture();
    let mut key = pm.reserve_native_registry_key_handle(user, 0).unwrap();
    key.bind(&mut pm, 33, 1).unwrap();
    let value = key.publish(&mut pm).unwrap();
    pm.set_handle_flags(
        user.effective_process(),
        value as u32,
        HandleFlags {
            inherit: false,
            protect_from_close: true,
        },
    )
    .unwrap();
    assert_eq!(
        pm.close_native_registry_key_handle(user, value),
        Err(NativePsCloseError::Status(
            crate::STATUS_HANDLE_NOT_CLOSABLE
        ))
    );
    assert_eq!(
        pm.close_native_registry_key_handle(kernel, value | 3),
        Err(NativePsCloseError::BugCheck {
            code: INVALID_KERNEL_HANDLE_BUGCHECK,
            parameters: [value | 3, 0, 0, 0],
        })
    );
    assert_eq!(pm.lookup_native_registry_key_handle(user, value, 1), Ok(33));
}
