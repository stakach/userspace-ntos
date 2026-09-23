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
fn system_and_caller_directory_handles_remain_invisible_until_publish() {
    let (mut pm, user, kernel) = fixture();
    let mut local = pm.reserve_native_object_directory_handle(user, 0).unwrap();
    let mut system = pm
        .reserve_native_object_directory_handle(kernel, OBJ_KERNEL_HANDLE | OBJ_INHERIT)
        .unwrap();
    assert_eq!(system.value(), KERNEL_HANDLE_TAG | local.value());
    local.bind(&mut pm, 11, 1).unwrap();
    system.bind(&mut pm, 22, 2).unwrap();
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, system.value(), 0),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(user, local.value(), 0),
        Err(STATUS_INVALID_HANDLE)
    );
    local.publish(&mut pm).unwrap();
    system.publish(&mut pm).unwrap();
    assert_eq!(
        pm.lookup_native_object_directory_handle(user, system.value(), 0),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, system.value() | 3, 2),
        Ok(22)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, local.value(), 1),
        Ok(11)
    );
    assert!(
        pm.handle_flags(system.process_id(), local.value() as u32)
            .unwrap()
            .inherit
    );
    assert_eq!(
        pm.close_native_object_directory_handle(kernel, system.value()),
        Ok(22)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(user, local.value(), 1),
        Ok(11)
    );
}

#[test]
fn directory_native_admission_type_and_access_are_strict() {
    let (mut pm, user, kernel) = fixture();
    assert!(matches!(
        pm.reserve_native_object_directory_handle(user, OBJ_KERNEL_HANDLE),
        Err(crate::STATUS_INVALID_PARAMETER)
    ));
    assert!(matches!(
        pm.reserve_native_object_directory_handle(kernel, 1),
        Err(crate::STATUS_INVALID_PARAMETER)
    ));
    let mut directory = pm.reserve_native_object_directory_handle(user, 0).unwrap();
    directory.bind(&mut pm, 33, 1).unwrap();
    let value = directory.publish(&mut pm).unwrap();
    assert_eq!(
        pm.lookup_native_object_directory_handle(user, value, 2),
        Err(crate::STATUS_ACCESS_DENIED)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, value, 2),
        Ok(33)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, value | 0x1_0000_0000, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, u64::MAX, 0),
        Err(STATUS_OBJECT_TYPE_MISMATCH)
    );
    let (foreign, _, _) = fixture();
    assert_eq!(
        foreign.lookup_native_object_directory_handle(kernel, value, 0),
        Err(STATUS_INVALID_HANDLE)
    );
    let other = pm
        .insert_handle(user.effective_process(), HandleObject::Opaque(77), 0)
        .unwrap();
    assert_eq!(
        pm.close_native_object_directory_handle(user, other as u64),
        Err(NativePsCloseError::Status(STATUS_OBJECT_TYPE_MISMATCH))
    );
    assert_eq!(
        pm.lookup_handle(user.effective_process(), other),
        Some(HandleObject::Opaque(77))
    );
}

#[test]
fn abort_cancels_exact_bound_generation_and_returns_cleanup_identity() {
    let (mut pm, _, kernel) = fixture();
    let mut abandoned = pm
        .reserve_native_object_directory_handle(kernel, OBJ_KERNEL_HANDLE)
        .unwrap();
    abandoned.bind(&mut pm, 41, 0).unwrap();
    assert_eq!(abandoned.abort(&mut pm), Ok(Some(41)));
    assert_eq!(abandoned.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    let mut replacement = pm
        .reserve_native_object_directory_handle(kernel, OBJ_KERNEL_HANDLE)
        .unwrap();
    replacement.bind(&mut pm, 42, 0).unwrap();
    assert_eq!(abandoned.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    replacement.publish(&mut pm).unwrap();
    assert_eq!(
        pm.lookup_native_object_directory_handle(kernel, replacement.value(), 0),
        Ok(42)
    );
}

#[test]
fn protected_directory_close_keeps_reference_in_both_modes() {
    let (mut pm, user, kernel) = fixture();
    let mut directory = pm.reserve_native_object_directory_handle(user, 0).unwrap();
    directory.bind(&mut pm, 51, 1).unwrap();
    let value = directory.publish(&mut pm).unwrap();
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
        pm.close_native_object_directory_handle(user, value),
        Err(NativePsCloseError::Status(
            crate::STATUS_HANDLE_NOT_CLOSABLE
        ))
    );
    assert_eq!(
        pm.close_native_object_directory_handle(kernel, value | 3),
        Err(NativePsCloseError::BugCheck {
            code: INVALID_KERNEL_HANDLE_BUGCHECK,
            parameters: [value | 3, 0, 0, 0],
        })
    );
    assert_eq!(
        pm.lookup_native_object_directory_handle(user, value, 1),
        Ok(51)
    );
}
