use super::*;

fn fixture() -> (ProcessManager, ProcessId) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("key-client", None, None);
    (pm, pid)
}

#[test]
fn registry_mount_selector_retains_invisible_and_visible_keys() {
    let (mut pm, pid) = fixture();
    let selector = 0x3000_0000;
    let mask = 0xf000_0000;
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    assert!(!pm.has_registry_key_selector_references(selector, mask));
    transaction.bind(&mut pm, selector | 0x1234, 1).unwrap();
    assert!(pm.has_registry_key_selector_references(selector, mask));
    assert!(!pm.has_registry_key_selector_references(0x5000_0000, mask));
    transaction.abort(&mut pm).unwrap();
    assert!(!pm.has_registry_key_selector_references(selector, mask));
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    transaction.bind(&mut pm, selector | 0x5678, 1).unwrap();
    let handle = transaction.publish(&mut pm).unwrap();
    assert!(pm.has_registry_key_selector_references(selector, mask));
    pm.close_handle(pid, handle as crate::Handle).unwrap();
    assert!(!pm.has_registry_key_selector_references(selector, mask));
}

#[test]
fn key_remains_invisible_until_exact_publication() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    let handle = transaction.value() as crate::Handle;
    assert_eq!(pm.lookup_handle(pid, handle), None);
    transaction.bind(&mut pm, 17, 0x20019).unwrap();
    assert_eq!(pm.lookup_handle(pid, handle), None);
    assert_eq!(pm.handle_object_count(HandleObject::RegistryKey(17)), 0);
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(17)),
        1
    );
    assert_eq!(pm.handle_reservation_count(pid), 1);
    assert_eq!(transaction.publish(&mut pm), Ok(handle as u64));
    assert_eq!(
        pm.lookup_handle(pid, handle),
        Some(HandleObject::RegistryKey(17))
    );
    assert_eq!(pm.handle_access(pid, handle), Some(0x20019));
    assert_eq!(pm.handle_reservation_count(pid), 0);
    assert_eq!(transaction.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(transaction.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn failed_output_returns_owned_key_once() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    transaction.bind(&mut pm, 73, 1).unwrap();
    assert_eq!(transaction.abort(&mut pm), Ok(Some(73)));
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(73)),
        0
    );
    assert_eq!(
        pm.lookup_handle(pid, transaction.value() as crate::Handle),
        None
    );
    assert_eq!(transaction.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(pm.handle_reservation_count(pid), 0);
}

#[test]
fn empty_abort_and_unbound_publish_do_not_acquire_a_key() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    assert_eq!(transaction.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(transaction.abort(&mut pm), Ok(None));
    assert_eq!(transaction.bind(&mut pm, 4, 1), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn dying_owner_refuses_admission_but_keeps_bound_cleanup() {
    for state in [ProcessState::Exiting, ProcessState::Terminated] {
        let (mut pm, pid) = fixture();
        let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
        transaction.bind(&mut pm, 73, 1).unwrap();
        pm.processes.get_mut(&pid).unwrap().state = state;
        assert!(matches!(
            pm.reserve_registry_key_handle(pid),
            Err(STATUS_PROCESS_IS_TERMINATING)
        ));
        assert_eq!(
            transaction.publish(&mut pm),
            Err(STATUS_PROCESS_IS_TERMINATING)
        );
        assert_eq!(transaction.abort(&mut pm), Ok(Some(73)));
    }
}

#[test]
fn failed_bind_leaves_empty_reservation_and_external_target() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    pm.processes.get_mut(&pid).unwrap().state = ProcessState::Exiting;
    assert_eq!(
        transaction.bind(&mut pm, 73, 1),
        Err(STATUS_PROCESS_IS_TERMINATING)
    );
    assert_eq!(transaction.abort(&mut pm), Ok(None));
}

#[test]
fn stale_generation_cannot_publish_or_abort_replacement() {
    let (mut pm, pid) = fixture();
    let mut old = pm.reserve_registry_key_handle(pid).unwrap();
    old.bind(&mut pm, 1, 1).unwrap();
    assert_eq!(
        pm.cancel_bound_handle(old.reservation),
        Ok(HandleObject::RegistryKey(1))
    );
    let mut replacement = pm.reserve_registry_key_handle(pid).unwrap();
    assert_eq!(old.value(), replacement.value());
    replacement.bind(&mut pm, 2, 2).unwrap();
    assert_eq!(old.publish(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(old.abort(&mut pm), Err(STATUS_INVALID_HANDLE));
    assert_eq!(replacement.publish(&mut pm), Ok(replacement.value()));
}

#[test]
fn failed_rebind_preserves_original_target_and_grant() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    transaction.bind(&mut pm, 1, 3).unwrap();
    assert_eq!(transaction.bind(&mut pm, 2, 7), Err(STATUS_INVALID_HANDLE));
    assert_eq!(transaction.abort(&mut pm), Ok(Some(1)));
    assert!(matches!(
        pm.reserve_registry_key_handle(ProcessId::MAX),
        Err(STATUS_INVALID_HANDLE)
    ));
}

#[test]
fn closing_visible_alias_keeps_bound_key_reference() {
    let (mut pm, pid) = fixture();
    let mut visible = pm.reserve_registry_key_handle(pid).unwrap();
    visible.bind(&mut pm, 17, 1).unwrap();
    let handle = visible.publish(&mut pm).unwrap() as crate::Handle;
    let mut pending = pm.reserve_registry_key_handle(pid).unwrap();
    pending.bind(&mut pm, 17, 1).unwrap();
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(17)),
        2
    );
    pm.take_handle(pid, handle).unwrap();
    assert_eq!(pm.handle_object_count(HandleObject::RegistryKey(17)), 0);
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(17)),
        1
    );
    assert_eq!(pending.abort(&mut pm), Ok(Some(17)));
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(17)),
        0
    );
}

#[test]
fn reserved_slot_retains_terminated_process_until_abort() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    pm.terminate_process(pid, 0).unwrap();
    assert!(pm.delete_process_object_if_unreferenced(pid).is_none());
    assert_eq!(
        transaction.bind(&mut pm, 17, 1),
        Err(STATUS_PROCESS_IS_TERMINATING)
    );
    assert_eq!(transaction.abort(&mut pm), Ok(None));
    assert!(pm.delete_process_object_if_unreferenced(pid).is_some());
}

#[test]
fn failed_publication_retains_terminated_process_and_exact_key_until_abort() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    transaction.bind(&mut pm, 0x1234, 0x20019).unwrap();
    pm.terminate_process(pid, 0).unwrap();
    assert_eq!(
        transaction.publish(&mut pm),
        Err(STATUS_PROCESS_IS_TERMINATING)
    );
    assert!(pm.delete_process_object_if_unreferenced(pid).is_none());
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(0x1234)),
        1
    );
    assert_eq!(transaction.abort(&mut pm), Ok(Some(0x1234)));
    assert!(pm.delete_process_object_if_unreferenced(pid).is_some());
}

#[test]
fn foreign_manager_with_identical_slot_and_generation_cannot_change_publication() {
    let (mut first, pid) = fixture();
    let (mut second, other_pid) = fixture();
    assert_eq!(pid, other_pid);
    let mut own = first.reserve_registry_key_handle(pid).unwrap();
    let mut foreign = second.reserve_registry_key_handle(pid).unwrap();
    assert_eq!(own.value(), foreign.value());
    assert_eq!(own.reservation.generation, foreign.reservation.generation);
    assert_eq!(own.bind(&mut second, 17, 1), Err(STATUS_INVALID_HANDLE));
    assert_eq!(own.abort(&mut second), Err(STATUS_INVALID_HANDLE));
    own.bind(&mut first, 17, 1).unwrap();
    foreign.bind(&mut second, 17, 1).unwrap();
    assert_eq!(own.publish(&mut second), Err(STATUS_INVALID_HANDLE));
    assert_eq!(own.abort(&mut second), Err(STATUS_INVALID_HANDLE));
    assert_eq!(first.handle_reservation_count(pid), 1);
    assert_eq!(second.handle_reservation_count(pid), 1);
    assert_eq!(own.abort(&mut first), Ok(Some(17)));
    assert_eq!(foreign.abort(&mut second), Ok(Some(17)));
}

#[test]
fn manager_move_preserves_publication_authority() {
    let (mut pm, pid) = fixture();
    let mut transaction = pm.reserve_registry_key_handle(pid).unwrap();
    let mut moved = pm;
    transaction.bind(&mut moved, 17, 1).unwrap();
    let mut moved_again = moved;
    assert_eq!(
        transaction.publish(&mut moved_again),
        Ok(transaction.value())
    );
}

#[test]
fn authorization_updates_only_an_invisible_exact_bound_target() {
    let (mut pm, pid) = fixture();
    let mut publication = pm.reserve_registry_key_handle(pid).unwrap();
    assert_eq!(
        publication.authorize_bound_grant(&mut pm, 7),
        Err(STATUS_INVALID_HANDLE)
    );
    publication.bind(&mut pm, 17, 0).unwrap();
    publication.authorize_bound_grant(&mut pm, 3).unwrap();
    assert_eq!(pm.lookup_handle(pid, publication.value() as u32), None);
    assert_eq!(
        pm.handle_object_reference_count(HandleObject::RegistryKey(17)),
        1
    );
    publication.publish(&mut pm).unwrap();
    assert_eq!(pm.handle_access(pid, publication.value() as u32), Some(3));
    assert_eq!(
        publication.authorize_bound_grant(&mut pm, 7),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(pm.handle_access(pid, publication.value() as u32), Some(3));
}
