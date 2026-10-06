use super::*;
use crate::native_handle::KERNEL_HANDLE_TAG;

fn fixture() -> (
    ProcessManager,
    NativeHandleCaller,
    ProcessId,
    crate::ThreadId,
) {
    let mut pm = ProcessManager::new();
    let system = pm.create_process("system", None, None);
    let system_thread = pm.create_thread(system, 0, 0, true).unwrap();
    pm.designate_initial_system(system, system_thread).unwrap();
    assert!(pm.publish_process_kernel_object(system, 0x1000));
    assert!(pm.publish_thread_kernel_object(system_thread, 0x2000));
    let owner = pm.create_process("caller", None, None);
    let thread = pm.create_thread(owner, 0, 0, false).unwrap();
    let caller = pm
        .capture_native_handle_caller(pm.thread_lifetime(thread).unwrap(), AccessMode::KernelMode)
        .unwrap();
    (pm, caller, owner, thread)
}

#[test]
fn target_scope_wildcard_and_first_match_preserve_ownership() {
    let (mut pm, caller, owner, _) = fixture();
    let target = pm.create_process("target", None, None);
    let own = pm.insert_handle(owner, HandleObject::Opaque(1), 7).unwrap();
    let first = pm
        .insert_handle(target, HandleObject::Opaque(2), 3)
        .unwrap();
    let second = pm
        .insert_handle(target, HandleObject::Opaque(2), 4)
        .unwrap();
    assert_eq!(own, first); // Same numeric handle, distinct process-table authority.
    let counts = (pm.handle_count(owner), pm.handle_count(target));
    assert_eq!(
        pm.find_native_handle(caller, target, None, |_| true),
        Ok(Some(first))
    );
    assert_eq!(
        pm.find_native_handle(caller, target, None, |o| o == HandleObject::Opaque(1)),
        Ok(None)
    );
    assert_eq!(
        pm.find_native_handle(caller, target, None, |o| o == HandleObject::Opaque(2)),
        Ok(Some(first))
    );
    assert_eq!(u64::from(first) & KERNEL_HANDLE_TAG, 0);
    assert_eq!((pm.handle_count(owner), pm.handle_count(target)), counts);
    assert_eq!(
        pm.lookup_handle(target, second),
        Some(HandleObject::Opaque(2))
    );
}

#[test]
fn repeated_searches_do_not_acquire_canonical_ps_references() {
    let (mut pm, caller, owner, _) = fixture();
    let target = pm.create_process("canonical target", None, None);
    let thread = pm.create_thread(target, 0, 0, false).unwrap();
    assert!(pm.publish_process_kernel_object(target, 0x5000));
    assert!(pm.publish_thread_kernel_object(thread, 0x6000));
    let object = HandleObject::Process(target);
    let handle = pm.insert_handle(owner, object, 0x123).unwrap();
    let before = (
        pm.process(target).unwrap().kernel_pointer_references,
        pm.thread(thread).unwrap().kernel_pointer_references,
        pm.handle_object_reference_count(object),
        pm.handle_count(owner),
    );
    for _ in 0..3 {
        assert_eq!(
            pm.find_native_handle(caller, owner, None, |entry| entry == object),
            Ok(Some(handle))
        );
        assert_eq!(
            pm.find_native_handle(
                caller,
                owner,
                Some(NativeHandleInformation {
                    attributes: 0,
                    granted_access: Some(0x123),
                }),
                |entry| matches!(entry, HandleObject::Process(_))
            ),
            Ok(Some(handle))
        );
    }
    assert_eq!(
        (
            pm.process(target).unwrap().kernel_pointer_references,
            pm.thread(thread).unwrap().kernel_pointer_references,
            pm.handle_object_reference_count(object),
            pm.handle_count(owner),
        ),
        before
    );
    assert_eq!(pm.lookup_handle(owner, handle), Some(object));
}

#[test]
fn object_and_type_predicates_are_independent_optional_filters() {
    let (mut pm, caller, owner, thread) = fixture();
    let other = pm.create_process("other", None, None);
    let opaque = pm.insert_handle(owner, HandleObject::Opaque(8), 0).unwrap();
    let process_a = pm
        .insert_handle(owner, HandleObject::Process(owner), 1)
        .unwrap();
    let process_b = pm
        .insert_handle(owner, HandleObject::Process(other), 2)
        .unwrap();
    let thread_handle = pm
        .insert_handle(owner, HandleObject::Thread(thread), 3)
        .unwrap();
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |_| true),
        Ok(Some(opaque))
    );
    // Exact object only, without a type constraint.
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |entry| entry
            == HandleObject::Process(other)),
        Ok(Some(process_b))
    );
    // Type only, without an object constraint.
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |entry| matches!(
            entry,
            HandleObject::Process(_)
        )),
        Ok(Some(process_a))
    );
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |entry| matches!(
            entry,
            HandleObject::Thread(_)
        )),
        Ok(Some(thread_handle))
    );
    // Both filters must match the same actual typed entry.
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |entry| matches!(
            entry,
            HandleObject::Process(_)
        ) && entry
            == HandleObject::Process(other)),
        Ok(Some(process_b))
    );
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |entry| matches!(
            entry,
            HandleObject::Thread(_)
        ) && entry
            == HandleObject::Process(other)),
        Ok(None)
    );
}

#[test]
fn information_is_an_exact_immutable_input_filter() {
    let (mut pm, caller, owner, _) = fixture();
    let handle = pm
        .insert_handle(owner, HandleObject::Opaque(3), 0x12)
        .unwrap();
    pm.set_handle_flags(
        owner,
        handle,
        crate::HandleFlags {
            inherit: true,
            protect_from_close: true,
        },
    )
    .unwrap();
    let exact = NativeHandleInformation {
        attributes: 3,
        granted_access: Some(0x12),
    };
    assert_eq!(
        pm.find_native_handle(caller, owner, Some(exact), |_| true),
        Ok(Some(handle))
    );
    for filter in [
        NativeHandleInformation {
            attributes: 2,
            ..exact
        },
        NativeHandleInformation {
            granted_access: Some(0x10),
            ..exact
        },
        NativeHandleInformation {
            granted_access: None,
            ..exact
        },
    ] {
        assert_eq!(
            pm.find_native_handle(caller, owner, Some(filter), |_| true),
            Ok(None)
        );
    }
    assert_eq!(
        exact,
        NativeHandleInformation {
            attributes: 3,
            granted_access: Some(0x12)
        }
    );
    assert_eq!(pm.handle_access(owner, handle), Some(0x12));
    assert_eq!(pm.handle_count(owner), 1);
}

#[test]
fn reserved_and_bound_entries_are_invisible_until_publication() {
    let (mut pm, caller, owner, _) = fixture();
    let reservation = pm.try_reserve_handle_slot(owner).unwrap();
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |_| true),
        Ok(None)
    );
    pm.bind_reserved_handle(reservation, HandleObject::Opaque(4), 5)
        .unwrap();
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |_| true),
        Ok(None)
    );
    pm.publish_reserved_handle(reservation).unwrap();
    assert_eq!(
        pm.find_native_handle(caller, owner, None, |_| true),
        Ok(Some(reservation.handle))
    );
}

#[test]
fn user_mode_and_stale_callers_are_refused_before_predicate() {
    let (mut pm, kernel, owner, thread) = fixture();
    let user = pm
        .capture_native_handle_caller(pm.thread_lifetime(thread).unwrap(), AccessMode::UserMode)
        .unwrap();
    assert_eq!(
        pm.find_native_handle(user, owner, None, |_| panic!("not admitted")),
        Err(crate::STATUS_ACCESS_DENIED)
    );
    pm.terminate_thread(thread, 0).unwrap();
    assert_eq!(
        pm.find_native_handle(kernel, owner, None, |_| panic!("stale caller")),
        Err(crate::STATUS_INVALID_HANDLE)
    );
}

#[test]
fn missing_and_teardown_targets_are_refused_before_predicate() {
    let (mut pm, caller, _, _) = fixture();
    assert_eq!(
        pm.find_native_handle(caller, ProcessId::MAX, None, |_| panic!("missing")),
        Err(crate::STATUS_INVALID_HANDLE)
    );
    let target = pm.create_process("target", None, None);
    pm.create_thread(target, 0, 0, false).unwrap();
    pm.insert_handle(target, HandleObject::Opaque(5), 0)
        .unwrap();
    pm.terminate_process(target, 0).unwrap();
    assert_eq!(
        pm.find_native_handle(caller, target, None, |_| panic!("teardown")),
        Err(crate::STATUS_INVALID_HANDLE)
    );
}
