use super::*;

const DESKTOP_TYPE: u64 = 0xD000;
const WINSTA_TYPE: u64 = 0x5000;

fn inserted(store: &mut UserObjectStore, kind: ObKind, body: u64, name: UserObjectName) -> UserObjectIdentity {
    let object_type = if kind == ObKind::Desktop { DESKTOP_TYPE } else { WINSTA_TYPE };
    store.create(kind, object_type, body, None, name, 0).unwrap();
    store.insert(body).unwrap().0
}

#[test]
fn recycled_body_gets_a_new_generation_and_stale_targets_are_refused() {
    let mut store = UserObjectStore::new();
    let first = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    assert_eq!(
        store.close_handle(first),
        Ok(UserObjectRelease::Final(first))
    );
    let second = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    assert_eq!(second.body, first.body);
    assert_ne!(second.generation, first.generation);

    assert_eq!(store.open_handle(0x7000, first.generation), Err(UserObjectError::Stale));
    assert_eq!(store.apply_acquired_handles(first, 1), Err(UserObjectError::Stale));
    assert_eq!(store.apply_released_handles(first, 1), Err(UserObjectError::Stale));
    assert_eq!(store.inserted_identity(0x7000, first.generation), None);
    assert_eq!(store.security_descriptor_for(0x7000, first.generation), None);
    assert!(!store.set_security_descriptor_for(0x7000, first.generation, &[1]));
    assert_eq!(store.counts(0x7000), Some((1, 1)));
    assert_eq!(store.inserted_identity(0x7000, second.generation), Some(second));
}

#[test]
fn a_type_mismatch_is_a_stale_target_even_at_the_same_generation() {
    let mut store = UserObjectStore::new();
    let desktop = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    let forged = UserObjectIdentity { object_type: WINSTA_TYPE, ..desktop };
    assert_eq!(store.apply_acquired_handles(forged, 1), Err(UserObjectError::Stale));
    assert_eq!(store.apply_released_handles(forged, 1), Err(UserObjectError::Stale));
    assert_eq!(store.counts(0x7000), Some((1, 1)));
}

#[test]
fn insert_consumes_the_creator_reference_and_publishes_the_name() {
    let mut store = UserObjectStore::new();
    let generation = store
        .create(ObKind::WindowStation, WINSTA_TYPE, 0x5000, Some(&[1, 2]),
            UserObjectName::InteractiveWindowStation, 2)
        .unwrap();
    assert_eq!(store.counts(0x5000), Some((1, 0)));
    assert_eq!(store.named(UserObjectName::InteractiveWindowStation), None);
    assert_eq!(store.open_handle(0x5000, generation), Err(UserObjectError::WrongState));

    let (identity, attributes) = store.insert(0x5000).unwrap();
    assert_eq!(attributes, 2);
    assert_eq!(identity.generation, generation);
    assert_eq!(store.counts(0x5000), Some((1, 1)));
    assert_eq!(store.named(UserObjectName::InteractiveWindowStation), Some(identity));
    assert_eq!(store.insert(0x5000), Err(UserObjectError::WrongState));
    assert_eq!(
        store.security_descriptor_for(0x5000, generation),
        Some(Some([1, 2].as_slice()))
    );
}

#[test]
fn the_last_handle_removes_the_name_and_the_last_pointer_finalizes() {
    let mut store = UserObjectStore::new();
    let winsta = inserted(&mut store, ObKind::WindowStation, 0x5000,
        UserObjectName::InteractiveWindowStation);
    // win32k's own pointer reference (InputWindowStation) outlives every handle.
    assert_eq!(store.reference(0x5000), Ok(2));
    assert_eq!(
        store.close_handle(winsta),
        Ok(UserObjectRelease::Retained { pointers: 1, handles: 0 })
    );
    assert_eq!(store.named(UserObjectName::InteractiveWindowStation), None);
    assert_eq!(store.open_handle(0x5000, winsta.generation), Ok(winsta));
    assert_eq!(store.named(UserObjectName::InteractiveWindowStation), None,
        "a name removed at handle count zero is not restored by a pointer open");
    assert_eq!(
        store.close_handle(winsta),
        Ok(UserObjectRelease::Retained { pointers: 1, handles: 0 })
    );
    assert_eq!(store.dereference(0x5000), Ok(UserObjectRelease::Final(winsta)));
    assert_eq!(store.identity(0x5000), None);
}

#[test]
fn copied_handles_keep_the_body_alive_until_every_release() {
    let mut store = UserObjectStore::new();
    let desktop = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    // Two inherited copies, then the parent's original and one copy close.
    store.apply_acquired_handles(desktop, 2).unwrap();
    assert_eq!(store.counts(0x7000), Some((3, 3)));
    assert_eq!(
        store.apply_released_handles(desktop, 2),
        Ok(UserObjectRelease::Retained { pointers: 1, handles: 1 })
    );
    assert_eq!(store.apply_released_handles(desktop, 2), Err(UserObjectError::Underflow));
    assert_eq!(store.counts(0x7000), Some((1, 1)));
    assert_eq!(
        store.apply_released_handles(desktop, 1),
        Ok(UserObjectRelease::Final(desktop))
    );
}

#[test]
fn acquisitions_need_a_live_handle_to_copy() {
    let mut store = UserObjectStore::new();
    let generation = store
        .create(ObKind::Desktop, DESKTOP_TYPE, 0x7000, None, UserObjectName::Unnamed, 0)
        .unwrap();
    let pending = store.identity(0x7000).unwrap();
    assert_eq!(pending.generation, generation);
    assert_eq!(store.apply_acquired_handles(pending, 1), Err(UserObjectError::WrongState));
    store.insert(0x7000).unwrap();
    assert_eq!(store.reference(0x7000), Ok(2));
    store.close_handle(pending).unwrap();
    assert_eq!(store.apply_acquired_handles(pending, 1), Err(UserObjectError::WrongState));
    assert_eq!(store.counts(0x7000), Some((1, 0)));
}

#[test]
fn pointer_references_cannot_cross_the_handle_owned_floor() {
    let mut store = UserObjectStore::new();
    let desktop = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    assert_eq!(store.dereference(0x7000), Err(UserObjectError::Underflow));
    assert_eq!(store.reference(0x7000), Ok(2));
    assert_eq!(
        store.dereference(0x7000),
        Ok(UserObjectRelease::Retained { pointers: 1, handles: 1 })
    );
    assert_eq!(store.counts(0x7000), Some((1, 1)));
    assert_eq!(store.identity(0x7000), Some(desktop));
}

#[test]
fn an_uninserted_creator_reference_finalizes_its_exact_body() {
    let mut store = UserObjectStore::new();
    store.create(ObKind::Desktop, DESKTOP_TYPE, 0x7000, None, UserObjectName::Unnamed, 0).unwrap();
    store.create(ObKind::WindowStation, WINSTA_TYPE, 0x5000, None, UserObjectName::Unnamed, 0).unwrap();
    let desktop = store.identity(0x7000).unwrap();
    assert_eq!(store.reference(0x7000), Ok(2));
    assert_eq!(
        store.dereference(0x7000),
        Ok(UserObjectRelease::Retained { pointers: 1, handles: 0 })
    );
    assert_eq!(store.dereference(0x7000), Ok(UserObjectRelease::Final(desktop)));
    assert_eq!(store.counts(0x5000), Some((1, 0)));
    assert_eq!(store.dereference(0x7000), Err(UserObjectError::Unknown));
}

#[test]
fn a_newer_holder_takes_over_a_name_and_service_names_stay_distinct() {
    let mut store = UserObjectStore::new();
    let older = inserted(&mut store, ObKind::WindowStation, 0x5000,
        UserObjectName::InteractiveWindowStation);
    let newer = inserted(&mut store, ObKind::WindowStation, 0x6000,
        UserObjectName::InteractiveWindowStation);
    assert_eq!(store.named(UserObjectName::InteractiveWindowStation), Some(newer));
    assert_ne!(store.named(UserObjectName::InteractiveWindowStation), Some(older));

    let system = UserObjectName::ServiceWindowStation { authentication_id: 0x3e7 };
    let network = UserObjectName::ServiceWindowStation { authentication_id: 0x3e4 };
    let first = inserted(&mut store, ObKind::WindowStation, 0x8000, system);
    let second = inserted(&mut store, ObKind::WindowStation, 0x9000, network);
    assert_eq!(store.named(system), Some(first));
    assert_eq!(store.named(network), Some(second));
    assert_eq!(store.named(UserObjectName::Unnamed), None);
}

#[test]
fn create_refuses_duplicates_capacity_and_oversize_without_displacing_owners() {
    let mut store = UserObjectStore::new();
    store.create(ObKind::Desktop, DESKTOP_TYPE, 0x7000, None, UserObjectName::Unnamed, 0).unwrap();
    assert_eq!(
        store.create(ObKind::WindowStation, WINSTA_TYPE, 0x7000, None, UserObjectName::Unnamed, 0),
        Err(UserObjectError::WrongState)
    );
    let oversized = [0u8; OB_SECURITY_DESCRIPTOR_MAX + 1];
    assert_eq!(
        store.create(ObKind::Desktop, DESKTOP_TYPE, 0x8000, Some(&oversized),
            UserObjectName::Unnamed, 0),
        Err(UserObjectError::Exhausted)
    );
    assert_eq!(
        store.create(ObKind::Desktop, 0, 0x8000, None, UserObjectName::Unnamed, 0),
        Err(UserObjectError::InvalidParameter)
    );
    for index in 1..USER_OBJECT_CAPACITY as u64 {
        store
            .create(ObKind::Desktop, DESKTOP_TYPE, 0x10_0000 + index * 0x1000, None,
                UserObjectName::Unnamed, 0)
            .unwrap();
    }
    assert_eq!(
        store.create(ObKind::Desktop, DESKTOP_TYPE, 0xdead_0000, None, UserObjectName::Unnamed, 0),
        Err(UserObjectError::Exhausted)
    );
    assert_eq!(store.kind_by_body(0x7000), Some(ObKind::Desktop));
}

#[test]
fn an_exhausted_generation_counter_refuses_new_bodies() {
    let mut store = UserObjectStore::new();
    store.next_generation = USER_OBJECT_GENERATION_MAX;
    assert_eq!(
        store.create(ObKind::Desktop, DESKTOP_TYPE, 0x7000, None, UserObjectName::Unnamed, 0),
        Ok(USER_OBJECT_GENERATION_MAX)
    );
    assert_eq!(
        store.create(ObKind::Desktop, DESKTOP_TYPE, 0x8000, None, UserObjectName::Unnamed, 0),
        Err(UserObjectError::Exhausted)
    );
}

#[test]
fn object_type_is_reported_only_for_registered_kinds() {
    let mut store = UserObjectStore::new();
    inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    store.create(ObKind::Other, 0xABC0, 0x9000, None, UserObjectName::Unnamed, 0).unwrap();
    assert_eq!(store.object_type_addr_by_body(0x7000), Some(DESKTOP_TYPE));
    assert_eq!(store.object_type_addr_by_body(0x9000), None);
    assert_eq!(store.object_type_addr_by_body(0xDEAD), None);
    assert_eq!(store.identity(0x9000).unwrap().object_type, 0xABC0);
}

#[test]
fn security_by_body_and_by_generation_name_one_entry() {
    let mut store = UserObjectStore::new();
    let desktop = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    assert_eq!(store.security_descriptor_by_body(0x7000), Some((ObKind::Desktop, None)));
    assert!(store.set_security_descriptor_by_body(0x7000, ObKind::Desktop, &[1, 2]));
    assert!(!store.set_security_descriptor_by_body(0x7000, ObKind::WindowStation, &[3]));
    assert!(store.set_security_descriptor_for(0x7000, desktop.generation, &[4, 5]));
    assert_eq!(
        store.security_descriptor_by_body(0x7000),
        Some((ObKind::Desktop, Some([4, 5].as_slice())))
    );
    let oversized = [0u8; OB_SECURITY_DESCRIPTOR_MAX + 1];
    assert!(!store.set_security_descriptor_for(0x7000, desktop.generation, &oversized));
    assert!(store.set_security_descriptor_for(0x7000, desktop.generation, &[]));
    assert_eq!(store.security_descriptor_for(0x7000, desktop.generation), Some(None));
    assert_eq!(store.security_descriptor_by_body(0), None);
}


/// IntDesktopObjectParse created "Default": the ObCreateObject reference becomes the handle's.
#[test]
fn a_parse_created_desktop_is_inserted_and_opens_by_pointer() {
    let mut store = UserObjectStore::new();
    store.create(ObKind::Desktop, DESKTOP_TYPE, 0x7000, None, UserObjectName::Unnamed, 0x2).unwrap();
    let admission = store.admit_desktop_parse_result(NtStatus::SUCCESS, 0x7000, true).unwrap();
    assert_eq!(admission.status, NtStatus::SUCCESS);
    assert_eq!(admission.identity.body, 0x7000);
    assert!(store.is_inserted(0x7000));
    assert_eq!(store.counts(0x7000), Some((1, 1)));
    // csrss's IntGetDesktopObjectHandle(pti->rpdesk) -> ObOpenObjectByPointer: the same body.
    assert_eq!(store.open_handle(0x7000, admission.identity.generation), Ok(admission.identity));
    assert_eq!(store.counts(0x7000), Some((2, 2)));
    // A created result must be the unpublished body, and only with plain success.
    assert_eq!(store.admit_desktop_parse_result(NtStatus::SUCCESS, 0x7000, true),
        Err(NtStatus::INVALID_PARAMETER));
}

/// Open by name: IntDesktopObjectParse walked DesktopListHead and referenced the existing body;
/// the new handle consumes that reference, and OBJ_OPENIF keeps its informational status.
#[test]
fn a_parse_opened_desktop_handle_consumes_the_parse_reference() {
    let mut store = UserObjectStore::new();
    let default = inserted(&mut store, ObKind::Desktop, 0x7000, UserObjectName::Unnamed);
    assert_eq!(store.reference(0x7000), Ok(2));
    let opened = store.admit_desktop_parse_result(NtStatus::SUCCESS, 0x7000, false).unwrap();
    assert_eq!(opened.identity, default);
    assert_eq!(store.counts(0x7000), Some((2, 2)));
    assert_eq!(store.reference(0x7000), Ok(3));
    let exists = store.admit_desktop_parse_result(NtStatus::OBJECT_NAME_EXISTS, 0x7000, false).unwrap();
    assert_eq!(exists.status, NtStatus::OBJECT_NAME_EXISTS);
    assert_eq!(store.counts(0x7000), Some((3, 3)));
    // Without the parse's reference there is nothing for a handle to consume.
    assert_eq!(store.admit_desktop_parse_result(NtStatus::SUCCESS, 0x7000, false),
        Err(NtStatus::INVALID_PARAMETER));
    assert_eq!(store.counts(0x7000), Some((3, 3)));
}

#[test]
fn a_failed_or_foreign_parse_result_is_not_admitted() {
    let mut store = UserObjectStore::new();
    let failed = NtStatus(0xC000_0017u32 as i32);
    assert_eq!(store.admit_desktop_parse_result(failed, 0, true), Err(failed));
    inserted(&mut store, ObKind::WindowStation, 0x5000, UserObjectName::Unnamed);
    assert_eq!(store.reference(0x5000), Ok(2));
    assert_eq!(store.admit_desktop_parse_result(NtStatus::SUCCESS, 0x5000, false),
        Err(NtStatus::OBJECT_TYPE_MISMATCH));
    assert_eq!(store.admit_desktop_parse_result(NtStatus::SUCCESS, 0x9000, false),
        Err(NtStatus::INVALID_HANDLE));
    assert_eq!(store.admit_desktop_parse_result(NtStatus::OBJECT_NAME_EXISTS, 0x9000, true),
        Err(NtStatus::INVALID_PARAMETER));
}
