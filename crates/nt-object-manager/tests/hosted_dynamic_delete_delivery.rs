use nt_object_manager::hosted_dynamic_type::{
    DynamicHandleOwner, DynamicTypeDefinition, DynamicTypeOwner, HostedDynamicTypeRegistry,
};

fn type_owner() -> DynamicTypeOwner {
    DynamicTypeOwner {
        image_base: 0x1000_0000,
        image_len: 0x10000,
        image_generation: 7,
        domain_id: 3,
        domain_cookie: 11,
    }
}

fn definition() -> DynamicTypeDefinition {
    DynamicTypeDefinition {
        name: "SharedResource".encode_utf16().collect(),
        delete_procedure: 0x1000_1234,
        invalid_attributes: 0,
        generic_mapping: [0; 4],
        valid_access_mask: u32::MAX,
        pool_type: 0,
        default_nonpaged_pool_charge: 0,
        use_default_object: false,
        security_required: false,
    }
}

#[test]
fn last_handle_close_only_exposes_delete_after_borrowed_reference_drops() {
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = registry.register(type_owner(), definition()).unwrap();
    let object = registry.publish_object(ty, 0x2000_0000).unwrap();
    assert!(registry.owns_live_body(ty, object.body()));
    let owner = DynamicHandleOwner { process_id: 9, creation_sequence: 5 };
    registry.insert_object(object, owner, 0x40).unwrap();
    let borrowed = registry.reference_handle(owner, 0x40, ty).unwrap();
    assert_eq!(borrowed, object);
    registry.close_handle(owner, 0x40).unwrap();
    assert_eq!(registry.next_ready_delete(), None);
    registry.dereference_object(borrowed).unwrap();
    assert_eq!(registry.next_ready_delete(), Some(object));
    let ticket = registry.take_delete(object).unwrap();
    assert_eq!(ticket.owner, type_owner());
    assert_eq!(ticket.callback, 0x1000_1234);
    assert_eq!(ticket.object, 0x2000_0000);
    assert_eq!(registry.next_ready_delete(), None);
    assert_eq!(registry.take_delete(object), None);
    registry.complete_delete(ticket).unwrap();
    assert!(!registry.owns_live_body(ty, object.body()));
    assert_eq!(registry.lease_for_live_body(0x2000_0000), None);
}

#[test]
fn failed_insert_is_retained_until_definite_callback_return() {
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = registry.register(type_owner(), definition()).unwrap();
    let object = registry.publish_object(ty, 0x2000_0000).unwrap();
    assert!(registry.owns_live_body(ty, object.body()));
    registry.fail_insert(object).unwrap();
    assert_eq!(registry.next_ready_delete(), Some(object));
    let ticket = registry.take_delete(object).unwrap();
    assert!(registry.owns_live_body(ty, object.body()));
    assert_eq!(registry.next_ready_delete(), None);
    assert_eq!(registry.take_delete(object), None);
    registry.complete_delete(ticket).unwrap();
    assert!(!registry.owns_live_body(ty, object.body()));
    assert_eq!(registry.next_ready_delete(), None);
}
