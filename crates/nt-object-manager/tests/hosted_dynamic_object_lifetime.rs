//! RED contract for LiberNT dxgkrnl's `DxgkSharedResource` object lifetime.
//!
//! The pinned `drivers/directx/dxgkrnl/d3dkmt.c` calls ObCreateObject, writes a
//! resource pointer into the returned body, then calls ObInsertObject. Its type's
//! DeleteProcedure releases that resource. These transitions must be owned by the
//! object manager, including the failure path where insertion consumes the creator
//! reference and deletion invokes the callback exactly once.

use nt_object_manager::hosted_dynamic_type::{
    DynamicHandleOwner, DynamicTypeDefinition, DynamicTypeOwner, HostedDynamicTypeRegistry,
};

fn handle_owner(process_id: u32, creation_sequence: u64) -> DynamicHandleOwner {
    DynamicHandleOwner { process_id, creation_sequence }
}

fn owner() -> DynamicTypeOwner {
    DynamicTypeOwner {
        image_base: 0xFFFF_8000_1000_0000,
        image_len: 0x20_0000,
        image_generation: 7,
        domain_id: 11,
        domain_cookie: 13,
    }
}

fn register_type(registry: &mut HostedDynamicTypeRegistry) -> nt_object_manager::hosted_dynamic_type::DynamicTypeId {
    let owner = owner();
    registry.register(
        owner,
        DynamicTypeDefinition {
            name: "DxgkSharedResource".encode_utf16().collect(),
            delete_procedure: owner.image_base + 0x1234,
            invalid_attributes: 0x100,
            generic_mapping: [0x20000, 0x20001, 0x20000, 0x1f0001],
            valid_access_mask: 0x1f0001,
            pool_type: 0,
            default_nonpaged_pool_charge: 8,
            use_default_object: true,
            security_required: true,
        },
    ).unwrap()
}

#[test]
fn insert_transfers_the_creator_reference_to_a_real_handle() {
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = register_type(&mut registry);
    let body = 0xFFFF_9000_0000_1000;
    let handle = 0x44;
    let process = handle_owner(4, 7);
    let object = registry.publish_object(ty, body).unwrap();

    assert!(registry.take_delete(object).is_none(), "creator still owns the body");
    registry.insert_object(object, process, handle).unwrap();
    assert!(registry.take_delete(object).is_none(), "handle now owns the body");
    registry.close_handle(process, handle).unwrap();

    let ticket = registry.take_delete(object).expect("last handle schedules deletion");
    assert_eq!(ticket.object, body);
    assert_eq!(ticket.owner, owner());
    assert!(registry.take_delete(object).is_none(), "callback may start only once");
    registry.complete_delete(ticket).unwrap();
}

#[test]
fn failed_insertion_consumes_the_creator_and_schedules_the_type_delete() {
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = register_type(&mut registry);
    let object = registry.publish_object(ty, 0xFFFF_9000_0000_2000).unwrap();

    registry.fail_insert(object).unwrap();
    let ticket = registry.take_delete(object).expect("failure still releases dxgkrnl Resource");
    assert_eq!(ticket.callback, owner().image_base + 0x1234);
    assert!(registry.fail_insert(object).is_err(), "creator reference is already consumed");
    assert!(registry.take_delete(object).is_none(), "delete callback is already in flight");
    registry.complete_delete(ticket).unwrap();
}

#[test]
fn typed_reference_outlives_handle_close_and_rejects_wrong_type() {
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = register_type(&mut registry);
    let other = registry.register(owner(), DynamicTypeDefinition {
        name: "OtherType".encode_utf16().collect(),
        delete_procedure: owner().image_base + 0x5678,
        invalid_attributes: 0,
        generic_mapping: [0; 4],
        valid_access_mask: 0,
        pool_type: 0,
        default_nonpaged_pool_charge: 8,
        use_default_object: true,
        security_required: false,
    }).unwrap();
    let body = 0xFFFF_9000_0000_3000;
    let handle = 0x48;
    let process = handle_owner(4, 7);
    let object = registry.publish_object(ty, body).unwrap();
    registry.insert_object(object, process, handle).unwrap();

    assert!(registry.reference_handle(process, handle, other).is_err());
    assert_eq!(registry.reference_handle(process, handle, ty).unwrap(), object);
    registry.close_handle(process, handle).unwrap();
    assert!(registry.take_delete(object).is_none(), "typed reference retains the body");
    registry.dereference_object(object).unwrap();
    let ticket = registry.take_delete(object).expect("last reference schedules deletion");
    assert_eq!(ticket.object, body);
    registry.complete_delete(ticket).unwrap();
}

#[test]
fn equal_handle_numbers_are_scoped_by_nonreused_process_creation_identity() {
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = register_type(&mut registry);
    let old_process = handle_owner(4, 7);
    let new_process = handle_owner(4, 8);
    let other_process = handle_owner(5, 9);
    let handle = 0x4c;
    let first = registry.publish_object(ty, 0xFFFF_9000_0000_4000).unwrap();
    let second = registry.publish_object(ty, 0xFFFF_9000_0000_5000).unwrap();
    let third = registry.publish_object(ty, 0xFFFF_9000_0000_6000).unwrap();
    registry.insert_object(first, old_process, handle).unwrap();
    registry.insert_object(second, new_process, handle).unwrap();
    registry.insert_object(third, other_process, handle).unwrap();

    assert_eq!(registry.reference_handle(old_process, handle, ty).unwrap(), first);
    assert_eq!(registry.reference_handle(new_process, handle, ty).unwrap(), second);
    assert_eq!(registry.reference_handle(other_process, handle, ty).unwrap(), third);
    registry.dereference_object(first).unwrap();
    registry.dereference_object(second).unwrap();
    registry.dereference_object(third).unwrap();
    registry.close_handle(old_process, handle).unwrap();
    assert!(registry.reference_handle(old_process, handle, ty).is_err());
    assert_eq!(registry.reference_handle(new_process, handle, ty).unwrap(), second);
    registry.dereference_object(second).unwrap();
}
