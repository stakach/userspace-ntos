//! LiberNT dxgkrnl registers `DxgkSharedResource` from DriverEntry. Its type descriptor carries
//! a delete procedure in the same loaded image; a type pointer or callback VA alone is not
//! sufficient authority to invoke that procedure or retire its provider.

use nt_object_manager::hosted_dynamic_type::{
    DynamicTypeDefinition, DynamicTypeOwner, HostedDynamicTypeRegistry,
};

fn dxgk_owner(generation: u64) -> DynamicTypeOwner {
    DynamicTypeOwner {
        image_base: 0xFFFF_8000_1000_0000,
        image_len: 0x20_0000,
        image_generation: generation,
        domain_id: 7,
        domain_cookie: 11,
    }
}

fn dxgk_type(delete_procedure: u64) -> DynamicTypeDefinition {
    DynamicTypeDefinition {
        name: "DxgkSharedResource".encode_utf16().collect(),
        delete_procedure,
        invalid_attributes: 0x100, // OBJ_OPENLINK
        generic_mapping: [0x20000, 0x20001, 0x20000, 0x1F0001],
        valid_access_mask: 0x1F0001,
        pool_type: 0, // NonPagedPool
        default_nonpaged_pool_charge: 8,
        use_default_object: true,
        security_required: true,
    }
}

#[test]
fn dxgk_type_retains_exact_image_generation_and_delete_procedure() {
    let owner = dxgk_owner(3);
    let callback = owner.image_base + 0x35A0;
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = registry.register(owner, dxgk_type(callback)).unwrap();

    assert_eq!(registry.definition(ty).unwrap().delete_procedure, callback);
    assert_eq!(registry.owner(ty), Some(owner));
    assert!(registry.register(owner, dxgk_type(callback)).is_err());
    assert!(registry.blocks_owner_retirement(owner));
}

#[test]
fn callback_address_must_belong_to_the_published_image_generation() {
    let owner = dxgk_owner(5);
    let mut registry = HostedDynamicTypeRegistry::new();
    assert!(registry.register(owner, dxgk_type(owner.image_base - 8)).is_err());
    assert!(registry.register(owner, dxgk_type(owner.image_base + owner.image_len)).is_err());
    assert_eq!(registry.type_count(), 0);

    let callback = owner.image_base + 0x35A0;
    let ty = registry.register(owner, dxgk_type(callback)).unwrap();
    assert_eq!(registry.owner(ty), Some(owner));
    assert_ne!(registry.owner(ty), Some(dxgk_owner(6)));
    assert!(!registry.blocks_owner_retirement(dxgk_owner(6)));
}

#[test]
fn deletion_is_one_shot_and_keeps_callback_owner_live_until_completion() {
    let owner = dxgk_owner(9);
    let callback = owner.image_base + 0x35A0;
    let mut registry = HostedDynamicTypeRegistry::new();
    let ty = registry.register(owner, dxgk_type(callback)).unwrap();
    let object = registry.publish_object(ty, 0xFFFF_9000_0000_1000).unwrap();
    let ticket = registry.take_delete(object).unwrap();

    assert_eq!(ticket.owner, owner);
    assert_eq!(ticket.callback, callback);
    assert_eq!(ticket.object, 0xFFFF_9000_0000_1000);
    assert!(registry.take_delete(object).is_none());
    assert!(registry.blocks_owner_retirement(owner));
    registry.complete_delete(ticket).unwrap();
    assert!(registry.complete_delete(ticket).is_err());
    // ObCreateObjectType has no corresponding unregister; the type's callback still owns the image.
    assert!(registry.blocks_owner_retirement(owner));
}
