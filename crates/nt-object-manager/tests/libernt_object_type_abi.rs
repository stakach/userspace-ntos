//! Pinned LiberNT x64 object-type ABI used by the released dxgkrnl binary.
//!
//! Source: LiberNT 8e478a22a1e8f8a22bab17131f3184a7b4548c3d,
//! sdk/include/ndk/obtypes.h, OBJECT_TYPE_INITIALIZER and OBJECT_TYPE.

use core::mem::{offset_of, size_of, size_of_val};
use nt_object_manager::object_type::{ObjectType, ObjectTypeInitializer};

#[test]
fn released_initializer_has_nt10_x64_layout() {
    assert_eq!(size_of::<ObjectTypeInitializer>(), 0x78);
    assert_eq!(offset_of!(ObjectTypeInitializer, length), 0x00);
    assert_eq!(offset_of!(ObjectTypeInitializer, object_type_flags), 0x02);
    assert_eq!(offset_of!(ObjectTypeInitializer, object_type_code), 0x04);
    assert_eq!(offset_of!(ObjectTypeInitializer, invalid_attributes), 0x08);
    assert_eq!(offset_of!(ObjectTypeInitializer, generic_mapping), 0x0c);
    assert_eq!(offset_of!(ObjectTypeInitializer, valid_access_mask), 0x1c);
    assert_eq!(offset_of!(ObjectTypeInitializer, retain_access), 0x20);
    assert_eq!(offset_of!(ObjectTypeInitializer, pool_type), 0x24);
    assert_eq!(offset_of!(ObjectTypeInitializer, default_paged_pool_charge), 0x28);
    assert_eq!(offset_of!(ObjectTypeInitializer, default_nonpaged_pool_charge), 0x2c);
    assert_eq!(offset_of!(ObjectTypeInitializer, methods), 0x30);
    assert_eq!(offset_of!(ObjectTypeInitializer, wait_object_flag_mask), 0x70);
    assert_eq!(offset_of!(ObjectTypeInitializer, wait_object_flag_offset), 0x74);
    assert_eq!(offset_of!(ObjectTypeInitializer, wait_object_pointer_offset), 0x76);
}

#[test]
fn released_object_type_places_identity_and_initializer_at_nt10_offsets() {
    assert_eq!(size_of::<ObjectType>(), 0xe0);
    assert_eq!(offset_of!(ObjectType, name), 0x10);
    assert_eq!(offset_of!(ObjectType, default_object), 0x20);
    assert_eq!(offset_of!(ObjectType, index), 0x28);
    assert_eq!(size_of::<u8>(), size_of_val_index());
    assert_eq!(offset_of!(ObjectType, type_info), 0x40);
    assert_eq!(offset_of!(ObjectType, key), 0xc0);
}

fn size_of_val_index() -> usize {
    let object_type = ObjectType::new(&[], 26);
    size_of_val(&object_type.index)
}

#[test]
fn dxg_initializer_flags_and_delete_callback_are_decoded_without_old_byte_fields() {
    // dxgkrnl's DxgkSharedObjectsInitialize sets UseDefaultObject,
    // SecurityRequired and DeleteProcedure after zeroing this structure.
    let mut raw = [0u8; 0x78];
    raw[0..2].copy_from_slice(&(0x78u16).to_le_bytes());
    raw[2..4].copy_from_slice(&((1u16 << 2) | (1u16 << 3)).to_le_bytes());
    raw[0x48..0x50].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let initializer = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast::<ObjectTypeInitializer>()) };
    assert!(initializer.use_default_object());
    assert!(initializer.security_required());
    assert_eq!(initializer.methods[3], 0x1122_3344_5566_7788);
    assert!(initializer.supports_hosted_delete());
}

#[test]
fn initializer_with_unimplemented_callbacks_or_wait_policy_is_not_admitted() {
    let mut raw = [0u8; 0x78];
    raw[0..2].copy_from_slice(&0x78u16.to_le_bytes());
    raw[0x48..0x50].copy_from_slice(&0x1122_3344_5566_7788u64.to_le_bytes());
    let mut initializer = unsafe { core::ptr::read_unaligned(raw.as_ptr().cast::<ObjectTypeInitializer>()) };
    initializer.object_type_flags = 1 << 6; // SupportsObjectCallbacks
    assert!(!initializer.supports_hosted_delete());
    initializer.object_type_flags = 0;
    initializer.wait_object_flag_mask = 1;
    assert!(!initializer.supports_hosted_delete());
}
