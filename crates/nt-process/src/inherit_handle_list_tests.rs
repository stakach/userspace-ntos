//! Handle-list inheritance follows the winetest `test_handle_list_attribute`: the listed pipe end is
//! inherited with HANDLE_FLAG_INHERIT at the same value, the other inheritable end is not.

use crate::*;

fn parent_with_two_inheritable_handles() -> (ProcessManager, ProcessId, Handle, Handle, Handle) {
    let mut pm = ProcessManager::new();
    let parent = pm.create_process("cmd.exe", None, None);
    let inherit = HandleFlags { inherit: true, protect_from_close: false };
    let listed = pm.insert_handle(parent, HandleObject::Opaque(0x10), 0x0012_019f).unwrap();
    pm.set_handle_flags(parent, listed, inherit).unwrap();
    let other = pm.insert_handle(parent, HandleObject::Opaque(0x20), 0x0012_019f).unwrap();
    pm.set_handle_flags(parent, other, inherit).unwrap();
    let private = pm.insert_handle(parent, HandleObject::Opaque(0x30), 0x0012_019f).unwrap();
    (pm, parent, listed, other, private)
}

#[test]
fn only_listed_handles_are_inherited_at_their_values() {
    let (pm, parent, listed, _other, _private) = parent_with_two_inheritable_handles();
    let inherited = pm.inheritable_handles_from_list(parent, &[u64::from(listed)]).unwrap();
    assert_eq!(inherited.len(), 1);
    assert_eq!(inherited[0].handle, listed);
    assert_eq!(inherited[0].object, HandleObject::Opaque(0x10));
    assert!(inherited[0].flags.inherit);
}

#[test]
fn a_listed_handle_must_exist_and_be_inheritable() {
    let (pm, parent, listed, _other, private) = parent_with_two_inheritable_handles();
    assert_eq!(
        pm.inheritable_handles_from_list(parent, &[u64::from(listed), u64::from(private)]),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert_eq!(
        pm.inheritable_handles_from_list(parent, &[u64::from(listed), 0x7ffc]),
        Err(STATUS_INVALID_HANDLE)
    );
    assert_eq!(pm.inheritable_handles_from_list(parent, &[u64::MAX]), Err(STATUS_INVALID_HANDLE));
}

#[test]
fn a_repeated_listed_handle_is_inherited_once() {
    let (pm, parent, listed, _other, _private) = parent_with_two_inheritable_handles();
    let inherited =
        pm.inheritable_handles_from_list(parent, &[u64::from(listed), u64::from(listed)]).unwrap();
    assert_eq!(inherited.len(), 1);
}

fn create_args(list: u64, size: u64) -> [u64; 11] {
    [0, 0, 0, 0x40, u64::from(PROCESS_CREATE_FLAGS_INHERIT_HANDLES), 0x100, 0, 0, 0, list, size]
}

#[test]
fn the_private_service_captures_the_listed_handles() {
    let list: [u64; 2] = [0x1c, 0x24];
    let bytes: alloc::vec::Vec<u8> = list.iter().flat_map(|value| value.to_le_bytes()).collect();
    let create = decode_process_create_with_handle_list(&create_args(0x5000, 16), |va, out| {
        let at = usize::try_from(va - 0x5000).unwrap();
        out.copy_from_slice(&bytes[at..at + out.len()]);
        true
    })
    .unwrap();
    assert_eq!(create.flags, PROCESS_CREATE_FLAGS_INHERIT_HANDLES);
    assert_eq!(create.section_handle, 0x100);
    assert_eq!(create.inherit_list.unwrap().values(), &list);
}

#[test]
fn the_handle_list_size_must_be_whole_handles_within_capacity_and_needs_inheritance() {
    let ok = |_: u64, out: &mut [u8]| {
        out.fill(0);
        true
    };
    assert_eq!(decode_process_create_with_handle_list(&create_args(0x5000, 0), ok), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(decode_process_create_with_handle_list(&create_args(0x5000, 12), ok), Err(STATUS_INVALID_PARAMETER));
    let too_long = (INHERIT_HANDLE_LIST_CAPACITY as u64 + 1) * 8;
    assert_eq!(
        decode_process_create_with_handle_list(&create_args(0x5000, too_long), ok),
        Err(STATUS_INSUFFICIENT_RESOURCES)
    );
    let mut no_inherit = create_args(0x5000, 8);
    no_inherit[4] = 0;
    assert_eq!(decode_process_create_with_handle_list(&no_inherit, ok), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        decode_process_create_with_handle_list(&create_args(0x5000, 8), |_, _| false),
        Err(STATUS_ACCESS_VIOLATION)
    );
}
