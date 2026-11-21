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
