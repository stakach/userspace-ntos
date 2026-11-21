//! A handle created through `OBJECT_ATTRIBUTES` keeps the request's `OBJ_INHERIT`.

use crate::*;

const OBJ_INHERIT: u32 = 0x2;
const OBJ_CASE_INSENSITIVE: u32 = 0x40;

fn bound(pm: &mut ProcessManager, pid: ProcessId, attributes: u32, tag: u64) -> Handle {
    let reservation = pm.try_reserve_handle_slot_for_attributes(pid, attributes).unwrap();
    pm.bind_reserved_handle(reservation, HandleObject::Opaque(tag), 0x0012_019f).unwrap();
    pm.publish_reserved_handle(reservation).unwrap()
}

#[test]
fn obj_inherit_create_is_inherited_by_a_child_at_the_same_value() {
    // Boot 44873582254: kernelbase opens \Device\ConDrv\Server with OBJ_INHERIT and passes it
    // in conhost's PROC_THREAD_ATTRIBUTE_HANDLE_LIST. kernel32 requires HANDLE_FLAG_INHERIT on
    // every listed handle, so a handle without it failed CreateProcessW before any service.
    let mut pm = ProcessManager::new();
    let parent = pm.create_process("cmd.exe", None, None);
    let server = bound(&mut pm, parent, OBJ_INHERIT, 0x10);
    let private = bound(&mut pm, parent, OBJ_CASE_INSENSITIVE, 0x20);

    assert_eq!(
        pm.handle_flags(parent, server),
        Some(HandleFlags { inherit: true, protect_from_close: false })
    );
    assert_eq!(pm.handle_flags(parent, private), Some(HandleFlags::default()));
    let inherited: Vec<Handle> =
        pm.inheritable_handles(parent).unwrap().iter().map(|entry| entry.handle).collect();
    assert_eq!(inherited, [server]);
}

#[test]
fn a_cancelled_inheritable_reservation_leaves_no_flags_for_the_next_handle() {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("cmd.exe", None, None);
    let reservation = pm.try_reserve_handle_slot_for_attributes(pid, OBJ_INHERIT).unwrap();
    pm.cancel_reserved_handle(reservation).unwrap();
    let plain = bound(&mut pm, pid, 0, 0x30);
    assert_eq!(pm.handle_flags(pid, plain), Some(HandleFlags::default()));
}
