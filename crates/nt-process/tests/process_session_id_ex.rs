//! Session membership is distinct from the numeric ProcessSessionInformation value.

use nt_process::ProcessManager;

#[test]
fn session_id_ex_distinguishes_unattached_leader_member_and_detach() {
    let mut pm = ProcessManager::new();
    let leader = pm.create_process("session-leader.exe", None, None);
    let member = pm.create_process("session-member.exe", Some(leader), None);
    assert!(pm.publish_process_kernel_object(leader, 0x1000));
    assert!(pm.publish_process_kernel_object(member, 0x2000));

    // A numeric default of zero does not establish a Session-space attachment.
    assert_eq!(pm.kernel_process_session_id_ex(0x1000), Some(u32::MAX));
    assert_eq!(pm.kernel_process_session_id_ex(0x2000), Some(u32::MAX));

    // MmSessionCreate marks the caller as leader. Its Ex result is zero even
    // when the created session's numeric ID is nonzero.
    pm.create_process_session(leader, 3).unwrap();
    assert_eq!(pm.kernel_process_session_id_ex(0x1000), Some(0));

    // A child created before the leader's transition is not retroactively attached.
    assert_eq!(pm.kernel_process_session_id_ex(0x2000), Some(u32::MAX));
    pm.attach_process_session(member, 3).unwrap();
    assert_eq!(pm.kernel_process_session_id_ex(0x2000), Some(3));
    assert_eq!(pm.kernel_process_session_id_ex(0x1000), Some(0));

    let inherited = pm.create_process("inherited-member.exe", Some(leader), None);
    assert!(pm.publish_process_kernel_object(inherited, 0x6000));
    assert_eq!(pm.kernel_process_session_id_ex(0x6000), Some(3));

    // Session delete is the leader-only SystemSessionDetach transition.
    assert!(pm.delete_process_session(member, 3).is_err());
    assert!(pm.delete_process_session(leader, 2).is_err());
    assert_eq!(pm.kernel_process_session_id_ex(0x2000), Some(3));

    pm.detach_process_session(member).unwrap();
    assert_eq!(pm.kernel_process_session_id_ex(0x2000), Some(u32::MAX));
    pm.delete_process_session(leader, 3).unwrap();
    assert_eq!(pm.kernel_process_session_id_ex(0x1000), Some(0));
    assert_eq!(pm.kernel_process_session_id_ex(0), None);
    assert_eq!(pm.kernel_process_session_id_ex(0x3000), None);
}

#[test]
fn session_zero_member_and_stale_eprocess_are_not_confused() {
    let mut pm = ProcessManager::new();
    let leader = pm.create_process("leader-zero.exe", None, None);
    let member = pm.create_process("member-zero.exe", Some(leader), None);
    assert!(pm.publish_process_kernel_object(leader, 0x4000));
    assert!(pm.publish_process_kernel_object(member, 0x5000));
    pm.create_process_session(leader, 0).unwrap();
    pm.attach_process_session(member, 0).unwrap();
    assert_eq!(pm.kernel_process_session_id_ex(0x4000), Some(0));
    assert_eq!(pm.kernel_process_session_id_ex(0x5000), Some(0));

    pm.terminate_process(member, 0).unwrap();
    assert!(pm.delete_process_object_if_unreferenced(member).is_some());
    assert_eq!(pm.kernel_process_session_id_ex(0x5000), None);

    // Reused addresses resolve only to the new published process incarnation.
    let replacement = pm.create_process("replacement.exe", None, None);
    assert!(pm.publish_process_kernel_object(replacement, 0x5000));
    assert_eq!(pm.kernel_process_session_id_ex(0x5000), Some(u32::MAX));
}
