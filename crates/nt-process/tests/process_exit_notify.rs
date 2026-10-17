use nt_process::{ProcessExitNotifyOwner, ProcessManager, STATUS_DEVICE_BUSY};

#[test]
fn exit_notification_retains_exact_provider_and_process_lifetimes_until_completion() {
    let mut processes = ProcessManager::new();
    let owner = ProcessExitNotifyOwner {
        image_base: 0x1000_0000,
        image_generation: 7,
    };
    processes
        .register_process_exit_notify(owner, 0x1000_1234)
        .unwrap();

    let pid = processes.create_process("first.exe", None, None);
    assert!(processes.publish_process_kernel_object(pid, 0x3000_0000));
    processes.terminate_process(pid, 0x1234).unwrap();
    let delivery = processes.take_process_exit_notification().unwrap();
    assert_eq!(delivery.owner, owner);
    assert_eq!(delivery.callback, 0x1000_1234);
    assert_eq!(delivery.process_id, pid);
    assert_eq!(delivery.process_object, 0x3000_0000);
    assert_ne!(delivery.process_sequence, 0);
    assert_eq!(delivery.exit_status, 0x1234);
    assert_eq!(
        processes.process_object_delete_blockers(pid).unwrap().process_exit_notifications,
        1
    );

    // A provider may not retire its image while an exact callback is in flight.
    assert_eq!(
        processes.unregister_process_exit_notify(owner, 0x1000_1234),
        Err(STATUS_DEVICE_BUSY)
    );
    processes.terminate_process(pid, 0x5678).unwrap();
    assert!(processes.take_process_exit_notification().is_none());
    processes.complete_process_exit_notification(delivery).unwrap();
    assert_eq!(
        processes.process_object_delete_blockers(pid).unwrap().process_exit_notifications,
        0
    );
    assert!(processes.complete_process_exit_notification(delivery).is_err());
    processes
        .unregister_process_exit_notify(owner, 0x1000_1234)
        .unwrap();
}

#[test]
fn registration_identity_prevents_stale_image_generation_from_removing_a_callback() {
    let mut processes = ProcessManager::new();
    let owner = ProcessExitNotifyOwner {
        image_base: 0x2000_0000,
        image_generation: 3,
    };
    let stale = ProcessExitNotifyOwner {
        image_base: owner.image_base,
        image_generation: 2,
    };
    processes
        .register_process_exit_notify(owner, 0x2000_4321)
        .unwrap();
    assert!(processes
        .register_process_exit_notify(owner, 0x2000_4321)
        .is_err());
    assert!(processes
        .unregister_process_exit_notify(stale, 0x2000_4321)
        .is_err());

    let pid = processes.create_process("second.exe", None, None);
    assert!(processes.publish_process_kernel_object(pid, 0x4000_0000));
    processes.terminate_process(pid, 0).unwrap();
    let delivery = processes.take_process_exit_notification().unwrap();
    assert_eq!(delivery.owner, owner);
    processes.complete_process_exit_notification(delivery).unwrap();
    processes
        .unregister_process_exit_notify(owner, 0x2000_4321)
        .unwrap();
}

#[test]
fn exit_callback_requires_a_published_eprocess_before_terminal_transition() {
    let mut processes = ProcessManager::new();
    let owner = ProcessExitNotifyOwner {
        image_base: 0x5000_0000,
        image_generation: 1,
    };
    processes.register_process_exit_notify(owner, 0x5000_1234).unwrap();
    let pid = processes.create_process("unpublished.exe", None, None);
    assert!(processes.terminate_process(pid, 0).is_err());
    assert!(!processes.is_process_signaled(pid));
    assert!(processes.take_process_exit_notification().is_none());
}
