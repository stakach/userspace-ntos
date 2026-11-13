use nt_kernel_exec::hosted_process_exit_notify::{
    HostedImageIdentity, HostedProcessExitDelivery, HostedProcessNotifyOwner, ProcessExitCall,
};
use nt_process::{ProcessManager, ProcessExitNotifyOwner};

#[test]
fn callback_address_must_belong_to_exact_loaded_image_instance() {
    let image = HostedImageIdentity {
        run_base: 0x5000_0000,
        image_len: 0x4000,
        publication_generation: 11,
    };
    assert_eq!(
        image.owner_for_callback(0x5000_1000),
        Some(HostedProcessNotifyOwner {
            image_base: image.run_base,
            image_generation: image.publication_generation,
        })
    );
    assert!(image.owner_for_callback(image.run_base - 1).is_none());
    assert!(image.owner_for_callback(image.run_base + image.image_len).is_none());
    assert!(HostedImageIdentity { publication_generation: 0, ..image }
        .owner_for_callback(0x5000_1000).is_none());
}

#[test]
fn exit_call_uses_retained_process_and_exact_provider_generation() {
    let mut processes = ProcessManager::new();
    let image = HostedImageIdentity {
        run_base: 0x6000_0000,
        image_len: 0x8000,
        publication_generation: 15,
    };
    let callback = 0x6000_2340;
    let owner = image.owner_for_callback(callback).unwrap();
    processes.register_process_exit_notify(ProcessExitNotifyOwner {
        image_base: owner.image_base,
        image_generation: owner.image_generation,
    }, callback).unwrap();
    let pid = processes.create_process("exiting.exe", None, None);
    assert!(processes.publish_process_kernel_object(pid, 0x7000_0000));
    processes.terminate_process(pid, 7).unwrap();
    let delivery = processes.take_process_exit_notification().unwrap();
    let view = HostedProcessExitDelivery {
        owner,
        callback: delivery.callback,
        process_id: delivery.process_id,
        process_object: delivery.process_object,
    };

    assert_eq!(
        ProcessExitCall::for_delivery(view, image).unwrap(),
        ProcessExitCall {
            callback,
            process_object: 0x7000_0000,
            process_id: pid,
            create_info: 0,
        }
    );
    assert!(ProcessExitCall::for_delivery(view,
        HostedImageIdentity { publication_generation: 16, ..image }).is_none());
    assert_eq!(processes.process_object_delete_blockers(pid).unwrap().process_exit_notifications, 1);
    processes.complete_process_exit_notification(delivery).unwrap();
    assert_eq!(processes.process_object_delete_blockers(pid).unwrap().process_exit_notifications, 0);
}
