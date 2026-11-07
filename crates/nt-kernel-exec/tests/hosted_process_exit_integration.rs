use nt_kernel_exec::hosted_process_exit_notify::{
    HostedImageIdentity, HostedProcessExitDelivery, HostedProcessNotifyBinding,
    HostedProcessNotifyTransport, ProcessExitDispatchResult,
};
use nt_process::{ProcessExitNotifyOwner, ProcessManager, STATUS_DEVICE_BUSY};

#[test]
fn exact_driver_transport_registers_and_completes_a_real_pm_exit_ticket() {
    let mut processes = ProcessManager::new();
    let binding = HostedProcessNotifyBinding {
        image: HostedImageIdentity {
            run_base: 0x8000_0000,
            image_len: 0x4000,
            publication_generation: 8,
        },
        transport: HostedProcessNotifyTransport {
            domain_id: 23,
            domain_cookie: 31,
            endpoint: 41,
            vspace: 51,
            shared: 61,
        },
    };
    let callback = 0x8000_0120;
    binding.register(callback, |owner, address| {
        processes.register_process_exit_notify(
            ProcessExitNotifyOwner {
                image_base: owner.image_base,
                image_generation: owner.image_generation,
            },
            address,
        )
    }).unwrap();
    let pid = processes.create_process("gpu-client.exe", None, None);
    assert!(processes.publish_process_kernel_object(pid, 0x9000_0000));
    processes.terminate_process(pid, 0).unwrap();
    let ticket = processes.take_process_exit_notification().unwrap();
    let view = HostedProcessExitDelivery {
        owner: binding.image.owner_for_callback(callback).unwrap(),
        callback: ticket.callback,
        process_id: ticket.process_id,
        process_object: ticket.process_object,
    };
    let stale_transport = HostedProcessNotifyBinding {
        transport: HostedProcessNotifyTransport {
            domain_cookie: binding.transport.domain_cookie + 1,
            ..binding.transport
        },
        ..binding
    };
    assert!(binding.plan_exit(view, stale_transport).is_none());
    let plan = binding.plan_exit(view, binding).unwrap();
    let mut calls = 0;
    assert_eq!(
        plan.execute(
            |call, transport| {
                calls += 1;
                assert_eq!(transport, binding.transport);
                assert_eq!(call.callback, callback);
                assert_eq!(call.process_object, 0x9000_0000);
                assert_eq!(call.process_id, pid);
                assert_eq!(call.create_info, 0);
                Ok::<(), u32>(())
            },
            || processes.complete_process_exit_notification(ticket),
        ),
        ProcessExitDispatchResult::Completed
    );
    assert_eq!(calls, 1);
    assert_eq!(processes.process_object_delete_blockers(pid).unwrap().process_exit_notifications, 0);
}

#[test]
fn uncertain_provider_call_keeps_ticket_and_image_retirement_blocked() {
    let mut processes = ProcessManager::new();
    let binding = HostedProcessNotifyBinding {
        image: HostedImageIdentity {
            run_base: 0xA000_0000,
            image_len: 0x1000,
            publication_generation: 5,
        },
        transport: HostedProcessNotifyTransport {
            domain_id: 2,
            domain_cookie: 3,
            endpoint: 4,
            vspace: 5,
            shared: 6,
        },
    };
    let callback = 0xA000_0020;
    let owner = ProcessExitNotifyOwner { image_base: binding.image.run_base, image_generation: binding.image.publication_generation };
    binding.register(callback, |_, address| processes.register_process_exit_notify(owner, address)).unwrap();
    let pid = processes.create_process("uncertain.exe", None, None);
    assert!(processes.publish_process_kernel_object(pid, 0xB000_0000));
    processes.terminate_process(pid, 0).unwrap();
    let ticket = processes.take_process_exit_notification().unwrap();
    let view = HostedProcessExitDelivery {
        owner: binding.image.owner_for_callback(callback).unwrap(),
        callback: ticket.callback,
        process_id: ticket.process_id,
        process_object: ticket.process_object,
    };
    let plan = binding.plan_exit(view, binding).unwrap();
    assert_eq!(
        plan.execute(|_, _| Err::<(), u32>(0xDEAD), || panic!("uncertain callback cannot acknowledge")),
        ProcessExitDispatchResult::CallbackUncertain(0xDEAD)
    );
    assert!(processes.take_process_exit_notification().is_none());
    assert_eq!(processes.unregister_process_exit_notify(owner, callback), Err(STATUS_DEVICE_BUSY));
    assert_eq!(processes.process_object_delete_blockers(pid).unwrap().process_exit_notifications, 1);
}
