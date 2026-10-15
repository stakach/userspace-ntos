use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_ledger::{SourceIrpAllocation, SourceIrpForwardIdentity, SourceIrpOwner};
use nt_io_manager::start_io_current::{CompletionObservation, CurrentPhase, CurrentReceipt, LivePacket};
use nt_io_manager::start_io_native_transaction::{StartIoCallbackFence, StartIoTransactionId};
use nt_io_manager::start_io_queued::QueuedStartIo;
use nt_io_manager::{DeviceCharacteristics, DeviceFlags, DeviceType, IoManager,
    MockDriverBackend, MockObjectPort};
use nt_types::NtPath;

fn packet(domain: nt_io_manager::HostedDomainIdentity, address: u64, generation: u64)
    -> SourceIrpForwardIdentity
{
    let allocation = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedCaller(3), domain,
        component_address: address, bytes: 0x128, stack_count: 2,
        pool_generation: generation,
    };
    SourceIrpForwardIdentity::new(
        SourceIrpTicket::new(domain, generation, generation).unwrap(), allocation,
    ).unwrap()
}

fn device() -> (IoManager<MockObjectPort>, nt_io_manager::HostedDevicePointerRegistration) {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.create_driver(&NtPath::parse_str(r"\Driver\StartIoSlot").unwrap(),
        Box::new(MockDriverBackend::new())).unwrap();
    let device = io.create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let domain = io.register_hosted_domain();
    let registration = io.bind_hosted_device_pointer(domain, 0x4000, device).unwrap();
    (io, registration)
}

#[test]
fn terminal_old_packet_settles_before_empty_next_without_losing_current_provenance() {
    let (_io, registration) = device();
    let old = packet(registration.domain(), 0x2000, 7);
    let mut current = CurrentReceipt::new(registration, registration.domain(), ());
    current.prepare_update(registration, 0, Some(LivePacket::new(old, 11u64)))
        .unwrap().commit();
    let id = StartIoTransactionId::new(41, 7).unwrap();
    let mut callback = StartIoCallbackFence::new(old, id, 99u64);
    callback.begin_reply().unwrap();
    callback.callback_returned(id).unwrap();
    callback.observe_terminal(old).unwrap();
    let pin = current.observe_completion(registration, old,
        CompletionObservation::Acknowledged).unwrap().unwrap();
    callback.retain_source(pin).unwrap();
    let (pin, owner) = callback.finish().ok().unwrap();
    assert_eq!(pin.identity(), old);
    assert_eq!(pin.into_owner(), 11);
    assert_eq!(owner, 99);
    assert_eq!(current.snapshot().phase, CurrentPhase::Completed);
    assert!(current.prepare_update(registration, old.allocation().component_address, None)
        .unwrap().commit().is_none());
    assert_eq!(current.snapshot().phase, CurrentPhase::Empty);
}

#[test]
fn selected_wdm_packet_displaces_live_current_into_old_callback_fence() {
    let (_io, registration) = device();
    let old = packet(registration.domain(), 0x2000, 7);
    let next = packet(registration.domain(), 0x3000, 8);
    let mut current = CurrentReceipt::new(registration, registration.domain(), ());
    current.prepare_update(registration, 0, Some(LivePacket::new(old, 11u64)))
        .unwrap().commit();
    let old_id = StartIoTransactionId::new(41, 7).unwrap();
    let mut old_callback = StartIoCallbackFence::new(old, old_id, 99u64);
    old_callback.begin_reply().unwrap();
    let queued = QueuedStartIo::new(next, LivePacket::new(next, 22u64));
    let selected = queued.select(next).ok().unwrap();
    let displaced = current.prepare_update(registration,
        old.allocation().component_address, Some(selected)).unwrap().commit().unwrap();
    assert_eq!(displaced.identity(), old);
    old_callback.retain_source(displaced).unwrap();
    assert_eq!(current.snapshot().packet, Some(next));
    assert_eq!(current.snapshot().phase, CurrentPhase::Live);
    old_callback.observe_terminal(old).unwrap();
    let mut old_callback = old_callback.finish().err()
        .expect("terminal completion cannot free an active callback");
    old_callback.callback_returned(old_id).unwrap();
    let (pin, owner) = old_callback.finish().ok().unwrap();
    assert_eq!(pin.identity(), old);
    assert_eq!(pin.into_owner(), 11);
    assert_eq!(owner, 99);
    assert_eq!(current.snapshot().packet, Some(next));
}
