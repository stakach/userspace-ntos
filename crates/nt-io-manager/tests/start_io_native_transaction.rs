use nt_io_manager::source_irp_ledger::{SourceIrpAllocation, SourceIrpLedger, SourceIrpOwner};
use nt_io_manager::start_io_current::{CompletionObservation, CurrentPhase, CurrentReceipt, LivePacket};
use nt_io_manager::start_io_native_owner::{PendingStartIoNodeIdentity,
    PendingStartIoQueueIdentity, StartIoAdmission};
use nt_io_manager::start_io_native_transaction::{CommittedStartIo, ReplyPhase, StartIoTransactionId};
use nt_io_manager::{DeviceCharacteristics, DeviceFlags, DeviceType, IoManager, MockDriverBackend,
    MockObjectPort};
use nt_status::NtStatus;
use nt_types::NtPath;
use std::cell::Cell;
use std::rc::Rc;

struct CallbackImageOwner(Rc<Cell<usize>>);
impl Drop for CallbackImageOwner {
    fn drop(&mut self) { self.0.set(self.0.get() + 1); }
}

#[test]
fn uncertain_start_reply_retains_exact_source_device_current_and_callback() {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.create_driver(&NtPath::parse_str(r"\Driver\StartIoTransaction").unwrap(),
        Box::new(MockDriverBackend::new())).unwrap();
    let device = io.create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let source_domain = io.register_hosted_domain();
    let projection_domain = io.register_hosted_domain();
    let registration = io.bind_hosted_device_pointer(projection_domain, 0x4000, device).unwrap();
    let source = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedDriver(3), domain: source_domain,
        component_address: 0x2000, bytes: 0x128, stack_count: 2, pool_generation: 7,
    };
    let mut ledger = SourceIrpLedger::new();
    let ticket = ledger.register(source).unwrap();
    let admission = StartIoAdmission::acquire(&mut io, &mut ledger, source, registration).unwrap();
    let identity = admission.source_identity();
    assert_eq!(identity.ticket(), ticket);
    let (device_owner, source_owner) = admission.into_owners();
    let mut current = CurrentReceipt::new(registration, source_domain, device_owner);
    assert!(current.prepare_update(registration, 0,
        Some(LivePacket::new(identity, source_owner))).unwrap().commit().is_none());
    let callback_drops = Rc::new(Cell::new(0));
    let transaction_id = StartIoTransactionId::new(41, 9).unwrap();
    let mut committed = CommittedStartIo::new(current, identity, transaction_id,
        CallbackImageOwner(callback_drops.clone())).unwrap();

    // Reply publication is an uncertain native effect. Mark it before attempting the Reply;
    // neither a lost result nor a second request authorizes queue replay or owner release.
    let reply = committed.begin_reply().unwrap();
    assert_eq!(reply.transaction_id(), transaction_id);
    assert_eq!(committed.phase(), ReplyPhase::Uncertain);
    assert!(committed.begin_reply().is_err());
    assert_eq!(committed.current_snapshot().phase, CurrentPhase::Live);
    assert_eq!(ledger.prepare_driver_free(3, source_domain, source.component_address),
        Err(nt_io_manager::source_irp_ledger::SourceIrpLedgerError::Pinned));
    assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
    assert_eq!(callback_drops.get(), 0);

    // A callback-return observation may resolve whether the command ran, but it is never IRP
    // completion. A wrong generation cannot settle the retained transaction.
    assert!(committed.callback_returned(StartIoTransactionId::new(41, 10).unwrap()).is_err());
    assert_eq!(committed.current_snapshot().phase, CurrentPhase::Live);
    committed.callback_returned(transaction_id).unwrap();
    assert_eq!(committed.current_snapshot().phase, CurrentPhase::Live);
    assert_eq!(callback_drops.get(), 0);
    drop(committed);
    assert_eq!(callback_drops.get(), 0);
    assert_eq!(ledger.prepare_driver_free(3, source_domain, source.component_address),
        Err(nt_io_manager::source_irp_ledger::SourceIrpLedgerError::Pinned));
    assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
}

#[test]
fn projected_op6_packet_commits_exact_current_before_uncertain_callback_reply() {
    let mut io = IoManager::new(MockObjectPort::new());
    let driver = io.create_driver(&NtPath::parse_str(r"\Driver\ProjectedStartIoTransaction").unwrap(),
        Box::new(MockDriverBackend::new())).unwrap();
    let device = io.create_device(driver, None, DeviceType::UNKNOWN,
        DeviceCharacteristics::empty(), DeviceFlags::empty(), 0).unwrap();
    let physical = io.register_hosted_domain();
    let logical = io.register_hosted_domain();
    let registration = io.bind_hosted_device_pointer(logical, 0x4000, device).unwrap();
    let source = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedCaller(3), domain: physical,
        component_address: 0x2000, bytes: 0x128, stack_count: 2, pool_generation: 7,
    };
    let mut ledger = SourceIrpLedger::new();
    let ticket = ledger.register(source).unwrap();
    let node = PendingStartIoNodeIdentity::new(0x1000, 0x100, 31, 0x2000, ticket).unwrap();
    let queue = PendingStartIoQueueIdentity::new(node, registration).unwrap();
    let admission = StartIoAdmission::acquire_projected(&mut io, &mut ledger, source, queue, node,
        registration)
        .unwrap();
    let identity = admission.source_identity();
    let (device_owner, source_owner) = admission.into_owners();
    let mut current = CurrentReceipt::new(registration, physical, device_owner);
    current.prepare_update(registration, 0, Some(LivePacket::new(identity, source_owner)))
        .unwrap().commit();
    let callback_drops = Rc::new(Cell::new(0));
    let transaction = StartIoTransactionId::new(41, 9).unwrap();
    let mut committed = CommittedStartIo::new(current, identity, transaction,
        CallbackImageOwner(callback_drops.clone())).unwrap();
    assert_eq!(committed.current_snapshot().packet, Some(identity));
    assert_eq!(ledger.begin_hosted_caller_retirement(ticket, source),
        Err(nt_io_manager::source_irp_ledger::SourceIrpLedgerError::Pinned));
    committed.begin_reply().unwrap();
    assert!(committed.observe_completion(registration, identity,
        CompletionObservation::Uncertain).unwrap().is_none());
    assert_eq!(committed.current_snapshot().phase, CurrentPhase::Live);
    assert_eq!(callback_drops.get(), 0);
    // Terminal completion and callback return are independent. An exact terminal observation
    // transfers the source pin; it does not release the callback image or device owner.
    let packet = committed.observe_completion(registration, identity,
        CompletionObservation::Acknowledged).unwrap().unwrap();
    assert_eq!(packet.identity(), identity);
    assert_eq!(committed.current_snapshot().phase, CurrentPhase::Completed);
    assert_eq!(io.retire_hosted_device_pointer(registration), Err(NtStatus::DEVICE_BUSY));
    assert_eq!(callback_drops.get(), 0);
    let mut source_owner = packet.into_owner();
    source_owner.release(&mut ledger).unwrap();
    committed.callback_returned(transaction).unwrap();
    let (current, callback) = committed.into_completed().ok().unwrap();
    drop(callback);
    assert_eq!(callback_drops.get(), 1);
    drop(current);
}
