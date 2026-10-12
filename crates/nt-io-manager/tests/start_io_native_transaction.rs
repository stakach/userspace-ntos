use nt_io_manager::source_irp_ledger::{SourceIrpAllocation, SourceIrpLedger, SourceIrpOwner};
use nt_io_manager::start_io_current::{CurrentPhase, CurrentReceipt, LivePacket};
use nt_io_manager::start_io_native_owner::StartIoAdmission;
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
