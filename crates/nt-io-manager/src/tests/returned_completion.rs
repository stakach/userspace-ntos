//! A later synchronous return published as a pending IRP's ordinary completion (#420).
use super::*;
use std::cell::RefCell;
use std::rc::Rc;

/// A hosted backend whose dispatch is still running: it tells the I/O Manager `Pending` and
/// retains nothing, so a returned completion must never reach its copy or ACK.
#[derive(Default)]
struct Calls {
    copies: usize,
    acknowledgements: usize,
}

struct Running(Rc<RefCell<Calls>>);

impl DriverDispatchBackend for Running {
    fn dispatch_irp(
        &mut self,
        _ctx: DispatchContext<'_>,
        _irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        Ok(DispatchOutcome::Pending)
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Ok(())
    }

    fn copy_completion_output(
        &mut self,
        _irp_id: IrpId,
        _offset: u64,
        _output: &mut [u8],
    ) -> Result<usize, NtStatus> {
        self.0.borrow_mut().copies += 1;
        Err(NtStatus::INVALID_PARAMETER)
    }

    fn acknowledge_completion(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        self.0.borrow_mut().acknowledgements += 1;
        Err(NtStatus::INVALID_PARAMETER)
    }
}

fn pending_read(len: usize) -> (IoManager<MockObjectPort>, DriverId, IrpId, Rc<RefCell<Calls>>) {
    let mut io = io();
    let client = io.register_client();
    let calls = Rc::new(RefCell::new(Calls::default()));
    let driver = io
        .create_driver(&path("\\Driver\\Running"), Box::new(Running(calls.clone())))
        .unwrap();
    let device = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::BUFFERED_IO,
            0,
        )
        .unwrap();
    let mut output = alloc::vec![0; len];
    let ExternalDispatchResult::Pending { irp_id } =
        io.read_exact_device(client, device, 0, &mut output).unwrap()
    else {
        panic!("a running dispatch is pending");
    };
    (io, driver, irp_id, calls)
}

fn returned(irp_id: IrpId, information: u64, output: &[u8]) -> ReturnedIrp {
    ReturnedIrp {
        irp_id,
        status: NtStatus::SUCCESS,
        information,
        file_context: None,
        output: output.to_vec(),
    }
}

#[test]
fn a_returned_irp_is_read_as_its_ordinary_completion_with_its_output() {
    let (mut io, driver, irp, calls) = pending_read(8);
    io.complete_returned_irp(driver, returned(irp, 4, b"data\0\0\0\0")).unwrap();
    let completion = io.completed_irp(irp).expect("the return is published");
    assert_eq!((completion.status, completion.information), (NtStatus::SUCCESS, 4));
    assert_eq!(io.next_completed_irp().map(|c| c.id), Some(irp));
    let mut copied = [0u8; 8];
    assert_eq!(io.copy_completed_irp_output(irp, 0, &mut copied), Ok(4),
        "the returned bytes are the completion's output, never lost");
    assert_eq!(&copied[..4], b"data");
    let mut tail = [0u8; 2];
    assert_eq!(io.copy_completed_irp_output(irp, 2, &mut tail), Ok(2));
    assert_eq!(&tail, b"ta", "a retried or chunked copy reads the same held bytes");
    assert_eq!(calls.borrow().copies, 0, "no backend holds a returned completion's output");
}

#[test]
fn a_returned_completion_retires_without_a_backend_ack() {
    let (mut io, driver, irp, calls) = pending_read(4);
    io.complete_returned_irp(driver, returned(irp, 4, b"data")).unwrap();
    let acknowledged = io.acknowledge_completed_irp_strict(irp).unwrap();
    assert_eq!(acknowledged.id, irp);
    assert!(io.irp(irp).is_none(), "acknowledgement retires the IRP");
    assert_eq!(calls.borrow().acknowledgements, 0, "a driver that returned owes no ACK");
}

#[test]
fn a_returned_irp_is_published_exactly_once() {
    let (mut io, driver, irp, _) = pending_read(4);
    io.complete_returned_irp(driver, returned(irp, 4, b"data")).unwrap();
    let rejection = io
        .complete_returned_irp(driver, returned(irp, 1, b"late"))
        .unwrap_err();
    assert_eq!(rejection.status, NtStatus::INVALID_PARAMETER);
    assert_eq!(rejection.returned.output, b"late", "a refused return is handed back whole");
    assert_eq!(io.completed_irp(irp).map(|c| c.information), Some(4),
        "the first publication stands");
    assert!(!io.publish_driver_completion(driver, DriverCompletion {
        irp_id: irp,
        status: NtStatus::UNSUCCESSFUL,
        information: 0,
        file_context: None,
    }), "a later backend completion cannot replace it");
}

#[test]
fn a_return_for_another_driver_or_still_pending_is_refused_with_nothing_published() {
    let (mut io, driver, irp, _) = pending_read(4);
    let foreign = io
        .create_driver(&path("\\Driver\\Foreign"), Box::new(MockDriverBackend::new()))
        .unwrap();
    let rejection = io.complete_returned_irp(foreign, returned(irp, 4, b"data")).unwrap_err();
    assert_eq!(rejection.returned.output, b"data");
    let mut pending = returned(irp, 0, b"");
    pending.status = NtStatus::PENDING;
    assert!(io.complete_returned_irp(driver, pending).is_err(),
        "a return that left the IRP pending is not a terminal");
    assert!(io.completed_irp(irp).is_none());
    io.complete_returned_irp(driver, returned(irp, 4, b"data")).unwrap();
}

#[test]
fn a_returned_pnp_completion_is_acknowledged_without_invoking_its_backend() {
    let mut io = io();
    let (retained, _release) = super::detached_external_pnp_completion::pending(&mut io);
    let irp = retained.irp_id();
    let driver = io.irp(irp).unwrap().current_stack().unwrap().driver_id;
    io.complete_returned_irp(driver, returned(irp, 0, b"")).unwrap();
    let invocation = io.prepare_external_pnp_completion(retained).unwrap();
    assert!(!invocation.owes_backend_acknowledgement());
    let returned = invocation.invoke(|_| panic!("no backend retains a returned completion"));
    let (receipt, _) = io.finish_external_pnp_completion(returned).unwrap();
    assert_eq!(receipt.irp_id(), irp);
    assert!(io.irp(irp).is_none());
}

#[test]
fn a_returned_power_completion_is_acknowledged_without_invoking_its_backend() {
    use crate::power_irp_request::PowerParameters;
    let mut io = io();
    let ready = Rc::new(RefCell::new(Vec::new()));
    let release = Rc::new(std::cell::Cell::new(false));
    let (client, _, _, device) =
        pnp_test_stack(&mut io, Box::new(PendingPnpBackend { ready, release }));
    let parameters = PowerParameters::device(nt_power_types::IRP_MN_QUERY_POWER, 1).unwrap();
    let prepared = io.prepare_external_power_to_exact_device(client, device, 11, parameters).unwrap();
    let irp = prepared.irp_id();
    let invocation = io.begin_prepared_external_power(prepared).unwrap();
    let backend = io.driver(invocation.projection().driver_id).unwrap().backend.0 as usize;
    let dispatched =
        invocation.invoke(|ctx, projection| io.backends[backend].dispatch_power_irp(ctx, projection));
    let ExternalPowerFinishResult::Retained(retained) = io.finish_external_power(dispatched).unwrap()
    else {
        panic!("a running POWER dispatch is retained pending");
    };
    let driver = io.irp(irp).unwrap().current_stack().unwrap().driver_id;
    io.complete_returned_irp(driver, returned(irp, 0, b"")).unwrap();
    let invocation = io.prepare_external_power_completion(retained).unwrap();
    assert!(!invocation.owes_backend_acknowledgement());
    let acknowledged = invocation.invoke(|_| panic!("no backend retains a returned completion"));
    let receipt = io.finish_external_power_completion(acknowledged).unwrap();
    assert_eq!((receipt.irp_id(), receipt.status()), (irp, NtStatus::SUCCESS));
    assert!(io.irp(irp).is_none());
}
