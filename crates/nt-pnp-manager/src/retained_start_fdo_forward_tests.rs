//! Exact FDO-to-FDO START forwarding contract regressions.

use super::*;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec;
use core::cell::{Cell, RefCell};
use nt_io_manager::{
    retained_query_path_forward::SourceIrpTicket, DeviceCharacteristics, DeviceFlags, DeviceType,
    DispatchContext, DispatchOutcome, DriverCompletion, DriverDispatchBackend,
    ExternalPnpDispatchResult, IrpId, IrpProjection, MockObjectPort, PnpBackendDispatch, PnpParameters,
    source_irp_ledger::{SourceIrpAllocation, SourceIrpOwner},
};
use nt_status::NtStatus;
use nt_types::NtPath;

struct StartBackend;

struct PendingSource {
    ready: Rc<Cell<bool>>,
    pending: Rc<RefCell<Option<IrpId>>>,
}

impl DriverDispatchBackend for PendingSource {
    fn dispatch_irp(
        &mut self,
        _context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        *self.pending.borrow_mut() = Some(irp.irp_id);
        Ok(DispatchOutcome::Pending)
    }

    fn cancel_irp(&mut self, _irp: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        if !self.ready.get() {
            return None;
        }
        self.pending.borrow_mut().take().map(|irp_id| DriverCompletion {
            irp_id,
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: None,
        })
    }
}

impl DriverDispatchBackend for StartBackend {
    fn dispatch_irp(
        &mut self,
        _context: DispatchContext<'_>,
        _irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: 0,
            file_context: None,
        })
    }

    fn cancel_irp(&mut self, _irp: nt_io_manager::IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }
}

#[test]
fn exact_lower_fdo_start_retains_source_until_terminal() {
    let mut io = nt_io_manager::IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let source_ready = Rc::new(Cell::new(false));
    let source_pending = Rc::new(RefCell::new(None));
    let lower_driver = io
        .create_kernel_driver_with_majors(
            &NtPath::parse_str(r"\Driver\PortStart").unwrap(),
            Box::new(StartBackend),
            &[nt_pnp_abi::IRP_MJ_PNP],
        )
        .unwrap();
    let upper_driver = io
        .create_kernel_driver_with_majors(
            &NtPath::parse_str(r"\Driver\ClassStart").unwrap(),
            Box::new(PendingSource {
                ready: source_ready.clone(),
                pending: source_pending,
            }),
            &[nt_pnp_abi::IRP_MJ_PNP],
        )
        .unwrap();
    let lower_device = io
        .create_device(
            lower_driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    let upper_device = io
        .create_device(
            upper_driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    io.attach_device_to_stack(upper_device, lower_device)
        .unwrap();
    let upper_domain = io.register_hosted_domain();
    let lower_domain = io.register_hosted_domain();
    io.bind_hosted_device_pointer(upper_domain, 0x2000, upper_device)
        .unwrap();
    let lower = io
        .bind_hosted_device_pointer(lower_domain, 0x1000, lower_device)
        .unwrap();
    let mut pnp = PnpManager::new();
    let devnode = pnp.create_service_bound_devnode_without_resources(
        r"ACPI\PNP0303\0",
        Some("i8042prt"),
        0x9000,
    );
    pnp.set_fdo(devnode, lower_device.raw()).unwrap();
    let mut raw = vec![0u8; 20];
    raw[..4].copy_from_slice(&1u32.to_le_bytes());
    let mut translated = raw.clone();
    translated[4..8].copy_from_slice(&1u32.to_le_bytes());
    let mut source_payload = raw.clone();
    source_payload.extend_from_slice(&translated);
    let source = io
        .prepare_external_pnp_owned_to_exact_device(
            client,
            upper_device,
            12,
            PnpParameters::start(raw.len() as u32, translated.len() as u32).unwrap(),
            source_payload,
        )
        .unwrap();
    io.irp_mut(source.irp_id()).unwrap().stack[1].minor = nt_pnp_abi::IRP_MN_START_DEVICE;
    let source_irp = source.irp_id();
    let ticket = SourceIrpTicket::new(upper_domain, 7, 1).unwrap();
    let allocation = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedCaller(0),
        domain: upper_domain,
        component_address: 0x4000,
        bytes: 0x100,
        stack_count: 2,
        pool_generation: 3,
    };
    let mut prepared = PreparedStartFdoForward::prepare(
        &pnp,
        &mut io,
        ticket,
        source.irp_id(),
        0x2000,
        lower,
        devnode,
        client,
        12,
        raw,
        translated,
    )
    .unwrap();
    prepared.bind_native_source_allocation(allocation).unwrap();
    let identity = prepared.identity();
    let invocation = prepared.begin(&pnp, &mut io, identity).unwrap();
    let returned = invocation.invoke(|_, _| PnpBackendDispatch::Returned {
        status: NtStatus::SUCCESS,
        information: 0,
    });
    let terminal = match returned.finish(&mut io).unwrap() {
        StartFdoForwardResult::Terminal(terminal) => terminal,
        result => panic!("unexpected START result: {result:?}"),
    };
    assert_eq!(terminal.status(), NtStatus::SUCCESS);
    let wrong_stop = unsafe {
        StartFdoSourceStopWitness::after_native_source_stop(
            ticket,
            source_irp,
            SourceIrpAllocation {
                pool_generation: 4,
                ..allocation
            },
        )
        .unwrap()
    };
    let terminal = match terminal.retire_after_source_stop(&mut io, wrong_stop) {
        Err((StartFdoForwardError::WrongSource, terminal, _)) => terminal,
        outcome => panic!("stale stopped-source witness retired START owner: {outcome:?}"),
    };
    let terminal = match terminal.retire_after_host_source_stop(&mut io) {
        Err((StartFdoForwardError::WrongSource, terminal)) => terminal,
        outcome => panic!("host stop bypassed native source binding: {outcome:?}"),
    };
    let retained = terminal.retire(&mut io);
    let (_, mut terminal) = retained.expect_err("source completion is required");
    assert_eq!(
        terminal.mark_source_completed(&io, identity),
        Err(StartFdoForwardError::WrongSource)
    );
    assert!(matches!(
        io.dispatch_prepared_external_pnp(source).unwrap(),
        ExternalPnpDispatchResult::Pending { .. }
    ));
    assert_eq!(
        terminal.mark_source_completed(&io, identity),
        Err(StartFdoForwardError::WrongSource)
    );
    source_ready.set(true);
    assert_eq!(io.pump(), 1);
    let stale = StartFdoForwardIdentity {
        source: SourceIrpTicket::new(upper_domain, 7, 2).unwrap(),
        ..identity
    };
    assert_eq!(
        terminal.mark_source_completed(&io, stale),
        Err(StartFdoForwardError::WrongIdentity)
    );
    assert_eq!(
        terminal.mark_source_completed(&io, identity),
        Err(StartFdoForwardError::WrongSource),
        "a native-bound source requires its physical completion witness",
    );
    let wrong_allocation = SourceIrpAllocation {
        pool_generation: 4,
        ..allocation
    };
    let wrong_witness = unsafe {
        StartFdoSourceCompletionWitness::after_native_terminal(
            ticket,
            source_irp,
            wrong_allocation,
        )
        .unwrap()
    };
    assert!(matches!(
        terminal.mark_source_completed_from_native_witness(wrong_witness),
        Err((StartFdoForwardError::WrongSource, _))
    ));
    let witness = unsafe {
        StartFdoSourceCompletionWitness::after_native_terminal(ticket, source_irp, allocation)
            .unwrap()
    };
    terminal
        .mark_source_completed_from_native_witness(witness)
        .unwrap();
    assert_eq!(terminal.retire(&mut io).unwrap(), NtStatus::SUCCESS);
}
