//! Detached FDO FILTER forwarding regressions.

use super::*;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec;
use core::cell::{Cell, RefCell};
use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext, DispatchOutcome,
    DriverCompletion, DriverDispatchBackend, IrpProjection, MockObjectPort,
};
use nt_types::NtPath;

struct OptionalFilter;

impl DriverDispatchBackend for OptionalFilter {
    fn dispatch_irp(
        &mut self,
        _context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        assert_eq!(irp.minor, nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS);
        Ok(DispatchOutcome::Completed {
            status: NtStatus::NOT_SUPPORTED,
            information: irp.information,
            file_context: None,
        })
    }
    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }
}

struct PendingFilter {
    ready: Rc<Cell<bool>>,
    pending: Rc<RefCell<Option<IrpId>>>,
}

impl DriverDispatchBackend for PendingFilter {
    fn dispatch_irp(
        &mut self,
        _context: DispatchContext<'_>,
        irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        *self.pending.borrow_mut() = Some(irp.irp_id);
        Ok(DispatchOutcome::Pending)
    }
    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::NOT_SUPPORTED)
    }
    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        if !self.ready.get() {
            return None;
        }
        self.pending
            .borrow_mut()
            .take()
            .map(|irp_id| DriverCompletion {
                irp_id,
                status: NtStatus::NOT_SUPPORTED,
                information: 0,
                file_context: None,
            })
    }
}

struct Fixture {
    pnp: PnpManager,
    io: IoManager<MockObjectPort>,
    source_prepared: PreparedExternalPnpIrp,
    source: SourceIrpTicket,
    upper_domain: nt_io_manager::HostedDomainIdentity,
    upper_address: u64,
    lower: HostedDevicePointerRegistration,
    devnode: u64,
    client: ClientId,
}

fn fixture_with_lower(backend: Box<dyn DriverDispatchBackend>) -> Fixture {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let lower_driver = io
        .create_kernel_driver_with_majors(
            &NtPath::parse_str(r"\Driver\PortFilter").unwrap(),
            backend,
            &[nt_pnp_abi::IRP_MJ_PNP],
        )
        .unwrap();
    let upper_driver = io
        .create_kernel_driver_with_majors(
            &NtPath::parse_str(r"\Driver\ClassFilter").unwrap(),
            Box::new(OptionalFilter),
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
    let source_prepared = io
        .prepare_external_pnp_owned_to_exact_device(
            client,
            upper_device,
            12,
            PnpParameters::filter_resource_requirements(40).unwrap(),
            valid_requirements(),
        )
        .unwrap();
    // The upper driver has copied its FILTER minor into the next stack frame before
    // forwarding. The initial I/O Manager snapshot only populates the first frame.
    io.irp_mut(source_prepared.irp_id()).unwrap().stack[1].minor =
        nt_pnp_abi::IRP_MN_FILTER_RESOURCE_REQUIREMENTS;
    Fixture {
        pnp,
        io,
        source_prepared,
        source: SourceIrpTicket::new(upper_domain, 7, 1).unwrap(),
        upper_domain,
        upper_address: 0x2000,
        lower,
        devnode,
        client,
    }
}

fn fixture() -> Fixture {
    fixture_with_lower(Box::new(OptionalFilter))
}

fn valid_requirements() -> Vec<u8> {
    let mut bytes = vec![0; 40];
    bytes[0..4].copy_from_slice(&40u32.to_le_bytes());
    bytes[28..32].copy_from_slice(&1u32.to_le_bytes());
    bytes
}

#[test]
fn filter_output_uses_original_for_unsupported_and_requires_exact_copied_success() {
    let input_pointer = 0x1234_5000;
    let provider_pointer = 0x5678_9000;
    assert!(valid_output(
        NtStatus::NOT_SUPPORTED,
        input_pointer,
        &ExternalPnpFilterOutput::Original
    ));
    assert!(!valid_output(
        NtStatus::SUCCESS,
        provider_pointer,
        &ExternalPnpFilterOutput::Original
    ));
    assert!(!valid_output(
        NtStatus::SUCCESS,
        provider_pointer,
        &ExternalPnpFilterOutput::Copied {
            provider_pointer: provider_pointer + 8,
            bytes: valid_requirements(),
        }
    ));
    assert!(valid_output(
        NtStatus::SUCCESS,
        provider_pointer,
        &ExternalPnpFilterOutput::Copied {
            provider_pointer,
            bytes: valid_requirements(),
        }
    ));
}

fn prepare(f: &mut Fixture) -> PreparedFilterFdoForward {
    PreparedFilterFdoForward::prepare(
        &f.pnp,
        &mut f.io,
        f.source,
        f.source_prepared.irp_id(),
        f.upper_address,
        f.lower,
        f.devnode,
        f.client,
        12,
        valid_requirements(),
    )
    .unwrap()
}

#[test]
fn exact_lower_fdo_receives_optional_filter_and_source_completion_precedes_retirement() {
    let mut f = fixture();
    let prepared = prepare(&mut f);
    let identity = prepared.identity();
    let invocation = prepared.begin(&f.pnp, &mut f.io, identity).unwrap();
    let returned = invocation.invoke_with_output(|_, _| {
        (
            PnpBackendDispatch::Returned {
                status: NtStatus::NOT_SUPPORTED,
                information: 0,
            },
            ExternalPnpFilterOutput::Original,
        )
    });
    let terminal = match returned.finish(&mut f.io).unwrap() {
        FilterFdoForwardResult::Terminal(terminal) => terminal,
        outcome => panic!("unexpected FILTER outcome: {outcome:?}"),
    };
    assert_eq!(terminal.status(), NtStatus::NOT_SUPPORTED);
    assert_eq!(
        terminal.return_action(),
        FilterRequirementsReturnAction::UseOriginal
    );
    let mut terminal = match terminal.retire(&mut f.io) {
        Err((FilterFdoForwardError::SourceCompletionRequired, terminal)) => terminal,
        outcome => panic!("retired before source completion: {outcome:?}"),
    };
    terminal.mark_source_completed(identity).unwrap();
    match terminal.retire(&mut f.io) {
        Ok(status) => assert_eq!(status, NtStatus::NOT_SUPPORTED),
        outcome => panic!("source-complete FILTER did not retire: {outcome:?}"),
    }
    f.io.discard_prepared_external_pnp(f.source_prepared)
        .unwrap();
}

#[test]
fn synchronous_borrow_is_rejected_and_copied_success_keeps_the_same_entered_owner() {
    let mut f = fixture();
    let prepared = prepare(&mut f);
    let identity = prepared.identity();
    let provider_irp = prepared.provider_irp();
    let returned = prepared
        .begin(&f.pnp, &mut f.io, identity)
        .unwrap()
        .invoke_with_output(|_, _| {
            (
                PnpBackendDispatch::Returned {
                    status: NtStatus::SUCCESS,
                    information: 0x1234_5000,
                },
                ExternalPnpFilterOutput::Original,
            )
        });
    let refusal = returned.finish(&mut f.io).unwrap_err();
    assert_eq!(refusal.error(), FilterFdoForwardError::InvalidOutput);
    assert!(f.io.irp(provider_irp).is_some());
    let returned = refusal
        .into_return()
        .with_output(ExternalPnpFilterOutput::BorrowedInput {
            provider_pointer: 0x1234_5000,
            input_allocation: nt_io_manager::source_irp_auxiliary::SourcePoolAllocationIdentity {
                component_address: 0x1234_5000,
                capacity: 40,
                pool_generation: 7,
            },
        });
    let refusal = returned.finish(&mut f.io).unwrap_err();
    assert_eq!(refusal.error(), FilterFdoForwardError::InvalidOutput);
    let returned = refusal
        .into_return()
        .with_output(ExternalPnpFilterOutput::Copied {
            provider_pointer: 0x1234_5000,
            bytes: valid_requirements(),
        });
    let mut terminal = match returned.finish(&mut f.io).unwrap() {
        FilterFdoForwardResult::Terminal(terminal) => terminal,
        outcome => panic!("copied FILTER did not terminate: {outcome:?}"),
    };
    assert_eq!(
        terminal.return_action(),
        FilterRequirementsReturnAction::CopyProviderOutput { information: 0x1234_5000 }
    );
    assert_eq!(terminal.original_requirements(), valid_requirements());
    terminal.mark_source_completed(identity).unwrap();
    assert_eq!(terminal.retire(&mut f.io).unwrap(), NtStatus::SUCCESS);
    f.io.discard_prepared_external_pnp(f.source_prepared)
        .unwrap();
}

#[test]
fn wrong_devnode_or_same_domain_cannot_enter_lower_fdo() {
    let mut f = fixture();
    assert!(matches!(
        PreparedFilterFdoForward::prepare(
            &f.pnp,
            &mut f.io,
            f.source,
            f.source_prepared.irp_id(),
            f.upper_address,
            f.lower,
            f.devnode + 1,
            f.client,
            12,
            valid_requirements(),
        ),
        Err(FilterFdoForwardError::WrongLower)
    ));
    let prepared = prepare(&mut f);
    let mut wrong = prepared.identity();
    wrong.source = SourceIrpTicket::new(f.upper_domain, 7, 2).unwrap();
    let prepared = match prepared.begin(&f.pnp, &mut f.io, wrong) {
        Err((FilterFdoForwardError::WrongIdentity, prepared)) => prepared,
        outcome => panic!("wrong source entered provider: {outcome:?}"),
    };
    assert!(matches!(
        prepared.discard(&mut f.io),
        FilterFdoDiscardResult::Retired
    ));
    f.io.discard_prepared_external_pnp(f.source_prepared)
        .unwrap();
}

#[test]
fn pending_lower_completion_keeps_owner_until_source_then_exact_ack() {
    let ready = Rc::new(Cell::new(false));
    let pending = Rc::new(RefCell::new(None));
    let mut f = fixture_with_lower(Box::new(PendingFilter {
        ready: ready.clone(),
        pending: pending.clone(),
    }));
    let prepared = prepare(&mut f);
    let identity = prepared.identity();
    let invocation = prepared.begin(&f.pnp, &mut f.io, identity).unwrap();
    let returned = invocation.invoke_with_output(|_, projection| {
        *pending.borrow_mut() = Some(projection.irp_id);
        (
            PnpBackendDispatch::Pending,
            ExternalPnpFilterOutput::Original,
        )
    });
    let retained = match returned.finish(&mut f.io).unwrap() {
        FilterFdoForwardResult::Retained(retained) => retained,
        outcome => panic!("pending FILTER did not retain: {outcome:?}"),
    };
    let provider_irp = retained.provider_irp();
    assert_eq!(*pending.borrow(), Some(provider_irp));
    ready.set(true);
    assert_eq!(f.io.pump(), 1);
    let completion = retained
        .prepare_completion(
            &f.pnp,
            &mut f.io,
            identity,
            ExternalPnpFilterOutput::Original,
        )
        .unwrap();
    let acknowledged = completion.invoke(|_| CompletionAcknowledgement::Acknowledged);
    let mut terminal = match acknowledged.finish(&mut f.io).unwrap() {
        FilterFdoForwardResult::Terminal(terminal) => terminal,
        outcome => panic!("wrong pending FILTER terminal: {outcome:?}"),
    };
    assert!(f.io.irp(provider_irp).is_none());
    terminal.mark_source_completed(identity).unwrap();
    match terminal.retire(&mut f.io) {
        Ok(status) => assert_eq!(status, NtStatus::NOT_SUPPORTED),
        outcome => panic!("ACKed FILTER did not retire: {outcome:?}"),
    }
    f.io.discard_prepared_external_pnp(f.source_prepared)
        .unwrap();
}
