use std::boxed::Box;

use nt_io_manager::{
    DeviceCharacteristics, DeviceFlags, DeviceType, DispatchContext, DispatchOutcome,
    DriverCompletion, DriverDispatchBackend, ExternalPnpDispatchResult, IoManager, IrpId,
    IrpProjection, MockObjectPort, PnpParameters,
};
use nt_pnp_abi::TARGET_DEVICE_RELATION;
use nt_pnp_manager::{
    TargetRelationDelivery, TargetRelationError, TargetRelationPhase,
    TARGET_DEVICE_RELATIONS_X64_BYTES,
};
use nt_provider_wait::{ProviderAllocationCatalog, ProviderArenaIdentity};
use nt_status::NtStatus;
use nt_types::NtPath;

struct RelationBackend;

impl DriverDispatchBackend for RelationBackend {
    fn dispatch_irp(
        &mut self,
        _context: DispatchContext<'_>,
        _irp: &IrpProjection,
    ) -> Result<DispatchOutcome, NtStatus> {
        Ok(DispatchOutcome::Completed {
            status: NtStatus::SUCCESS,
            information: 0x9000,
            file_context: None,
        })
    }

    fn cancel_irp(&mut self, _irp_id: IrpId) -> Result<(), NtStatus> {
        Err(NtStatus::INVALID_PARAMETER)
    }

    fn poll_completion(&mut self) -> Option<DriverCompletion> {
        None
    }
}

fn fixture(
    relation_type: u32,
) -> (
    IoManager<MockObjectPort>,
    nt_io_manager::ExternalPnpTerminalReceipt,
    nt_io_manager::DeviceId,
    nt_io_manager::HostedDomainIdentity,
    ProviderAllocationCatalog,
    nt_provider_wait::ProviderAllocationSnapshot,
    [u8; TARGET_DEVICE_RELATIONS_X64_BYTES],
) {
    let mut io = IoManager::new(MockObjectPort::new());
    let client = io.register_client();
    let driver = io
        .create_kernel_driver_with_majors(
            &NtPath::parse_str(r"\Driver\Relation").unwrap(),
            Box::new(RelationBackend),
            &[nt_io_abi::major::IRP_MJ_PNP],
        )
        .unwrap();
    let device = io
        .create_device(
            driver,
            None,
            DeviceType::UNKNOWN,
            DeviceCharacteristics::empty(),
            DeviceFlags::empty(),
            0,
        )
        .unwrap();
    let domain = io.register_hosted_domain();
    io.bind_hosted_device_identity(domain, 0x4000, device)
        .unwrap();
    io.register_hosted_device_pointer(domain, 0x4000).unwrap();
    let prepared = io
        .prepare_external_pnp_to_exact_device(
            client,
            device,
            7,
            PnpParameters::query_device_relations(relation_type),
            &[],
        )
        .unwrap();
    let terminal = match io.dispatch_prepared_external_pnp(prepared).unwrap() {
        ExternalPnpDispatchResult::Returned {
            status,
            information,
            receipt,
        } => {
            assert_eq!(status, NtStatus::SUCCESS);
            assert_eq!(information, 0x9000);
            receipt
        }
        other => panic!("unexpected PnP dispatch: {other:?}"),
    };
    let mut allocations = ProviderAllocationCatalog::new();
    allocations
        .register(
            ProviderArenaIdentity {
                id: 1,
                generation: 1,
            },
            0x5000,
            16,
        )
        .unwrap();
    let source_allocation = allocations
        .register(
            ProviderArenaIdentity {
                id: 2,
                generation: 1,
            },
            0x9000,
            16,
        )
        .unwrap();
    let mut source = [0u8; TARGET_DEVICE_RELATIONS_X64_BYTES];
    source[..4].copy_from_slice(&1u32.to_le_bytes());
    source[8..].copy_from_slice(&0x6000u64.to_le_bytes());
    (
        io,
        terminal,
        device,
        domain,
        allocations,
        source_allocation,
        source,
    )
}

#[test]
fn transfers_one_referenced_pdo_only_after_relation_iosb_and_ack() {
    let (mut io, terminal, pdo, domain, mut allocations, source_allocation, source) =
        fixture(TARGET_DEVICE_RELATION);
    let baseline = io.device_reference_count(pdo);
    let mut delivery = TargetRelationDelivery::capture(
        &mut io,
        &mut allocations,
        &terminal,
        pdo,
        0x9000,
        source_allocation,
        &source,
        0x6000,
        domain,
        0x4000,
        pdo,
        0x5000,
    )
    .unwrap();
    assert_eq!(delivery.phase(), TargetRelationPhase::Prepared);
    assert_eq!(io.device_reference_count(pdo), baseline + 1);
    assert!(matches!(
        delivery.transfer(&mut io, &mut allocations),
        Err(TargetRelationError::WrongPhase)
    ));
    let mut short = [0x5a; 15];
    assert!(delivery
        .write_relation(&io, &allocations, &mut short)
        .is_err());
    assert_eq!(short, [0x5a; 15]);
    let mut destination = [0u8; TARGET_DEVICE_RELATIONS_X64_BYTES];
    delivery
        .write_relation(&io, &allocations, &mut destination)
        .unwrap();
    assert_eq!(u32::from_le_bytes(destination[..4].try_into().unwrap()), 1);
    assert_eq!(
        u64::from_le_bytes(destination[8..].try_into().unwrap()),
        0x4000
    );
    assert!(matches!(
        delivery.abort(&mut io, &mut allocations),
        Err(TargetRelationError::WrongPhase)
    ));
    assert_eq!(
        delivery.iosb_published(NtStatus::SUCCESS, 0x9000),
        Err(TargetRelationError::WrongIosb)
    );
    delivery.iosb_published(NtStatus::SUCCESS, 0x5000).unwrap();
    assert_eq!(
        delivery.canonical_acknowledged(IrpId(u64::MAX)),
        Err(TargetRelationError::WrongIrp)
    );
    delivery.canonical_acknowledged(terminal.irp_id()).unwrap();
    let receipt = delivery.transfer(&mut io, &mut allocations).unwrap();
    assert_eq!(receipt.relation.base, 0x5000);
    assert_eq!(receipt.projected_pdo, 0x4000);
    assert_eq!(receipt.pdo_reference.device_id(), pdo);
    assert_eq!(io.device_reference_count(pdo), baseline + 1);
    io.dereference_hosted_device_pointer(receipt.pdo_reference)
        .unwrap();
    assert_eq!(io.device_reference_count(pdo), baseline);
    allocations
        .begin_retirement(receipt.relation.identity)
        .unwrap();
}

#[test]
fn malformed_source_and_wrong_projection_publish_no_reference_or_allocation_pin() {
    let (mut io, terminal, pdo, domain, mut allocations, source_allocation, source) =
        fixture(TARGET_DEVICE_RELATION);
    let baseline = io.device_reference_count(pdo);
    let mut malformed = source;
    malformed[..4].copy_from_slice(&2u32.to_le_bytes());
    assert!(matches!(
        TargetRelationDelivery::capture(
            &mut io,
            &mut allocations,
            &terminal,
            pdo,
            0x9000,
            source_allocation,
            &malformed,
            0x6000,
            domain,
            0x4000,
            pdo,
            0x5000
        ),
        Err(TargetRelationError::Source(_))
    ));
    assert!(matches!(
        TargetRelationDelivery::capture(
            &mut io,
            &mut allocations,
            &terminal,
            pdo,
            0x9000,
            source_allocation,
            &source,
            0x6001,
            domain,
            0x4000,
            pdo,
            0x5000
        ),
        Err(TargetRelationError::WrongSourcePdo)
    ));
    assert!(matches!(
        TargetRelationDelivery::capture(
            &mut io,
            &mut allocations,
            &terminal,
            pdo,
            0x9000,
            source_allocation,
            &source,
            0x6000,
            domain,
            0x4000,
            nt_io_manager::DeviceId(u64::MAX),
            0x5000
        ),
        Err(TargetRelationError::WrongConsumerPdo)
    ));
    assert_eq!(io.device_reference_count(pdo), baseline);
    allocations
        .begin_retirement(allocations.containing(0x5000, 16).unwrap().identity)
        .unwrap();
}

#[test]
fn abort_before_write_releases_both_owners_without_a_caller_visible_relation() {
    let (mut io, terminal, pdo, domain, mut allocations, source_allocation, source) =
        fixture(TARGET_DEVICE_RELATION);
    let baseline = io.device_reference_count(pdo);
    let mut delivery = TargetRelationDelivery::capture(
        &mut io,
        &mut allocations,
        &terminal,
        pdo,
        0x9000,
        source_allocation,
        &source,
        0x6000,
        domain,
        0x4000,
        pdo,
        0x5000,
    )
    .unwrap();
    assert_eq!(io.device_reference_count(pdo), baseline + 1);
    delivery.abort(&mut io, &mut allocations).unwrap();
    assert_eq!(delivery.phase(), TargetRelationPhase::Aborted);
    assert_eq!(io.device_reference_count(pdo), baseline);
    allocations
        .begin_retirement(delivery.allocation().identity)
        .unwrap();
}

#[test]
fn bus_relations_receipt_cannot_authorize_target_relation_delivery() {
    let (mut io, terminal, pdo, domain, mut allocations, source_allocation, source) =
        fixture(nt_pnp_abi::BUS_RELATIONS);
    let baseline = io.device_reference_count(pdo);
    assert_eq!(terminal.relation_type(), Some(nt_pnp_abi::BUS_RELATIONS));
    assert!(matches!(
        TargetRelationDelivery::capture(
            &mut io,
            &mut allocations,
            &terminal,
            pdo,
            0x9000,
            source_allocation,
            &source,
            0x6000,
            domain,
            0x4000,
            pdo,
            0x5000,
        ),
        Err(TargetRelationError::WrongTerminal)
    ));
    assert_eq!(io.device_reference_count(pdo), baseline);
    allocations
        .begin_retirement(source_allocation.identity)
        .unwrap();
}

#[test]
fn stopped_consumer_discards_written_relation_only_with_exact_terminal_receipt() {
    let (mut io, terminal, pdo, domain, mut allocations, source_allocation, source) =
        fixture(TARGET_DEVICE_RELATION);
    let baseline = io.device_reference_count(pdo);
    let mut delivery = TargetRelationDelivery::capture(
        &mut io,
        &mut allocations,
        &terminal,
        pdo,
        0x9000,
        source_allocation,
        &source,
        0x6000,
        domain,
        0x4000,
        pdo,
        0x5000,
    )
    .unwrap();
    let mut destination = [0; TARGET_DEVICE_RELATIONS_X64_BYTES];
    delivery
        .write_relation(&io, &allocations, &mut destination)
        .unwrap();
    let (_, other, _, _, _, _, _) = fixture(nt_pnp_abi::BUS_RELATIONS);
    // Both independent managers can mint the same numeric IRP: receipt semantics still differ.
    assert!(delivery
        .discard_after_canonical_retirement(&mut io, &mut allocations, &other)
        .is_err());
    delivery
        .discard_after_canonical_retirement(&mut io, &mut allocations, &terminal)
        .unwrap();
    assert_eq!(delivery.phase(), TargetRelationPhase::Aborted);
    assert_eq!(io.device_reference_count(pdo), baseline);
    assert!(delivery
        .discard_after_canonical_retirement(&mut io, &mut allocations, &terminal)
        .is_err());
    allocations
        .begin_retirement(delivery.allocation().identity)
        .unwrap();
}

#[test]
fn wrong_or_stale_source_allocation_cannot_authorize_delivery() {
    let (mut io, terminal, pdo, domain, mut allocations, source_allocation, source) =
        fixture(TARGET_DEVICE_RELATION);
    let baseline = io.device_reference_count(pdo);
    assert!(matches!(
        TargetRelationDelivery::capture(
            &mut io,
            &mut allocations,
            &terminal,
            pdo,
            0x9001,
            source_allocation,
            &source,
            0x6000,
            domain,
            0x4000,
            pdo,
            0x5000,
        ),
        Err(TargetRelationError::WrongSourceAllocation)
    ));
    let mut stale = source_allocation;
    stale.identity.generation += 1;
    assert!(matches!(
        TargetRelationDelivery::capture(
            &mut io,
            &mut allocations,
            &terminal,
            pdo,
            0x9000,
            stale,
            &source,
            0x6000,
            domain,
            0x4000,
            pdo,
            0x5000,
        ),
        Err(TargetRelationError::WrongSourceAllocation)
    ));
    assert_eq!(io.device_reference_count(pdo), baseline);
    allocations
        .begin_retirement(source_allocation.identity)
        .unwrap();
}
