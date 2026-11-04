//! ClassPnP keeps a transfer packet's driver IRP for another SCSI command.
//! Completing a forward without IoFreeIrp must release the temporary free arm.

use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpLedger, SourceIrpLedgerError, SourceIrpOwner,
};
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

#[test]
fn completed_driver_packet_without_free_is_ready_for_ioreuse() {
    let mut ledger = SourceIrpLedger::new();
    let owner = SourceIrpAllocation {
        owner: SourceIrpOwner::HostedDriver(19),
        domain: HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 44 },
        component_address: 0x5000,
        bytes: 0x128,
        stack_count: 2,
        pool_generation: 44,
    };
    let ticket = ledger.register(owner).unwrap();
    ledger.pin_hosted_forward(19, owner.domain, owner.component_address).unwrap();
    ledger.arm_deferred_free(ticket).unwrap();
    assert_eq!(ledger.mutation_ready(ticket, owner),
        Err(SourceIrpLedgerError::RetirementStarted));

    // The provider acknowledged completion and the callback did not free the
    // packet. Exact release clears the unused temporary arm.
    ledger.complete_driver_forward_without_free(ticket, owner).unwrap();
    assert_eq!(ledger.mutation_ready(ticket, owner), Ok(()));
}
