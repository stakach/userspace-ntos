//! One physical ClassPnP packet may be prepared for a retry while its prior
//! terminal SCSI result still owns a provider acknowledgement.

use nt_io_manager::source_irp_ledger::{
    SourceIrpAllocation, SourceIrpLedger, SourceIrpOwner, SourceIrpRetirement,
    SourceIrpUseTicket,
};
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

fn packet() -> SourceIrpAllocation {
    SourceIrpAllocation {
        owner: SourceIrpOwner::HostedDriver(19),
        domain: HostedDomainIdentity { domain_id: HostedDomainId(7), cookie: 44 },
        component_address: 0x5000,
        bytes: 0x128,
        stack_count: 2,
        pool_generation: 44,
    }
}

#[test]
fn terminal_scsi_use_can_advance_before_old_ack_without_releasing_new_use() {
    let mut ledger = SourceIrpLedger::new();
    let allocation = packet();
    let registration = ledger.register(allocation).unwrap();
    let old: SourceIrpUseTicket = ledger.pin_scsi_use(registration, allocation).unwrap();
    assert_eq!(old.registration(), registration);
    ledger.arm_scsi_deferred_free(old, allocation).unwrap();
    // Retrying source publication after a retained Reply must not strand the
    // same exact use on a second arm attempt.
    ledger.arm_scsi_deferred_free(old, allocation).unwrap();

    // A pending or uncertain effect cannot authorize reuse. Raw Terminal is
    // also insufficient: source data/sense/SRB copyback must be committed
    // before the caller can rewrite the same packet header.
    let mut copyback_committed = false;
    assert!(ledger.plan_scsi_reuse(registration, allocation,
        |_| copyback_committed).is_err());
    assert!(ledger.plan_scsi_reuse(registration,
        SourceIrpAllocation { pool_generation: 45, ..allocation }, |_| true).is_err());

    // The exact old use has committed copyback and published its terminal
    // result. IoReuseIrp may now rewrite the header while the old ACK remains.
    copyback_committed = true;
    let next = ledger.plan_scsi_reuse(registration, allocation, |use_ticket| {
        assert_eq!(use_ticket, old);
        copyback_committed
    }).unwrap();
    assert_eq!(next.registration(), registration);
    assert_ne!(next, old);
    assert!(next.epoch().get() > old.epoch().get());
    let new = ledger.pin_scsi_use(registration, allocation).unwrap();
    assert_eq!(new, next);
    ledger.arm_scsi_deferred_free(new, allocation).unwrap();

    // An ACK for the old submission only releases its own lease. The new
    // submission stays pinned and cannot be mistaken for the old generation.
    ledger.complete_scsi_use(old, allocation).unwrap();
    assert!(ledger.complete_scsi_use(old, allocation).is_err());
    assert!(ledger.plan_scsi_reuse(registration, allocation, |_| false).is_err());
    ledger.complete_scsi_use(new, allocation).unwrap();
    assert!(ledger.mutation_ready(registration, allocation).is_ok());
    assert!(ledger.scsi_reuse_needed(registration, allocation));
    let after_ack = ledger.plan_scsi_reuse(registration, allocation, |_| true).unwrap();
    assert_ne!(after_ack, new);
    assert_eq!(ledger.pin_scsi_use(registration, allocation), Ok(after_ack));
}

#[test]
fn requested_free_and_generic_pin_fence_terminal_scsi_reuse() {
    let allocation = packet();
    let mut free = SourceIrpLedger::new();
    let registration = free.register(allocation).unwrap();
    let use_ticket = free.pin_scsi_use(registration, allocation).unwrap();
    free.arm_scsi_deferred_free(use_ticket, allocation).unwrap();
    assert_eq!(free.prepare_driver_free(19, allocation.domain, allocation.component_address),
        Ok(SourceIrpRetirement::Deferred(registration)));
    assert!(free.plan_scsi_reuse(registration, allocation, |_| true).is_err());
    assert_eq!(free.begin_deferred_scsi_retirement(use_ticket, allocation),
        Ok(SourceIrpRetirement::Retired(registration)));
    assert!(free.begin_deferred_scsi_retirement(use_ticket, allocation).is_err());
    free.retire(registration, allocation).unwrap();
    assert!(free.registered(allocation.owner, allocation.domain,
        allocation.component_address).is_none());

    let mut generic = SourceIrpLedger::new();
    let registration = generic.register(allocation).unwrap();
    generic.pin_hosted_forward(19, allocation.domain, allocation.component_address).unwrap();
    assert!(generic.plan_scsi_reuse(registration, allocation, |_| true).is_err());
}

#[test]
fn abandoned_capture_does_not_reissue_a_stale_use_ticket() {
    let mut ledger = SourceIrpLedger::new();
    let allocation = packet();
    let registration = ledger.register(allocation).unwrap();
    let abandoned = ledger.pin_scsi_use(registration, allocation).unwrap();
    ledger.abandon_scsi_use(abandoned, allocation).unwrap();
    assert!(ledger.pin_scsi_use(registration, allocation).is_err());
    let next = ledger.plan_scsi_reuse(registration, allocation, |_| true).unwrap();
    assert_ne!(next, abandoned);
    assert_eq!(ledger.pin_scsi_use(registration, allocation), Ok(next));
}

#[test]
fn generic_free_arm_cannot_bypass_an_unpublished_scsi_use() {
    let mut ledger = SourceIrpLedger::new();
    let allocation = packet();
    let registration = ledger.register(allocation).unwrap();
    let scsi = ledger.pin_scsi_use(registration, allocation).unwrap();
    ledger.pin_hosted_forward(19, allocation.domain, allocation.component_address).unwrap();
    ledger.arm_deferred_free(registration).unwrap();
    assert!(ledger.prepare_driver_free(
        19, allocation.domain, allocation.component_address,
    ).is_err());
    ledger.arm_scsi_deferred_free(scsi, allocation).unwrap();
    assert_eq!(ledger.prepare_driver_free(
        19, allocation.domain, allocation.component_address,
    ), Ok(SourceIrpRetirement::Deferred(registration)));
}
