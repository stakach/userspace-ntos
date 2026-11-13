//! Caller-IRP terminal acknowledgement receipts: what a repeated acknowledgement may name.

use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_caller_ack::CallerTerminalAcks;
use nt_io_manager::source_irp_ledger::SourceIrpOwner;
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

const OWNER: SourceIrpOwner = SourceIrpOwner::HostedCaller(3);

fn domain(id: u64) -> HostedDomainIdentity {
    HostedDomainIdentity { domain_id: HostedDomainId(id), cookie: 0x5eed_0000 + id }
}

/// The source-IRP ledger issues one serial as both the id and the generation.
fn ticket(serial: u64) -> SourceIrpTicket {
    SourceIrpTicket::new(domain(7), serial, serial).unwrap()
}

#[test]
fn an_immediate_repeat_of_the_consumed_ticket_is_authenticated() {
    let mut acks = CallerTerminalAcks::new();
    acks.consume(OWNER, ticket(41)).unwrap();
    assert!(acks.authenticates(OWNER, ticket(41)));
    // The repeat consumes nothing, so it can itself be repeated.
    assert!(acks.authenticates(OWNER, ticket(41)));
}

#[test]
fn a_ticket_that_was_never_consumed_is_refused() {
    let mut acks = CallerTerminalAcks::new();
    assert!(!acks.authenticates(OWNER, ticket(1)));
    acks.consume(OWNER, ticket(1)).unwrap();
    assert!(!acks.authenticates(OWNER, ticket(2)));
    // Same serial, wrong generation or wrong domain.
    assert!(!acks.authenticates(OWNER, SourceIrpTicket::new(domain(7), 1, 2).unwrap()));
    assert!(!acks.authenticates(OWNER, SourceIrpTicket::new(domain(8), 1, 1).unwrap()));
}

#[test]
fn a_foreign_owner_cannot_repeat_another_owners_acknowledgement() {
    let mut acks = CallerTerminalAcks::new();
    acks.consume(OWNER, ticket(1)).unwrap();
    assert!(!acks.authenticates(SourceIrpOwner::HostedCaller(4), ticket(1)));
    assert!(!acks.authenticates(SourceIrpOwner::HostedDriver(3), ticket(1)));
    assert!(!acks.authenticates(SourceIrpOwner::Win32k, ticket(1)));
}

#[test]
fn teardown_forgets_only_the_retiring_owners_receipts() {
    let other = SourceIrpOwner::HostedCaller(4);
    let mut acks = CallerTerminalAcks::new();
    for index in 0..8 {
        acks.consume(OWNER, ticket(1 + index)).unwrap();
        acks.consume(other, ticket(100 + index)).unwrap();
    }
    acks.drain_owner(OWNER);
    assert_eq!(acks.len(), 8);
    for index in 0..8 {
        assert!(!acks.authenticates(OWNER, ticket(1 + index)));
        assert!(acks.authenticates(other, ticket(100 + index)));
    }
    acks.drain_owner(other);
    assert!(acks.is_empty());
}
