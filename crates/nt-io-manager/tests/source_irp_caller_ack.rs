//! Caller-IRP terminal acknowledgement receipts: what a repeated acknowledgement may name,
//! and how much the executive keeps to decide it.

use nt_io_manager::retained_query_path_forward::SourceIrpTicket;
use nt_io_manager::source_irp_caller_ack::CallerTerminalAcks;
use nt_io_manager::source_irp_ledger::SourceIrpOwner;
use nt_io_manager::{HostedDomainId, HostedDomainIdentity};

/// The hosted pending-IRP table holds this many nodes before it spills into pool. A provider
/// links a new node only when none is free and never unlinks one.
const PENDING_NODES: u64 = 256;
const OWNER: SourceIrpOwner = SourceIrpOwner::HostedCaller(3);

fn domain(id: u64) -> HostedDomainIdentity {
    HostedDomainIdentity { domain_id: HostedDomainId(id), cookie: 0x5eed_0000 + id }
}

/// The source-IRP ledger issues one serial as both the id and the generation.
fn ticket(serial: u64) -> SourceIrpTicket {
    SourceIrpTicket::new(domain(7), serial, serial).unwrap()
}

fn node(index: u64) -> u64 {
    0x0000_0100_2000_0000 + index * 0x200
}

#[test]
fn two_hundred_thousand_acknowledgements_keep_one_receipt_per_pending_node() {
    let mut acks = CallerTerminalAcks::new();
    let mut high_water = 0;
    for serial in 1..=200_000u64 {
        let pending = node(serial % PENDING_NODES);
        acks.reserve(OWNER, pending).unwrap();
        acks.consume(OWNER, pending, ticket(serial)).unwrap();
        assert!(acks.authenticates(OWNER, ticket(serial)));
        high_water = high_water.max(acks.retained_bytes());
    }
    assert_eq!(acks.len(), PENDING_NODES as usize);
    // 48 bytes per receipt grew the old table to 6.3 MB by 131,072 completions and asked
    // for 12.6 MB next; the whole table now fits in a few pages.
    assert!(high_water <= 64 * 1024, "receipts retained {high_water} bytes");
}

#[test]
fn consuming_a_reserved_node_does_not_allocate() {
    let mut acks = CallerTerminalAcks::new();
    for index in 0..PENDING_NODES {
        acks.reserve(OWNER, node(index)).unwrap();
    }
    let reserved = acks.retained_bytes();
    for serial in 1..=10_000u64 {
        acks.consume(OWNER, node(serial % PENDING_NODES), ticket(serial)).unwrap();
        assert_eq!(acks.retained_bytes(), reserved);
    }
}

#[test]
fn an_immediate_repeat_of_the_consumed_ticket_is_authenticated() {
    let mut acks = CallerTerminalAcks::new();
    acks.reserve(OWNER, node(0)).unwrap();
    acks.consume(OWNER, node(0), ticket(41)).unwrap();
    assert!(acks.authenticates(OWNER, ticket(41)));
    // The repeat consumes nothing, so it can itself be repeated.
    assert!(acks.authenticates(OWNER, ticket(41)));
}

#[test]
fn a_repeat_survives_acknowledgements_on_every_other_node() {
    // Another provider thread, or a callback nested in the first acknowledgement, may
    // complete any number of other caller IRPs before the repeat arrives.
    let mut acks = CallerTerminalAcks::new();
    acks.reserve(OWNER, node(0)).unwrap();
    acks.consume(OWNER, node(0), ticket(1)).unwrap();
    for serial in 2..=50_000u64 {
        let pending = node(1 + serial % (PENDING_NODES - 1));
        acks.reserve(OWNER, pending).unwrap();
        acks.consume(OWNER, pending, ticket(serial)).unwrap();
    }
    assert!(acks.authenticates(OWNER, ticket(1)));
}

#[test]
fn an_older_ticket_is_refused_once_its_node_carries_a_newer_caller_irp() {
    let mut acks = CallerTerminalAcks::new();
    acks.reserve(OWNER, node(0)).unwrap();
    acks.consume(OWNER, node(0), ticket(1)).unwrap();

    // The provider reuses a node only after the release that sends the repeat has returned,
    // so projecting the next caller IRP on it closes the older ticket's repeat window.
    acks.reserve(OWNER, node(0)).unwrap();
    assert!(!acks.authenticates(OWNER, ticket(1)));

    acks.consume(OWNER, node(0), ticket(2)).unwrap();
    assert!(!acks.authenticates(OWNER, ticket(1)));
    assert!(acks.authenticates(OWNER, ticket(2)));
}

#[test]
fn a_ticket_that_was_never_consumed_is_refused() {
    let mut acks = CallerTerminalAcks::new();
    assert!(!acks.authenticates(OWNER, ticket(1)));

    acks.reserve(OWNER, node(0)).unwrap();
    // Projected but not yet acknowledged.
    assert!(!acks.authenticates(OWNER, ticket(1)));

    acks.consume(OWNER, node(0), ticket(1)).unwrap();
    assert!(!acks.authenticates(OWNER, ticket(2)));
    // Same serial, wrong generation or wrong domain.
    assert!(!acks.authenticates(OWNER, SourceIrpTicket::new(domain(7), 1, 2).unwrap()));
    assert!(!acks.authenticates(OWNER, SourceIrpTicket::new(domain(8), 1, 1).unwrap()));
}

#[test]
fn a_foreign_owner_cannot_repeat_another_owners_acknowledgement() {
    let mut acks = CallerTerminalAcks::new();
    acks.reserve(OWNER, node(0)).unwrap();
    acks.consume(OWNER, node(0), ticket(1)).unwrap();
    assert!(!acks.authenticates(SourceIrpOwner::HostedCaller(4), ticket(1)));
    assert!(!acks.authenticates(SourceIrpOwner::HostedDriver(3), ticket(1)));
    assert!(!acks.authenticates(SourceIrpOwner::Win32k, ticket(1)));
}

#[test]
fn two_owners_using_the_same_node_address_keep_separate_receipts() {
    // Every hosted component runs at the same addresses in its own address space.
    let other = SourceIrpOwner::HostedCaller(4);
    let mut acks = CallerTerminalAcks::new();
    acks.reserve(OWNER, node(0)).unwrap();
    acks.consume(OWNER, node(0), ticket(1)).unwrap();
    acks.reserve(other, node(0)).unwrap();
    acks.consume(other, node(0), ticket(2)).unwrap();
    assert!(acks.authenticates(OWNER, ticket(1)));
    assert!(acks.authenticates(other, ticket(2)));
    assert_eq!(acks.len(), 2);
}

#[test]
fn an_acknowledgement_without_a_reservation_is_still_recorded() {
    let mut acks = CallerTerminalAcks::new();
    acks.consume(OWNER, node(0), ticket(1)).unwrap();
    assert!(acks.authenticates(OWNER, ticket(1)));
    assert_eq!(acks.len(), 1);
}

#[test]
fn teardown_forgets_only_the_retiring_owners_receipts() {
    let other = SourceIrpOwner::HostedCaller(4);
    let mut acks = CallerTerminalAcks::new();
    for index in 0..8 {
        acks.reserve(OWNER, node(index)).unwrap();
        acks.consume(OWNER, node(index), ticket(1 + index)).unwrap();
        acks.reserve(other, node(index)).unwrap();
        acks.consume(other, node(index), ticket(100 + index)).unwrap();
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
