use super::*;
use nt_component_suspension::peer_registry::{PeerIdentity, PeerRegistry};
use nt_component_suspension::{ComponentSuspensionLanes, LaneBinding};

fn identity() -> ProviderFileCloseIdentity {
    let mut lanes = ComponentSuspensionLanes::<u64, u64>::new(1, 2);
    let lane = lanes
        .allocate(LaneBinding {
            executor_id: 3,
            receive_endpoint: 5,
            reply_object: 7,
        })
        .unwrap();
    lanes.begin_dispatch(lane, 7).unwrap();
    let dispatch = lanes.active_dispatch_identity(lane).unwrap().unwrap();
    let mut peers = PeerRegistry::new(5, 1);
    let staged = peers
        .stage(PeerIdentity {
            domain: 11,
            domain_generation: 13,
            executor: 3,
            lane,
        })
        .unwrap();
    ProviderFileCloseIdentity {
        route: staged.route().unwrap(),
        dispatch,
        reply: 7,
        token: 17,
        file_id: 19,
    }
}

#[test]
fn accepted_close_survives_cleanup_and_reply_until_ack() {
    let mut ledger = ProviderFileCloseLedger::new(1);
    let id = identity();
    let ticket = ledger.reserve(id, alloc::boxed::Box::new(41)).unwrap();
    assert_eq!(
        ledger.get(&ticket).unwrap().1,
        ProviderFileClosePhase::Reserved
    );
    ledger.admit(&ticket).unwrap();
    assert_eq!(
        ledger.ticket_for_file(id.file_id),
        Some(ProviderFileCloseTicket {
            slot: 0,
            generation: 1
        })
    );
    let ready = ledger.cleanup_ready_for_file(id.file_id).unwrap();
    assert_eq!(ready, ticket);
    assert_eq!(
        ledger.next_in_phase(ProviderFileClosePhase::ReadyToReply, None),
        Ok(Some(ProviderFileCloseTicket {
            slot: 0,
            generation: 1
        }))
    );
    ledger.enter_reply(&ticket).unwrap();
    assert_eq!(
        ledger.next_in_phase(ProviderFileClosePhase::ReadyToReply, None),
        Ok(None)
    );
    assert_eq!(
        ledger.next_in_phase(ProviderFileClosePhase::ReplyEntered, None),
        Ok(Some(ProviderFileCloseTicket {
            slot: 0,
            generation: 1
        }))
    );
    assert_eq!(
        ledger.enter_reply(&ticket),
        Err(ProviderFileCloseError::WrongPhase)
    );
    assert_eq!(
        ledger.abort_reservation(&ticket),
        Err(ProviderFileCloseError::WrongPhase)
    );
    assert_eq!(*ledger.retire_acknowledged(&ticket).unwrap(), 41);
    assert!(ledger.is_empty());
}

#[test]
fn duplicate_file_and_dispatch_do_not_consume_owner() {
    let mut ledger = ProviderFileCloseLedger::new(2);
    let id = identity();
    let _first = ledger.reserve(id, 1).unwrap();
    let mut other = id;
    other.token += 1;
    assert_eq!(
        ledger.reserve(other, 2),
        Err((ProviderFileCloseError::DuplicateFile, 2))
    );
    other = id;
    other.file_id += 1;
    assert_eq!(
        ledger.reserve(other, 3),
        Err((ProviderFileCloseError::DuplicateDispatch, 3))
    );
    assert_eq!(ledger.len(), 1);
}

#[test]
fn slot_reuse_rejects_stale_ticket_and_retained_reply_cannot_replay() {
    let mut ledger = ProviderFileCloseLedger::new(1);
    let id = identity();
    let old = ledger.reserve(id, 11).unwrap();
    ledger.admit(&old).unwrap();
    ledger.cleanup_ready(&old).unwrap();
    ledger.enter_reply(&old).unwrap();
    assert_eq!(
        ledger.cleanup_ready(&old),
        Err(ProviderFileCloseError::WrongPhase)
    );
    assert_eq!(ledger.retire_cancelled(&old), Ok(11));
    let mut next = id;
    next.file_id += 1;
    next.token += 1;
    let current = ledger.reserve(next, 12).unwrap();
    assert_ne!(old, current);
    assert_eq!(ledger.admit(&old), Err(ProviderFileCloseError::StaleTicket));
    assert_eq!(ledger.abort_reservation(&current), Ok(12));
}

#[test]
fn admission_fences_abort_and_capacity_does_not_evict() {
    let mut ledger = ProviderFileCloseLedger::new(1);
    let id = identity();
    let ticket = ledger.reserve(id, 1).unwrap();
    ledger.admit(&ticket).unwrap();
    assert_eq!(
        ledger.abort_reservation(&ticket),
        Err(ProviderFileCloseError::WrongPhase)
    );
    let mut other = id;
    other.file_id += 1;
    other.token += 1;
    assert_eq!(
        ledger.reserve(other, 2),
        Err((ProviderFileCloseError::NoCapacity, 2))
    );
    assert_eq!(ledger.retire_cancelled(&ticket), Ok(1));
}
