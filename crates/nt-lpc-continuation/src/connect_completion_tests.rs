use super::*;
use alloc::rc::Rc;
use core::cell::Cell;

struct Terminal(Rc<Cell<usize>>);
impl Drop for Terminal {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn pending(connection_id: u64) -> PendingConnect<u64> {
    PendingConnect {
        request: ConnectRequest {
            connection_id,
            port_handle: 0x1000,
            connection_information: 0,
            connection_information_length: 0,
            connection_information_capacity: 0,
            operation: ConnectOperation::SecureConnect,
        },
        continuation: 0x1234,
    }
}

fn admitted() -> (
    ConnectWaitTable<u64, Terminal>,
    Rc<Cell<usize>>,
    usize,
    ConnectCompletionTicket,
) {
    let mut table = ConnectWaitTable::with_completion_storage(1);
    let reservation = table.reserve().unwrap();
    let slot = table.publish(reservation, pending(71)).unwrap();
    let drops = Rc::new(Cell::new(0));
    let ticket = match table.begin_completion(71, Terminal(drops.clone())) {
        Ok(ticket) => ticket,
        Err(_) => panic!("fresh completion admission"),
    };
    (table, drops, slot, ticket)
}

#[test]
fn publishing_retains_terminal_and_wait_without_replay_or_reset() {
    let (mut table, drops, slot, ticket) = admitted();
    assert!(table.take(slot).is_none());
    assert_eq!(table.reset(), Err(TableError::InvalidRequest));
    assert!(table.completion(&ticket).is_some());
    assert_eq!(drops.get(), 0);
    let rejected = match table.begin_completion(71, Terminal(drops.clone())) {
        Err((TableError::InvalidRequest, terminal)) => terminal,
        _ => panic!("a publication intent cannot be replayed"),
    };
    assert_eq!(drops.get(), 0);
    drop(rejected);
    assert_eq!(drops.get(), 1);
    assert_eq!(table.find_connection(71).unwrap().1.continuation, 0x1234);
}

#[test]
fn uncertain_reply_keeps_exact_owner_and_terminal_sticky() {
    let (mut table, drops, slot, ticket) = admitted();
    table.begin_reply(&ticket, 0xc0000041).unwrap();
    assert!(table.take(slot).is_none());
    assert!(table.finish_reply(ticket, false).is_none());
    assert!(table.take(slot).is_none());
    assert_eq!(table.reset(), Err(TableError::InvalidRequest));
    assert!(table.find_connection(71).is_some());
    assert_eq!(drops.get(), 0);
    assert!(table.begin_completion(71, Terminal(drops.clone())).is_err());
    assert_eq!(
        drops.get(),
        1,
        "only the refused duplicate payload was released"
    );
}

#[test]
fn reply_ack_alone_transfers_wait_and_terminal_once() {
    let (mut table, drops, slot, ticket) = admitted();
    let stale = ConnectCompletionTicket {
        slot: ticket.slot,
        generation: ticket.generation,
        connection_id: ticket.connection_id,
    };
    table.begin_reply(&ticket, 0).unwrap();
    let (wait, terminal) = table.finish_reply(ticket, true).unwrap();
    assert_eq!(wait.request.connection_id, 71);
    assert!(table.get(slot).is_none());
    assert_eq!(drops.get(), 0);
    let next = table.reserve().unwrap();
    table.publish(next, pending(72)).unwrap();
    assert_eq!(
        table.begin_reply(&stale, 0),
        Err(TableError::InvalidRequest)
    );
    assert_eq!(table.take(slot).unwrap().request.connection_id, 72);
    drop(terminal);
    assert_eq!(drops.get(), 1);
}

#[test]
fn uncertain_cancellation_is_sticky_and_cannot_reuse_the_slot() {
    let mut table = ConnectWaitTable::<u64>::with_initial_reserve(1);
    let reservation = table.reserve().unwrap();
    let slot = table.publish(reservation, pending(71)).unwrap();
    let ticket = table.begin_cancel(71).unwrap();
    assert!(table.take(slot).is_none());
    assert!(table.finish_cancel(ticket, false).is_none());
    assert!(table.take(slot).is_none());
    assert!(matches!(
        table.begin_cancel(71),
        Err(TableError::InvalidRequest)
    ));
    assert!(table.begin_completion(71, ()).is_err());
    assert_eq!(table.reset(), Err(TableError::InvalidRequest));
    let other = table.reserve().unwrap();
    assert_ne!(other.slot, slot);
    assert_eq!(table.find_connection(71).unwrap().1.continuation, 0x1234);
}

#[test]
fn cancellation_ack_transfers_exact_wait_once() {
    let mut table = ConnectWaitTable::<u64>::new();
    let reservation = table.reserve().unwrap();
    let slot = table.publish(reservation, pending(71)).unwrap();
    let ticket = table.begin_cancel(71).unwrap();
    let stale = ConnectCompletionTicket {
        slot: ticket.slot,
        generation: ticket.generation,
        connection_id: ticket.connection_id,
    };
    assert_eq!(
        table
            .finish_cancel(ticket, true)
            .unwrap()
            .request
            .connection_id,
        71
    );
    assert!(table.finish_cancel(stale, true).is_none());
    assert!(table.get(slot).is_none());
}

#[test]
fn cancellation_cannot_consume_publication_or_reply_owner() {
    let (mut table, drops, slot, ticket) = admitted();
    assert!(matches!(
        table.begin_cancel(71),
        Err(TableError::InvalidRequest)
    ));
    table.begin_reply(&ticket, 0).unwrap();
    assert!(matches!(
        table.begin_cancel(71),
        Err(TableError::InvalidRequest)
    ));
    assert!(table.take(slot).is_none());
    assert_eq!(drops.get(), 0);
}
