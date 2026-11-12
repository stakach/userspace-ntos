//! A parked queued callback keeps one root turn and one retirement watch for its whole queue
//! claim. Resuming the parent can refresh its retained Reply without changing the queue row
//! generation; that is a new witness for the same owner, never a foreign or newer callback.

use nt_component_suspension::{
    RootChildOwner, RootChildRetirementError, RootChildRetirementWatches, RootChildTurn,
    RootChildTurnError,
};

/// Queue row generation: slot index, invocation ring head, and claim sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Claim {
    index: usize,
    head: u64,
    sequence: u64,
}

/// The claim plus the physical dispatch epoch and Reply authenticated for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Selector {
    claim: Claim,
    epoch: u64,
    reply: u64,
}

impl RootChildOwner for Selector {
    type Claim = Claim;

    fn claim(&self) -> Claim { self.claim }
}

#[derive(Debug, Eq, PartialEq)]
struct DeferredIngress {
    reply: Box<u64>,
    admission: u64,
}

const CLAIM: Claim = Claim { index: 9, head: 799, sequence: 5 };

fn selector(reply: u64) -> Selector {
    Selector { claim: CLAIM, epoch: 348, reply }
}

fn ingress(reply: u64, admission: u64) -> DeferredIngress {
    DeferredIngress { reply: Box::new(reply), admission }
}

#[test]
fn refreshed_reply_continues_the_parked_turn_and_retires_it_once() {
    // The reproduced row kept its index, key and sequence while its Reply was refreshed.
    let (parked, second, third) = (selector(73552), selector(73573), selector(73521));
    let mut watches = RootChildRetirementWatches::new();
    let mut turn = RootChildTurn::new(parked);
    turn.retain_ingress(parked, vec![ingress(101, 1)]).unwrap();
    watches.watch(parked.claim()).unwrap();
    assert_eq!(turn.arm_retry(parked, 100, 25), Ok(125));

    // The resumed parent yields again with another Reply. The root's next park presents the
    // row's current selector; it continues the same turn rather than requesting a second one.
    turn.advance_owner(parked, second).unwrap();
    assert_eq!(turn.owner(), second);
    assert_eq!(
        watches.watch(second.claim()),
        Err(RootChildRetirementError::AlreadyWatched),
        "one claim has exactly one retirement watch across every refreshed Reply"
    );
    assert_eq!(turn.retry_deadline(second), Ok(Some(125)));
    turn.retained_ingress_mut(second).unwrap().unwrap().push(ingress(102, 2));

    // The retired Reply is now as stale as any other owner.
    assert_eq!(turn.retained_ingress(parked), Err(RootChildTurnError::WrongOwner));
    assert_eq!(turn.arm_retry(parked, 130, 25), Err(RootChildTurnError::WrongOwner));
    assert_eq!(turn.advance_owner(parked, third), Err(RootChildTurnError::WrongOwner));
    let (error, refused) = turn.retain_ingress(parked, vec![ingress(999, 9)]).unwrap_err();
    assert_eq!((error, refused.len()), (RootChildTurnError::WrongOwner, 1));

    turn.advance_owner(second, third).unwrap();
    assert!(!watches.retired(turn.owner().claim()));
    assert!(!watches.consume(turn.owner().claim()), "an unsealed receipt cannot be consumed");

    // The callback returns under its latest Reply. Its one-use queue ACK seals the watch that
    // was registered two Replies earlier, and the root consumes that receipt exactly once.
    assert!(watches.acknowledge(third.claim()));
    assert!(!watches.acknowledge(third.claim()), "one claim is acknowledged once");
    assert!(watches.retired(parked.claim()));
    assert!(watches.consume(turn.owner().claim()));
    assert!(!watches.consume(turn.owner().claim()));
    assert!(!watches.watched(CLAIM));

    let turn = turn.settle(parked).unwrap_err();
    let turn = turn.settle(second).unwrap_err();
    let retained = turn.settle(third).unwrap().unwrap();
    assert_eq!(retained, vec![ingress(101, 1), ingress(102, 2)]);
}

#[test]
fn advance_needs_the_current_owner_and_a_changed_witness() {
    let parked = selector(73552);
    let mut turn = RootChildTurn::new(parked);
    turn.retain_ingress(parked, vec![ingress(101, 1)]).unwrap();

    assert_eq!(
        turn.advance_owner(parked, parked),
        Err(RootChildTurnError::WitnessUnchanged)
    );
    assert_eq!(
        turn.advance_owner(selector(73573), selector(73521)),
        Err(RootChildTurnError::WrongOwner),
        "a selector this turn never held cannot hand it to another Reply"
    );
    assert_eq!(turn.owner(), parked);
    assert_eq!(turn.settle(parked).unwrap().unwrap(), vec![ingress(101, 1)]);
}

#[test]
fn reused_slot_or_other_key_cannot_adopt_or_retire_the_parked_turn() {
    let parked = selector(73552);
    // Same slot and ring head claimed again later, and a different invocation in that slot.
    // Both carry the very Reply and epoch the parked callback was authenticated with.
    let reused_slot = Selector { claim: Claim { sequence: 6, ..CLAIM }, ..parked };
    let other_key = Selector { claim: Claim { head: 800, ..CLAIM }, ..parked };
    let mut watches = RootChildRetirementWatches::new();
    let mut turn = RootChildTurn::new(parked);
    turn.retain_ingress(parked, vec![ingress(101, 1)]).unwrap();
    watches.watch(parked.claim()).unwrap();

    for foreign in [reused_slot, other_key] {
        assert_eq!(
            turn.advance_owner(parked, foreign),
            Err(RootChildTurnError::ForeignClaim)
        );
        assert_eq!(turn.retained_ingress(foreign), Err(RootChildTurnError::WrongOwner));
        assert!(!watches.acknowledge(foreign.claim()));
        assert!(!watches.retired(foreign.claim()));
        assert!(!watches.consume(foreign.claim()));
    }
    assert_eq!(turn.owner(), parked);
    assert!(watches.watched(parked.claim()) && !watches.retired(parked.claim()));
    let turn = turn.settle(reused_slot).unwrap_err();
    assert_eq!(turn.settle(parked).unwrap().unwrap(), vec![ingress(101, 1)]);
}

#[test]
fn newer_claim_takes_its_own_turn_while_the_older_reply_refreshes() {
    let older = selector(73552);
    let older_refreshed = selector(73573);
    let newer = Selector { claim: Claim { index: 4, head: 12, sequence: 6 }, epoch: 351, reply: 73600 };
    let mut watches = RootChildRetirementWatches::new();
    let mut turns = Vec::new();

    let mut a = RootChildTurn::new(older);
    a.retain_ingress(older, vec![ingress(101, 1)]).unwrap();
    watches.watch(older.claim()).unwrap();
    turns.push(a);

    // A's resume refreshed its Reply and entered a nested callback B that now parks. B is
    // another claim: it cannot continue A's turn, and A's witness is refreshed in place.
    let top = turns.last_mut().unwrap();
    assert_eq!(top.advance_owner(older, newer), Err(RootChildTurnError::ForeignClaim));
    top.advance_owner(older, older_refreshed).unwrap();
    let mut b = RootChildTurn::new(newer);
    b.retain_ingress(newer, vec![ingress(102, 2)]).unwrap();
    watches.watch(newer.claim()).unwrap();
    turns.push(b);

    // B retires first; its ACK cannot seal A's receipt.
    assert!(watches.acknowledge(newer.claim()));
    assert!(!watches.retired(older_refreshed.claim()));
    let b = turns.pop().unwrap();
    assert!(watches.consume(b.owner().claim()));
    assert_eq!(b.settle(newer).unwrap().unwrap(), vec![ingress(102, 2)]);

    let a = turns.pop().unwrap();
    assert!(watches.acknowledge(a.owner().claim()));
    assert!(watches.consume(older.claim()));
    assert_eq!(a.settle(older_refreshed).unwrap().unwrap(), vec![ingress(101, 1)]);
    assert!(!watches.watched(older.claim()) && !watches.watched(newer.claim()));
}

#[test]
fn unwatched_claim_retires_without_a_receipt() {
    let mut watches = RootChildRetirementWatches::<Claim>::new();
    assert!(!watches.acknowledge(CLAIM), "a callback that never parked has no root receipt");
    assert!(!watches.retired(CLAIM));
    assert!(!watches.consume(CLAIM));
    watches.watch(CLAIM).unwrap();
    assert!(!watches.retired(CLAIM));
    assert!(!watches.consume(CLAIM));
}
