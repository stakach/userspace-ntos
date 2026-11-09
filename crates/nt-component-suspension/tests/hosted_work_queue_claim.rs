//! A dequeued provider callback can yield while its nested Hook File pump is unsettled.
//! The queue claim and exact invocation must survive until root observes its return.

use nt_component_suspension::{HostedWorkQueueClaim, HostedWorkQueueClaimError};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CallbackEntry {
    item: u64,
    routine: u64,
    arg0: u64,
    arg1: u64,
}

#[test]
fn entered_callback_keeps_its_exact_claim_through_nested_file_yield() {
    // Provider domain, generation, queue head and work item identify one physical slot.
    let exact = (11_u64, 22_u64, 33_u64, 44_u64);
    let stale_head = (11, 22, 34, 44);
    let recycled_generation = (11, 23, 33, 44);
    let entry = CallbackEntry { item: 101, routine: 202, arg0: 303, arg1: 404 };
    let mut claim = HostedWorkQueueClaim::dequeue(exact, entry);

    assert_eq!(claim.enter(stale_head), Err(HostedWorkQueueClaimError::WrongInvocation));
    assert_eq!(claim.retained_entry(exact), Ok(&entry));
    assert_eq!(claim.enter(exact), Ok(entry));
    // The native callback may now have yielded to a nested Hook File pump. Neither the
    // consumed shared slot nor a local stack copy is a durable root-turn owner.
    assert_eq!(claim.retained_entry(recycled_generation),
        Err(HostedWorkQueueClaimError::WrongInvocation));
    assert_eq!(claim.retained_entry(exact), Ok(&entry),
        "the exact queue entry must remain owned while the callback is suspended");
}

#[test]
fn returned_callback_acknowledges_one_claim_once() {
    let exact = (51_u64, 52_u64, 53_u64, 54_u64);
    let foreign_dispatch = (51, 55, 53, 54);
    let entry = CallbackEntry { item: 501, routine: 502, arg0: 503, arg1: 504 };
    let mut claim = HostedWorkQueueClaim::dequeue(exact, entry);

    assert_eq!(claim.acknowledge_return(exact), Err(HostedWorkQueueClaimError::NoClaim));
    assert_eq!(claim.enter(exact), Ok(entry));
    assert_eq!(claim.acknowledge_return(foreign_dispatch),
        Err(HostedWorkQueueClaimError::WrongInvocation));
    assert_eq!(claim.acknowledge_return(exact), Ok(()));
    assert_eq!(claim.acknowledge_return(exact), Err(HostedWorkQueueClaimError::NoClaim),
        "one returned callback may advance the drain counter only once");
}

#[test]
fn consumed_slot_without_callback_entry_aborts_without_a_terminal_acknowledgement() {
    let exact = (71_u64, 72_u64, 73_u64, 74_u64);
    let wrong_head = (71, 72, 75, 74);
    let entry = CallbackEntry { item: 701, routine: 702, arg0: 703, arg1: 704 };
    let mut claim = HostedWorkQueueClaim::dequeue(exact, entry);

    assert_eq!(claim.abort_before_enter(wrong_head),
        Err(HostedWorkQueueClaimError::WrongInvocation));
    assert_eq!(claim.retained_entry(exact), Ok(&entry));
    assert_eq!(claim.abort_before_enter(exact), Ok(()));
    assert_eq!(claim.enter(exact), Err(HostedWorkQueueClaimError::NoClaim));
    assert_eq!(claim.acknowledge_return(exact), Err(HostedWorkQueueClaimError::NoClaim));
    assert_eq!(claim.abort_before_enter(exact), Err(HostedWorkQueueClaimError::NoClaim));

    let mut entered = HostedWorkQueueClaim::dequeue(exact, entry);
    assert_eq!(entered.enter(exact), Ok(entry));
    assert_eq!(entered.abort_before_enter(exact), Err(HostedWorkQueueClaimError::NoClaim),
        "an entered callback must await its exact return or remain retained");
    assert_eq!(entered.retained_entry(exact), Ok(&entry));
}
