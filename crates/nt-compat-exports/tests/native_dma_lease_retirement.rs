//! Behavior contracts for exact hosted DMA lease retirement.

#[path = "../../../components/ntos-executive/src/hosted_dma_lease_retirement.rs"]
mod retirement;

use retirement::{retire_lease, LeaseIdentity};
use std::cell::RefCell;

fn lease(id: u64, adapter_id: u64, owner: u64) -> LeaseIdentity<u64> {
    LeaseIdentity {
        lease_id: id,
        adapter_id,
        owner,
    }
}

#[test]
fn first_exact_sibling_retires_its_private_graph_without_putting_shared_adapter() {
    let first = lease(11, 40, 7);
    let sibling = lease(12, 40, 7);
    let inventory = [first, sibling];
    let events = RefCell::new(Vec::new());

    retire_lease(
        first,
        inventory,
        true,
        || {
            events.borrow_mut().push("preflight");
            Ok::<_, &'static str>(())
        },
        || {
            events.borrow_mut().push("private");
            Ok(())
        },
        |put| {
            events
                .borrow_mut()
                .push(if put { "pair+put" } else { "pair" });
            Ok(())
        },
        || panic!("published lease must use its captured pair"),
    )
    .unwrap();

    assert_eq!(
        *events.borrow(),
        ["preflight", "private", "pair"],
        "the first exact sibling may retire its own pair but not the shared adapter"
    );
}

#[test]
fn live_shared_record_refuses_before_private_graph_or_pair_effects() {
    let target = lease(21, 50, 8);
    let events = RefCell::new(Vec::new());

    let result = retire_lease(
        target,
        [target],
        true,
        || {
            events.borrow_mut().push("preflight");
            Err::<(), _>("live DMA record")
        },
        || {
            events.borrow_mut().push("private");
            Ok(())
        },
        |_| {
            events.borrow_mut().push("pair");
            Ok(())
        },
        || panic!("published lease must use its captured pair"),
    );

    assert_eq!(result, Err("live DMA record"));
    assert_eq!(
        *events.borrow(),
        ["preflight"],
        "live shared record must be checked before any graph or pair effect"
    );
}

#[test]
fn unpublished_lease_removal_preserves_sibling_and_shared_adapter() {
    let unpublished = lease(31, 60, 9);
    let sibling = lease(32, 60, 9);
    let inventory = [unpublished, sibling];
    let events = RefCell::new(Vec::new());

    retire_lease(
        unpublished,
        inventory,
        false,
        || {
            events.borrow_mut().push("preflight");
            Ok::<_, &'static str>(())
        },
        || panic!("unpublished lease owns no private graph"),
        |_| panic!("unpublished lease owns no pair"),
        || {
            events.borrow_mut().push("put");
            Ok(())
        },
    )
    .unwrap();

    assert_eq!(
        *events.borrow(),
        ["preflight"],
        "the shared adapter remains live for the published sibling"
    );
}

#[test]
fn foreign_owner_or_adapter_is_not_a_sibling_lease() {
    let target = lease(41, 70, 10);
    let foreign_owner = lease(42, 70, 11);
    let different_adapter = lease(43, 71, 10);
    let events = RefCell::new(Vec::new());

    retire_lease(
        target,
        [target, foreign_owner, different_adapter],
        true,
        || {
            events.borrow_mut().push("preflight");
            Ok::<_, &'static str>(())
        },
        || {
            events.borrow_mut().push("private");
            Ok(())
        },
        |put| {
            events.borrow_mut().push(if put { "pair+put" } else { "pair" });
            Ok(())
        },
        || panic!("published lease must use its captured pair"),
    )
    .unwrap();

    assert_eq!(*events.borrow(), ["preflight", "private", "pair+put"]);
}
