//! Host-side contract for selecting one executor's ambient state by its exact TCB anchor.
//! Native FS installation and the executive's concrete state layout stay outside this crate.

use crate::executor_local::{
    ExecutorLocalError, ExecutorLocalRegistry, TcbIdentity, TcbRetirementObservation,
};
use crate::{ExecutorError, ExecutorResume, ExecutorTable, ExecutorYield};
use alloc::boxed::Box;
use alloc::rc::Rc;
use core::cell::Cell;

#[derive(Debug, Eq, PartialEq)]
struct LocalStateProbe {
    ipc_buffer: u64,
    reply_slot: u64,
    scheduler_depth: u64,
    transient_used: usize,
}

fn probe(ipc_buffer: u64, reply_slot: u64) -> LocalStateProbe {
    LocalStateProbe {
        ipc_buffer,
        reply_slot,
        scheduler_depth: 0,
        transient_used: 0,
    }
}

fn boxed_probe(ipc_buffer: u64, reply_slot: u64) -> Box<LocalStateProbe> {
    Box::new(probe(ipc_buffer, reply_slot))
}

// Tests model native's confirmed exact-TCB teardown; production callers must prove the effect.
fn retired(tcb: TcbIdentity) -> TcbRetirementObservation {
    unsafe { TcbRetirementObservation::new(tcb) }
}

#[test]
fn exact_tcb_anchors_select_distinct_ipc_reply_scheduler_and_transient_state() {
    let (mut table, root) = ExecutorTable::try_new(2).unwrap();
    let first = table.register(&root).unwrap();
    let second = table.register(&root).unwrap();
    let first_tcb = TcbIdentity::new(0x101, 1);
    let second_tcb = TcbIdentity::new(0x102, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let first_anchor = locals.bind(&table, first, first_tcb, boxed_probe(0x1000, 0x201));
    assert!(
        first_anchor.is_ok(),
        "an idle executor must receive its own local block"
    );
    let first_anchor = first_anchor.unwrap();
    let first_address = locals
        .resolve(Some(first_anchor), first_tcb, first)
        .unwrap() as *const _;
    let second_anchor = locals
        .bind(&table, second, second_tcb, boxed_probe(0x2000, 0x202))
        .unwrap();

    assert_ne!(first_anchor, second_anchor);
    assert!(core::ptr::eq(
        first_address,
        locals
            .resolve(Some(first_anchor), first_tcb, first)
            .unwrap(),
    ));
    {
        let selected = locals
            .resolve_mut(Some(first_anchor), first_tcb, first)
            .unwrap();
        selected.scheduler_depth = 2;
        selected.transient_used = 96;
    }
    {
        let selected = locals
            .resolve_mut(Some(second_anchor), second_tcb, second)
            .unwrap();
        selected.scheduler_depth = 1;
        selected.transient_used = 32;
    }

    assert_eq!(
        locals
            .resolve(Some(first_anchor), first_tcb, first)
            .unwrap(),
        &LocalStateProbe {
            ipc_buffer: 0x1000,
            reply_slot: 0x201,
            scheduler_depth: 2,
            transient_used: 96
        },
    );
    assert_eq!(
        locals
            .resolve(Some(second_anchor), second_tcb, second)
            .unwrap(),
        &LocalStateProbe {
            ipc_buffer: 0x2000,
            reply_slot: 0x202,
            scheduler_depth: 1,
            transient_used: 32
        },
    );
}

#[test]
fn missing_or_mismatched_anchor_refuses_access_without_changing_either_local() {
    let (mut table, root) = ExecutorTable::try_new(2).unwrap();
    let first = table.register(&root).unwrap();
    let second = table.register(&root).unwrap();
    let first_tcb = TcbIdentity::new(0x101, 1);
    let second_tcb = TcbIdentity::new(0x102, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let first_anchor = locals
        .bind(&table, first, first_tcb, boxed_probe(0x1000, 0x201))
        .unwrap();
    let second_anchor = locals
        .bind(&table, second, second_tcb, boxed_probe(0x2000, 0x202))
        .unwrap();

    assert!(matches!(
        locals.resolve_mut(None, first_tcb, first),
        Err(ExecutorLocalError::MissingAnchor)
    ));
    assert!(locals
        .resolve_mut(Some(first_anchor), second_tcb, first)
        .is_err());
    assert!(locals
        .resolve_mut(Some(first_anchor), first_tcb, second)
        .is_err());
    assert!(locals
        .resolve_mut(Some(second_anchor), first_tcb, first)
        .is_err());
    assert_eq!(
        locals
            .resolve(Some(first_anchor), first_tcb, first)
            .unwrap(),
        &probe(0x1000, 0x201)
    );
    assert_eq!(
        locals
            .resolve(Some(second_anchor), second_tcb, second)
            .unwrap(),
        &probe(0x2000, 0x202)
    );
}

#[test]
fn bind_requires_a_current_idle_executor_in_the_supplied_table() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let executor = table.register(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let mut locals = ExecutorLocalRegistry::new();

    for invalid in [TcbIdentity::new(0, 1), TcbIdentity::new(0x101, 0)] {
        let payload = boxed_probe(0x1000, 0x201);
        let original_address = &*payload as *const _;
        let (error, returned) = locals.bind(&table, executor, invalid, payload).unwrap_err();
        assert_eq!(error, ExecutorLocalError::InvalidTcbIdentity);
        assert!(core::ptr::eq(original_address, &*returned));
    }
    let (foreign_table, _) = ExecutorTable::try_new(1).unwrap();
    assert_eq!(
        locals
            .bind(&foreign_table, executor, tcb, boxed_probe(0x1000, 0x201))
            .unwrap_err()
            .0,
        ExecutorLocalError::Table(ExecutorError::WrongTable),
    );

    let run = table.resume(root, ExecutorResume::Unrouted).unwrap();
    assert!(locals
        .bind(&table, executor, tcb, boxed_probe(0x1000, 0x201))
        .is_err());
    let root = table.accept_yield(run, ExecutorYield::Idle).unwrap();
    let anchor = locals
        .bind(&table, executor, tcb, boxed_probe(0x1000, 0x201))
        .unwrap();
    assert_eq!(
        locals
            .bind(
                &table,
                executor,
                TcbIdentity::new(0x101, 2),
                boxed_probe(0x2000, 0x202)
            )
            .unwrap_err()
            .0,
        ExecutorLocalError::AlreadyBound,
    );

    let run = table.resume(root, ExecutorResume::Unrouted).unwrap();
    let root = table.accept_yield(run, ExecutorYield::Done).unwrap();
    assert!(locals
        .bind(
            &table,
            executor,
            TcbIdentity::new(0x102, 1),
            boxed_probe(0x2000, 0x202)
        )
        .is_err());
    let replacement = table.register(&root).unwrap();
    assert_ne!(executor.generation(), replacement.generation());
    assert!(locals
        .bind(
            &table,
            executor,
            TcbIdentity::new(0x103, 1),
            boxed_probe(0x3000, 0x203)
        )
        .is_err());
    assert_eq!(
        locals.resolve(Some(anchor), tcb, executor).unwrap(),
        &probe(0x1000, 0x201)
    );
}

#[test]
fn retired_tcb_anchor_cannot_resolve_a_reused_executor_slot() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let old = table.register(&root).unwrap();
    let old_tcb = TcbIdentity::new(0x101, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let old_anchor = locals
        .bind(&table, old, old_tcb, boxed_probe(0x1000, 0x201))
        .unwrap();

    // The block remains owned while its executor is live, including while it may be parked.
    assert!(locals.retire(old_anchor, &table, retired(old_tcb)).is_err());
    assert_eq!(
        locals.resolve(Some(old_anchor), old_tcb, old).unwrap(),
        &probe(0x1000, 0x201)
    );

    let run = table.resume(root, ExecutorResume::Unrouted).unwrap();
    let root = table.accept_yield(run, ExecutorYield::Done).unwrap();
    // Done alone cannot release an FS anchor: the exact TCB retirement must also be observed.
    assert_eq!(
        locals.resolve(Some(old_anchor), old_tcb, old).unwrap(),
        &probe(0x1000, 0x201)
    );
    assert!(locals
        .retire(old_anchor, &table, retired(TcbIdentity::new(0x101, 2)),)
        .is_err());
    assert_eq!(
        locals.resolve(Some(old_anchor), old_tcb, old).unwrap(),
        &probe(0x1000, 0x201)
    );
    locals.retire(old_anchor, &table, retired(old_tcb)).unwrap();
    let next = table.register(&root).unwrap();
    assert_eq!(old.index(), next.index());
    assert_ne!(old.generation(), next.generation());
    let next_tcb = TcbIdentity::new(0x101, 2);
    let next_anchor = locals
        .bind(&table, next, next_tcb, boxed_probe(0x3000, 0x203))
        .unwrap();

    assert!(matches!(
        locals.resolve(Some(old_anchor), old_tcb, old),
        Err(ExecutorLocalError::StaleAnchor)
    ));
    assert!(locals.resolve(Some(old_anchor), next_tcb, next).is_err());
    assert_eq!(
        locals.resolve(Some(next_anchor), next_tcb, next).unwrap(),
        &probe(0x3000, 0x203)
    );
}

#[test]
fn late_exact_tcb_retirement_releases_a_binding_after_executor_slot_reuse() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let old = table.register(&root).unwrap();
    let old_tcb = TcbIdentity::new(0x101, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = locals
        .bind(&table, old, old_tcb, boxed_probe(0x1000, 0x201))
        .unwrap();

    let run = table.resume(root, ExecutorResume::Unrouted).unwrap();
    let root = table.accept_yield(run, ExecutorYield::Done).unwrap();
    let replacement = table.register(&root).unwrap();
    assert_eq!(table.state(old), Err(ExecutorError::StaleGeneration));
    assert_eq!(
        locals.resolve(Some(anchor), old_tcb, old).unwrap(),
        &probe(0x1000, 0x201)
    );

    let (foreign_table, _) = ExecutorTable::try_new(1).unwrap();
    assert_eq!(
        locals.retire(anchor, &foreign_table, retired(old_tcb)),
        Err(ExecutorLocalError::Table(ExecutorError::WrongTable)),
    );
    assert_eq!(
        locals.resolve(Some(anchor), old_tcb, old).unwrap(),
        &probe(0x1000, 0x201)
    );
    locals.retire(anchor, &table, retired(old_tcb)).unwrap();
    assert!(matches!(
        locals.resolve(Some(anchor), old_tcb, old),
        Err(ExecutorLocalError::StaleAnchor)
    ));

    let replacement_tcb = TcbIdentity::new(0x101, 2);
    let replacement_anchor = locals
        .bind(
            &table,
            replacement,
            replacement_tcb,
            boxed_probe(0x3000, 0x203),
        )
        .unwrap();
    assert_eq!(
        locals
            .resolve(Some(replacement_anchor), replacement_tcb, replacement)
            .unwrap(),
        &probe(0x3000, 0x203),
    );
}

#[test]
fn losing_the_registry_quarantines_a_payload_still_reachable_by_a_tcb() {
    #[derive(Debug)]
    struct DropProbe(Rc<Cell<u32>>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.set(self.0.get() + 1);
        }
    }

    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let executor = table.register(&root).unwrap();
    let drops = Rc::new(Cell::new(0));
    let mut locals = ExecutorLocalRegistry::new();
    locals
        .bind(
            &table,
            executor,
            TcbIdentity::new(0x101, 1),
            Box::new(DropProbe(drops.clone())),
        )
        .unwrap();
    drop(locals);
    assert_eq!(drops.get(), 0);
}
