//! Host-side contract for selecting one executor's ambient state by its exact TCB anchor.
//! Native FS installation and the executive's concrete state layout stay outside this crate.
//! Calls to unsafe ready registration model a worker whose native bootstrap is already proven;
//! native installation tests use unready registration and an acknowledged FS transaction.

use crate::executor_local::{
    ExecutorLocalError, ExecutorLocalRegistry, PassiveWorkerReadyProof, PhysicalTcbClaim,
    PhysicalWorkerEndpointClaim, TcbIdentity, TcbRetirementObservation,
};
use crate::{
    ExecutorError, ExecutorFaultBinding, ExecutorResume, ExecutorState, ExecutorTable,
    ExecutorYield, RootReplySlotTable,
};
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::sync::Arc;
use core::cell::Cell;
use core::sync::atomic::{AtomicU32, Ordering};

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

// Tests model a native retype owner that keeps this exact cap and slot from being reused.
fn physical(tcb: TcbIdentity, cap: u64) -> PhysicalTcbClaim {
    unsafe { PhysicalTcbClaim::new(tcb, cap).expect("valid physical TCB claim") }
}

#[test]
fn endpoint_claim_accepts_cap_one_and_rejects_only_zero_identity_fields() {
    let tcb = TcbIdentity::new(2, 3);
    let claim = physical(tcb, 1);
    let endpoint = unsafe { PhysicalWorkerEndpointClaim::from_native(&claim, 1, 1).unwrap() };
    assert_eq!(endpoint.tcb(), tcb);
    assert_eq!(endpoint.target_cap(), 1);
    assert_eq!(endpoint.endpoint_cap(), 1);
    assert_eq!(endpoint.endpoint_generation(), 1);
    assert_eq!(
        unsafe { PhysicalWorkerEndpointClaim::from_native(&claim, 0, 1) }.err(),
        Some(ExecutorLocalError::InvalidEndpointIdentity),
    );
    assert_eq!(
        unsafe { PhysicalWorkerEndpointClaim::from_native(&claim, 1, 0) }.err(),
        Some(ExecutorLocalError::InvalidEndpointIdentity),
    );
}

#[test]
fn exact_tcb_anchors_select_distinct_ipc_reply_scheduler_and_transient_state() {
    let (mut table, root) = ExecutorTable::try_new(2).unwrap();
    let first = unsafe { table.register(&root) }.unwrap();
    let second = unsafe { table.register(&root) }.unwrap();
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
    let first = unsafe { table.register(&root) }.unwrap();
    let second = unsafe { table.register(&root) }.unwrap();
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
    let executor = unsafe { table.register(&root) }.unwrap();
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
    let replacement = unsafe { table.register(&root) }.unwrap();
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
    let old = unsafe { table.register(&root) }.unwrap();
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
    let next = unsafe { table.register(&root) }.unwrap();
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
    let old = unsafe { table.register(&root) }.unwrap();
    let old_tcb = TcbIdentity::new(0x101, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = locals
        .bind(&table, old, old_tcb, boxed_probe(0x1000, 0x201))
        .unwrap();

    let run = table.resume(root, ExecutorResume::Unrouted).unwrap();
    let root = table.accept_yield(run, ExecutorYield::Done).unwrap();
    let replacement = unsafe { table.register(&root) }.unwrap();
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
fn definite_no_effect_fs_install_can_unbind_unready_executor_and_return_exact_payload() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let executor = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let payload = boxed_probe(0x1000, 0x201);
    let original_address = &*payload as *const _;
    let anchor = locals.bind(&table, executor, tcb, payload).unwrap();

    // Model a definitive native refusal before FS publication. This worker cannot receive
    // ingress and cannot produce a Done yield merely to free its unpublished binding.
    assert_ne!(table.state(executor), Ok(crate::ExecutorState::Idle));
    let returned = unsafe { locals.abort_unpublished(anchor, &table, tcb) }
        .expect("no-effect FS refusal must return the unpublished payload");
    assert!(core::ptr::eq(original_address, &*returned));
    assert_ne!(table.state(executor), Ok(crate::ExecutorState::Idle));
    assert_eq!(
        locals.resolve(Some(anchor), tcb, executor),
        Err(ExecutorLocalError::StaleAnchor),
    );
    let replacement = locals.bind(&table, executor, tcb, returned).unwrap();
    assert_ne!(replacement, anchor);
    assert!(core::ptr::eq(
        original_address,
        locals.resolve(Some(replacement), tcb, executor).unwrap(),
    ));
}

#[test]
fn fs_install_authority_rejects_a_different_physical_tcb_target() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let executor = unsafe { table.register(&root) }.unwrap();
    let claimed = TcbIdentity::new(0x101, 1);
    let other_slot = TcbIdentity::new(0x102, 1);
    let reused_slot = TcbIdentity::new(0x101, 2);
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = locals
        .bind(&table, executor, claimed, boxed_probe(0x1000, 0x201))
        .unwrap();

    assert_eq!(
        locals.authorize_fs_install(anchor, executor, claimed, claimed),
        Ok(&probe(0x1000, 0x201)),
    );
    // The first identity is what the binding claims; the last is the exact TCB capability
    // about to receive SetTLSBase. Neither a different slot nor a reused incarnation may pass.
    for target in [other_slot, reused_slot] {
        assert_eq!(
            locals.authorize_fs_install(anchor, executor, claimed, target),
            Err(ExecutorLocalError::TcbMismatch),
        );
    }
    assert_eq!(
        locals.resolve(Some(anchor), claimed, executor),
        Ok(&probe(0x1000, 0x201)),
    );
}

#[test]
fn native_bind_refusal_returns_the_exact_payload_and_physical_claim() {
    let (mut table, root) = ExecutorTable::try_new(2).unwrap();
    let idle = unsafe { table.register(&root) }.unwrap();
    let unready = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let payload = boxed_probe(0x1000, 0x201);
    let original_address = &*payload as *const _;
    let mut locals = ExecutorLocalRegistry::new();

    let (error, returned, claim) = locals
        .bind_native(&table, idle, physical(tcb, 0x501), payload)
        .unwrap_err();
    assert_eq!(error, ExecutorLocalError::ExecutorNotIdle);
    assert!(core::ptr::eq(original_address, &*returned));
    assert_eq!(claim.identity(), tcb);

    let anchor = match locals.bind_native(&table, unready, claim, returned) {
        Ok(anchor) => anchor,
        Err(_) => panic!("a refused bind must return reusable owners"),
    };
    let attempt = locals.begin_fs_install(anchor, &table).unwrap();
    assert_eq!(attempt.target_cap(), 0x501);
    assert!(core::ptr::eq(original_address, attempt.base()));
}

#[test]
fn fault_binding_borrows_the_registrys_exact_retained_physical_claim() {
    let (mut table, root) = ExecutorTable::try_new(2).unwrap();
    let worker = table.register_unready(&root).unwrap();
    let other = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 3);
    let other_tcb = TcbIdentity::new(0x102, 3);
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = locals
        .bind_native(&table, worker, physical(tcb, 0x501), boxed_probe(0x1000, 0x201))
        .map_err(|(error, _, _)| error)
        .unwrap();
    let other_anchor = locals
        .bind_native(
            &table,
            other,
            physical(other_tcb, 0x502),
            boxed_probe(0x2000, 0x202),
        )
        .map_err(|(error, _, _)| error)
        .unwrap();

    let attempt = locals.begin_fs_install(anchor, &table).unwrap();
    let fs_ack = unsafe { locals.acknowledge_fs_install(attempt) }.unwrap();
    let ready = unsafe { PassiveWorkerReadyProof::from_checked_unbind(worker, tcb, 0x501) }
        .unwrap();
    table.activate_unready(&root, fs_ack, ready).unwrap();
    let run = table.resume(root, ExecutorResume::Unrouted).unwrap();

    let claim = locals.physical_claim_for(anchor, tcb, worker).unwrap();
    assert_eq!((claim.identity(), claim.target_cap()), (tcb, 0x501));
    assert_eq!(
        locals.physical_claim_for(anchor, TcbIdentity::new(0x101, 2), worker).err(),
        Some(ExecutorLocalError::StaleAnchor),
    );
    assert_eq!(
        locals.physical_claim_for(anchor, tcb, other).err(),
        Some(ExecutorLocalError::StaleAnchor),
    );
    assert_eq!(
        locals.physical_claim_for(other_anchor, tcb, worker).err(),
        Some(ExecutorLocalError::StaleAnchor),
    );
    // A refused lookup never transfers or drops the claim held by the registry.
    let claim = locals.physical_claim_for(anchor, tcb, worker).unwrap();
    let mut root_replies = RootReplySlotTable::new(1).unwrap();
    let mut supervisor_replies = RootReplySlotTable::new(1).unwrap();
    let root_reply = root_replies.insert_used(0x601).unwrap();
    let supervisor_reply = supervisor_replies.insert_used(0x602).unwrap();
    let binding = unsafe {
        ExecutorFaultBinding::from_native(worker, claim, root_reply, supervisor_reply)
    }
    .unwrap();
    table.bind_fault(&run, binding).unwrap();
    assert_eq!(table.state(worker), Ok(ExecutorState::Running));
    assert_eq!(table.state(other), Ok(ExecutorState::Unready));
}

#[test]
fn native_setup_can_return_both_owners_before_fs_install_begins() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let worker = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let payload = boxed_probe(0x1000, 0x201);
    let original_address = &*payload as *const _;
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = locals
        .bind_native(&table, worker, physical(tcb, 0x501), payload)
        .map_err(|(error, _, _)| error)
        .unwrap();

    let (returned, claim) = locals.cancel_unpublished_native(anchor, &table).unwrap();
    assert!(core::ptr::eq(original_address, &*returned));
    assert_eq!(claim.identity(), tcb);
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
    assert_eq!(
        locals.resolve(Some(anchor), tcb, worker),
        Err(ExecutorLocalError::StaleAnchor),
    );
    let rebound = locals
        .bind_native(&table, worker, claim, returned)
        .map_err(|(error, _, _)| error)
        .unwrap();
    assert_ne!(rebound, anchor);
    let attempt = locals.begin_fs_install(rebound, &table).unwrap();
    assert_eq!(attempt.target_cap(), 0x501);
    assert_eq!(
        locals.cancel_unpublished_native(rebound, &table).err(),
        Some(ExecutorLocalError::PublicationAlreadyStarted),
    );
}

#[test]
fn native_fs_install_acknowledgement_is_the_only_path_to_runnable() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let worker = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let payload = boxed_probe(0x1000, 0x201);
    let original_address = &*payload as *const _;
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = match locals.bind_native(&table, worker, physical(tcb, 0x501), payload) {
        Ok(anchor) => anchor,
        Err(_) => panic!("unready worker must accept its physical claim"),
    };

    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
    let attempt = locals.begin_fs_install(anchor, &table).unwrap();
    assert_eq!(attempt.target_cap(), 0x501);
    assert!(core::ptr::eq(original_address, attempt.base()));
    assert_eq!(
        locals.begin_fs_install(anchor, &table).err(),
        Some(ExecutorLocalError::PublicationAlreadyStarted),
    );
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));

    // Model a checked, successful kernel reply for this exact cap, base and FS selector.
    let acknowledged = unsafe { locals.acknowledge_fs_install(attempt) }.unwrap();
    assert_eq!(acknowledged.executor(), worker);
    assert_eq!(acknowledged.tcb(), tcb);
    assert_eq!(acknowledged.target_cap(), 0x501);
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
    let root = match table.resume(root, ExecutorResume::Unrouted) {
        Err((ExecutorError::NoIdleExecutor, root)) => root,
        _ => panic!("FS ACK alone cannot make the worker selectable"),
    };
    let ready = unsafe { PassiveWorkerReadyProof::from_checked_unbind(worker, tcb, 0x501) }
        .unwrap();
    assert!(matches!(
        table.activate_unready(&root, acknowledged, ready),
        Ok(activated) if activated == worker,
    ));
    assert_eq!(table.state(worker), Ok(ExecutorState::Idle));
    assert_eq!(
        table
            .resume(root, ExecutorResume::Unrouted)
            .unwrap()
            .executor(),
        worker
    );
}

#[test]
fn fs_ack_alone_cannot_activate_a_worker_before_checked_passive_unbind() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let worker = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = locals
        .bind_native(&table, worker, physical(tcb, 0x501), boxed_probe(0x1000, 0x201))
        .map_err(|(error, _, _)| error)
        .unwrap();
    let attempt = locals.begin_fs_install(anchor, &table).unwrap();
    let fs_ack = unsafe { locals.acknowledge_fs_install(attempt) }.unwrap();

    // No private receive, offered Reply, or checked bootstrap-SC unbind has been observed.
    // A SetTLSBase reply proves only FS publication; it cannot make this TCB runnable.
    assert_eq!(fs_ack.executor(), worker);
    // The activation API requires a separate checked-unbind proof. Holding only this FS ACK
    // leaves the worker unavailable for root ingress.
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
    assert!(matches!(
        table.resume(root, ExecutorResume::Unrouted),
        Err((ExecutorError::NoIdleExecutor, _))
    ));
}

#[test]
fn mismatched_ready_proofs_return_both_owners_without_publishing() {
    for mismatch in 0..3 {
        let (mut table, root) = ExecutorTable::try_new(2).unwrap();
        let worker = table.register_unready(&root).unwrap();
        let other = table.register_unready(&root).unwrap();
        let tcb = TcbIdentity::new(0x101, 1);
        let mut locals = ExecutorLocalRegistry::new();
        let anchor = locals
            .bind_native(&table, worker, physical(tcb, 0x501), boxed_probe(0x1000, 0x201))
            .map_err(|(error, _, _)| error)
            .unwrap();
        let attempt = locals.begin_fs_install(anchor, &table).unwrap();
        let fs_ack = unsafe { locals.acknowledge_fs_install(attempt) }.unwrap();
        let ready = unsafe {
            PassiveWorkerReadyProof::from_checked_unbind(
                if mismatch == 0 { other } else { worker },
                if mismatch == 1 { TcbIdentity::new(0x101, 2) } else { tcb },
                if mismatch == 2 { 0x502 } else { 0x501 },
            )
        }
        .unwrap();

        let (error, returned_fs, returned_ready) = table
            .activate_unready(&root, fs_ack, ready)
            .expect_err("different physical workers cannot become selectable");
        assert_eq!(error, ExecutorError::WorkerProofMismatch);
        assert_eq!(returned_fs.executor(), worker);
        assert_eq!(returned_fs.tcb(), tcb);
        assert_eq!(returned_fs.target_cap(), 0x501);
        assert_eq!(returned_ready.executor(), if mismatch == 0 { other } else { worker });
        assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
        assert!(matches!(
            table.resume(root, ExecutorResume::Unrouted),
            Err((ExecutorError::NoIdleExecutor, _))
        ));
    }
}

#[test]
fn definitive_no_effect_returns_both_native_owners_without_activation() {
    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let worker = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let payload = boxed_probe(0x1000, 0x201);
    let original_address = &*payload as *const _;
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = match locals.bind_native(&table, worker, physical(tcb, 0x501), payload) {
        Ok(anchor) => anchor,
        Err(_) => panic!("unready worker must accept its physical claim"),
    };
    assert_eq!(
        unsafe { locals.abort_unpublished(anchor, &table, tcb) }.err(),
        Some(ExecutorLocalError::NativeClaimNeedsTransaction),
    );

    let attempt = locals.begin_fs_install(anchor, &table).unwrap();
    // Model a definitive kernel refusal before any FS-base effect.
    let (returned, claim) = unsafe { locals.abort_no_effect(attempt, &table) }.unwrap();
    assert!(core::ptr::eq(original_address, &*returned));
    assert_eq!(claim.identity(), tcb);
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
    assert_eq!(
        locals.resolve(Some(anchor), tcb, worker),
        Err(ExecutorLocalError::StaleAnchor),
    );
    let replacement = match locals.bind_native(&table, worker, claim, returned) {
        Ok(anchor) => anchor,
        Err(_) => panic!("the exact returned owners must remain bindable"),
    };
    assert_ne!(replacement, anchor);
    assert_eq!(
        locals
            .begin_fs_install(replacement, &table)
            .unwrap()
            .target_cap(),
        0x501
    );
}

#[test]
fn dropped_native_attempt_cannot_replay_or_release_before_exact_tcb_teardown() {
    #[derive(Debug)]
    struct DropProbe(Arc<AtomicU32>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let worker = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let drops = Arc::new(AtomicU32::new(0));
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = match locals.bind_native(
        &table,
        worker,
        physical(tcb, 0x501),
        Box::new(DropProbe(drops.clone())),
    ) {
        Ok(anchor) => anchor,
        Err(_) => panic!("unready worker must accept its physical claim"),
    };

    // Dropping an attempt models a missing reply: the kernel may have selected this payload.
    drop(locals.begin_fs_install(anchor, &table).unwrap());
    assert_eq!(
        locals.begin_fs_install(anchor, &table).err(),
        Some(ExecutorLocalError::PublicationAlreadyStarted),
    );
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(
        locals.retire_unready_after_teardown(
            anchor,
            &mut table,
            &root,
            retired(TcbIdentity::new(0x101, 2)),
        ),
        Err(ExecutorLocalError::TcbMismatch),
    );
    assert_eq!(drops.load(Ordering::Relaxed), 0);
    assert_eq!(table.state(worker), Ok(ExecutorState::Unready));

    locals
        .retire_unready_after_teardown(anchor, &mut table, &root, retired(tcb))
        .unwrap();
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(table.state(worker), Ok(ExecutorState::Retired));
    assert_eq!(
        locals.resolve(Some(anchor), tcb, worker).err(),
        Some(ExecutorLocalError::StaleAnchor),
    );
}

#[test]
fn uncertain_fs_install_keeps_the_payload_owned_if_the_registry_is_lost() {
    #[derive(Debug)]
    struct DropProbe(Arc<AtomicU32>);
    impl Drop for DropProbe {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    let (mut table, root) = ExecutorTable::try_new(1).unwrap();
    let executor = table.register_unready(&root).unwrap();
    let tcb = TcbIdentity::new(0x101, 1);
    let drops = Arc::new(AtomicU32::new(0));
    let mut locals = ExecutorLocalRegistry::new();
    let anchor = match locals.bind_native(
        &table,
        executor,
        physical(tcb, 0x501),
        Box::new(DropProbe(drops.clone())),
    ) {
        Ok(anchor) => anchor,
        Err(_) => panic!("unready worker must accept its physical claim"),
    };

    // The exact native target and payload were selected for SetTLSBase, but no reply was
    // observed. Its possible effect cannot be undone by dropping the Rust registry.
    drop(locals.begin_fs_install(anchor, &table).unwrap());
    drop(locals);
    assert_eq!(drops.load(Ordering::Relaxed), 0);
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
    let executor = unsafe { table.register(&root) }.unwrap();
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
