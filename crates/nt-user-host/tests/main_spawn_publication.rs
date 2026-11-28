//! Main-thread construction must retain physical inventory across native publication refusals.
//! The executive supplies the actual TCB/SC and VSpace owners; this model only governs transfer.

use nt_types::{ProcessGeneration, ProcessIdentity};
use nt_user_host::main_spawn_publication::{
    MainSpawnPublication, PublicationEffect, PublicationPhase,
};
use nt_user_host::thread_physical_placement::PlacementIdentity;
use std::cell::Cell;
use std::rc::Rc;

#[derive(Debug)]
struct Resource {
    drops: Rc<Cell<u32>>,
    marker: u32,
}

impl Resource {
    fn new() -> (Self, Rc<Cell<u32>>) {
        let drops = Rc::new(Cell::new(0));
        (Self { drops: drops.clone(), marker: 0 }, drops)
    }
}

impl Drop for Resource {
    fn drop(&mut self) {
        self.drops.set(self.drops.get() + 1);
    }
}

fn identity(generation: u64, tcb: u64, sc: u64) -> PlacementIdentity {
    PlacementIdentity {
        process: ProcessIdentity {
            pid: 71,
            generation: ProcessGeneration::Hosted(generation),
        },
        tid: 901,
        tcb,
        sched_context: sc,
    }
}

#[test]
fn definite_vspace_refusal_retains_both_original_owners_for_exact_retry() {
    let key = identity(8, 120, 220);
    let wrong_generation = identity(9, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, vspace_drops) = Resource::new();
    let mut rows = vec![MainSpawnPublication::new(key, mechanism, vspace).unwrap()];

    assert!(rows[0].begin_vspace(wrong_generation).is_err());
    let first = rows[0].begin_vspace(key).unwrap();
    assert!(rows[0].begin_vspace(key).is_err());
    assert!(rows[0].begin_runtime(key).is_err());
    assert!(rows[0].settle_vspace(first, PublicationEffect::NoEffect).unwrap().is_none());
    assert_eq!(rows[0].phase(), PublicationPhase::Constructed);
    assert_eq!(mechanism_drops.get(), 0);
    assert_eq!(vspace_drops.get(), 0);

    // The retained actor may move; no refusal can turn the exact physical owners into copies.
    for generation in 10..40 {
        let (other_mechanism, _) = Resource::new();
        let (other_vspace, _) = Resource::new();
        rows.push(MainSpawnPublication::new(
            identity(generation, 120, 220), other_mechanism, other_vspace,
        ).unwrap());
    }
    let second = rows[0].begin_vspace(key).unwrap();
    assert_ne!(first, second);
    let published_vspace = rows[0]
        .settle_vspace(second, PublicationEffect::Applied)
        .unwrap()
        .expect("one exact VSpace owner transfers after an acknowledged publication");
    assert_eq!(rows[0].phase(), PublicationPhase::VspacePublished);
    assert_eq!(mechanism_drops.get(), 0);
    assert_eq!(vspace_drops.get(), 0);
    drop(published_vspace);
    assert_eq!(vspace_drops.get(), 1);
}

#[test]
fn peb_refusal_after_vspace_transfer_keeps_the_unregistered_tcb_and_sc() {
    let key = identity(8, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, vspace_drops) = Resource::new();
    let mut owner = MainSpawnPublication::new(key, mechanism, vspace).unwrap();
    let attempt = owner.begin_vspace(key).unwrap();
    let published_vspace = owner
        .settle_vspace(attempt, PublicationEffect::Applied)
        .unwrap()
        .unwrap();

    assert!(owner.record_peb(identity(8, 121, 220)).is_err());
    assert!(owner.record_peb(identity(8, 120, 221)).is_err());
    assert_eq!(owner.phase(), PublicationPhase::VspacePublished);
    assert!(owner.begin_runtime(key).is_err());
    assert_eq!(mechanism_drops.get(), 0);
    assert_eq!(vspace_drops.get(), 0);
    owner.record_peb(key).unwrap();
    assert_eq!(owner.phase(), PublicationPhase::PebPublished);
    drop(published_vspace);
    assert_eq!(vspace_drops.get(), 1);
    assert_eq!(mechanism_drops.get(), 0);
}

#[test]
fn runtime_publication_transfers_only_the_exact_mechanism_after_checked_peb() {
    let key = identity(8, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, _) = Resource::new();
    let mut owner = MainSpawnPublication::new(key, mechanism, vspace).unwrap();
    let vspace_attempt = owner.begin_vspace(key).unwrap();
    let _published_vspace = owner
        .settle_vspace(vspace_attempt, PublicationEffect::Applied)
        .unwrap()
        .unwrap();
    owner.record_peb(key).unwrap();

    let first = owner.begin_runtime(key).unwrap();
    assert!(owner.begin_runtime(key).is_err());
    assert!(owner.settle_runtime(first, PublicationEffect::NoEffect).unwrap().is_none());
    assert_eq!(owner.phase(), PublicationPhase::PebPublished);
    assert_eq!(mechanism_drops.get(), 0);
    let second = owner.begin_runtime(key).unwrap();
    assert_ne!(first, second);
    let published_mechanism = owner
        .settle_runtime(second, PublicationEffect::Applied)
        .unwrap()
        .expect("the exact TCB/SC owner transfers only after checked runtime publication");
    assert_eq!(owner.phase(), PublicationPhase::RuntimePublished);
    assert!(owner.begin_runtime(key).is_err());
    assert_eq!(mechanism_drops.get(), 0);
    drop(published_mechanism);
    assert_eq!(mechanism_drops.get(), 1);
}

#[test]
fn uncertain_native_effect_retains_the_original_owner_without_replay() {
    let key = identity(8, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, vspace_drops) = Resource::new();
    let mut owner = MainSpawnPublication::new(key, mechanism, vspace).unwrap();
    let attempt = owner.begin_vspace(key).unwrap();
    assert!(owner
        .settle_vspace(attempt, PublicationEffect::Uncertain)
        .unwrap()
        .is_none());
    assert_eq!(owner.phase(), PublicationPhase::VspaceUncertain);
    assert!(owner.begin_vspace(key).is_err());
    assert!(owner.begin_runtime(key).is_err());
    assert_eq!(mechanism_drops.get(), 0);
    assert_eq!(vspace_drops.get(), 0);
}

#[test]
fn uncertain_vspace_needs_exact_verified_reconciliation_before_retry() {
    let key = identity(8, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, vspace_drops) = Resource::new();
    let mut owner = MainSpawnPublication::new(key, mechanism, vspace).unwrap();
    assert!(owner.mechanism().is_some() && owner.vspace().is_some());
    let attempt = owner.begin_vspace(key).unwrap();
    assert!(owner.mechanism().is_some() && owner.vspace().is_some());
    owner.settle_vspace(attempt, PublicationEffect::Uncertain).unwrap();
    let (other_mechanism, _) = Resource::new();
    let (other_vspace, _) = Resource::new();
    let mut other = MainSpawnPublication::new(key, other_mechanism, other_vspace).unwrap();
    let wrong = other.begin_vspace(key).unwrap();
    assert!(owner.reconcile_vspace(wrong, PublicationEffect::Applied).is_err());
    assert!(owner.reconcile_vspace(attempt, PublicationEffect::Uncertain).is_err());
    assert_eq!(owner.phase(), PublicationPhase::VspaceUncertain);
    assert!(owner.mechanism().is_some() && owner.vspace().is_some());
    assert_eq!(mechanism_drops.get(), 0);
    assert_eq!(vspace_drops.get(), 0);

    assert!(owner.reconcile_vspace(attempt, PublicationEffect::NoEffect).unwrap().is_none());
    assert_eq!(owner.phase(), PublicationPhase::Constructed);
    assert!(owner.reconcile_vspace(attempt, PublicationEffect::Applied).is_err());
    let retry = owner.begin_vspace(key).unwrap();
    assert_ne!(attempt, retry);
    let published = owner.settle_vspace(retry, PublicationEffect::Applied).unwrap().unwrap();
    assert!(owner.vspace().is_none());
    assert!(owner.mechanism().is_some());
    drop(published);
    assert_eq!(vspace_drops.get(), 1);
    assert_eq!(mechanism_drops.get(), 0);
}

#[test]
fn uncertain_runtime_transfers_only_after_exact_verified_application() {
    let key = identity(8, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, _) = Resource::new();
    let mut owner = MainSpawnPublication::new(key, mechanism, vspace).unwrap();
    let vspace_attempt = owner.begin_vspace(key).unwrap();
    let _published_vspace = owner
        .settle_vspace(vspace_attempt, PublicationEffect::Applied)
        .unwrap()
        .unwrap();
    owner.record_peb(key).unwrap();
    let runtime_attempt = owner.begin_runtime(key).unwrap();
    owner.settle_runtime(runtime_attempt, PublicationEffect::Uncertain).unwrap();
    assert_eq!(owner.phase(), PublicationPhase::RuntimeUncertain);
    assert!(owner.mechanism().is_some());
    assert!(owner.vspace().is_none());
    assert!(owner.reconcile_runtime(vspace_attempt, PublicationEffect::Applied).is_err());
    assert!(owner.reconcile_runtime(runtime_attempt, PublicationEffect::Uncertain).is_err());
    assert!(owner.begin_runtime(key).is_err());
    assert_eq!(mechanism_drops.get(), 0);

    let published = owner
        .reconcile_runtime(runtime_attempt, PublicationEffect::Applied)
        .unwrap()
        .unwrap();
    assert_eq!(owner.phase(), PublicationPhase::RuntimePublished);
    assert!(owner.mechanism().is_none());
    assert!(owner.reconcile_runtime(runtime_attempt, PublicationEffect::Applied).is_err());
    drop(published);
    assert_eq!(mechanism_drops.get(), 1);
}

#[test]
fn mutable_mechanism_loan_is_limited_to_the_recorded_runtime_attempt() {
    let key = identity(8, 120, 220);
    let (mechanism, mechanism_drops) = Resource::new();
    let (vspace, _) = Resource::new();
    let mut owner = MainSpawnPublication::new(key, mechanism, vspace).unwrap();
    assert!(owner.mechanism_mut().is_none());
    let vspace_attempt = owner.begin_vspace(key).unwrap();
    assert!(owner.mechanism_mut().is_none());
    let _published_vspace = owner
        .settle_vspace(vspace_attempt, PublicationEffect::Applied)
        .unwrap()
        .unwrap();
    assert!(owner.mechanism_mut().is_none());
    owner.record_peb(key).unwrap();
    assert!(owner.mechanism_mut().is_none());

    let runtime_attempt = owner.begin_runtime(key).unwrap();
    let original = owner.mechanism().unwrap() as *const Resource;
    let borrowed = owner.mechanism_mut().unwrap();
    assert!(std::ptr::eq(borrowed as *const Resource, original));
    borrowed.marker = 41;
    owner.settle_runtime(runtime_attempt, PublicationEffect::Uncertain).unwrap();
    assert!(owner.mechanism_mut().is_none());
    assert_eq!(owner.mechanism().unwrap().marker, 41);
    assert_eq!(mechanism_drops.get(), 0);

    owner.reconcile_runtime(runtime_attempt, PublicationEffect::NoEffect).unwrap();
    assert!(owner.mechanism_mut().is_none());
    let retry = owner.begin_runtime(key).unwrap();
    assert_ne!(retry, runtime_attempt);
    owner.mechanism_mut().unwrap().marker = 42;
    let published = owner.settle_runtime(retry, PublicationEffect::Applied).unwrap().unwrap();
    assert_eq!(published.marker, 42);
    assert!(owner.mechanism_mut().is_none());
    assert_eq!(mechanism_drops.get(), 0);
    drop(published);
    assert_eq!(mechanism_drops.get(), 1);
}
