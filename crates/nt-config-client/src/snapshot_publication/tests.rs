extern crate std;

use super::test_support::*;
use super::*;
use crate::mutation_commit::test_support::{client, prepare, PARENT};
use alloc::rc::Rc;
use core::cell::Cell;
use nt_config_abi::hive_mutation_commit_operation as operation;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn retained_begin_upload_and_durable_publication_preserve_one_caller() {
    use crate::{
        CmMutationBeginAttempts, CmMutationBeginOperation as Begin,
        CmMutationPreparationOperation as Op, CmMutationPreparationPhase as Phase,
        SystemHiveMutation,
    };
    let mut client = client(1);
    let mut attempts = CmMutationBeginAttempts::with_slot_limit(1).unwrap();
    let drops = Rc::new(Cell::new(0));
    let mut attempt = match attempts.reserve(
        1,
        &[SystemHiveMutation::CreateKey {
            path: &alloc::format!("{PARENT}\\Child"),
        }],
        Caller {
            drops: drops.clone(),
            publications: 0,
        },
    ) {
        Ok(attempt) => attempt,
        Err(_) => panic!("caller admission failed"),
    };
    for op in [Begin::Query, Begin::Begin, Begin::Acknowledge] {
        let mut ticket = attempts.begin_exchange(&mut attempt, op).unwrap();
        let response = client.exchange_system_hive_mutation_begin(&ticket);
        attempts
            .complete_exchange(&mut attempt, &mut ticket, response)
            .unwrap();
    }
    let mut preparing = attempts
        .take_upload(&mut attempt)
        .unwrap()
        .into_preparation();
    while preparing.phase() != Phase::Prepared {
        let op = match preparing.phase() {
            Phase::Appending => Op::Append,
            Phase::Preparing => Op::Prepare,
            Phase::Allocating => {
                preparing.allocate_journal().unwrap();
                continue;
            }
            Phase::Pulling => Op::Pull,
            _ => panic!("unexpected preparation state"),
        };
        let mut ticket = preparing.begin_exchange(op).unwrap();
        let response = client.exchange_system_hive_mutation_preparation(&ticket);
        preparing.complete_exchange(&mut ticket, response).unwrap();
    }
    let (prepared, caller) = preparing.take_prepared().unwrap();
    assert_eq!(preparing.phase(), Phase::Taken);
    assert!(preparing.begin_exchange(Op::Cancel).is_err());
    assert_eq!(drops.get(), 0);
    let expected = prepared.durable_journal().to_vec();
    let (mut fs, mut dev, _) = disk();
    let mut work = match Work::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        prepared,
        caller,
    ) {
        Ok(work) => work,
        Err(_) => panic!("storage admission failed"),
    };
    work.make_durable().unwrap();
    work.commit().unwrap();
    publish(&mut work);
    work.acknowledge().unwrap();
    let (caller, generation) = work.take_completion().unwrap();
    assert_eq!(generation, 2);
    assert_eq!(caller.publications, 1);
    assert_eq!(drops.get(), 0);
    drop(work);
    recovered(&mut dev, &expected);
    assert!(client
        .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
        .is_ok());
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn repeated_storage_failure_blocks_commit_until_real_durability() {
    for (persist, barrier) in [false, true]
        .into_iter()
        .flat_map(|persist| (1..=3).map(move |barrier| (persist, barrier)))
    {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Child");
        let expected = prepared.durable_journal().to_vec();
        let before = client.backend.calls;
        let (mut fs, mut dev, controls) = disk();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
        controls.persist_before_error.set(persist);
        for attempt in 0..2 {
            let offset = if attempt == 0 { barrier } else { 1 };
            controls
                .fail_flush
                .set(Some(controls.flushes.get() + offset));
            assert!(work.make_durable().is_err());
            assert_eq!(
                work.phase(),
                SnapshotSystemHivePublicationPhase::StoragePending
            );
            assert_eq!(
                work.commit(),
                Err(SnapshotSystemHivePublicationError::InvalidPhase)
            );
            assert_eq!(work.client.backend.calls, before);
            assert_eq!(drops.get(), 0);
            assert!(work.take_completion().is_none());
        }
        controls.fail_flush.set(None);
        work.make_durable().unwrap();
        work.commit().unwrap();
        publish(&mut work);
        work.acknowledge().unwrap();
        let (caller, generation) = work.take_completion().unwrap();
        assert_eq!(caller.publications, 1);
        assert_eq!(generation, 2);
        assert!(work.take_completion().is_none());
        drop(work);
        recovered(&mut dev, &expected);
        drop(caller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn lost_and_malformed_replies_never_repeat_local_publication_or_storage() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let expected = prepared.durable_journal().to_vec();
    let (mut fs, mut dev, controls) = disk();
    let drops = Rc::new(Cell::new(0));
    let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
    work.make_durable().unwrap();
    let writes = controls.writes.get();
    let flushes = controls.flushes.get();
    for corruption in 0..=14 {
        work.client.backend.corrupt = Some((operation::COMMIT, corruption));
        assert!(matches!(
            work.commit(),
            Err(SnapshotSystemHivePublicationError::Protocol(_))
        ));
        assert_eq!(
            work.phase(),
            SnapshotSystemHivePublicationPhase::CommitRetry
        );
        assert_eq!(work.continuation().unwrap().publications, 0);
        assert_eq!(
            work.acknowledge(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert!(work.take_completion().is_none());
        assert_eq!(drops.get(), 0);
    }
    work.commit().unwrap();
    assert_eq!(
        work.acknowledge(),
        Err(SnapshotSystemHivePublicationError::InvalidPhase)
    );
    publish(&mut work);
    for corruption in 0..=16 {
        work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, corruption));
        assert!(matches!(
            work.acknowledge(),
            Err(SnapshotSystemHivePublicationError::Protocol(_))
        ));
        assert_eq!(
            work.phase(),
            SnapshotSystemHivePublicationPhase::AcknowledgeRetry
        );
        assert_eq!(
            work.publish_local(|_, _| panic!("repeated local effect")),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.commit(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert!(work.take_completion().is_none());
    }
    work.acknowledge().unwrap();
    assert_eq!(controls.writes.get(), writes);
    assert_eq!(controls.flushes.get(), flushes);
    let (caller, generation) = work.take_completion().unwrap();
    assert_eq!(caller.publications, 1);
    assert_eq!(generation, 2);
    assert!(work.take_completion().is_none());
    drop(work);
    assert!(client
        .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
        .is_ok());
    recovered(&mut dev, &expected);
    drop(caller);
    assert_eq!(drops.get(), 1);
}

#[test]
fn storage_commit_local_and_ack_unwinds_stay_inflight_without_implicit_retry() {
    use SnapshotSystemHivePublicationPhase::*;
    for expected_phase in [
        StorageInFlight,
        CommitInFlight,
        LocalInFlight,
        AcknowledgeInFlight,
    ] {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Child");
        let (mut fs, mut dev, controls) = disk();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
        let result = catch_unwind(AssertUnwindSafe(|| {
            if expected_phase == StorageInFlight {
                controls.panic_flush.set(true);
            }
            work.make_durable().unwrap();
            if expected_phase == CommitInFlight {
                work.client.backend.corrupt = Some((operation::COMMIT, 17));
            }
            work.commit().unwrap();
            work.publish_local(|caller, outcome| {
                caller.publications += 1;
                assert_ne!(
                    expected_phase, LocalInFlight,
                    "injected partial local effect"
                );
                outcome.generation
            })
            .unwrap();
            work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, 17));
            work.acknowledge().unwrap();
        }));
        assert!(result.is_err());
        assert_eq!(work.phase(), expected_phase);
        let calls = work.client.backend.calls;
        let writes = controls.writes.get();
        assert_eq!(
            work.make_durable(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.commit(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.publish_local(|_, _| panic!("second invocation")),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert_eq!(
            work.acknowledge(),
            Err(SnapshotSystemHivePublicationError::InvalidPhase)
        );
        assert!(work.take_completion().is_none());
        assert_eq!(work.client.backend.calls, calls);
        assert_eq!(controls.writes.get(), writes);
        assert_eq!(drops.get(), 0);
        assert_eq!(
            work.continuation().unwrap().publications,
            usize::from(matches!(
                expected_phase,
                LocalInFlight | AcknowledgeInFlight
            ))
        );
    }
}

#[test]
fn failed_admission_returns_original_preparation_and_caller_without_copying_journal() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let address = prepared.durable_journal().as_ptr();
    let expected = prepared.durable_journal().to_vec();
    let before = client.backend.calls;
    let (mut fs, mut dev, controls) = disk();
    let drops = Rc::new(Cell::new(0));
    let error = match Work::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        r"\??\C:\Config\Missing.LOG",
        prepared,
        Caller {
            drops: drops.clone(),
            publications: 0,
        },
    ) {
        Err(error) => error,
        Ok(_) => panic!("missing log accepted"),
    };
    assert_eq!(error.prepared.durable_journal().as_ptr(), address);
    assert_eq!(error.prepared.durable_journal(), expected);
    assert_eq!(client.backend.calls, before);
    assert_eq!(drops.get(), 0);
    let mut work = Work::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        error.prepared,
        error.continuation,
    )
    .ok()
    .unwrap();
    let writes = controls.writes.get();
    assert_eq!(
        work.acknowledge(),
        Err(SnapshotSystemHivePublicationError::InvalidPhase)
    );
    assert_eq!(
        work.publish_local(|_, _| panic!("early local effect")),
        Err(SnapshotSystemHivePublicationError::InvalidPhase)
    );
    assert_eq!(controls.writes.get(), writes);
    work.make_durable().unwrap();
    work.commit().unwrap();
    publish(&mut work);
    work.acknowledge().unwrap();
    let completion = work.take_completion().unwrap();
    drop(work);
    drop(completion);
    assert_eq!(drops.get(), 1);
}

#[test]
fn local_result_and_caller_survive_lost_ack_until_one_completion() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let (mut fs, mut dev, _) = disk();
    let caller_drops = Rc::new(Cell::new(0));
    let result_drops = Rc::new(Cell::new(0));
    let mut work = SnapshotSystemHivePublication::open(
        &mut client,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        prepared,
        Caller {
            drops: caller_drops.clone(),
            publications: 0,
        },
    )
    .ok()
    .unwrap();
    work.make_durable().unwrap();
    work.commit().unwrap();
    work.publish_local(|caller, _| {
        caller.publications += 1;
        Caller {
            drops: result_drops.clone(),
            publications: 0,
        }
    })
    .unwrap();
    work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, 0));
    assert!(work.acknowledge().is_err());
    assert!(work.take_completion().is_none());
    assert_eq!(caller_drops.get(), 0);
    assert_eq!(result_drops.get(), 0);
    work.acknowledge().unwrap();
    let completion = work.take_completion().unwrap();
    assert!(work.take_completion().is_none());
    drop(work);
    assert_eq!(caller_drops.get(), 0);
    assert_eq!(result_drops.get(), 0);
    drop(completion);
    assert_eq!(caller_drops.get(), 1);
    assert_eq!(result_drops.get(), 1);
}
