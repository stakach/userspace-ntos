extern crate std;

use super::super::test_support::*;
use super::*;
use crate::mutation_commit::test_support::{client, prepare, PARENT};
use alloc::rc::Rc;
use core::cell::Cell;
use nt_config_abi::hive_mutation_commit_operation as operation;
use std::panic::{catch_unwind, AssertUnwindSafe};

#[test]
fn first_journal_cancellation_removes_file_durably_before_abort_and_ack() {
    for persist in [false, true] {
        for barrier in 1..=3 {
            let mut client = client(1);
            let prepared = prepare(&mut client, 1, "Child");
            let (mut fs, mut dev, controls) = disk_without_log();
            let drops = Rc::new(Cell::new(0));
            let mut work = match Work::create(
                &mut client,
                &mut fs,
                &mut dev,
                SnapshotBlockStore::new(0, 64),
                LOG,
                prepared,
                Caller {
                    drops: drops.clone(),
                    publications: 0,
                },
            ) {
                Ok(work) => work,
                Err(_) => panic!("creation admission failed"),
            };
            controls
                .fail_flush
                .set(Some(controls.flushes.get() + barrier));
            controls.persist_before_error.set(persist);
            assert!(work.make_durable().is_err());
            assert!(work.commit().is_err());
            let calls = work.client.backend.calls;
            controls
                .fail_flush
                .set(Some(controls.flushes.get() + barrier));
            assert!(work.rollback_storage().is_err());
            assert!(work.abort().is_err());
            assert!(work.make_durable().is_err());
            assert!(work.take_cancelled().is_none());
            assert_eq!(work.client.backend.calls, calls);
            assert_eq!(drops.get(), 0);
            controls.fail_flush.set(None);
            work.rollback_storage().unwrap();
            let writes = controls.writes.get();
            work.client.backend.corrupt = Some((operation::ABORT, 0));
            assert!(work.abort().is_err());
            assert!(work.take_cancelled().is_none());
            work.abort().unwrap();
            work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, 0));
            assert!(work.acknowledge_abort().is_err());
            assert!(work.take_cancelled().is_none());
            work.acknowledge_abort().unwrap();
            assert_eq!(controls.writes.get(), writes);
            assert!(work.take_completion().is_none());
            let caller = work.take_cancelled().unwrap();
            assert_eq!(caller.publications, 0);
            assert!(work.take_cancelled().is_none());
            drop(work);
            dev.cache.copy_from_slice(&dev.stable);
            let (restored, _, _) = FileSystem::restore_volume_snapshot_from_store(
                &SnapshotBlockStore::new(0, 64),
                &mut dev,
            )
            .unwrap()
            .unwrap();
            assert_eq!(restored.try_file_len(LOG), Ok(None));
            let hive = nt_hive_core::decode_image(
                &restored.try_file_bytes_owned(PRIMARY).unwrap().unwrap(),
            )
            .unwrap();
            assert!(hive.open_key(r"ControlSet001\Services\Child").is_none());
            assert!(client
                .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
                .is_err());
            assert_eq!(drops.get(), 0);
            drop(caller);
            assert_eq!(drops.get(), 1);
        }
    }
}

fn recovered_without_mutation(dev: &mut Disk) {
    dev.cache.copy_from_slice(&dev.stable);
    let (fs, _, _) =
        FileSystem::restore_volume_snapshot_from_store(&SnapshotBlockStore::new(0, 64), dev)
            .unwrap()
            .unwrap();
    assert!(fs.try_file_bytes_owned(LOG).unwrap().unwrap().is_empty());
    let primary = fs.try_file_bytes_owned(PRIMARY).unwrap().unwrap();
    let hive = nt_hive_core::decode_image(&primary).unwrap();
    assert!(hive.open_key(r"ControlSet001\Services\Child").is_none());
}

#[test]
fn cancellation_requires_durable_rollback_and_ack_before_releasing_caller() {
    for stage in 0..=4 {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Child");
        let (mut fs, mut dev, controls) = disk();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
        assert!(work.abort().is_err());
        assert!(work.acknowledge_abort().is_err());
        assert!(work.take_cancelled().is_none());
        if stage == 1 {
            work.make_durable().unwrap();
        } else if stage > 1 {
            controls
                .fail_flush
                .set(Some(controls.flushes.get() + stage - 1));
            assert!(work.make_durable().is_err());
            assert_eq!(
                work.phase(),
                SnapshotSystemHivePublicationPhase::StoragePending
            );
            controls.fail_flush.set(None);
        }
        work.rollback_storage().unwrap();
        assert!(work.make_durable().is_err());
        assert!(work.commit().is_err());
        assert!(work.take_cancelled().is_none());
        work.abort().unwrap();
        assert!(work.take_cancelled().is_none());
        assert!(work.take_completion().is_none());
        work.acknowledge_abort().unwrap();
        assert_eq!(work.phase(), SnapshotSystemHivePublicationPhase::Cancelled);
        assert!(work.take_completion().is_none());
        assert_eq!(drops.get(), 0);
        let caller = work.take_cancelled().unwrap();
        assert_eq!(caller.publications, 0);
        assert!(work.take_cancelled().is_none());
        assert!(work.take_completion().is_none());
        drop(work);
        recovered_without_mutation(&mut dev);
        assert!(client
            .query_system_hive_key(&alloc::format!("{PARENT}\\Child"))
            .is_err());
        let next = prepare(&mut client, 1, "Next");
        let receipt = client
            .abort_prepared_system_hive_mutation_retained(&next)
            .unwrap();
        let _ = client
            .acknowledge_system_hive_mutation_abort(receipt)
            .unwrap();
        drop(caller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn failed_rollback_and_lost_abort_replies_retain_exact_cleanup() {
    for persist in [false, true] {
        for barrier in 1..=3 {
            let mut client = client(1);
            let prepared = prepare(&mut client, 1, "Child");
            let (mut fs, mut dev, controls) = disk();
            let drops = Rc::new(Cell::new(0));
            let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
            work.make_durable().unwrap();
            let calls = work.client.backend.calls;
            controls.persist_before_error.set(persist);
            for offset in [barrier, 1] {
                controls
                    .fail_flush
                    .set(Some(controls.flushes.get() + offset));
                assert!(work.rollback_storage().is_err());
                assert_eq!(
                    work.phase(),
                    SnapshotSystemHivePublicationPhase::RollbackRetry
                );
                assert!(work.abort().is_err());
                assert!(work.make_durable().is_err());
                assert!(work.commit().is_err());
                assert!(work.take_cancelled().is_none());
                assert_eq!(work.client.backend.calls, calls);
                assert_eq!(drops.get(), 0);
            }
            controls.fail_flush.set(None);
            work.rollback_storage().unwrap();
            let writes = controls.writes.get();
            let flushes = controls.flushes.get();
            for corruption in (0..=14).chain(core::iter::once(18)) {
                work.client.backend.corrupt = Some((operation::ABORT, corruption));
                assert!(work.abort().is_err());
                assert_eq!(work.phase(), SnapshotSystemHivePublicationPhase::AbortRetry);
                assert!(work.rollback_storage().is_err());
                assert!(work.acknowledge_abort().is_err());
                assert!(work.take_cancelled().is_none());
            }
            work.abort().unwrap();
            for corruption in 0..=16 {
                work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, corruption));
                assert!(work.acknowledge_abort().is_err());
                assert_eq!(
                    work.phase(),
                    SnapshotSystemHivePublicationPhase::AbortAcknowledgeRetry
                );
                assert!(work.abort().is_err());
                assert!(work.take_cancelled().is_none());
            }
            work.acknowledge_abort().unwrap();
            assert_eq!(controls.writes.get(), writes);
            assert_eq!(controls.flushes.get(), flushes);
            assert_eq!(drops.get(), 0);
            let caller = work.take_cancelled().unwrap();
            assert_eq!(caller.publications, 0);
            drop(work);
            recovered_without_mutation(&mut dev);
            drop(caller);
            assert_eq!(drops.get(), 1);
        }
    }
}

#[test]
fn cancellation_unwinds_remain_inflight_without_repeating_effects() {
    use SnapshotSystemHivePublicationPhase::*;
    for phase in [RollbackInFlight, AbortInFlight, AbortAcknowledgeInFlight] {
        let mut client = client(1);
        let prepared = prepare(&mut client, 1, "Child");
        let (mut fs, mut dev, controls) = disk();
        let drops = Rc::new(Cell::new(0));
        let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
        work.make_durable().unwrap();
        let result = catch_unwind(AssertUnwindSafe(|| {
            if phase == RollbackInFlight {
                controls.panic_flush.set(true);
            }
            work.rollback_storage().unwrap();
            if phase == AbortInFlight {
                work.client.backend.corrupt = Some((operation::ABORT, 17));
            }
            work.abort().unwrap();
            work.client.backend.corrupt = Some((operation::ACKNOWLEDGE, 17));
            work.acknowledge_abort().unwrap();
        }));
        assert!(result.is_err());
        assert_eq!(work.phase(), phase);
        let calls = work.client.backend.calls;
        let writes = controls.writes.get();
        assert!(work.rollback_storage().is_err());
        assert!(work.abort().is_err());
        assert!(work.acknowledge_abort().is_err());
        assert!(work.make_durable().is_err());
        assert!(work.commit().is_err());
        assert!(work
            .publish_local(|_, _| panic!("unexpected publication"))
            .is_err());
        assert!(work.acknowledge().is_err());
        assert!(work.take_completion().is_none());
        assert!(work.take_cancelled().is_none());
        assert_eq!(work.client.backend.calls, calls);
        assert_eq!(controls.writes.get(), writes);
        assert_eq!(drops.get(), 0);
    }
}

#[test]
fn failed_commit_permanently_forbids_cancellation_even_after_lost_reply() {
    let mut client = client(1);
    let prepared = prepare(&mut client, 1, "Child");
    let expected = prepared.durable_journal().to_vec();
    let (mut fs, mut dev, controls) = disk();
    let drops = Rc::new(Cell::new(0));
    let mut work = open(&mut client, &mut fs, &mut dev, prepared, &drops);
    work.make_durable().unwrap();
    work.client.backend.corrupt = Some((operation::COMMIT, 0));
    assert!(work.commit().is_err());
    let writes = controls.writes.get();
    for stage in 0..5 {
        let calls = work.client.backend.calls;
        assert!(work.rollback_storage().is_err());
        assert!(work.abort().is_err());
        assert!(work.acknowledge_abort().is_err());
        assert!(work.take_cancelled().is_none());
        assert_eq!(work.client.backend.calls, calls);
        assert_eq!(controls.writes.get(), writes);
        match stage {
            0 => work.commit().unwrap(),
            1 => publish(&mut work),
            2 => work.acknowledge().unwrap(),
            3 => {
                drop(work.take_completion().unwrap());
            }
            _ => {}
        }
    }
    drop(work);
    recovered(&mut dev, &expected);
    assert_eq!(drops.get(), 1);
}
