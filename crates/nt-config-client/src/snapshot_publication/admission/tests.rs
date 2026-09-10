use super::*;
use crate::mutation_commit::test_support::{client, prepare, Direct};
use crate::snapshot_publication::test_support::{
    checked, disk, disk_without_log, Caller, Disk, LOG,
};
use crate::{SnapshotSystemHivePublication, SnapshotSystemHivePublicationOpenError};
use alloc::rc::Rc;
use core::cell::Cell;
use nt_config_abi::CmReply;
use nt_fs::{FileSystem, SnapshotBlockStore};

fn rejected<B: Backend>(
    client: &mut ConfigClient<B>,
    fs: &mut FileSystem,
    dev: &mut Disk,
    prepared: PreparedSystemHiveMutation,
    drops: &Rc<Cell<usize>>,
    create: bool,
) -> SnapshotSystemHivePublicationOpenError<Caller> {
    let before = fs.export_volume_snapshot().unwrap();
    let stable = dev.stable.clone();
    let cache = dev.cache.clone();
    let counts = (
        dev.controls.reads.get(),
        dev.controls.writes.get(),
        dev.controls.flushes.get(),
    );
    let address = prepared.durable_journal().as_ptr();
    let bytes = prepared.durable_journal().to_vec();
    let mount = prepared.mount();
    let caller = Caller {
        drops: drops.clone(),
        publications: 0,
    };
    assert_eq!(fs.try_file_len(LOG).unwrap().is_none(), create);
    let mut admission = SystemHiveStorageAdmission::new(client, prepared, caller);
    assert!(admission.take_validated().is_none());
    let status = admission.validate().unwrap_err() as u32;
    assert_eq!(admission.phase(), SystemHiveStorageAdmissionPhase::Pending);
    assert!(admission.take_validated().is_none());
    let (prepared, continuation) = admission.release_before_storage().unwrap();
    assert!(admission.release_before_storage().is_none());
    let error = SnapshotSystemHivePublicationOpenError {
        status,
        prepared,
        continuation,
    };
    assert_eq!(error.prepared.mount(), mount);
    assert_eq!(error.prepared.durable_journal().as_ptr(), address);
    assert_eq!(error.prepared.durable_journal(), bytes);
    assert_eq!(drops.get(), 0);
    assert_eq!(error.continuation.publications, 0);
    assert_eq!(fs.export_volume_snapshot().unwrap(), before);
    assert_eq!(dev.stable, stable);
    assert_eq!(dev.cache, cache);
    assert_eq!(
        (
            dev.controls.reads.get(),
            dev.controls.writes.get(),
            dev.controls.flushes.get()
        ),
        counts
    );
    error
}

#[test]
fn foreign_client_rejection_precedes_existing_and_first_journal_admission() {
    for create in [false, true] {
        let mut issuer = client(701);
        let mut foreign = client(702);
        let prepared = prepare(&mut issuer, 1, "Child");
        let local = prepare(&mut foreign, 1, "Local");
        let (mut fs, mut dev, _) = if create { disk_without_log() } else { disk() };
        let drops = Rc::new(Cell::new(0));
        let error = rejected(&mut foreign, &mut fs, &mut dev, prepared, &drops, create);
        assert_eq!(error.status, 0xC000_0008);
        // A failed foreign admission neither consumes the issuing preparation nor the local one.
        foreign
            .validate_system_hive_preparation_for_storage(&local)
            .unwrap();
        let admitted = if create {
            SnapshotSystemHivePublication::<_, _, Caller, u64>::create(
                checked(&mut issuer, error.prepared),
                &mut fs,
                &mut dev,
                SnapshotBlockStore::new(0, 64),
                LOG,
                error.continuation,
            )
        } else {
            SnapshotSystemHivePublication::<_, _, Caller, u64>::open(
                checked(&mut issuer, error.prepared),
                &mut fs,
                &mut dev,
                SnapshotBlockStore::new(0, 64),
                LOG,
                error.continuation,
            )
        };
        let mut work = admitted.ok().unwrap();
        work.make_durable().unwrap();
        work.commit().unwrap();
        work.publish_local(|caller, outcome| {
            caller.publications += 1;
            outcome.generation
        })
        .unwrap();
        work.acknowledge().unwrap();
        let (caller, generation) = work.take_completion().unwrap();
        assert_eq!(generation, 2);
        assert_eq!(caller.publications, 1);
        drop(caller);
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn aborted_or_published_preparation_cannot_write_storage() {
    for published in [false, true] {
        let mut client = client(703);
        let prepared = prepare(&mut client, 1, "Child");
        if published {
            client.publish_system_hive_mutation(&prepared).unwrap();
        } else {
            client.abort_prepared_system_hive_mutation(&prepared);
            // The same mount/generation now owns a DIFFERENT preparation; neither is replaceable.
            let other = prepare(&mut client, 1, "Other");
            client
                .validate_system_hive_preparation_for_storage(&other)
                .unwrap();
        }
        let (mut fs, mut dev, _) = disk();
        let drops = Rc::new(Cell::new(0));
        let error = rejected(&mut client, &mut fs, &mut dev, prepared, &drops, false);
        assert_ne!(error.status, 0);
        drop(error);
        assert_eq!(drops.get(), 1);
    }
}

struct FaultyValidation {
    inner: Direct,
    fault: Option<u8>,
    validations: usize,
}

impl Backend for FaultyValidation {
    fn call(&mut self, opcode: u16, input: &[u8], output: &mut [u8]) -> CmReply {
        let mut reply = self.inner.call(opcode, input, output);
        if opcode == opcode::CM_OP_MUTATE_SYSTEM_HIVE
            && CmHiveMutationRequest::from_bytes(input).unwrap().operation
                == hive_mutation_transfer::VALIDATE_PREPARED
        {
            self.validations += 1;
            assert!(output.is_empty());
            assert_eq!(reply.status, 0);
            match self.fault.take() {
                Some(0) => reply.status = crate::STATUS_DEVICE_NOT_READY,
                Some(1) => reply.information = 1,
                Some(2) => reply.detail0 += 1,
                Some(3) => reply.detail1 += 1,
                Some(4) => reply.status = 0x103,
                Some(5) => panic!("validation transport unwind"),
                None => {}
                _ => unreachable!(),
            }
        }
        reply
    }
}

#[test]
fn malformed_or_lost_validation_reply_retains_everything_for_exact_retry() {
    for fault in 0..5 {
        let mut source = client(704);
        let prepared = prepare(&mut source, 1, "Child");
        let mut client = ConfigClient::new(FaultyValidation {
            inner: source.backend,
            fault: Some(fault),
            validations: 0,
        });
        let (mut fs, mut dev, _) = disk();
        let drops = Rc::new(Cell::new(0));
        let error = rejected(&mut client, &mut fs, &mut dev, prepared, &drops, false);
        assert_ne!(error.status, 0);
        assert_eq!(client.backend.validations, 1);
        let mut work = SnapshotSystemHivePublication::<_, _, Caller, ()>::open(
            checked(&mut client, error.prepared),
            &mut fs,
            &mut dev,
            SnapshotBlockStore::new(0, 64),
            LOG,
            error.continuation,
        )
        .ok()
        .unwrap();
        work.rollback_storage().unwrap();
        work.abort().unwrap();
        work.acknowledge_abort().unwrap();
        drop(work.take_cancelled().unwrap());
        assert_eq!(drops.get(), 1);
    }
}

#[test]
fn invalid_local_preparation_is_refused_before_any_transport_or_storage_access() {
    for field in 0..4 {
        let mut client = client(705);
        let mut prepared = prepare(&mut client, 1, "Child");
        match field {
            0 => prepared.lease_token = 0,
            1 => prepared.expected_generation = 0,
            2 => prepared.next_generation += 1,
            3 => prepared.semantic_journal_len = 0,
            _ => unreachable!(),
        }
        let before = client.backend.calls;
        let (mut fs, mut dev, _) = disk();
        let drops = Rc::new(Cell::new(0));
        let error = rejected(&mut client, &mut fs, &mut dev, prepared, &drops, false);
        assert_eq!(error.status, STATUS_INVALID_PARAMETER as u32);
        assert_eq!(client.backend.calls, before);
    }
}

#[test]
fn validation_unwind_retains_caller_and_preparation_in_flight() {
    extern crate std;
    let mut source = client(706);
    let prepared = prepare(&mut source, 1, "Child");
    let address = prepared.durable_journal().as_ptr();
    let mut client = ConfigClient::new(FaultyValidation {
        inner: source.backend,
        fault: Some(5),
        validations: 0,
    });
    let drops = Rc::new(Cell::new(0));
    let mut admission = SystemHiveStorageAdmission::new(
        &mut client,
        prepared,
        Caller {
            drops: drops.clone(),
            publications: 0,
        },
    );
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| admission.validate()));
    assert!(result.is_err());
    assert_eq!(admission.phase(), SystemHiveStorageAdmissionPhase::InFlight);
    assert_eq!(
        admission
            .prepared
            .as_ref()
            .unwrap()
            .durable_journal()
            .as_ptr(),
        address
    );
    assert_eq!(admission.continuation().unwrap().publications, 0);
    assert_eq!(drops.get(), 0);
    assert!(admission.take_validated().is_none());
    assert!(admission.release_before_storage().is_none());
    assert_eq!(admission.validate(), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(admission.client.as_ref().unwrap().backend.validations, 1);
}

#[test]
fn returned_validation_failure_can_retry_in_the_same_owner() {
    let mut source = client(707);
    let prepared = prepare(&mut source, 1, "Child");
    let address = prepared.durable_journal().as_ptr();
    let mut client = ConfigClient::new(FaultyValidation {
        inner: source.backend,
        fault: Some(0),
        validations: 0,
    });
    let drops = Rc::new(Cell::new(0));
    let mut admission = SystemHiveStorageAdmission::new(
        &mut client,
        prepared,
        Caller {
            drops: drops.clone(),
            publications: 0,
        },
    );
    assert_eq!(admission.validate(), Err(crate::STATUS_DEVICE_NOT_READY));
    assert_eq!(admission.phase(), SystemHiveStorageAdmissionPhase::Pending);
    assert_eq!(drops.get(), 0);
    admission.validate().unwrap();
    assert_eq!(
        admission.phase(),
        SystemHiveStorageAdmissionPhase::Validated
    );
    assert_eq!(admission.validate(), Err(STATUS_INVALID_PARAMETER));
    let (checked, caller) = admission.take_validated().unwrap();
    assert_eq!(checked.prepared.durable_journal().as_ptr(), address);
    assert!(admission.take_validated().is_none());
    assert!(admission.release_before_storage().is_none());
    assert_eq!(checked.client.backend.validations, 2);
    let (mut fs, mut dev, _) = disk();
    let mut work = SnapshotSystemHivePublication::<_, _, Caller, ()>::open(
        checked,
        &mut fs,
        &mut dev,
        SnapshotBlockStore::new(0, 64),
        LOG,
        caller,
    )
    .ok()
    .unwrap();
    work.rollback_storage().unwrap();
    work.abort().unwrap();
    work.acknowledge_abort().unwrap();
    drop(work.take_cancelled().unwrap());
    assert_eq!(drops.get(), 1);
}

#[test]
fn unstarted_admission_can_return_ownership_without_ipc() {
    let mut client = client(708);
    let prepared = prepare(&mut client, 1, "Child");
    let address = prepared.durable_journal().as_ptr();
    let calls = client.backend.calls;
    let mut admission = SystemHiveStorageAdmission::new(&mut client, prepared, 17);
    assert!(admission.take_validated().is_none());
    let (prepared, caller) = admission.release_before_storage().unwrap();
    assert_eq!(caller, 17);
    assert_eq!(prepared.durable_journal().as_ptr(), address);
    assert!(admission.release_before_storage().is_none());
    assert_eq!(admission.validate(), Err(STATUS_INVALID_PARAMETER));
    drop(admission);
    assert_eq!(client.backend.calls, calls);
    client
        .validate_system_hive_preparation_for_storage(&prepared)
        .unwrap();
}

#[test]
fn successful_validation_can_be_withdrawn_before_or_after_checked_handoff() {
    for extract in [false, true] {
        let mut client = client(709);
        let prepared = prepare(&mut client, 1, "Child");
        let address = prepared.durable_journal().as_ptr();
        let calls = client.backend.calls;
        let mut admission = SystemHiveStorageAdmission::new(&mut client, prepared, 23);
        admission.validate().unwrap();
        if extract {
            let (checked, caller) = admission.take_validated().unwrap();
            assert_eq!(caller, 23);
            assert!(admission.release_before_storage().is_none());
            let (client, prepared) = checked.into_preparation();
            assert_eq!(prepared.durable_journal().as_ptr(), address);
            assert_eq!(client.backend.calls, calls + 1);
            client
                .validate_system_hive_preparation_for_storage(&prepared)
                .unwrap();
            client.abort_prepared_system_hive_mutation(&prepared);
        } else {
            let (prepared, caller) = admission.release_before_storage().unwrap();
            assert_eq!(caller, 23);
            assert_eq!(prepared.durable_journal().as_ptr(), address);
            assert!(admission.take_validated().is_none());
            assert!(admission.release_before_storage().is_none());
            drop(admission);
            assert_eq!(client.backend.calls, calls + 1);
            client
                .validate_system_hive_preparation_for_storage(&prepared)
                .unwrap();
            client.abort_prepared_system_hive_mutation(&prepared);
        }
    }
}
