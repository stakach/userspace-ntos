use super::*;
use crate::internal_block_io::{
    InternalBlockOperation, InternalBlockPending, InternalBlockResult, InternalBlockRoute,
    PreparedInternalBlockIrp,
};

fn route(f: &Fixture) -> InternalBlockRoute {
    InternalBlockRoute {
        file_id: f.file,
        device_id: f.device,
        top_device_id: f.device,
        logical_block_bytes: 4,
        max_transfer_bytes: 8,
    }
}

#[test]
fn raw_block_admission_rejects_zero_misaligned_overflow_and_excess_transfer() {
    let mut f = fixture();
    for operation in [
        InternalBlockOperation::Read {
            offset: 0,
            length: 0,
        },
        InternalBlockOperation::Read {
            offset: 1,
            length: 4,
        },
        InternalBlockOperation::Read {
            offset: 0,
            length: 3,
        },
        InternalBlockOperation::Read {
            offset: u64::MAX - 3,
            length: 8,
        },
        InternalBlockOperation::Read {
            offset: 0,
            length: 12,
        },
        InternalBlockOperation::Write {
            offset: 5,
            bytes: vec![1, 2, 3, 4],
        },
        InternalBlockOperation::Write {
            offset: 0,
            bytes: vec![1, 2, 3],
        },
        InternalBlockOperation::Write {
            offset: 0,
            bytes: vec![],
        },
        InternalBlockOperation::Write {
            offset: 0,
            bytes: vec![0; 12],
        },
    ] {
        assert_eq!(
            f.io.prepare_internal_block_irp_owned(f.client, route(&f), 42, operation)
                .unwrap_err(),
            NtStatus::INVALID_PARAMETER,
        );
        assert_eq!(f.io.irp_count(), 0);
    }
}

fn prepare(f: &mut Fixture, operation: InternalBlockOperation) -> PreparedInternalBlockIrp {
    f.io.prepare_internal_block_irp_owned(f.client, route(f), 42, operation)
        .unwrap()
}

fn pending_block(f: &mut Fixture, operation: InternalBlockOperation) -> InternalBlockPending {
    let prepared = prepare(f, operation);
    let invocation = f.io.begin_prepared_internal_block_irp(prepared).unwrap();
    let InternalBlockResult::Pending(owner) =
        f.io.finish_internal_block_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!()
    };
    owner
}

#[test]
fn internal_block_preparation_requires_the_open_file_and_exact_live_stack() {
    let mut f = fixture();
    let mut stale = route(&f);
    stale.top_device_id = DeviceId::new(9, 9);
    assert_eq!(
        f.io.prepare_internal_block_irp_owned(
            f.client,
            stale,
            42,
            InternalBlockOperation::Read {
                offset: 512,
                length: 4
            }
        )
        .unwrap_err(),
        NtStatus::INVALID_DEVICE_REQUEST,
    );
    assert_eq!(f.io.irp_count(), 0);
    let prepared = prepare(
        &mut f,
        InternalBlockOperation::Read {
            offset: 512,
            length: 4,
        },
    );
    assert_eq!(prepared.projection().device_id, f.device);
    assert_eq!(prepared.projection().file_id, Some(f.file));
    assert_eq!(
        prepared.projection().parameters,
        IoParameters::Read(ReadWriteParameters {
            length: 4,
            key: 0,
            offset: 512,
        })
    );
    assert_eq!(prepared.buffers().output().len(), 4);
    f.io.discard_prepared_internal_block_irp(prepared).unwrap();
}

#[test]
fn pending_block_read_retains_buffers_and_checks_the_exact_completion() {
    let mut f = fixture();
    let owner = pending_block(
        &mut f,
        InternalBlockOperation::Read {
            offset: 4096,
            length: 4,
        },
    );
    assert_eq!(owner.buffers().output().len(), 4);
    let id = owner.irp_id();
    complete(&mut f, id);
    let completion = f.io.prepare_internal_block_completion(owner).unwrap();
    assert_eq!(completion.capture_len(), 4);
    let mut copy = f.io.begin_internal_block_copy(completion, 4).unwrap();
    copy.staging_mut().copy_from_slice(&[5, 6, 7, 8]);
    let completion = f
        .io
        .finish_internal_block_copy(copy.returned(ExternalFileIrpCopyOutcome::Copied { bytes: 4 }))
        .unwrap();
    let ack = f.io.begin_internal_block_ack(completion).unwrap();
    let (receipt, buffers) =
        f.io.finish_internal_block_completion(
            ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
        )
        .unwrap();
    assert_eq!(receipt.completion().id, id);
    assert_eq!(buffers.output(), &[5, 6, 7, 8]);
    assert_eq!(f.io.irp_count(), 0);
}

#[test]
fn pending_block_write_and_flush_accept_exact_completion() {
    let mut f = fixture();
    for (operation, information) in [
        (
            InternalBlockOperation::Write {
                offset: 8192,
                bytes: vec![1, 2, 3, 4],
            },
            4,
        ),
        (InternalBlockOperation::Flush, 0),
    ] {
        let owner = pending_block(&mut f, operation);
        let id = owner.irp_id();
        f.trace.borrow_mut().ready.push(DriverCompletion {
            irp_id: id,
            status: NtStatus::SUCCESS,
            information,
            file_context: None,
        });
        f.io.pump();
        let completion = f.io.prepare_internal_block_completion(owner).unwrap();
        assert!(completion.capture_complete());
        let ack = f.io.begin_internal_block_ack(completion).unwrap();
        let (receipt, _) =
            f.io.finish_internal_block_completion(
                ack.acknowledged(ExternalFileIrpAcknowledgement::Acknowledged),
            )
            .unwrap();
        assert_eq!(receipt.completion().information, information);
        assert_eq!(f.io.irp_count(), 0);
    }
}

#[test]
fn short_or_oversized_success_cannot_retire_the_block_terminal() {
    for information in [3, 5] {
        let mut f = fixture();
        let prepared = prepare(
            &mut f,
            InternalBlockOperation::Write {
                offset: 8192,
                bytes: vec![1, 2, 3, 4],
            },
        );
        let invocation = f.io.begin_prepared_internal_block_irp(prepared).unwrap();
        let id = invocation.irp_id();
        let InternalBlockResult::Returned(terminal) =
            f.io.finish_internal_block_irp(invocation.returned(ExternalFileIrpOutcome::Returned {
                status: NtStatus::SUCCESS,
                information,
                file_context: None,
            }))
            .unwrap()
        else {
            panic!()
        };
        let rejection = f.io.retire_internal_block_terminal(terminal).unwrap_err();
        assert_eq!(rejection.status(), NtStatus::INVALID_PARAMETER);
        let retained = rejection.into_owner();
        assert_eq!(retained.irp_id(), id);
        assert!(f.io.irp(id).is_some());
        // The block path cannot retire this malformed terminal; retain it for quarantine.
        let _retained = retained;
    }
}

#[test]
fn malformed_pending_completion_stays_owned_without_ack() {
    let mut f = fixture();
    let owner = pending_block(
        &mut f,
        InternalBlockOperation::Read {
            offset: 0,
            length: 4,
        },
    );
    let id = owner.irp_id();
    f.trace.borrow_mut().ready.push(DriverCompletion {
        irp_id: id,
        status: NtStatus::SUCCESS,
        information: 3,
        file_context: None,
    });
    f.io.pump();
    let rejected = f.io.prepare_internal_block_completion(owner).unwrap_err();
    assert_eq!(rejected.status(), NtStatus::INVALID_PARAMETER);
    assert!(f.io.irp(id).is_some());
    assert!(f.trace.borrow().acknowledgements.is_empty());
    let _retained = rejected.into_owner();
}

#[test]
fn indeterminate_block_entry_cannot_be_replayed() {
    let mut f = fixture();
    let prepared = prepare(&mut f, InternalBlockOperation::Flush);
    assert_eq!(prepared.buffers().input(), &[]);
    assert_eq!(prepared.buffers().output(), &[]);
    let invocation = f.io.begin_prepared_internal_block_irp(prepared).unwrap();
    let InternalBlockResult::Indeterminate { retained, .. } = f
        .io
        .finish_internal_block_irp(invocation.returned(ExternalFileIrpOutcome::Indeterminate {
            transport_status: NtStatus::UNSUCCESSFUL,
        }))
        .unwrap()
    else {
        panic!()
    };
    assert!(retained.is_indeterminate());
    assert!(f.io.free_irp(retained.irp_id()).is_none());
}
