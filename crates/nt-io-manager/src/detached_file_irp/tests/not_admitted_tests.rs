//! A hosted lane-admission refusal is not a completion (#427).
//!
//! Boot 44957371959 completed condrv IRPs that no lane could admit yet with
//! STATUS_DEVICE_BUSY, a status NT never returns for that. A not-admitted IRP goes back to its
//! queued owner and is begun again later; a queued cancel or abandon completes it without entry.

use super::*;

fn not_admitted(f: &mut Fixture, prepared: PreparedExternalFileIrp) -> PreparedExternalFileIrp {
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    match f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::NotAdmitted))
        .unwrap()
    {
        ExternalFileIrpResult::NotAdmitted { prepared } => prepared,
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn a_not_admitted_irp_returns_to_its_owner_and_is_begun_again() {
    let mut f = fixture();
    let prepared = f.io.prepare_external_file_irp_owned(read(&f), buffers()).unwrap();
    let id = prepared.irp_id();
    let prepared = not_admitted(&mut f, prepared);
    assert_eq!(f.io.irp(id).unwrap().state, IrpState::Initialized);
    assert!(f.io.completed_irp(id).is_none(), "no-admission is not a completion");
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let terminal = terminal(&mut f, invocation);
    assert_eq!(terminal.completion().status, NtStatus::SUCCESS);
}

#[test]
fn a_not_admitted_result_never_mints_a_no_entry_failure() {
    let mut f = fixture();
    let prepared = f.io.prepare_external_file_irp_owned(read(&f), buffers()).unwrap();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let result = f.io
        .finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::NotAdmitted))
        .unwrap();
    assert!(result.into_no_entry_receipt().is_err());
}

#[test]
fn a_queued_ordinary_irp_cancelled_before_admission_completes_without_entry() {
    let mut f = fixture();
    let prepared = f.io.prepare_external_file_irp_owned(read(&f), buffers()).unwrap();
    let id = prepared.irp_id();
    let prepared = not_admitted(&mut f, prepared);
    assert!(f.io.cancel_if_pending(f.client, id).unwrap());
    let refusal = f.io.begin_prepared_external_file_irp(prepared).unwrap_err();
    assert_eq!(refusal.status(), NtStatus::CANCELLED);
    let retained = f.io.complete_prepared_external_file_irp_without_entry(
        refusal.into_owner(),
        ExternalFileIrpPreEntryFailure::Cancelled,
    ).unwrap();
    let completion = f.io.prepare_external_file_irp_completion(retained).unwrap();
    assert_eq!(completion.completion().status, NtStatus::CANCELLED);
    assert_eq!(completion.completion().completion_origin, IrpCompletionOrigin::NoBackendEntry);
    f.io.retire_external_file_irp_completion_without_backend(completion).unwrap();
    assert!(f.io.irp(id).is_none());
    assert!(f.trace.borrow().calls.is_empty(), "the provider was never entered");
}

#[test]
fn an_abandoned_queued_create_completes_without_entry_and_closes_its_file() {
    let mut f = fixture();
    let child = create_file(&mut f, false);
    let prepared = f.io.prepare_external_file_irp_owned(
        create(&f, child), ExternalFileIrpBuffers::new(vec![], vec![]),
    ).unwrap();
    let id = prepared.irp_id();
    let prepared = not_admitted(&mut f, prepared);
    assert_eq!(f.io.file(child).unwrap().state, FileState::Allocated);
    f.io.abandon_irp_delivery(f.client, id).unwrap();
    let retained = f.io.complete_prepared_external_file_irp_without_entry(
        prepared, ExternalFileIrpPreEntryFailure::Cancelled,
    ).unwrap();
    assert_eq!(f.io.file(child).unwrap().state, FileState::Closed);
    let completion = f.io.prepare_external_file_irp_completion(retained).unwrap();
    assert_eq!(completion.completion().status, NtStatus::CANCELLED);
    f.io.retire_external_file_irp_completion_without_backend(completion).unwrap();
    assert!(f.io.irp(id).is_none());
    assert!(f.trace.borrow().calls.is_empty());
}
