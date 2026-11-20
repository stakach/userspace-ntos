//! A synchronous return published to a caller already told STATUS_PENDING (#420).
use super::*;

fn returned_read(f: &mut Fixture, information: u64) -> (IrpId, ExternalFileIrpTerminal) {
    let prepared = f.io.prepare_external_file_irp_owned(read(f), buffers()).unwrap();
    let irp = prepared.irp_id();
    let mut invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let (_, output) = invocation.buffers_mut().split();
    output.copy_from_slice(&[1, 2, 3, 4]);
    let ExternalFileIrpResult::Returned(terminal) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Returned {
            status: NtStatus::SUCCESS,
            information,
            file_context: None,
        }))
        .unwrap()
    else {
        panic!("expected a synchronous terminal")
    };
    (irp, terminal)
}

#[test]
fn a_queued_synchronous_return_is_read_as_the_irps_ordinary_completion() {
    let mut f = fixture();
    let (irp, terminal) = returned_read(&mut f, 3);
    let completion = f.io
        .queue_external_file_irp_terminal(terminal, ExternalFileIrpOutputCapture::Information)
        .unwrap();
    let published = f.io.completed_irp(irp).expect("the terminal is published");
    assert_eq!((published.status, published.information), (NtStatus::SUCCESS, 3));
    assert_eq!(completion.completion(), &published);
    assert!(completion.capture_complete(), "the returned bytes are already captured");
    assert_eq!(completion.capture_len(), 3);
    assert_eq!(&completion.buffers().output()[..3], &[1, 2, 3]);
    assert!(!completion.owes_backend_acknowledgement());
    assert!(f.io.irp(irp).is_some(), "publication is not retirement");
}

#[test]
fn a_queued_synchronous_return_retires_without_a_backend_ack_or_copy() {
    let mut f = fixture();
    let (irp, terminal) = returned_read(&mut f, 4);
    let completion = f.io
        .queue_external_file_irp_terminal(terminal, ExternalFileIrpOutputCapture::Information)
        .unwrap();
    let (status, completion) = f.io.begin_external_file_irp_copy(completion, 4096)
        .unwrap_err().into_parts();
    assert_eq!(status, NtStatus::INVALID_PARAMETER, "no backend holds the bytes");
    let (status, completion) = f.io.begin_external_file_irp_acknowledgement(completion)
        .unwrap_err().into_parts();
    assert_eq!(status, NtStatus::INVALID_PARAMETER, "a driver that returned owes no ACK");
    let (receipt, buffers) =
        f.io.retire_external_file_irp_completion_without_backend(completion).unwrap();
    assert!(!receipt.backend_acknowledged());
    assert!(f.io.accepts_external_file_irp_receipt(&receipt));
    assert_eq!(buffers.output(), &[1, 2, 3, 4]);
    assert!(f.io.irp(irp).is_none());
    assert!(f.trace.borrow().acknowledgements.is_empty());
    assert!(f.trace.borrow().copies.is_empty());
}

#[test]
fn a_pended_completion_still_owes_its_backend_ack() {
    let mut f = fixture();
    let prepared = f.io.prepare_external_file_irp_owned(read(&f), buffers()).unwrap();
    let irp = prepared.irp_id();
    let invocation = f.io.begin_prepared_external_file_irp(prepared).unwrap();
    let ExternalFileIrpResult::Pending(retained) =
        f.io.finish_external_file_irp(invocation.returned(ExternalFileIrpOutcome::Pending))
            .unwrap()
    else {
        panic!("expected a pending owner")
    };
    f.trace.borrow_mut().ready.push(DriverCompletion {
        irp_id: irp,
        status: NtStatus::SUCCESS,
        information: 0,
        file_context: None,
    });
    f.io.pump();
    let completion = f.io.prepare_external_file_irp_completion(retained).unwrap();
    assert!(completion.owes_backend_acknowledgement());
    let (status, _) = f.io.retire_external_file_irp_completion_without_backend(completion)
        .unwrap_err().into_parts();
    assert_eq!(status, NtStatus::INVALID_PARAMETER);
}

#[test]
fn a_capture_larger_than_the_held_bytes_is_refused_with_the_terminal_kept() {
    let mut f = fixture();
    let (irp, terminal) = returned_read(&mut f, 0);
    // A METHOD_NEITHER input capture does not apply to a READ: the owner is handed back.
    let (status, terminal) = f.io
        .queue_external_file_irp_terminal(terminal, ExternalFileIrpOutputCapture::MethodNeitherInput)
        .unwrap_err().into_parts();
    assert_eq!(status, NtStatus::INVALID_PARAMETER);
    assert_eq!(terminal.completion().id, irp);
    f.io.retire_external_file_irp_terminal(terminal).unwrap();
    assert!(f.io.irp(irp).is_none());
}
