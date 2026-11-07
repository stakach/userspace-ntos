//! A parked hosted READ must retain its exact prepared owner until the parent is restored.

const OWNERS: &str = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");

#[test]
fn queued_read_cannot_enter_provider_during_preparation() {
    let prepare = OWNERS
        .split_once("pub(super) fn queue_read(")
        .expect("hosted READ queue entry")
        .1
        .split_once("pub(super) fn redrive_queued_read(")
        .expect("queued READ redrive boundary")
        .0;
    assert!(prepare.contains("capture_route(id, &prepared)"));
    assert!(prepare.contains("Payload::Prepared(prepared)"));
    assert!(prepare.contains("Flight::QueuedDispatch"));
    assert!(!prepare.contains("begin_prepared_external_file_irp"));
    assert!(!prepare.contains("hosted_file_dispatch::invoke"));
}

#[test]
fn queued_read_enters_once_and_retains_terminal_for_delivery() {
    let redrive = OWNERS
        .split_once("pub(super) fn redrive_queued_read(")
        .expect("queued READ redrive")
        .1
        .split_once("pub(super) fn contains(")
        .expect("redrive boundary")
        .0;
    let begin = redrive.find("begin_prepared_external_file_irp").expect("manager begin");
    let entered = redrive.find("Flight::Dispatch").expect("entered flight");
    let invoke = redrive.find("hosted_file_dispatch::invoke").expect("provider invoke");
    assert!(begin < entered && entered < invoke);
    assert!(redrive.contains("Payload::Terminal(terminal)"));
    assert!(redrive.contains("ExternalFileIrpResult::Indeterminate"));
    assert!(redrive.contains("ExternalFileIrpResult::NotEntered { status, prepared }"));
    assert!(redrive.contains("block(id, Payload::Prepared(prepared), status)"));
}

#[test]
fn queued_terminal_delivery_does_not_issue_an_extra_backend_ack() {
    let completion = OWNERS
        .split_once("fn acknowledge_with_buffers(")
        .expect("terminal delivery")
        .1;
    let terminal = completion
        .split_once("if matches!(row(id).payload.as_ref(), Some(Payload::Terminal(_)))")
        .expect("synchronous terminal branch")
        .1
        .split_once("if monotonic_time_100ns() < row(id).retry_after")
        .expect("terminal branch boundary")
        .0;
    assert!(terminal.contains("retire_external_file_irp_terminal(terminal)"));
    assert!(!terminal.contains("hosted_file_dispatch::acknowledge"));
    assert!(completion.contains("retire_external_file_irp_completion_without_backend(completion)"));
}
