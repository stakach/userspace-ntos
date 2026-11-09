//! A nested native pump may unwind only after the File IRP invocation has a durable owner.

const OWNERS: &str = include_str!("../../../components/ntos-executive/src/hosted_file_owners.rs");

#[test]
fn suspended_file_dispatch_keeps_its_move_only_invocation_in_the_exact_row() {
    assert!(OWNERS.contains("PumpSuspended(SuspendedFilePumpOwner)"));
    assert!(OWNERS.contains("struct SuspendedFilePumpOwner"));
    assert!(OWNERS.contains("invocation: SuspendedExternalFileIrpInvocation"));
    assert!(OWNERS.contains("continuation: FileDispatchContinuation"));
    assert!(OWNERS.contains("Flight::PumpSuspended"));

    let park = OWNERS
        .split_once("fn suspend_dispatch_for_pump(")
        .expect("durable File pump suspension entry")
        .1
        .split_once("fn resume_dispatch_from_pump(")
        .expect("File pump resume boundary")
        .0;
    assert!(park.contains("find(irp_id)"));
    assert!(park.contains("Flight::Dispatch"));
    assert!(park.contains("suspend_for_pump(key)"));
    assert!(park.contains("Payload::PumpSuspended(SuspendedFilePumpOwner"));
    assert!(!park.contains("finish_external_file_irp"));
    assert!(!park.contains("ExternalFileIrpOutcome::Returned"));

    let resume = OWNERS
        .split_once("fn resume_dispatch_from_pump(")
        .expect("exact File pump resume entry")
        .1
        .split_once("fn quarantine_dispatch_pump(")
        .expect("File pump quarantine boundary")
        .0;
    assert!(resume.contains("find(irp_id)"));
    assert!(resume.contains("Flight::PumpSuspended"));
    assert!(resume.contains("resume(key)"));
    assert!(resume.contains("Flight::Dispatch"));
    assert!(!resume.contains("finish_external_file_irp"));
    assert!(!resume.contains("ExternalFileIrpOutcome::Returned"));
}

#[test]
fn uncertain_pump_effect_retains_the_file_owner_without_replay() {
    let quarantine = OWNERS
        .split_once("fn quarantine_dispatch_pump(")
        .expect("File pump quarantine entry")
        .1
        .split_once("fn ")
        .expect("quarantine boundary")
        .0;
    assert!(quarantine.contains("quarantine(key)"));
    assert!(quarantine.contains("Payload::PumpSuspended"));
    assert!(!quarantine.contains("hosted_file_dispatch::invoke"));
    assert!(!quarantine.contains("finish_external_file_irp"));
}
