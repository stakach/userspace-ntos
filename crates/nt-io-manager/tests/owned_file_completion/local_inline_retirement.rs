use nt_io_completion::{FileIoMode, FileReferenceRelease};
use nt_io_manager::inline_file_retirement::*;
use nt_io_manager::{FileIoBusyOwner, FileIoWaitKey};

#[test]
fn overlay_zero_inline_retirement_keeps_exact_busy_and_reference_followup() {
    let owner = FileIoBusyOwner {
        key: FileIoWaitKey::LocalOverlay(0),
        tid: 73,
        mode: FileIoMode::SynchronousNonAlertable,
    };
    let mut table = InlineFileRetirementTable::new();
    let reserved = table.reserve(owner).expect("canonical Overlay zero is a valid Busy owner");
    let identity = table.activate(reserved).unwrap();
    assert_eq!(table.active_owner(identity), Ok(owner));
    table.retire_active(identity).unwrap();
    let mut policy = table.begin_step(identity).unwrap();
    table.record_step(&mut policy, InlineFileRetirementOutcome::PolicyReleased { waiters: 0 }).unwrap();
    let mut wake = table.begin_step(identity).unwrap();
    table.record_step(&mut wake, InlineFileRetirementOutcome::Completed(InlineFileRetirementEffect::Wake)).unwrap();
    let mut reference = table.begin_step(identity).unwrap();
    let receipt = FileReferenceRelease::default();
    table.record_step(&mut reference, InlineFileRetirementOutcome::ReferenceReleased(receipt)).unwrap();
    let mut followup = table.begin_step(identity).unwrap();
    assert_eq!(followup.reference_release(), Some(receipt));
    table.record_step(&mut followup, InlineFileRetirementOutcome::NotEntered(0xc000_000d)).unwrap();
    assert!(table.finish(identity).is_none());
    let mut retry = table.begin_step(identity).unwrap();
    assert_eq!(retry.effect(), InlineFileRetirementEffect::ReferenceFollowup);
    assert_eq!(retry.reference_release(), Some(receipt));
    table.record_step(&mut retry, InlineFileRetirementOutcome::Completed(InlineFileRetirementEffect::ReferenceFollowup)).unwrap();
    assert_eq!(table.finish(identity), Some(owner));
    assert!(table.finish(identity).is_none());
}
