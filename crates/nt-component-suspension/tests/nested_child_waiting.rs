//! A nested child that could not be admitted yet is waiting, not uncertain (#427).
//!
//! Boot 44999127278: Disk's AddDevice ran the SCSI claim SRB as a nested child. storahci's
//! primary was busy starting its second adapter, so no lane admitted the SRB
//! (STATUS_DEVICE_BUSY, nothing entered). The redrive reported "no progress", the step
//! classified that as Indeterminate, the AddDevice child was quarantined, and the root service
//! loop exited. Only an effect that actually reached the driver may be uncertain.

use nt_component_suspension::{nested_child_redrive, NestedChildDecision, NestedChildRedrive};

#[test]
fn a_child_no_lane_admitted_restores_its_parent_and_waits() {
    let redrive = nested_child_redrive(false, true);
    assert_eq!(redrive, NestedChildRedrive::Waiting);
    assert_eq!(redrive.decision(), NestedChildDecision::RestoreParent);
}

#[test]
fn only_an_entered_uncertain_child_is_quarantined() {
    assert_eq!(nested_child_redrive(false, false), NestedChildRedrive::Uncertain);
    assert_eq!(NestedChildRedrive::Uncertain.decision(), NestedChildDecision::Quarantine);
    assert_eq!(nested_child_redrive(true, false), NestedChildRedrive::Progressed);
    assert_eq!(nested_child_redrive(true, true), NestedChildRedrive::Progressed);
    assert_eq!(NestedChildRedrive::Progressed.decision(), NestedChildDecision::RestoreParent);
}
