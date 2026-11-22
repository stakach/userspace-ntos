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

mod a_pass_of_several_runners {
    use nt_component_suspension::{combine_nested_child_redrives, NestedChildRedrive::*};

    #[test]
    fn one_busy_and_one_uncertain_runner_is_uncertain() {
        assert_eq!(combine_nested_child_redrives(&[Waiting, Uncertain]), Uncertain);
        assert_eq!(combine_nested_child_redrives(&[Uncertain, Waiting]), Uncertain);
    }

    #[test]
    fn only_an_all_busy_pass_is_waiting() {
        assert_eq!(combine_nested_child_redrives(&[Waiting]), Waiting);
        assert_eq!(combine_nested_child_redrives(&[Waiting, Waiting]), Waiting);
    }

    #[test]
    fn a_progressed_runner_beside_a_busy_one_progresses() {
        assert_eq!(combine_nested_child_redrives(&[Waiting, Progressed]), Progressed);
        assert_eq!(combine_nested_child_redrives(&[Progressed]), Progressed);
        // Progress restores the parent; an uncertain runner's work stays retained with it.
        assert_eq!(combine_nested_child_redrives(&[Uncertain, Progressed]), Progressed);
    }

    #[test]
    fn a_ready_pass_that_tried_no_runner_stays_uncertain() {
        assert_eq!(combine_nested_child_redrives(&[]), Uncertain);
    }
}

mod one_runner_over_several_rows {
    use core::cell::Cell;
    use nt_component_suspension::{nested_rows_pass, AdmissionCounts, NestedChildRedrive, NestedChildRedrive::*};

    /// One row attempt: whether it progressed, how many dispatches were refused admission and
    /// how many admitted dispatches returned or yielded during it (nested ones included).
    #[derive(Clone, Copy)]
    struct Row { progressed: bool, refused: u64, admitted: u64 }
    const REFUSED: Row = Row { progressed: false, refused: 1, admitted: 0 };
    const UNCERTAIN: Row = Row { progressed: false, refused: 0, admitted: 1 };
    const PROGRESSED: Row = Row { progressed: true, refused: 0, admitted: 1 };

    fn run(rows: &[Row]) -> (bool, Option<NestedChildRedrive>) {
        let counts = Cell::new(AdmissionCounts::default());
        let next = Cell::new(0usize);
        nested_rows_pass(rows.len(), || counts.get(), || {
            let row = rows[next.get()];
            next.set(next.get() + 1);
            let now = counts.get();
            counts.set(AdmissionCounts {
                refusals: now.refusals + row.refused,
                admitted: now.admitted + row.admitted,
            });
            row.progressed
        })
    }

    #[test]
    fn a_refused_row_beside_an_uncertain_row_is_uncertain() {
        assert_eq!(run(&[REFUSED, UNCERTAIN]), (false, Some(Uncertain)));
        assert_eq!(run(&[UNCERTAIN, REFUSED]), (false, Some(Uncertain)));
    }

    #[test]
    fn an_admitted_row_whose_nested_dispatch_was_refused_is_uncertain() {
        // The row's own dispatch entered; a refusal inside its provider is not its own.
        let nested_refusal = Row { progressed: false, refused: 1, admitted: 1 };
        assert_eq!(run(&[nested_refusal]), (false, Some(Uncertain)));
    }

    #[test]
    fn only_all_refused_rows_are_waiting() {
        assert_eq!(run(&[REFUSED, REFUSED]), (false, Some(Waiting)));
    }

    #[test]
    fn the_pass_stops_at_the_first_progressed_row() {
        assert_eq!(run(&[REFUSED, PROGRESSED, UNCERTAIN]), (true, Some(Progressed)));
        assert_eq!(run(&[UNCERTAIN, PROGRESSED]), (true, Some(Progressed)));
    }

    #[test]
    fn a_pass_over_no_rows_records_nothing() {
        assert_eq!(run(&[]), (false, None));
    }
}
