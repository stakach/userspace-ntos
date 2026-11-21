//! A dispatch parked inside another pump's receive must not yield (#420, #427 A).
//!
//! The model is boot 44950677448. partmgr reads the partition table: its lane parks in its
//! own service wait for the READ it sent to disk. Root stays inside partmgr's pump receive,
//! whose nested File work pass enters disk's READ as an ordinary File plain pump. disk then
//! parks its own lane on the SCSI READ(10), which goes pending, and a hosted DPC later
//! completes it, acknowledging disk's parked Call.
//!
//! The only resumer of a yielded dispatch is the root boundary (`drain_root_restores`). Root
//! reaches it only once partmgr's receive returns, and that receive waits on disk's READ. A
//! yield there leaves the dispatch with no resumer: every vCPU halts.

use nt_component_suspension::{parked_dispatch_receive, ParkedDispatch, ParkedDispatchReceive};

/// disk's READ, as its own receive sees it once its lane has parked on the SCSI READ(10).
const DISK_READ_IN_PARTMGR_RECEIVE: ParkedDispatch = ParkedDispatch {
    own_wait_parked: true,
    // The File row would keep the plain pump.
    owner_keeps_continuation: true,
    // partmgr's lane is parked, not running, so no running lane is held.
    nested_in_lane: false,
    enclosing_receive: true,
};

#[derive(Debug, Default)]
struct Boot {
    /// Root is inside disk's pump, itself inside partmgr's receive.
    in_disk_pump: bool,
    /// The File row keeps disk's yielded receive half.
    disk_kept: bool,
    /// The SCSI DPC has completed READ(10) and acknowledged disk's parked Call.
    dpc_completed: bool,
    disk_completed: bool,
    /// partmgr's own service wait has been answered.
    partmgr_settled: bool,
    /// Root has returned to its own loop.
    at_root_boundary: bool,
    resumes: u32,
}

impl Boot {
    fn new() -> Self { Self { in_disk_pump: true, ..Self::default() } }

    /// One root step, using exactly the policy the executive applies.
    fn step(&mut self) {
        if self.in_disk_pump {
            match parked_dispatch_receive(DISK_READ_IN_PARTMGR_RECEIVE) {
                ParkedDispatchReceive::Continue => {
                    // disk's own receive services the hosted DPC inline; the wake replies the
                    // parked Call and disk's next Call finishes the READ.
                    if self.dpc_completed {
                        self.in_disk_pump = false;
                        self.disk_completed = true;
                    } else {
                        self.dpc_completed = true;
                    }
                }
                ParkedDispatchReceive::YieldToRoot => {
                    self.in_disk_pump = false;
                    self.disk_kept = true;
                }
            }
            return;
        }
        if !self.at_root_boundary {
            // Back in partmgr's receive: its nested passes run the SCSI work and the DPC, but
            // nothing there resumes a kept File pump.
            self.dpc_completed = true;
            if self.disk_completed {
                self.partmgr_settled = true;
                self.at_root_boundary = true;
            }
            return;
        }
        if self.disk_kept && self.dpc_completed {
            self.resumes += 1;
            self.disk_kept = false;
            self.disk_completed = true;
        }
    }
}

#[test]
fn a_park_inside_another_pumps_receive_is_completed_by_its_dpc_wake() {
    let mut boot = Boot::new();
    for _ in 0..64 {
        boot.step();
        if boot.partmgr_settled { break; }
    }
    assert!(!boot.disk_kept, "disk's READ yielded where only the root boundary resumes it");
    assert!(boot.disk_completed, "the DPC wake must finish disk's READ");
    assert!(boot.partmgr_settled, "partmgr's partition read must settle");
    assert_eq!(boot.resumes, 0, "the READ continues in its own receive; nothing resumes it");
}

#[test]
fn every_yield_has_a_root_boundary_resumer() {
    for bits in 0..16u8 {
        let dispatch = ParkedDispatch {
            own_wait_parked: bits & 1 != 0,
            owner_keeps_continuation: bits & 2 != 0,
            nested_in_lane: bits & 4 != 0,
            enclosing_receive: bits & 8 != 0,
        };
        let resumable = dispatch.own_wait_parked && dispatch.owner_keeps_continuation
            && !dispatch.nested_in_lane && !dispatch.enclosing_receive;
        assert_eq!(
            parked_dispatch_receive(dispatch) == ParkedDispatchReceive::YieldToRoot,
            resumable,
            "{dispatch:?}",
        );
    }
}
