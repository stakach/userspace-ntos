//! The raw input thread keeps reading while condrv's dispatch is parked (#421, #427).
//!
//! Boot 44914465319 with the own-FILE_OBJECT reference: cmd's console calls reached condrv, and
//! condrv waited inside one for conhost's answer. While the root pumped that dispatch, the
//! RIT's keyboard read completed but was never resubmitted, so the desktop froze. With (A) the
//! parked dispatch yields to the root, and with (B) cmd's next ConDrv request takes a worker lane.
//! The root therefore keeps running the RIT's read -> complete -> resubmit loop.

use nt_component_suspension::{
    parked_dispatch_receive, IngressExecutionOwner, ParkedDispatch, ParkedDispatchReceive,
};
use nt_hosted_runtime::{select_ordinary_irp_lane, OrdinaryIrpLane};

/// cmd's DEVICE_CONTROL on condrv's primary, parked in KeWaitForSingleObject for conhost.
const CONDRV_PARKED: ParkedDispatch = ParkedDispatch {
    own_wait_parked: true,
    owner_keeps_continuation: true,
    nested_in_lane: false,
    enclosing_receive: false,
};

#[derive(Default)]
struct Desktop {
    /// The root is still inside condrv's IRP pump.
    root_in_condrv_pump: bool,
    /// The RIT's outstanding IRP_MJ_READ on kbdclass.
    rit_read_pending: bool,
    rit_reads_completed: u32,
    rit_reads_submitted: u32,
    root_receive_owners: Vec<IngressExecutionOwner>,
    condrv_lanes: Vec<OrdinaryIrpLane>,
}

impl Desktop {
    fn new() -> Self {
        Self { root_in_condrv_pump: true, rit_read_pending: true, rit_reads_submitted: 1, ..Self::default() }
    }

    /// One root turn in which one key event arrives at kbdclass.
    fn turn(&mut self, cmd_sends_console_request: bool) {
        if self.root_in_condrv_pump {
            match parked_dispatch_receive(CONDRV_PARKED) {
                // Inside the pump the root sees only condrv's Calls and timers: the key event
                // completes the read, but the RIT's hosted syscalls are never delivered.
                ParkedDispatchReceive::Continue => return,
                ParkedDispatchReceive::YieldToRoot => self.root_in_condrv_pump = false,
            }
        }
        // The root loop's own receive, with no dispatch entered.
        self.root_receive_owners.push(IngressExecutionOwner::Idle);
        if self.rit_read_pending {
            // kbdclass completes the read; the RIT consumes it and resubmits on kbdclass's
            // primary lane, which is not condrv's and is free.
            self.rit_reads_completed += 1;
            assert_eq!(select_ordinary_irp_lane(true, false, false), OrdinaryIrpLane::Primary);
            self.rit_reads_submitted += 1;
        }
        if cmd_sends_console_request {
            // condrv's primary is still parked and holds its waiter row, so a worker admits it.
            self.condrv_lanes.push(select_ordinary_irp_lane(false, true, true));
        }
    }
}

#[test]
fn the_rit_read_loop_continues_while_a_condrv_dispatch_is_parked() {
    let mut desktop = Desktop::new();
    for turn in 0..64 {
        desktop.turn(turn % 8 == 0);
    }
    assert!(!desktop.root_in_condrv_pump, "the root is still blocked in condrv's pump");
    assert_eq!(desktop.rit_reads_completed, 64, "a key event went unread");
    assert_eq!(desktop.rit_reads_submitted, 65, "a completed read was not resubmitted");
    assert!(desktop.root_receive_owners.iter().all(|owner| *owner == IngressExecutionOwner::Idle));
    assert_eq!(desktop.condrv_lanes, vec![OrdinaryIrpLane::Worker; 8]);
}

#[test]
fn only_the_root_level_condrv_dispatch_yields() {
    // cmd's request entered from the root loop yields; the same park reached inside another
    // pump's receive keeps receiving, because only the root resumes a kept dispatch.
    assert_eq!(parked_dispatch_receive(CONDRV_PARKED), ParkedDispatchReceive::YieldToRoot);
    let nested = ParkedDispatch { enclosing_receive: true, ..CONDRV_PARKED };
    assert_eq!(parked_dispatch_receive(nested), ParkedDispatchReceive::Continue);
}

#[test]
fn a_console_request_with_no_free_worker_waits_rather_than_entering_the_parked_primary() {
    assert_eq!(select_ordinary_irp_lane(false, true, false), OrdinaryIrpLane::Busy);
    assert_eq!(select_ordinary_irp_lane(false, false, true), OrdinaryIrpLane::Busy);
}
