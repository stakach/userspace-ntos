//! A caller is inside IoCallDriver until the driver returns (#427).
//!
//! Boot 44963863150: kernelbase opens the console Connection without FILE_SYNCHRONOUS_IO_* and
//! issues 0x5000d4 with no event, treating any status but success as failure. condrv serves it
//! in FastIoDeviceControl, which waits for conhost on the caller's thread. Our parked dispatch
//! (#420 A) yielded, its File owner kept it, and the asynchronous caller was told 0x103 while its
//! request was still inside condrv. An IRP that no lane has admitted yet (e9f94cb58) was treated
//! the same way. A caller sees only the driver's own return; an asynchronous caller is released
//! early only by a genuine STATUS_PENDING return.

use nt_hosted_runtime::{in_flight_caller_reply, parks_file_caller, DispatchProgress, InFlightReply};

#[test]
fn an_async_caller_of_a_kept_parked_dispatch_stays_blocked_until_the_driver_returns() {
    assert!(parks_file_caller(false, true), "kept dispatch: the async caller is parked");
    assert_eq!(in_flight_caller_reply(false, DispatchProgress::InFlight), InFlightReply::Hold);
    // condrv's fast I/O returned conhost's answer: the caller gets that status, not 0x103.
    assert_eq!(
        in_flight_caller_reply(false, DispatchProgress::Completed),
        InFlightReply::Completion,
    );
}

#[test]
fn an_async_caller_of_a_queued_unadmitted_irp_stays_blocked_until_it_is_dispatched() {
    // A queued IRP has not even entered the driver: it is in flight to its caller.
    assert!(parks_file_caller(false, true));
    assert_eq!(in_flight_caller_reply(false, DispatchProgress::InFlight), InFlightReply::Hold);
    // Once dispatched, a genuine STATUS_PENDING return releases it; the row keeps the
    // completion for the IOSB, Event, APC or IOCP.
    assert_eq!(
        in_flight_caller_reply(false, DispatchProgress::ReturnedPending),
        InFlightReply::Pending,
    );
}

#[test]
fn a_sync_caller_of_a_kept_or_queued_irp_waits_for_completion_as_before() {
    assert!(parks_file_caller(true, true));
    assert!(parks_file_caller(true, false));
    for progress in [DispatchProgress::InFlight, DispatchProgress::ReturnedPending] {
        assert_eq!(in_flight_caller_reply(true, progress), InFlightReply::Hold);
    }
    assert_eq!(in_flight_caller_reply(true, DispatchProgress::Completed), InFlightReply::Completion);
}

#[test]
fn an_async_caller_whose_driver_returned_pending_is_not_parked() {
    // The ordinary case: the dispatch itself returned STATUS_PENDING.
    assert!(!parks_file_caller(false, false));
}

mod release_is_event_driven {
    use nt_hosted_runtime::InFlightCallers;

    /// A pending-row identity: slot plus generation, never a bare number.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct Row { slot: usize, generation: u64 }

    #[test]
    fn a_pass_without_a_driver_return_visits_no_caller() {
        let mut callers = InFlightCallers::new();
        callers.hold(Row { slot: 3, generation: 7 }, 0x51);
        callers.hold(Row { slot: 4, generation: 2 }, 0x52);
        assert!(!callers.any_ready(), "nothing returned: the pass is skipped in O(1)");
        assert!(callers.take_ready().is_empty(), "no caller is visited");
        assert_eq!(callers.held(), 2);
    }

    #[test]
    fn a_driver_return_readies_exactly_its_caller_for_the_next_boundary() {
        let mut callers = InFlightCallers::new();
        let cmd = Row { slot: 3, generation: 7 };
        callers.hold(cmd, 0x51);
        callers.hold(Row { slot: 4, generation: 2 }, 0x52);
        assert!(callers.dispatch_returned(0x51));
        assert!(!callers.dispatch_returned(0x99), "an unrelated IRP readies no one");
        assert!(callers.any_ready());
        assert_eq!(callers.take_ready(), [(cmd, 0x51)]);
        assert!(!callers.any_ready());
        assert_eq!(callers.held(), 1, "the other caller stays held");
    }

    #[test]
    fn a_caller_not_yet_released_can_be_readied_again() {
        let mut callers = InFlightCallers::new();
        let cmd = Row { slot: 3, generation: 7 };
        callers.hold(cmd, 0x51);
        callers.dispatch_returned(0x51);
        let ready = callers.take_ready();
        // Its reply could not be sent yet: it goes back, still ready, for the next boundary.
        callers.retry(ready[0].0, ready[0].1);
        assert_eq!(callers.take_ready(), [(cmd, 0x51)]);
    }
}
