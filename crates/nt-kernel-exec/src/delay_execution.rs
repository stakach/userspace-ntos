//! `KeDelayExecutionThread` as issued by a provider lane.
//!
//! A delay is a dispatcher wait with no object. A lane that owns a wait rendezvous leaves the
//! processor in one captured timed wait, so the root that runs it is told what it waits for
//! and is free until the interval expires. Polling a clock between yields keeps that root on
//! the lane for the whole interval.

pub const STATUS_SUCCESS: i32 = 0;
pub const STATUS_TIMEOUT: i32 = 0x102;

/// What one delay request asks of the lane that issued it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DelayExecution {
    /// A zero interval gives up the processor once and completes.
    YieldOnce,
    /// A relative (negative) or absolute (positive) interval, in the caller's own encoding.
    TimedWait { interval_100ns: i64 },
}

impl DelayExecution {
    pub const fn for_interval(interval_100ns: i64) -> Self {
        if interval_100ns == 0 {
            Self::YieldOnce
        } else {
            Self::TimedWait { interval_100ns }
        }
    }
}

/// The delay's status once its timed wait finished with `wait_status`. Expiry of the interval
/// is the delay's success. An alert or user APC that ended an alertable delay early, and a
/// refused wait, are reported unchanged.
pub const fn completion_status(wait_status: i32) -> i32 {
    if wait_status == STATUS_TIMEOUT {
        STATUS_SUCCESS
    } else {
        wait_status
    }
}

/// Run one delay. `timed_wait` is the lane's wait rendezvous, when it has one: it waits on no
/// object for the interval and returns the wait status. `without_rendezvous` is the delay of a
/// lane that has none and returns the delay status itself.
pub fn delay_execution_thread(
    interval_100ns: i64,
    timed_wait: Option<impl FnOnce(i64) -> i32>,
    yield_once: impl FnOnce(),
    without_rendezvous: impl FnOnce(i64) -> i32,
) -> i32 {
    match DelayExecution::for_interval(interval_100ns) {
        DelayExecution::YieldOnce => {
            yield_once();
            STATUS_SUCCESS
        }
        DelayExecution::TimedWait { interval_100ns } => match timed_wait {
            Some(timed_wait) => completion_status(timed_wait(interval_100ns)),
            None => without_rendezvous(interval_100ns),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    const STATUS_ALERTED: i32 = 0x101;
    const STATUS_USER_APC: i32 = 0xC0;
    const STATUS_INVALID_PARAMETER: i32 = 0xC000_000Du32 as i32;

    #[test]
    fn interval_sign_selects_the_delay() {
        assert_eq!(DelayExecution::for_interval(0), DelayExecution::YieldOnce);
        assert_eq!(
            DelayExecution::for_interval(-1_000_000),
            DelayExecution::TimedWait { interval_100ns: -1_000_000 }
        );
        assert_eq!(
            DelayExecution::for_interval(133_000_000_000_000_000),
            DelayExecution::TimedWait { interval_100ns: 133_000_000_000_000_000 }
        );
    }

    #[test]
    fn a_lane_with_a_rendezvous_waits_once_and_never_yields() {
        for interval in [-1_000_000i64, 133_000_000_000_000_000] {
            let waited = Cell::new(None);
            let status = delay_execution_thread(
                interval,
                Some(|requested| {
                    assert_eq!(waited.replace(Some(requested)), None, "one wait per delay");
                    STATUS_TIMEOUT
                }),
                || panic!("a captured delay must not yield-poll"),
                |_| panic!("a lane with a rendezvous must not take the unowned path"),
            );
            assert_eq!(status, STATUS_SUCCESS);
            assert_eq!(waited.get(), Some(interval));
        }
    }

    #[test]
    fn a_zero_interval_gives_up_the_processor_once_without_waiting() {
        let yields = Cell::new(0u32);
        let status = delay_execution_thread(
            0,
            Some(|_| panic!("a zero interval is not a wait")),
            || yields.set(yields.get() + 1),
            |_| panic!("a zero interval is not a wait"),
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(yields.get(), 1);
    }

    #[test]
    fn only_expiry_is_the_delays_success() {
        assert_eq!(completion_status(STATUS_TIMEOUT), STATUS_SUCCESS);
        // An alertable delay ended early, and a refused wait, are reported as they are.
        assert_eq!(completion_status(STATUS_ALERTED), STATUS_ALERTED);
        assert_eq!(completion_status(STATUS_USER_APC), STATUS_USER_APC);
        assert_eq!(completion_status(STATUS_INVALID_PARAMETER), STATUS_INVALID_PARAMETER);
        let status = delay_execution_thread(
            -10_000,
            Some(|_| STATUS_USER_APC),
            || panic!("a captured delay must not yield-poll"),
            |_| panic!("unowned path"),
        );
        assert_eq!(status, STATUS_USER_APC);
    }

    #[test]
    fn a_lane_without_a_rendezvous_keeps_its_own_delay() {
        let requested = Cell::new(None);
        let status = delay_execution_thread(
            -20_000,
            None::<fn(i64) -> i32>,
            || panic!("a nonzero interval is not a bare yield"),
            |interval| {
                requested.set(Some(interval));
                STATUS_SUCCESS
            },
        );
        assert_eq!(status, STATUS_SUCCESS);
        assert_eq!(requested.get(), Some(-20_000));
    }
}
