//! Demand-driven timer setup at a receive boundary.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RearmCheckpoint<T> {
    Idle,
    Programmed(T),
}

/// Recollect canonical demand after initialization, which may perform IPC or switch clocks.
/// Each collection must take a fresh time snapshot. No queue or request-latch borrow should
/// span these effects. Only a successful result permits completing the captured rearm request;
/// newer requests and pending timer notifications remain owned by the caller.
pub fn reconcile_rearm<T, E>(
    mut collect: impl FnMut() -> Result<Option<T>, E>,
    initialize: impl FnOnce() -> Result<(), E>,
    program: impl FnOnce(T) -> Result<(), E>,
) -> Result<RearmCheckpoint<T>, E>
where
    T: Copy,
{
    if collect()?.is_none() {
        return Ok(RearmCheckpoint::Idle);
    }
    initialize()?;
    match collect()? {
        Some(target) => {
            program(target)?;
            Ok(RearmCheckpoint::Programmed(target))
        }
        None => Ok(RearmCheckpoint::Idle),
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use crate::{AdjustableClock, Deadline, DeferredRearm};
    use core::cell::{Cell, RefCell};
    use std::vec::Vec;

    #[test]
    fn no_demand_does_not_initialize_or_program() {
        let result = reconcile_rearm::<u64, ()>(
            || Ok(None),
            || panic!("no timer is needed"),
            |_| panic!("no target exists"),
        );
        assert_eq!(result, Ok(RearmCheckpoint::Idle));
    }

    #[test]
    fn initialization_recollects_with_fresh_clock_and_source() {
        let clock = RefCell::new(AdjustableClock::new(100, 1_000));
        let now = Cell::new(100);
        let deadline = Cell::new(Deadline::Absolute {
            system_time_100ns: 2_000,
        });
        let source = Cell::new(1);
        let effects = RefCell::new(Vec::new());
        let result = reconcile_rearm::<_, ()>(
            || {
                let snapshot = clock.borrow().snapshot(now.get());
                let target = deadline.get().monotonic_target(snapshot).unwrap();
                effects.borrow_mut().push((0, target, source.get()));
                Ok(Some((target, source.get())))
            },
            || {
                effects.borrow_mut().push((1, 0, 0));
                now.set(200);
                clock.borrow_mut().set_system_time(200, 5_000).unwrap();
                deadline.set(Deadline::Absolute {
                    system_time_100ns: 5_050,
                });
                source.set(2);
                Ok(())
            },
            |(target, source)| {
                effects.borrow_mut().push((2, target, source));
                Ok(())
            },
        );
        assert_eq!(result, Ok(RearmCheckpoint::Programmed((250, 2))));
        assert_eq!(
            *effects.borrow(),
            [(0, 1_100, 1), (1, 0, 0), (0, 250, 2), (2, 250, 2)]
        );
    }

    #[test]
    fn demand_withdrawn_during_initialization_is_not_programmed() {
        let target = Cell::new(Some(100));
        let requests = RefCell::new(DeferredRearm::new());
        assert!(requests.borrow_mut().request());
        let request = requests.borrow().pending().unwrap();
        let result = reconcile_rearm::<_, ()>(
            || Ok(target.get()),
            || {
                target.set(None);
                assert!(requests.borrow_mut().request());
                Ok(())
            },
            |_| panic!("withdrawn demand must not be programmed"),
        );
        assert_eq!(result, Ok(RearmCheckpoint::Idle));
        assert!(requests.borrow_mut().complete(request));
        assert_ne!(requests.borrow().pending().unwrap(), request);
    }

    #[test]
    fn every_failed_effect_preserves_request_and_stops_the_sequence() {
        // Effects are initial collection, initialization, fresh collection and programming.
        for failed_effect in 0..4 {
            let mut requests = DeferredRearm::new();
            assert!(requests.request());
            let request = requests.pending().unwrap();
            let step = Cell::new(0);
            let effect = || {
                let current = step.get();
                step.set(current + 1);
                if current == failed_effect {
                    Err(current)
                } else {
                    Ok(())
                }
            };
            let result = reconcile_rearm(|| effect().map(|()| Some(100)), effect, |_| effect());
            if result.is_ok() {
                assert!(requests.complete(request));
            }
            assert_eq!(result, Err(failed_effect));
            assert_eq!(step.get(), failed_effect + 1);
            assert_eq!(requests.pending(), Some(request));
        }
    }

    #[test]
    fn nested_requests_survive_successful_programming() {
        let requests = RefCell::new(DeferredRearm::new());
        assert!(requests.borrow_mut().request());
        let request = requests.borrow().pending().unwrap();
        let result = reconcile_rearm::<_, ()>(
            || Ok(Some(100)),
            || {
                assert!(requests.borrow_mut().request());
                Ok(())
            },
            |_| {
                assert!(requests.borrow_mut().request());
                Ok(())
            },
        );
        assert_eq!(result, Ok(RearmCheckpoint::Programmed(100)));
        assert!(requests.borrow_mut().complete(request));
        let remaining = requests.borrow().pending().unwrap();
        assert_ne!(remaining, request);
    }
}
