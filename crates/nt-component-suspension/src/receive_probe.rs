//! Classify a captured receive using capability observations, never message contents.
//!
//! These are serialized observations, not reservations. The caller must exclusively own the
//! Reply object, capture the message before querying, and authenticate the endpoint, badge,
//! physical domain generation, and live TCB when resolving the expected caller.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplyBindingObservation {
    Free,
    Offered,
    BoundToTarget,
    BoundElsewhere,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiveProbeError<E> {
    Query(E),
    ReplyNotFree,
    UnknownCaller,
    BindingMismatch,
}

/// Reject reuse of an offered or bound Reply object before entering receive.
pub fn require_free_reply<E>(
    observation: Result<ReplyBindingObservation, E>,
) -> Result<(), ReceiveProbeError<E>> {
    match observation.map_err(ReceiveProbeError::Query)? {
        ReplyBindingObservation::Free => Ok(()),
        _ => Err(ReceiveProbeError::ReplyNotFree),
    }
}

/// Return whether this receive retained a Call from its authenticated live caller.
///
/// The first query uses the channel TCB only to distinguish an unbound Reply from a bound one.
/// A bound Reply must then be checked against the resolved caller, even if the first query matched.
/// This allows worker TCBs on a shared endpoint without treating channel membership as authority.
/// Errors leave ownership unresolved; they do not authorize a reply or another receive.
pub fn classify_received_call<T: Copy, E>(
    channel_tcb: T,
    mut query: impl FnMut(T) -> Result<ReplyBindingObservation, E>,
    expected_caller: impl FnOnce() -> Option<T>,
) -> Result<bool, ReceiveProbeError<E>> {
    match query(channel_tcb).map_err(ReceiveProbeError::Query)? {
        ReplyBindingObservation::Free => return Ok(false),
        ReplyBindingObservation::Offered => return Err(ReceiveProbeError::BindingMismatch),
        ReplyBindingObservation::BoundToTarget | ReplyBindingObservation::BoundElsewhere => {}
    }
    let caller = expected_caller().ok_or(ReceiveProbeError::UnknownCaller)?;
    match query(caller).map_err(ReceiveProbeError::Query)? {
        ReplyBindingObservation::BoundToTarget => Ok(true),
        _ => Err(ReceiveProbeError::BindingMismatch),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::cell::Cell;

    #[test]
    fn preflight_accepts_only_free() {
        assert_eq!(
            require_free_reply::<u8>(Ok(ReplyBindingObservation::Free)),
            Ok(())
        );
        for binding in [
            ReplyBindingObservation::Offered,
            ReplyBindingObservation::BoundToTarget,
            ReplyBindingObservation::BoundElsewhere,
        ] {
            assert_eq!(
                require_free_reply::<u8>(Ok(binding)),
                Err(ReceiveProbeError::ReplyNotFree)
            );
        }
        assert_eq!(
            require_free_reply(Err(7u8)),
            Err(ReceiveProbeError::Query(7))
        );
    }

    #[test]
    fn free_receive_does_not_resolve_or_query_again() {
        let queries = Cell::new(0);
        let result = classify_received_call(
            11,
            |target| {
                assert_eq!(target, 11);
                queries.set(queries.get() + 1);
                Ok::<_, u8>(ReplyBindingObservation::Free)
            },
            || panic!("unbound receive has no caller to authenticate"),
        );
        assert_eq!(result, Ok(false));
        assert_eq!(queries.get(), 1);
    }

    #[test]
    fn offered_or_failed_initial_query_does_not_resolve() {
        for (observation, expected) in [
            (
                Ok(ReplyBindingObservation::Offered),
                ReceiveProbeError::BindingMismatch,
            ),
            (Err(9u8), ReceiveProbeError::Query(9)),
        ] {
            let queries = Cell::new(0);
            let result = classify_received_call(
                11,
                |_| {
                    queries.set(queries.get() + 1);
                    observation
                },
                || panic!("unresolved binding must not resolve a caller"),
            );
            assert_eq!(result, Err(expected));
            assert_eq!(queries.get(), 1);
        }
    }

    #[test]
    fn bound_receive_requires_live_caller_even_when_initial_target_matches() {
        for binding in [
            ReplyBindingObservation::BoundToTarget,
            ReplyBindingObservation::BoundElsewhere,
        ] {
            let queries = Cell::new(0);
            let result = classify_received_call(
                11,
                |_| {
                    queries.set(queries.get() + 1);
                    Ok::<_, u8>(binding)
                },
                || None,
            );
            assert_eq!(result, Err(ReceiveProbeError::UnknownCaller));
            assert_eq!(queries.get(), 1);
        }
    }

    #[test]
    fn channel_and_worker_calls_are_checked_against_resolved_caller() {
        for (initial, caller) in [
            (ReplyBindingObservation::BoundToTarget, 11),
            (ReplyBindingObservation::BoundElsewhere, 23),
        ] {
            let queries = Cell::new(0);
            let result = classify_received_call(
                11,
                |target| {
                    let index = queries.get();
                    queries.set(index + 1);
                    match index {
                        0 => {
                            assert_eq!(target, 11);
                            Ok::<_, u8>(initial)
                        }
                        1 => {
                            assert_eq!(target, caller);
                            Ok(ReplyBindingObservation::BoundToTarget)
                        }
                        _ => panic!("classification must not retry"),
                    }
                },
                || Some(caller),
            );
            assert_eq!(result, Ok(true));
            assert_eq!(queries.get(), 2);
        }
    }

    #[test]
    fn second_query_mismatch_or_error_never_retries_or_classifies_no_call() {
        for initial in [
            ReplyBindingObservation::BoundToTarget,
            ReplyBindingObservation::BoundElsewhere,
        ] {
            for (second, expected) in [
                (
                    Ok(ReplyBindingObservation::Free),
                    ReceiveProbeError::BindingMismatch,
                ),
                (
                    Ok(ReplyBindingObservation::Offered),
                    ReceiveProbeError::BindingMismatch,
                ),
                (
                    Ok(ReplyBindingObservation::BoundElsewhere),
                    ReceiveProbeError::BindingMismatch,
                ),
                (Err(3u8), ReceiveProbeError::Query(3)),
            ] {
                let queries = Cell::new(0);
                let result = classify_received_call(
                    11,
                    |target| {
                        let index = queries.get();
                        queries.set(index + 1);
                        match index {
                            0 => {
                                assert_eq!(target, 11);
                                Ok(initial)
                            }
                            1 => {
                                assert_eq!(target, 23);
                                second
                            }
                            _ => panic!("classification must not retry"),
                        }
                    },
                    || Some(23),
                );
                assert_eq!(result, Err(expected));
                assert_eq!(queries.get(), 2);
            }
        }
    }
}
