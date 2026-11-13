//! A refused provider Timer operation reports why. The win32k Ke*Timer exports have no
//! failure result, so this status is all a terminal report can say about the cause.

use nt_provider_wait::ProviderTimerError;

const STATUS_INVALID_PARAMETER: u32 = 0xC000_000D;
const STATUS_DELETE_PENDING: u32 = 0xC000_0056;
const STATUS_INSUFFICIENT_RESOURCES: u32 = 0xC000_009A;

#[test]
fn exhaustion_is_reported_as_insufficient_resources() {
    for error in [
        ProviderTimerError::NoCapacity,
        ProviderTimerError::IdentityExhausted,
        ProviderTimerError::LeaseOverflow,
    ] {
        assert_eq!(error.nt_status(), STATUS_INSUFFICIENT_RESOURCES, "{error:?}");
    }
}

#[test]
fn a_timer_being_retired_is_reported_as_delete_pending() {
    assert_eq!(ProviderTimerError::DeletePending.nt_status(), STATUS_DELETE_PENDING);
}

#[test]
fn identity_and_argument_errors_stay_invalid_parameter() {
    for error in [
        ProviderTimerError::InvalidProvider,
        ProviderTimerError::InvalidIdentity,
        ProviderTimerError::NotFound,
        ProviderTimerError::StaleIdentity,
        ProviderTimerError::NotPublished,
        ProviderTimerError::AlreadyPublished,
    ] {
        assert_eq!(error.nt_status(), STATUS_INVALID_PARAMETER, "{error:?}");
    }
}
