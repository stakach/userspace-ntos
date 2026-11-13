//! The stopped source may not cause a new provider POWER effect or release a live callback.

use nt_io_manager::power_forward_cancel::{decision, PowerForwardDecision, PowerForwardProgress};

#[test]
fn stopped_before_reply_prevents_provider_entry_and_releases_unentered_source() {
    let progress = PowerForwardProgress {
        cancelled: true, reply_entered: false, source_published: false,
        native_completed: false,
    };
    assert_eq!(decision(progress), PowerForwardDecision::RetireStoppedSource);
}

#[test]
fn stopped_after_reply_retains_source_until_trusted_native_completion() {
    let mut progress = PowerForwardProgress {
        cancelled: true, reply_entered: true, source_published: true,
        native_completed: false,
    };
    assert_eq!(decision(progress), PowerForwardDecision::RetainLiveCallback);
    progress.native_completed = true;
    assert_eq!(decision(progress), PowerForwardDecision::RetireAfterNativeCompletion);
}

#[test]
fn stopped_rejection_reply_has_no_native_callback_to_wait_for() {
    let progress = PowerForwardProgress {
        cancelled: true, reply_entered: true, source_published: false,
        native_completed: false,
    };
    assert_eq!(decision(progress), PowerForwardDecision::RetireStoppedSource);
}

#[test]
fn active_source_is_the_only_state_that_may_dispatch() {
    let progress = PowerForwardProgress {
        cancelled: false, reply_entered: false, source_published: false,
        native_completed: false,
    };
    assert_eq!(decision(progress), PowerForwardDecision::MayDispatch);
}
