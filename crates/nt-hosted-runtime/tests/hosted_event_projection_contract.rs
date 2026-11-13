//! A native driver Event body is owned by one domain and one pool generation.

use nt_hosted_runtime::{HostedEventProjectionKey, HostedEventProjectionLifetime,
    HostedEventWaitDelivery};

#[test]
fn event_pointer_release_and_reclaim_require_exact_owner_and_generation() {
    let key = HostedEventProjectionKey::new(7, 70, 0x1000, 91,
        0x2000, 101).unwrap();
    assert!(key.matches(7, 70, 0x1000, 91, 0x2000, 101));
    assert!(!key.matches(7, 71, 0x1000, 91, 0x2000, 101));
    assert!(!key.matches(7, 70, 0x1000, 92, 0x2000, 101));
    assert!(!key.matches(7, 70, 0x1000, 91, 0x2000, 102));
    assert!(!key.matches(7, 70, 0x1000, 91, 0x3000, 101));
    assert!(HostedEventProjectionKey::new(0, 70, 0x1000, 91, 0x2000, 101).is_none());
    assert!(HostedEventProjectionKey::new(7, 70, 0x1000, 91, 0, 101).is_none());
}

#[test]
fn parked_wait_and_unacknowledged_dereference_hold_projected_body() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert!(lifetime.retain_wait());
    assert!(lifetime.begin_dereference());
    assert!(!lifetime.retirable());
    assert!(lifetime.acknowledge_dereference());
    assert!(!lifetime.retirable());
    assert!(lifetime.release_wait());
    assert!(lifetime.retirable());
    assert!(!lifetime.retain_reference());
    assert!(!lifetime.acknowledge_dereference());
}

#[test]
fn last_reference_waits_for_dereference_ack_even_without_waiters() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert!(lifetime.begin_dereference());
    assert!(!lifetime.retirable());
    assert!(lifetime.acknowledge_dereference());
    assert!(lifetime.retirable());
}

#[test]
fn uncertain_wait_reply_reconciles_without_reissuing_reply() {
    let mut delivery = HostedEventWaitDelivery::new();
    assert!(delivery.select());
    assert!(delivery.enter_reply());
    assert!(!delivery.enter_reply());
    assert!(!delivery.reconcile(false));
    assert!(!delivery.retirable());
    assert!(delivery.reconcile(true));
    assert!(delivery.retirable());
    assert!(!delivery.enter_reply());
}

#[test]
fn sealed_cancellation_retires_wait_without_reply_replay() {
    let mut delivery = HostedEventWaitDelivery::new();
    assert!(delivery.select());
    assert!(delivery.enter_reply());
    assert!(!delivery.cancel(false));
    assert!(!delivery.retirable());
    assert!(delivery.cancel(true));
    assert!(delivery.retirable());
    assert!(!delivery.enter_reply());
}

#[test]
fn parked_wait_can_resurrect_exact_body_after_last_reference_ack() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert!(lifetime.retain_wait());
    assert!(lifetime.begin_dereference());
    assert!(!lifetime.retain_reference()); // Pending ACK fences resurrection.
    assert!(lifetime.acknowledge_dereference());
    assert!(lifetime.retain_reference()); // Same pinned body and exact owner remain live.
    assert_eq!(lifetime.references(), 1);
    assert!(lifetime.release_wait());
    assert!(!lifetime.retirable());
}

#[test]
fn concurrent_dereference_ack_reports_current_reference_count() {
    let mut lifetime = HostedEventProjectionLifetime::new().unwrap();
    assert!(lifetime.retain_reference());
    assert!(lifetime.retain_reference());
    assert!(lifetime.begin_dereference());
    let first_reply_count = lifetime.references();
    assert!(lifetime.begin_dereference());
    assert_ne!(first_reply_count, lifetime.references());
    assert_eq!(lifetime.complete_dereference_ack(), Some(1));
    assert_eq!(lifetime.complete_dereference_ack(), Some(1));
}
