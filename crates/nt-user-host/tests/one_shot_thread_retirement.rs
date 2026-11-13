use nt_user_host::one_shot_thread_retirement::OneShotThreadRetirement;

#[test]
fn one_shot_tcb_requires_acknowledged_suspend_before_retirement() {
    assert!(OneShotThreadRetirement::new(0).is_none());
    assert!(OneShotThreadRetirement::new(1).is_none());
    let mut owner = OneShotThreadRetirement::new(733).unwrap();
    assert_eq!(owner.retirement_request(), None);
    assert_eq!(owner.suspension_request(), Some(733));
    assert_eq!(owner.suspension_request(), None);
    assert_eq!(owner.retirement_request(), None);
    assert!(!owner.acknowledge_suspension(false));
    assert_eq!(owner.suspension_request(), None);
    assert_eq!(owner.retirement_request(), None);
    assert!(owner.acknowledge_suspension(true));
    assert_eq!(owner.retirement_request(), Some(733));
    assert_eq!(owner.retirement_request(), None);
    assert!(!owner.acknowledge_retirement(false));
    assert_eq!(owner.retirement_request(), None);
    assert!(owner.acknowledge_retirement(true));
    assert!(owner.is_retired());
}
