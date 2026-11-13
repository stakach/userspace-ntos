use nt_user_host::hosted_priority::hosted_tcb_priority;

#[test]
fn default_nt_priority_competes_with_provider_and_full_range_is_ordered() {
    assert_eq!(hosted_tcb_priority(13), Ok(100));
    let mapped: Vec<u8> = (0..=31).map(|priority| hosted_tcb_priority(priority).unwrap()).collect();
    assert!(mapped.windows(2).all(|pair| pair[0] < pair[1]));
    assert_eq!(hosted_tcb_priority(-1), Err(nt_process::STATUS_INVALID_PARAMETER));
    assert_eq!(hosted_tcb_priority(32), Err(nt_process::STATUS_INVALID_PARAMETER));
}
