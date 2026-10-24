use nt_kernel_exec::hosted_kmutex::{initial_header, HostedKmutexManager, KmutexError, KmutexWait};

#[test]
fn initialized_x64_header_is_a_signaled_mutant() {
    let bytes = initial_header(0x1000);
    assert_eq!(bytes.len(), 0x38);
    assert_eq!(bytes[0], 2);
    assert_eq!(bytes[2], 14);
    assert_eq!(i32::from_le_bytes(bytes[4..8].try_into().unwrap()), 1);
    assert_eq!(u64::from_le_bytes(bytes[8..16].try_into().unwrap()), 0x1008);
    assert_eq!(u64::from_le_bytes(bytes[0x28..0x30].try_into().unwrap()), 0);
    assert_eq!(bytes[0x30], 0);
    assert_eq!(bytes[0x31], 1);
}

#[test]
fn initialized_mutex_acquires_recursively_and_wakes_other_owner_on_final_release() {
    let mut manager = HostedKmutexManager::new();
    let key = manager.initialize((7, 11), 0x1000).unwrap();
    assert_eq!(manager.wait(key, 21).unwrap(), KmutexWait::Acquired { count: 0 });
    assert_eq!(manager.wait(key, 21).unwrap(), KmutexWait::Acquired { count: -1 });
    assert_eq!(manager.wait(key, 22).unwrap(), KmutexWait::Busy);
    assert_eq!(manager.release(key, 22), Err(KmutexError::NotOwned));
    assert_eq!(manager.release(key, 21).unwrap(), -1);
    assert_eq!(manager.wait(key, 22).unwrap(), KmutexWait::Busy);
    assert_eq!(manager.release(key, 21).unwrap(), 0);
    assert_eq!(manager.wait(key, 22).unwrap(), KmutexWait::Acquired { count: 0 });
}

#[test]
fn reinitialization_cannot_replay_a_waiting_generation() {
    let mut manager = HostedKmutexManager::new();
    let first = manager.initialize((7, 11), 0x1000).unwrap();
    assert_eq!(manager.wait(first, 21).unwrap(), KmutexWait::Acquired { count: 0 });
    assert_eq!(manager.initialize((7, 11), 0x1000), Err(KmutexError::Busy));
    assert_eq!(manager.release(first, 21).unwrap(), 0);
    let second = manager.initialize((7, 11), 0x1000).unwrap();
    assert_ne!(first, second);
    assert_eq!(manager.wait(first, 22), Err(KmutexError::Stale));
    assert_eq!(manager.wait(second, 22).unwrap(), KmutexWait::Acquired { count: 0 });
}

#[test]
fn pool_free_waits_for_owner_and_revokes_the_exact_allocation_generation() {
    let mut manager = HostedKmutexManager::new();
    let domain = (7, 11);
    let pool = (0x2000, 9);
    let key = manager.initialize_with_pool(domain, 0x2010, Some(pool)).unwrap();
    assert_eq!(manager.wait(key, 21).unwrap(), KmutexWait::Acquired { count: 0 });
    assert!(!manager.pool_free_admission(domain, pool));
    assert_eq!(manager.release(key, 21).unwrap(), 0);
    assert!(manager.pool_free_admission(domain, pool));
    manager.retire_pool(domain, pool).unwrap();
    assert_eq!(manager.wait(key, 21), Err(KmutexError::Stale));
    assert!(manager.pool_free_admission(domain, (0x2000, 10)));
}
