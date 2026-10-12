use super::writeback_owner::{BatchResult, RegistryWritebackOwner, WritebackError};

#[test]
fn mutations_coalesce_into_one_batch_and_new_writes_stay_dirty() {
    let mut owner = RegistryWritebackOwner::new(7);
    let first = owner.record_mutation().unwrap();
    owner.record_mutation().unwrap();
    let batch = owner.begin_batch().unwrap().unwrap();
    let later = owner.record_mutation().unwrap();
    assert_eq!(owner.begin_batch(), Err(WritebackError::InFlight));
    owner.complete(batch, BatchResult::Durable).unwrap();
    assert!(owner.is_durable(first));
    assert!(!owner.is_durable(later));
    assert_eq!(owner.begin_batch().unwrap().unwrap().generation(), later);
}

#[test]
fn explicit_flush_waits_for_its_captured_generation() {
    let mut owner = RegistryWritebackOwner::new(9);
    let target = owner.flush_target();
    assert!(owner.is_durable(target));
    owner.record_mutation().unwrap();
    let target = owner.flush_target();
    let batch = owner.begin_batch().unwrap().unwrap();
    assert!(!owner.is_durable(target));
    owner.complete(batch, BatchResult::Durable).unwrap();
    assert!(owner.is_durable(target));
}

#[test]
fn uncertain_effect_retains_exact_batch_and_prevents_replay() {
    let mut owner = RegistryWritebackOwner::new(11);
    let target = owner.record_mutation().unwrap();
    let batch = owner.begin_batch().unwrap().unwrap();
    owner.complete(batch, BatchResult::Uncertain).unwrap();
    assert_eq!(owner.begin_batch(), Err(WritebackError::Uncertain));
    assert!(!owner.is_durable(target));
    assert_eq!(owner.pending_batch(), Some(batch));
    assert_eq!(owner.complete(batch, BatchResult::NoEffect), Err(WritebackError::Uncertain));
    owner.complete(batch, BatchResult::Durable).unwrap();
    assert!(owner.is_durable(target));
}

#[test]
fn proven_no_effect_can_retry_and_old_ack_is_rejected() {
    let mut owner = RegistryWritebackOwner::new(13);
    owner.record_mutation().unwrap();
    let first = owner.begin_batch().unwrap().unwrap();
    owner.complete(first, BatchResult::NoEffect).unwrap();
    let second = owner.begin_batch().unwrap().unwrap();
    assert_ne!(first, second);
    assert_eq!(owner.complete(first, BatchResult::Durable), Err(WritebackError::StaleBatch));
    owner.complete(second, BatchResult::Durable).unwrap();
    assert!(!owner.is_dirty());
}

#[test]
fn stale_mount_and_retirement_cannot_discard_dirty_ownership() {
    let mut owner = RegistryWritebackOwner::new(15);
    owner.record_mutation().unwrap();
    assert_eq!(owner.retire(), Err(WritebackError::Dirty));
    let batch = owner.begin_batch().unwrap().unwrap();
    assert_eq!(owner.retire(), Err(WritebackError::InFlight));
    let mut replacement = RegistryWritebackOwner::new(16);
    assert!(!replacement.is_durable(owner.flush_target()));
    replacement.record_mutation().unwrap();
    let current = replacement.begin_batch().unwrap().unwrap();
    assert_eq!(replacement.complete(batch, BatchResult::Durable), Err(WritebackError::StaleBatch));
    replacement.complete(current, BatchResult::Durable).unwrap();
    assert_eq!(replacement.retire(), Ok(()));
}
