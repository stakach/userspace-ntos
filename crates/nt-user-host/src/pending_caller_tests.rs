use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::provider_logical_caller::ProviderCallerError;
use crate::thread_binding::ThreadBinding;
use nt_process::ProcessManager;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Key {
    table: u64,
    slot: usize,
    generation: u64,
}

fn key(slot: usize) -> Key {
    Key {
        table: 1,
        slot,
        generation: 1,
    }
}

fn caller() -> (ProcessManager, ThreadBinding<()>, ProviderLogicalCaller) {
    let mut pm = ProcessManager::new();
    let pid = pm.create_process("host.exe", None, None);
    pm.create_thread(pid, 0x1000, 0, false).unwrap();
    let tid = pm.create_thread(pid, 0x2000, 0, false).unwrap();
    let binding = ThreadBinding {
        pi: 2,
        process: ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(3),
        },
        tid: u64::from(tid),
        badge: 4,
        role: (),
        tcb: 8,
        reservations: None,
    };
    let caller = ProviderLogicalCaller::capture(binding, pm.thread_lifetime(tid).unwrap()).unwrap();
    (pm, binding, caller)
}

#[test]
fn reserve_publish_and_removal_enforce_exact_phases() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let key = key(0);
    assert!(table.is_empty());
    assert_eq!(table.reserve(0, key, caller), Ok(()));
    assert!(!table.is_empty());
    assert_eq!(table.get_reserved(0, key), Some(caller));
    assert_eq!(table.get_published(0, key), None);
    assert_eq!(
        table.retire_published(0, key),
        Err(PendingCallerError::InvalidPhase)
    );
    assert_eq!(table.publish(0, key), Ok(caller));
    assert_eq!(table.get_reserved(0, key), None);
    assert_eq!(table.get_published(0, key), Some(caller));
    assert_eq!(table.publish(0, key), Err(PendingCallerError::InvalidPhase));
    assert_eq!(
        table.cancel_reserved(0, key),
        Err(PendingCallerError::InvalidPhase)
    );
    assert_eq!(table.retire_published(0, key), Ok(caller));
    assert!(table.is_empty());
    assert_eq!(table.get_published(0, key), None);
    assert_eq!(
        table.retire_published(0, key),
        Err(PendingCallerError::WrongKey)
    );
}

#[test]
fn failed_or_cancelled_publication_does_not_replace_provenance() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let original = key(2);
    let replacement = Key {
        generation: 2,
        ..original
    };
    table.reserve(2, original, caller).unwrap();
    assert_eq!(
        table.reserve(2, replacement, caller),
        Err(PendingCallerError::Occupied)
    );
    assert_eq!(table.get_reserved(2, original), Some(caller));
    assert_eq!(table.get_reserved(2, replacement), None);
    assert_eq!(table.cancel_reserved(2, original), Ok(caller));
    assert_eq!(
        table.publish(2, original),
        Err(PendingCallerError::WrongKey)
    );
    table.reserve(2, replacement, caller).unwrap();
    table.publish(2, replacement).unwrap();
    assert_eq!(
        table.reserve(2, original, caller),
        Err(PendingCallerError::Occupied)
    );
    assert_eq!(table.get_published(2, replacement), Some(caller));
}

#[test]
fn stale_foreign_or_wrong_slot_keys_cannot_observe_or_mutate_owner() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let original = key(2);
    table.reserve(2, original, caller).unwrap();
    let wrong = [
        Key {
            table: 2,
            ..original
        },
        Key {
            generation: 2,
            ..original
        },
        Key {
            slot: 3,
            ..original
        },
    ];
    for key in wrong {
        assert_eq!(table.get_reserved(2, key), None);
        assert_eq!(table.publish(2, key), Err(PendingCallerError::WrongKey));
        assert_eq!(
            table.cancel_reserved(2, key),
            Err(PendingCallerError::WrongKey)
        );
    }
    assert_eq!(
        table.publish(3, original),
        Err(PendingCallerError::WrongKey)
    );
    assert_eq!(
        table.publish(usize::MAX, original),
        Err(PendingCallerError::WrongKey)
    );
    table.publish(2, original).unwrap();
    for key in wrong {
        assert_eq!(table.get_published(2, key), None);
        assert_eq!(
            table.retire_published(2, key),
            Err(PendingCallerError::WrongKey)
        );
    }
    assert_eq!(table.get_published(2, original), Some(caller));
}

#[test]
fn generation_reuse_with_identical_caller_does_not_authorize_old_key() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let old = key(0);
    let new = Key {
        generation: 2,
        ..old
    };
    table.reserve(0, old, caller).unwrap();
    table.publish(0, old).unwrap();
    table.retire_published(0, old).unwrap();
    table.reserve(0, new, caller).unwrap();
    assert_eq!(
        table.cancel_reserved(0, old),
        Err(PendingCallerError::WrongKey)
    );
    assert_eq!(table.publish(0, old), Err(PendingCallerError::WrongKey));
    table.publish(0, new).unwrap();
    assert_eq!(table.get_published(0, old), None);
    assert_eq!(
        table.retire_published(0, old),
        Err(PendingCallerError::WrongKey)
    );
    assert_eq!(table.get_published(0, new), Some(caller));
}

#[test]
fn publication_and_removal_reuse_reserved_storage() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let key = key(31);
    table.reserve(31, key, caller).unwrap();
    let capacity = table.capacity();
    let storage = table.entries.as_ptr();
    assert_eq!(table.publish(31, key), Ok(caller));
    assert_eq!(table.capacity(), capacity);
    assert_eq!(table.entries.as_ptr(), storage);
    assert_eq!(table.entries.len(), 32);
    assert_eq!(table.retire_published(31, key), Ok(caller));
    assert_eq!(table.capacity(), capacity);
    assert_eq!(table.entries.as_ptr(), storage);
    assert!(table.entries.iter().all(Option::is_none));
}

#[test]
fn moves_preserve_owners_and_reset_refuses_both_live_phases() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let old = key(0);
    table.reserve(0, old, caller).unwrap();
    assert!(!table.reset());
    let mut moved = alloc::boxed::Box::new(table);
    assert_eq!(moved.get_reserved(0, old), Some(caller));
    moved.publish(0, old).unwrap();
    assert!(!moved.reset());
    assert_eq!(moved.get_published(0, old), Some(caller));
    moved.retire_published(0, old).unwrap();
    let capacity = moved.capacity();
    assert!(moved.reset());
    assert_eq!(moved.capacity(), capacity);
    assert!(moved.entries.is_empty());
    let new = Key {
        generation: 2,
        ..old
    };
    moved.reserve(0, new, caller).unwrap();
    assert_eq!(moved.publish(0, old), Err(PendingCallerError::WrongKey));
    assert_eq!(moved.get_reserved(0, new), Some(caller));
}

#[test]
fn impossible_slot_bounds_fail_without_allocating_or_disturbing_live_owners() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    assert_eq!(
        table.reserve(usize::MAX, key(usize::MAX), caller),
        Err(PendingCallerError::InvalidSlot)
    );
    assert_eq!(
        table.reserve(usize::MAX - 1, key(usize::MAX - 1), caller),
        Err(PendingCallerError::AllocationFailed)
    );
    assert_eq!(table.capacity(), 0);
    assert!(table.entries.is_empty());
    table.reserve(0, key(0), caller).unwrap();
    let capacity = table.capacity();
    let storage = table.entries.as_ptr();
    assert_eq!(
        table.reserve(usize::MAX - 1, key(usize::MAX - 1), caller),
        Err(PendingCallerError::AllocationFailed)
    );
    assert_eq!(table.capacity(), capacity);
    assert_eq!(table.entries.as_ptr(), storage);
    assert_eq!(table.get_reserved(0, key(0)), Some(caller));
}

#[test]
fn publication_retains_original_thread_lifetime_even_if_coordinates_are_reused() {
    let (mut pm, binding, original) = caller();
    let mut table = PendingCallerTable::new();
    let key = key(0);
    table.reserve(0, key, original).unwrap();
    let tid = binding.tid as u32;
    pm.terminate_thread(tid, 0).unwrap();
    let plan = pm
        .prepare_thread_activation(tid, 0x3000, 0, false, 0x7000, 0, false)
        .unwrap();
    pm.commit_thread_activation(plan).unwrap();
    let replacement_thread = pm.thread_lifetime(tid).unwrap();
    let replacement = ProviderLogicalCaller::capture(binding, replacement_thread).unwrap();
    assert_eq!(original.pi(), replacement.pi());
    assert_eq!(original.badge(), replacement.badge());
    assert_eq!(original.tcb(), replacement.tcb());
    assert_eq!(
        original.thread().thread_id(),
        replacement.thread().thread_id()
    );
    assert_ne!(original.thread(), replacement.thread());
    assert_eq!(table.publish(0, key), Ok(original));
    let retained = table.get_published(0, key).unwrap();
    assert_eq!(
        retained.validate(Some(binding), Some(replacement_thread)),
        Err(ProviderCallerError::LifetimeChanged)
    );
    assert_eq!(
        replacement.validate(Some(binding), Some(replacement_thread)),
        Ok(())
    );
    assert_eq!(table.retire_published(0, key), Ok(original));
}

#[test]
fn zero_process_slot_and_badge_do_not_make_captured_provenance_empty() {
    let (pm, mut binding, _) = caller();
    binding.pi = 0;
    binding.badge = 0;
    let caller =
        ProviderLogicalCaller::capture(binding, pm.thread_lifetime(binding.tid as u32).unwrap())
            .unwrap();
    let mut table = PendingCallerTable::new();
    table.reserve(0, key(0), caller).unwrap();
    table.publish(0, key(0)).unwrap();
    assert!(!table.is_empty());
    assert_eq!(table.get_published(0, key(0)), Some(caller));
}

#[test]
fn retargeting_external_irp_does_not_change_owner_key_or_original_caller() {
    let (_, _, caller) = caller();
    let mut table = PendingCallerTable::new();
    let mut operation = (key(0), 100u64);
    table.reserve(0, operation.0, caller).unwrap();
    table.publish(0, operation.0).unwrap();
    for irp in [101, 102] {
        operation.1 = irp;
        assert_eq!(table.get_published(0, operation.0), Some(caller));
        assert_eq!(operation.1, irp);
    }
    assert_eq!(table.retire_published(0, operation.0), Ok(caller));
}
