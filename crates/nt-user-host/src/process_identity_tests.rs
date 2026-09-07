use super::*;

#[test]
fn claim_and_exact_release_preserve_pid_and_lifetime() {
    let mut slots = TemporaryProcessSlots::try_new(3).unwrap();
    let claim = slots.claim(2, 90).unwrap();
    assert_eq!(claim.pi(), 2);
    assert_eq!(claim.pid(), 90);
    assert!(claim.identity().is_valid());
    assert!(matches!(
        claim.identity().generation,
        ProcessGeneration::Temporary(_)
    ));
    assert_eq!(slots.get(2), Some(claim));
    assert_eq!(slots.pi_for_pid(90), Some(2));
    assert_eq!(slots.pi_for_pid(0), None);
    slots.release_exact(claim).unwrap();
    assert_eq!(slots.get(2), None);
    assert_eq!(slots.pi_for_pid(90), None);
    assert_eq!(
        slots.release_exact(claim),
        Err(TemporaryProcessError::StaleClaim)
    );
}

#[test]
fn invalid_claim_does_not_consume_generation_or_change_slots() {
    let mut slots = TemporaryProcessSlots::try_new(2).unwrap();
    let counter = AtomicU64::new(1);
    assert_eq!(
        slots.claim_with_counter(2, 90, &counter),
        Err(TemporaryProcessError::OutOfRange)
    );
    assert_eq!(
        slots.claim_with_counter(0, 0, &counter),
        Err(TemporaryProcessError::InvalidPid)
    );
    assert_eq!(counter.load(Ordering::Relaxed), 1);
    assert_eq!(slots.get(0), None);
    assert_eq!(slots.get(1), None);
}

#[test]
fn occupied_slots_and_duplicate_pids_cannot_be_rebound() {
    let mut slots = TemporaryProcessSlots::try_new(2).unwrap();
    let counter = AtomicU64::new(1);
    let claim = slots.claim_with_counter(0, 90, &counter).unwrap();
    for pid in [90, 91] {
        assert_eq!(
            slots.claim_with_counter(0, pid, &counter),
            Err(TemporaryProcessError::Occupied)
        );
    }
    assert_eq!(
        slots.claim_with_counter(1, 90, &counter),
        Err(TemporaryProcessError::DuplicatePid)
    );
    assert_eq!(slots.get(0), Some(claim));
    assert_eq!(slots.get(1), None);
    assert_eq!(counter.load(Ordering::Relaxed), 2);
}

#[test]
fn same_pid_and_slot_reuse_gets_a_distinct_lifetime() {
    let mut slots = TemporaryProcessSlots::try_new(1).unwrap();
    let old = slots.claim(0, 90).unwrap();
    slots.release_exact(old).unwrap();
    let new = slots.claim(0, 90).unwrap();
    assert_ne!(old.identity(), new.identity());
    assert_eq!(
        slots.release_exact(old),
        Err(TemporaryProcessError::StaleClaim)
    );
    assert_eq!(slots.get(0), Some(new));
    slots.release_exact(new).unwrap();
}

#[test]
fn recreated_tables_do_not_restart_lifetime_identity() {
    let old = TemporaryProcessSlots::try_new(1)
        .unwrap()
        .claim(0, 90)
        .unwrap();
    let mut slots = TemporaryProcessSlots::try_new(1).unwrap();
    let new = slots.claim(0, 90).unwrap();
    assert_ne!(old, new);
    assert_eq!(
        slots.release_exact(old),
        Err(TemporaryProcessError::StaleClaim)
    );
    assert_eq!(slots.get(0), Some(new));
}

#[test]
fn exact_release_rejects_changed_pid_generation_or_slot_without_mutation() {
    let mut slots = TemporaryProcessSlots::try_new(2).unwrap();
    let owner = slots.claim(0, 90).unwrap();
    let other = slots.claim(1, 91).unwrap();
    for changed in [
        TemporaryProcessClaim { pid: 91, ..owner },
        TemporaryProcessClaim {
            generation: owner.generation + 1,
            ..owner
        },
        TemporaryProcessClaim { pi: 1, ..owner },
    ] {
        assert_eq!(
            slots.release_exact(changed),
            Err(TemporaryProcessError::StaleClaim)
        );
        assert_eq!(slots.get(0), Some(owner));
        assert_eq!(slots.get(1), Some(other));
    }
    assert_eq!(
        slots.release_exact(TemporaryProcessClaim { pi: 2, ..owner }),
        Err(TemporaryProcessError::OutOfRange)
    );
}

#[test]
fn generation_exhaustion_never_wraps_or_publishes_an_owner() {
    let mut slots = TemporaryProcessSlots::try_new(2).unwrap();
    let counter = AtomicU64::new(u64::MAX - 1);
    let last = slots.claim_with_counter(0, 90, &counter).unwrap();
    assert_eq!(last.generation, u64::MAX - 1);
    for _ in 0..3 {
        assert_eq!(
            slots.claim_with_counter(1, 91, &counter),
            Err(TemporaryProcessError::InsufficientResources)
        );
        assert_eq!(slots.get(0), Some(last));
        assert_eq!(slots.get(1), None);
        assert_eq!(counter.load(Ordering::Relaxed), u64::MAX);
    }
    slots.release_exact(last).unwrap();
    assert_eq!(
        slots.claim_with_counter(0, 90, &counter),
        Err(TemporaryProcessError::InsufficientResources)
    );
    assert_eq!(slots.get(0), None);
}

#[test]
fn invalid_zero_counter_does_not_publish_a_zero_generation() {
    let mut slots = TemporaryProcessSlots::try_new(1).unwrap();
    let counter = AtomicU64::new(0);
    assert_eq!(
        slots.claim_with_counter(0, 90, &counter),
        Err(TemporaryProcessError::InsufficientResources)
    );
    assert_eq!(slots.get(0), None);
    assert_eq!(counter.load(Ordering::Relaxed), 0);
}

#[test]
fn process_generation_domains_are_distinct_and_zero_is_invalid() {
    assert_ne!(
        ProcessGeneration::Hosted(7),
        ProcessGeneration::Temporary(7)
    );
    for generation in [
        ProcessGeneration::Hosted(0),
        ProcessGeneration::Temporary(0),
    ] {
        assert!(!ProcessIdentity {
            pid: 90,
            generation
        }
        .is_valid());
    }
    for generation in [
        ProcessGeneration::Hosted(7),
        ProcessGeneration::Temporary(7),
    ] {
        assert!(ProcessIdentity {
            pid: 90,
            generation
        }
        .is_valid());
        assert!(!ProcessIdentity { pid: 0, generation }.is_valid());
    }
    assert!(!ProcessIdentity::empty().is_valid());
}

#[test]
fn table_capacity_failure_is_reported_before_claim_admission() {
    assert!(matches!(
        TemporaryProcessSlots::try_new(usize::MAX),
        Err(TemporaryProcessError::InsufficientResources)
    ));
    assert_eq!(
        TemporaryProcessSlots::try_new(0).unwrap().claim(0, 90),
        Err(TemporaryProcessError::OutOfRange)
    );
}

fn hosted() -> crate::ProcessMechanism {
    crate::ProcessMechanism {
        pi: 2,
        pid: 90,
        generation: 7,
        ..Default::default()
    }
}

#[test]
fn thread_provenance_resolves_one_exact_authority() {
    assert_eq!(
        resolve_thread_process_identity(2, 90, Some(hosted()), None),
        Some(ProcessIdentity {
            pid: 90,
            generation: ProcessGeneration::Hosted(7)
        })
    );
    let temporary = TemporaryProcessSlots::try_new(3)
        .unwrap()
        .claim(2, 90)
        .unwrap();
    assert_eq!(
        resolve_thread_process_identity(2, 90, None, Some(temporary)),
        Some(temporary.identity())
    );
    assert_eq!(resolve_thread_process_identity(2, 90, None, None), None);
}

#[test]
fn ambiguous_process_authorities_are_not_a_fallback() {
    let temporary = TemporaryProcessSlots::try_new(3)
        .unwrap()
        .claim(2, 90)
        .unwrap();
    for owner in [
        hosted(),
        crate::ProcessMechanism {
            generation: 0,
            ..hosted()
        },
    ] {
        assert_eq!(
            resolve_thread_process_identity(2, 90, Some(owner), Some(temporary)),
            None
        );
    }
}

#[test]
fn thread_provenance_rejects_wrong_slot_and_thread_pid() {
    let temporary = TemporaryProcessSlots::try_new(3)
        .unwrap()
        .claim(2, 90)
        .unwrap();
    for (pi, pid) in [(1, 90), (2, 91), (2, 0)] {
        assert_eq!(
            resolve_thread_process_identity(pi, pid, Some(hosted()), None),
            None
        );
        assert_eq!(
            resolve_thread_process_identity(pi, pid, None, Some(temporary)),
            None
        );
    }
    for owner in [
        crate::ProcessMechanism { pid: 0, ..hosted() },
        crate::ProcessMechanism {
            generation: 0,
            ..hosted()
        },
    ] {
        assert_eq!(
            resolve_thread_process_identity(2, owner.pid, Some(owner), None),
            None
        );
    }
}
