use super::*;

fn binding() -> ThreadBinding<u32> {
    ThreadBinding {
        pi: 27,
        tid: 301,
        badge: 90,
        role: 3,
        tcb: 100,
    }
}

fn plan(
    requested: ThreadBinding<u32>,
    owner: ThreadBinding<u32>,
) -> Result<ThreadBindingAdmission, ThreadBindingError> {
    admit_thread_binding(requested, [(7, owner)])
}

#[test]
fn empty_table_inserts_both_reservation_and_real_binding() {
    for tcb in [1, 100] {
        assert_eq!(
            admit_thread_binding(ThreadBinding { tcb, ..binding() }, []),
            Ok(ThreadBindingAdmission::Insert)
        );
    }
}

#[test]
fn exact_reservation_and_registered_replays_preserve_the_owner_slot() {
    for tcb in [1, 100] {
        let owner = ThreadBinding { tcb, ..binding() };
        assert_eq!(
            plan(owner, owner),
            Ok(ThreadBindingAdmission::Replay { index: 7 })
        );
    }
}

#[test]
fn only_an_exact_reservation_can_be_promoted() {
    let owner = ThreadBinding {
        tcb: 1,
        ..binding()
    };
    assert_eq!(
        plan(binding(), owner),
        Ok(ThreadBindingAdmission::Promote { index: 7 })
    );
    for requested in [
        ThreadBinding {
            pi: 28,
            ..binding()
        },
        ThreadBinding {
            badge: 91,
            ..binding()
        },
        ThreadBinding {
            role: 4,
            ..binding()
        },
    ] {
        assert_eq!(
            plan(requested, owner),
            Err(ThreadBindingError::IdentityConflict)
        );
    }
}

#[test]
fn live_tcb_cannot_be_replaced_or_demoted_to_a_reservation() {
    for tcb in [1, 101] {
        assert_eq!(
            plan(ThreadBinding { tcb, ..binding() }, binding()),
            Err(ThreadBindingError::TcbConflict)
        );
    }
}

#[test]
fn same_tid_cannot_move_process_role_or_badge() {
    for requested in [
        ThreadBinding {
            pi: 28,
            ..binding()
        },
        ThreadBinding {
            badge: 91,
            ..binding()
        },
        ThreadBinding {
            role: 4,
            ..binding()
        },
    ] {
        assert_eq!(
            plan(requested, binding()),
            Err(ThreadBindingError::IdentityConflict)
        );
    }
}

#[test]
fn another_tid_cannot_claim_a_live_routing_or_mechanism_identity() {
    let other = ThreadBinding {
        pi: 28,
        tid: 302,
        badge: 91,
        role: 4,
        tcb: 101,
    };
    for tcb in [1, 100] {
        let owner = ThreadBinding { tcb, ..binding() };
        assert_eq!(
            plan(
                ThreadBinding {
                    badge: owner.badge,
                    ..other
                },
                owner
            ),
            Err(ThreadBindingError::BadgeConflict)
        );
        assert_eq!(
            plan(
                ThreadBinding {
                    pi: owner.pi,
                    role: owner.role,
                    ..other
                },
                owner
            ),
            Err(ThreadBindingError::RoleConflict)
        );
    }
    assert_eq!(
        plan(
            ThreadBinding {
                tcb: binding().tcb,
                ..other
            },
            binding()
        ),
        Err(ThreadBindingError::TcbConflict)
    );
    assert_eq!(plan(other, binding()), Ok(ThreadBindingAdmission::Insert));
}

#[test]
fn reservation_sentinel_and_roles_in_other_processes_are_shareable() {
    let reserved = ThreadBinding {
        tcb: 1,
        ..binding()
    };
    let other = ThreadBinding {
        pi: 28,
        tid: 302,
        badge: 91,
        ..reserved
    };
    assert_eq!(plan(other, reserved), Ok(ThreadBindingAdmission::Insert));
}

#[test]
fn badge_zero_is_valid_but_still_unique() {
    let owner = ThreadBinding {
        badge: 0,
        ..binding()
    };
    assert_eq!(
        admit_thread_binding(owner, []),
        Ok(ThreadBindingAdmission::Insert)
    );
    assert_eq!(
        plan(owner, owner),
        Ok(ThreadBindingAdmission::Replay { index: 7 })
    );
    assert_eq!(
        plan(
            ThreadBinding {
                pi: 28,
                tid: 302,
                role: 4,
                tcb: 101,
                ..owner
            },
            owner
        ),
        Err(ThreadBindingError::BadgeConflict)
    );
}

#[test]
fn complete_scan_checks_conflicts_before_and_after_a_matching_owner() {
    let requested = binding();
    for conflict in [
        ThreadBinding {
            tid: 302,
            badge: 90,
            tcb: 101,
            role: 4,
            ..requested
        },
        ThreadBinding {
            tid: 302,
            badge: 91,
            tcb: 100,
            role: 4,
            ..requested
        },
        ThreadBinding {
            tid: 302,
            badge: 91,
            tcb: 101,
            role: 3,
            ..requested
        },
    ] {
        for rows in [
            [(7, requested), (9, conflict)],
            [(9, conflict), (7, requested)],
        ] {
            assert!(admit_thread_binding(requested, rows).is_err());
        }
    }
}

#[test]
fn duplicate_exact_owners_are_not_an_idempotent_replay() {
    assert_eq!(
        admit_thread_binding(binding(), [(7, binding()), (8, binding())]),
        Err(ThreadBindingError::DuplicateOwner)
    );
}

#[test]
fn invalid_requests_are_refused_without_insertion() {
    for requested in [
        ThreadBinding {
            tid: 0,
            ..binding()
        },
        ThreadBinding {
            tcb: 0,
            ..binding()
        },
    ] {
        assert_eq!(
            admit_thread_binding(requested, []),
            Err(ThreadBindingError::InvalidIdentity)
        );
    }
}

#[test]
fn identity_can_be_reused_after_explicit_owner_removal() {
    let requested = ThreadBinding {
        pi: 28,
        badge: 91,
        role: 4,
        tcb: 101,
        ..binding()
    };
    assert!(plan(requested, binding()).is_err());
    assert_eq!(
        admit_thread_binding(requested, []),
        Ok(ThreadBindingAdmission::Insert)
    );
}

#[test]
fn main_mechanism_publication_is_empty_to_owned_or_exact_replay_only() {
    let caps = [100, 101, 102];
    assert!(admits_mechanism_publication([0; 3], caps));
    assert!(admits_mechanism_publication(caps, caps));
    assert!(!admits_mechanism_publication([0; 3], [0; 3]));
    assert!(!admits_mechanism_publication(caps, [0; 3]));
    for field in 0..3 {
        for replacement in [0, 200] {
            let mut changed = caps;
            changed[field] = replacement;
            assert!(!admits_mechanism_publication(caps, changed));
        }
    }
}
