use super::*;

fn binding() -> ThreadBinding<u32> {
    ThreadBinding {
        pi: 27,
        process: ProcessIdentity {
            pid: 90,
            generation: crate::process_identity::ProcessGeneration::Hosted(7),
        },
        tid: 301,
        badge: 90,
        role: 3,
        tcb: 100,
        reservations: None,
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
        process: binding().process,
        tid: 302,
        badge: 91,
        role: 4,
        tcb: 101,
        reservations: None,
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

fn pooled() -> ThreadBinding<u32> {
    ThreadBinding {
        reservations: Some(ThreadRuntimeReservations {
            badge: binding().badge,
            pool_slot: 4,
            window_slot: Some(19),
        }),
        ..binding()
    }
}

fn other_pooled(pool_slot: usize, window_slot: Option<usize>) -> ThreadBinding<u32> {
    ThreadBinding {
        tid: 302,
        badge: 91,
        role: 4,
        tcb: 101,
        reservations: Some(ThreadRuntimeReservations {
            badge: 91,
            pool_slot,
            window_slot,
        }),
        ..binding()
    }
}

#[test]
fn captured_reservations_survive_exact_replay_and_tcb_promotion() {
    let owner = ThreadBinding { tcb: 1, ..pooled() };
    assert_eq!(
        plan(owner, owner),
        Ok(ThreadBindingAdmission::Replay { index: 7 })
    );
    assert_eq!(
        plan(pooled(), owner),
        Ok(ThreadBindingAdmission::Promote { index: 7 })
    );
    assert_eq!(
        plan(pooled(), pooled()),
        Ok(ThreadBindingAdmission::Replay { index: 7 })
    );
}

#[test]
fn same_tid_cannot_change_or_discard_its_captured_reservations() {
    let holds = pooled().reservations.unwrap();
    for reservations in [
        None,
        Some(ThreadRuntimeReservations {
            pool_slot: 5,
            ..holds
        }),
        Some(ThreadRuntimeReservations {
            window_slot: None,
            ..holds
        }),
        Some(ThreadRuntimeReservations {
            window_slot: Some(20),
            ..holds
        }),
    ] {
        for tcb in [1, 100] {
            let owner = ThreadBinding { tcb, ..pooled() };
            assert_eq!(
                plan(
                    ThreadBinding {
                        reservations,
                        ..owner
                    },
                    owner
                ),
                Err(ThreadBindingError::IdentityConflict)
            );
            assert_eq!(
                plan(
                    ThreadBinding {
                        reservations,
                        tcb: 100,
                        ..owner
                    },
                    owner
                ),
                Err(ThreadBindingError::IdentityConflict)
            );
        }
    }
    assert_eq!(
        plan(pooled(), binding()),
        Err(ThreadBindingError::IdentityConflict)
    );
}

#[test]
fn captured_badge_must_match_the_runtime_binding() {
    let mut requested = pooled();
    requested.reservations.as_mut().unwrap().badge += 1;
    assert_eq!(
        admit_thread_binding(requested, []),
        Err(ThreadBindingError::InvalidIdentity)
    );
    let zero = ThreadBinding {
        badge: 0,
        reservations: Some(ThreadRuntimeReservations {
            badge: 0,
            ..pooled().reservations.unwrap()
        }),
        ..pooled()
    };
    assert_eq!(
        admit_thread_binding(zero, []),
        Ok(ThreadBindingAdmission::Insert)
    );
}

#[test]
fn pool_hold_conflicts_even_with_a_different_role_badge_and_window() {
    for tcb in [1, 100] {
        let owner = ThreadBinding { tcb, ..pooled() };
        assert_eq!(
            plan(other_pooled(4, Some(20)), owner),
            Err(ThreadBindingError::ReservationConflict)
        );
        assert_eq!(
            plan(other_pooled(4, None), owner),
            Err(ThreadBindingError::ReservationConflict)
        );
    }
}

#[test]
fn window_hold_conflicts_even_with_a_different_pool_slot() {
    for tcb in [1, 100] {
        assert_eq!(
            plan(other_pooled(5, Some(19)), ThreadBinding { tcb, ..pooled() }),
            Err(ThreadBindingError::ReservationConflict)
        );
    }
}

#[test]
fn independent_reservations_and_other_processes_do_not_conflict() {
    for requested in [
        other_pooled(5, Some(20)),
        other_pooled(5, None),
        ThreadBinding {
            pi: 28,
            ..other_pooled(4, Some(19))
        },
        ThreadBinding {
            reservations: None,
            ..other_pooled(4, Some(19))
        },
    ] {
        assert_eq!(
            plan(requested, pooled()),
            Ok(ThreadBindingAdmission::Insert)
        );
    }
}

#[test]
fn complete_scan_checks_reservation_conflicts_on_both_sides_of_replay() {
    let owner = pooled();
    for conflict in [other_pooled(4, Some(20)), other_pooled(5, Some(19))] {
        for rows in [[(7, owner), (9, conflict)], [(9, conflict), (7, owner)]] {
            assert_eq!(
                admit_thread_binding(owner, rows),
                Err(ThreadBindingError::ReservationConflict)
            );
        }
    }
}

#[test]
fn ownership_queries_do_not_depend_on_tcb_or_construction_state() {
    for tcb in [1, 100] {
        let owner = ThreadBinding { tcb, ..pooled() };
        assert!(owner.holds_pool_slot(27, 4));
        assert!(owner.holds_window_slot(27, 19));
        assert!(!owner.holds_pool_slot(28, 4));
        assert!(!owner.holds_pool_slot(27, 5));
        assert!(!owner.holds_window_slot(28, 19));
        assert!(!owner.holds_window_slot(27, 20));
    }
    for slot in [0, 4, 19, usize::MAX] {
        assert!(!binding().holds_pool_slot(27, slot));
        assert!(!binding().holds_window_slot(27, slot));
    }
    assert!(other_pooled(0, None).holds_pool_slot(27, 0));
    assert!(!other_pooled(0, None).holds_window_slot(27, 0));
}

#[test]
fn held_slots_become_available_only_after_owner_removal() {
    let requested = other_pooled(4, Some(19));
    assert_eq!(
        plan(requested, pooled()),
        Err(ThreadBindingError::ReservationConflict)
    );
    assert_eq!(
        admit_thread_binding(requested, []),
        Ok(ThreadBindingAdmission::Insert)
    );
}

#[test]
fn publication_ticket_retains_exact_reservations_through_failed_finish() {
    use crate::thread_publication::{PublicationError, ThreadPublicationSlot};
    let owner = ThreadBinding { tcb: 1, ..pooled() };
    let holds = owner.reservations.unwrap();
    let mut slot = ThreadPublicationSlot::empty();
    let mut ticket = slot.prepare(owner).unwrap();
    for reservations in [
        None,
        Some(ThreadRuntimeReservations {
            pool_slot: 5,
            ..holds
        }),
        Some(ThreadRuntimeReservations {
            window_slot: Some(20),
            ..holds
        }),
    ] {
        let (error, retained) = slot
            .finish(
                ticket,
                &ThreadBinding {
                    reservations,
                    ..owner
                },
            )
            .err()
            .unwrap();
        assert_eq!(error, PublicationError::OwnerChanged);
        assert!(slot.is_busy());
        assert_eq!(retained.owner(), &owner);
        ticket = retained;
    }
    assert_eq!(slot.finish(ticket, &owner).unwrap(), owner);
    assert!(!slot.is_busy());
}

fn changed_processes() -> [ProcessIdentity; 3] {
    use crate::process_identity::ProcessGeneration;
    [
        ProcessIdentity {
            pid: 91,
            ..binding().process
        },
        ProcessIdentity {
            generation: ProcessGeneration::Hosted(8),
            ..binding().process
        },
        ProcessIdentity {
            generation: ProcessGeneration::Temporary(7),
            ..binding().process
        },
    ]
}

#[test]
fn replay_and_promotion_require_exact_pid_generation_and_domain() {
    for process in changed_processes() {
        for tcb in [1, 100] {
            let owner = ThreadBinding { tcb, ..pooled() };
            assert_eq!(
                plan(ThreadBinding { process, ..owner }, owner),
                Err(ThreadBindingError::IdentityConflict)
            );
            assert_eq!(
                plan(
                    ThreadBinding {
                        tcb: 100,
                        process,
                        ..owner
                    },
                    owner
                ),
                Err(ThreadBindingError::IdentityConflict)
            );
        }
    }
}

#[test]
fn distinct_threads_cannot_mix_process_lifetimes_in_one_vspace_slot() {
    let owner = pooled();
    for process in changed_processes() {
        let requested = ThreadBinding {
            process,
            ..other_pooled(5, Some(20))
        };
        assert_eq!(
            plan(requested, owner),
            Err(ThreadBindingError::ProcessConflict)
        );
        for rows in [[(7, requested), (9, owner)], [(9, owner), (7, requested)]] {
            assert_eq!(
                admit_thread_binding(requested, rows),
                Err(ThreadBindingError::ProcessConflict)
            );
        }
        assert_eq!(
            plan(
                ThreadBinding {
                    pi: 28,
                    ..requested
                },
                owner
            ),
            Ok(ThreadBindingAdmission::Insert)
        );
    }
}

#[test]
fn invalid_process_lifetimes_cannot_enter_the_runtime_table() {
    use crate::process_identity::ProcessGeneration;
    for process in [
        ProcessIdentity {
            pid: 0,
            ..binding().process
        },
        ProcessIdentity {
            generation: ProcessGeneration::Hosted(0),
            ..binding().process
        },
        ProcessIdentity {
            generation: ProcessGeneration::Temporary(0),
            ..binding().process
        },
    ] {
        assert_eq!(
            admit_thread_binding(
                ThreadBinding {
                    process,
                    ..binding()
                },
                []
            ),
            Err(ThreadBindingError::InvalidIdentity)
        );
    }
}

#[test]
fn temporary_lifetimes_support_exact_replay_and_promotion() {
    let owner = ThreadBinding {
        process: ProcessIdentity {
            generation: crate::process_identity::ProcessGeneration::Temporary(7),
            ..binding().process
        },
        tcb: 1,
        ..pooled()
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
        plan(ThreadBinding { tcb: 100, ..owner }, owner),
        Ok(ThreadBindingAdmission::Promote { index: 7 })
    );
}

#[test]
fn publication_ticket_preserves_process_provenance_on_rejection() {
    use crate::thread_publication::{PublicationError, ThreadPublicationSlot};
    let owner = ThreadBinding { tcb: 1, ..pooled() };
    let mut slot = ThreadPublicationSlot::empty();
    let mut ticket = slot.prepare(owner).unwrap();
    for process in changed_processes() {
        let (error, retained) = slot
            .finish(ticket, &ThreadBinding { process, ..owner })
            .err()
            .unwrap();
        assert_eq!(error, PublicationError::OwnerChanged);
        assert!(slot.is_busy());
        assert_eq!(retained.owner(), &owner);
        ticket = retained;
    }
    assert_eq!(slot.finish(ticket, &owner).unwrap(), owner);
}
