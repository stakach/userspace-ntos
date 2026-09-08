use super::*;
use crate::thread_memory_retirement_access::StackRetirementAccessError as Error;

fn entries(
    slots: &[ThreadRuntimeSlot<Runtime>],
) -> impl Iterator<Item = PendingThreadMemory<'_, 2>> {
    slots.iter().filter_map(|slot| {
        let owner = slot.pending()?;
        let runtime = owner.runtime();
        Some(PendingThreadMemory {
            owner: owner.id(),
            memory: &runtime.memory,
            user_stack_allocation_base: runtime.bottom,
            user_stack_base: runtime.top,
        })
    })
}

fn process() -> ProcessIdentity {
    ProcessIdentity {
        pid: 8,
        generation: ProcessGeneration::Hosted(7),
    }
}

#[test]
fn only_completed_mechanisms_can_issue_a_cleanup_permit() {
    let mut slot = slot(runtime(2, process().generation));
    let id = slot.begin_pending(slot.owner().unwrap().binding).unwrap();
    assert!(matches!(
        slot.pending().unwrap().user_stack_retirement_permit(),
        Err(Error::MechanismsPending)
    ));
    slot.handoff_registered_mechanisms(id).unwrap();
    assert!(matches!(
        slot.pending().unwrap().user_stack_retirement_permit(),
        Err(Error::MechanismsPending)
    ));
    crate::thread_pending::registered_tests::finish_slot(&mut slot, id);
    assert!(slot
        .pending()
        .unwrap()
        .user_stack_retirement_permit()
        .is_ok());
}

#[test]
fn exact_stack_cleanup_does_not_change_ordinary_exclusions() {
    let slots = [pending(runtime(2, process().generation))];
    let owner = slots[0].pending().unwrap();
    let permit = owner.user_stack_retirement_permit().unwrap();
    assert_eq!(permit.owner(), owner.id());
    assert_eq!(
        permit.range(),
        ThreadMemoryRange {
            base: 0x10000,
            size: 0x10000
        }
    );
    for (base, size) in [(0x10000, 0x10000), (0x10000, 0x1000), (0x1f000, 0x1000)] {
        assert_eq!(
            permit.check(2, process(), base, size, entries(&slots)),
            Ok(())
        );
        assert_eq!(
            check(&slots, 2, base, size),
            Err(ThreadMemoryAccessError::Excluded(owner.id()))
        );
    }
}

#[test]
fn range_admission_is_bounded_aligned_nonempty_and_overflow_checked() {
    let slots = [pending(runtime(2, process().generation))];
    let permit = slots[0]
        .pending()
        .unwrap()
        .user_stack_retirement_permit()
        .unwrap();
    for (base, size) in [
        (0x10000, 0),
        (0x10001, 0x1000),
        (0x10000, 1),
        (u64::MAX - 4095, 4096),
    ] {
        assert_eq!(
            permit.check(2, process(), base, size, entries(&slots)),
            Err(Error::InvalidRange)
        );
    }
    for (base, size) in [
        (0xf000, 0x2000),
        (0x1f000, 0x2000),
        (0x20000, 0x1000),
        (0x6000, 0x1000),
    ] {
        assert_eq!(
            permit.check(2, process(), base, size, entries(&slots)),
            Err(Error::OutsideStack)
        );
    }
}

#[test]
fn current_process_and_retained_attempt_must_match_exactly() {
    let slots = [pending(runtime(2, process().generation))];
    let permit = slots[0]
        .pending()
        .unwrap()
        .user_stack_retirement_permit()
        .unwrap();
    for (pi, process) in [
        (3, process()),
        (
            2,
            ProcessIdentity {
                pid: 9,
                ..process()
            },
        ),
        (
            2,
            ProcessIdentity {
                generation: ProcessGeneration::Hosted(8),
                ..process()
            },
        ),
        (
            2,
            ProcessIdentity {
                generation: ProcessGeneration::Temporary(7),
                ..process()
            },
        ),
    ] {
        assert_eq!(
            permit.check(pi, process, 0x10000, 0x1000, entries(&slots)),
            Err(Error::StaleOwner)
        );
    }
    assert_eq!(
        permit.check::<2>(2, process(), 0x10000, 0x1000, []),
        Err(Error::StaleOwner)
    );
    let replacement = [pending(runtime(2, process().generation))];
    assert!(permit
        .check(2, process(), 0x10000, 0x1000, entries(&replacement))
        .is_err());
    assert_eq!(
        permit.check(
            2,
            process(),
            0x10000,
            0x1000,
            entries(&slots).chain(entries(&slots))
        ),
        Err(Error::StaleOwner)
    );
}

#[test]
fn another_pending_owner_is_never_exempt_even_for_same_tid_or_old_generation() {
    for generation in [
        ProcessGeneration::Hosted(7),
        ProcessGeneration::Hosted(6),
        ProcessGeneration::Temporary(7),
    ] {
        let slots = [
            pending(runtime(2, process().generation)),
            pending(runtime(2, generation)),
        ];
        let permit = slots[0]
            .pending()
            .unwrap()
            .user_stack_retirement_permit()
            .unwrap();
        assert_eq!(
            permit.check(2, process(), 0x10000, 0x1000, entries(&slots)),
            Err(Error::Exclusion(ThreadMemoryAccessError::Excluded(
                slots[1].pending().unwrap().id()
            )))
        );
    }
    let slots = [
        pending(runtime(2, process().generation)),
        pending(runtime(3, process().generation)),
    ];
    let permit = slots[0]
        .pending()
        .unwrap()
        .user_stack_retirement_permit()
        .unwrap();
    assert_eq!(
        permit.check(2, process(), 0x10000, 0x1000, entries(&slots)),
        Ok(())
    );
}

#[test]
fn malformed_or_overlapping_geometry_cannot_issue_a_permit() {
    for (bottom, top) in [
        (0, 0),
        (0x10000, 0),
        (0x10000, 0x10000),
        (0x10001, 0x20000),
        (0x6000, 0x20000),
    ] {
        let mut runtime = runtime(2, process().generation);
        runtime.bottom = bottom;
        runtime.top = top;
        let slot = pending(runtime);
        assert!(matches!(
            slot.pending().unwrap().user_stack_retirement_permit(),
            Err(Error::InvalidGeometry)
        ));
    }
    let mut runtime = runtime(2, process().generation);
    runtime.memory.client_pi = 3;
    let slot = pending(runtime);
    assert!(matches!(
        slot.pending().unwrap().user_stack_retirement_permit(),
        Err(Error::InvalidGeometry)
    ));
}

#[test]
fn changed_geometry_or_unlocated_capabilities_in_retained_table_are_refused() {
    let slots = [pending(runtime(2, process().generation))];
    let owner = slots[0].pending().unwrap();
    let permit = owner.user_stack_retirement_permit().unwrap();
    let memory = owner.runtime().memory;
    let changed_memory = ThreadMemoryResources::new(
        2,
        ThreadMemoryLayout::new(0x30000, 2, 0x40000, 0x50000, 0x60000).unwrap(),
    )
    .unwrap();
    for (memory, bottom, top) in [
        (&memory, 0x11000, 0x20000),
        (&changed_memory, 0x10000, 0x20000),
    ] {
        assert_eq!(
            permit.check(
                2,
                process(),
                0x12000,
                0x1000,
                [PendingThreadMemory {
                    owner: owner.id(),
                    memory,
                    user_stack_allocation_base: bottom,
                    user_stack_base: top,
                }]
            ),
            Err(Error::StaleOwner)
        );
    }
    let mut malformed = ThreadMemoryResources::<2>::empty();
    malformed.client_pi = 2;
    malformed.teb_owner = 123;
    assert_eq!(
        permit.check(
            2,
            process(),
            0x12000,
            0x1000,
            [PendingThreadMemory {
                owner: owner.id(),
                memory: &malformed,
                user_stack_allocation_base: 0x10000,
                user_stack_base: 0x20000,
            }]
        ),
        Err(Error::InvalidGeometry)
    );
}

#[test]
fn malformed_foreign_owner_is_not_hidden_by_own_exemption() {
    let mut foreign = runtime(2, process().generation);
    foreign.bottom = 0;
    let slots = [pending(runtime(2, process().generation)), pending(foreign)];
    let permit = slots[0]
        .pending()
        .unwrap()
        .user_stack_retirement_permit()
        .unwrap();
    assert_eq!(
        permit.check(2, process(), 0x10000, 0x1000, entries(&slots)),
        Err(Error::Exclusion(ThreadMemoryAccessError::InvalidOwner(
            slots[1].pending().unwrap().id()
        )))
    );
}
