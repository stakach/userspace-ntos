use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use crate::thread_binding::{ThreadBinding, ThreadRuntimeReservations};
use crate::thread_publication::ThreadPublicationSlot;
use crate::thread_resources::ThreadMemoryLayout;
use crate::thread_rollback::{ThreadRollbackIo, ThreadRollbackResource};
use crate::thread_slot::{RuntimeIdentity, ThreadRuntimeSlot};

struct Runtime {
    binding: ThreadBinding<()>,
    publication: ThreadPublicationSlot,
    memory: ThreadMemoryResources<2>,
    bottom: u64,
    top: u64,
}

impl RuntimeIdentity for Runtime {
    type Role = ();
    fn binding(&self) -> ThreadBinding<()> {
        self.binding
    }
    fn publication(&self) -> &ThreadPublicationSlot {
        &self.publication
    }
}

fn runtime(pi: usize, generation: ProcessGeneration) -> Runtime {
    Runtime {
        binding: ThreadBinding {
            pi,
            process: ProcessIdentity { pid: 8, generation },
            tid: 24,
            tcb: 100,
            badge: 4,
            role: (),
            reservations: Some(ThreadRuntimeReservations {
                badge: 4,
                pool_slot: 2,
                window_slot: Some(3),
            }),
        },
        publication: ThreadPublicationSlot::empty(),
        memory: ThreadMemoryResources::new(
            pi,
            ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x6000, 0xa000).unwrap(),
        )
        .unwrap(),
        bottom: 0x10000,
        top: 0x20000,
    }
}

fn slot(runtime: Runtime) -> ThreadRuntimeSlot<Runtime> {
    let mut slot = ThreadRuntimeSlot::empty();
    assert!(slot.insert(runtime).is_ok());
    slot
}

fn pending(runtime: Runtime) -> ThreadRuntimeSlot<Runtime> {
    let mut slot = slot(runtime);
    slot.begin_pending(slot.owner().unwrap().binding).unwrap();
    slot
}

fn check(
    slots: &[ThreadRuntimeSlot<Runtime>],
    pi: usize,
    base: u64,
    size: u64,
) -> Result<(), ThreadMemoryAccessError> {
    check_pending_thread_memory(
        pi,
        base,
        size,
        slots.iter().filter_map(|slot| {
            let owner = slot.pending()?;
            let runtime = owner.runtime();
            Some(PendingThreadMemory {
                owner: owner.id(),
                memory: &runtime.memory,
                user_stack_allocation_base: runtime.bottom,
                user_stack_base: runtime.top,
            })
        }),
    )
}

#[test]
fn vacant_and_published_memory_is_not_a_pending_exclusion() {
    let slots = [
        ThreadRuntimeSlot::empty(),
        slot(runtime(2, ProcessGeneration::Hosted(7))),
    ];
    assert_eq!(check(&slots, 2, 0x1000, 1), Ok(()));
}

#[test]
fn all_layout_pages_are_excluded_before_any_cap_or_journal_allocation() {
    let slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    let id = slots[0].pending().unwrap().id();
    assert!(slots[0].pending().unwrap().cleanup().is_none());
    assert!(!slots[0].owner().unwrap().memory.has_capabilities());
    for base in [0x1000, 0x2000, 0x4000, 0x6000, 0x7000, 0x8000, 0xa000] {
        assert_eq!(
            check(&slots, 2, base, 4096),
            Err(ThreadMemoryAccessError::Excluded(id))
        );
    }
}

#[test]
fn full_application_stack_includes_guard_and_uncommitted_pages() {
    let slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    let id = slots[0].pending().unwrap().id();
    for base in [0x10000, 0x18000, 0x1ffff] {
        assert_eq!(
            check(&slots, 2, base, 1),
            Err(ThreadMemoryAccessError::Excluded(id))
        );
    }
    assert_eq!(check(&slots, 2, 0x20000, 1), Ok(()));
}

#[test]
fn half_open_boundaries_and_cross_range_requests() {
    let slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    let id = slots[0].pending().unwrap().id();
    for (base, size) in [(0xfff, 1), (0x3000, 4096), (0x9000, 4096), (0xb000, 1)] {
        assert_eq!(check(&slots, 2, base, size), Ok(()));
    }
    for (base, size) in [(0xfff, 2), (0x3000, 4097), (0x5000, 0x6001), (0xffff, 2)] {
        assert_eq!(
            check(&slots, 2, base, size),
            Err(ThreadMemoryAccessError::Excluded(id))
        );
    }
}

#[test]
fn zero_length_and_overflow_are_independent_of_owner_presence() {
    let slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    for owners in [&slots[..], &[][..]] {
        assert_eq!(check(owners, 2, u64::MAX, 0), Ok(()));
        assert_eq!(
            check(owners, 2, u64::MAX, 1),
            Err(ThreadMemoryAccessError::InvalidRange)
        );
        assert_eq!(check(owners, 2, u64::MAX - 1, 1), Ok(()));
    }
}

#[test]
fn exclusions_are_process_scoped_but_never_hide_old_generations() {
    for generation in [
        ProcessGeneration::Hosted(7),
        ProcessGeneration::Hosted(8),
        ProcessGeneration::Temporary(7),
    ] {
        let slots = [pending(runtime(2, generation))];
        let id = slots[0].pending().unwrap().id();
        assert_eq!(check(&slots, 3, 0x1000, 4096), Ok(()));
        assert_eq!(
            check(&slots, 2, 0x1000, 4096),
            Err(ThreadMemoryAccessError::Excluded(id))
        );
        assert_eq!(id.identity().process_generation, generation);
    }
}

#[test]
fn every_pending_owner_participates_in_the_query() {
    let slots = [
        pending(runtime(1, ProcessGeneration::Hosted(1))),
        pending(runtime(2, ProcessGeneration::Hosted(2))),
    ];
    let id = slots[1].pending().unwrap().id();
    assert_eq!(
        check(&slots, 2, 0x1000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
}

#[test]
fn partial_physical_inventory_does_not_shrink_geometry() {
    let mut owner = runtime(2, ProcessGeneration::Hosted(7));
    owner.memory.stack_owner[0] = 90;
    owner.memory.teb2_target = 91;
    let slots = [pending(owner)];
    assert!(slots[0].owner().unwrap().memory.has_capabilities());
    let id = slots[0].pending().unwrap().id();
    assert_eq!(
        check(&slots, 2, 0x2000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
    assert_eq!(
        check(&slots, 2, 0x8000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
}

#[test]
fn invalid_owner_geometry_blocks_even_disjoint_addresses() {
    for (bottom, top) in [
        (0, 0x20000),
        (0x10000, 0),
        (0x20000, 0x10000),
        (0x10000, 0x10000),
        (0x10001, 0x20000),
        (0x10000, u64::MAX),
    ] {
        let mut owner = runtime(2, ProcessGeneration::Hosted(7));
        owner.bottom = bottom;
        owner.top = top;
        let slots = [pending(owner)];
        let id = slots[0].pending().unwrap().id();
        assert_eq!(
            check(&slots, 2, 0x50000, 1),
            Err(ThreadMemoryAccessError::InvalidOwner(id))
        );
        assert_eq!(check(&slots, 3, 0x50000, 1), Ok(()));
    }
    let mut owner = runtime(2, ProcessGeneration::Hosted(7));
    owner.memory.client_pi = 3;
    let slots = [pending(owner)];
    assert!(matches!(
        check(&slots, 2, 0x50000, 1),
        Err(ThreadMemoryAccessError::InvalidOwner(_))
    ));
}

#[test]
fn capabilities_outside_the_retained_stack_geometry_fail_closed() {
    for index in 0..3 {
        let mut owner = runtime(2, ProcessGeneration::Hosted(7));
        owner.memory = ThreadMemoryResources::new(
            2,
            ThreadMemoryLayout::new(0x1000, 1, 0x4000, 0x6000, 0xa000).unwrap(),
        )
        .unwrap();
        match index {
            0 => owner.memory.stack_owner[1] = 99,
            1 => owner.memory.stack_target[1] = 99,
            _ => owner.memory.stack_mirror[1] = 99,
        }
        let slots = [pending(owner)];
        assert!(matches!(
            check(&slots, 2, 0x50000, 1),
            Err(ThreadMemoryAccessError::InvalidOwner(_))
        ));
    }
}

#[test]
fn transport_geometry_does_not_require_a_separate_application_stack() {
    let mut owner = runtime(2, ProcessGeneration::Hosted(7));
    owner.bottom = 0;
    owner.top = 0;
    let slots = [pending(owner)];
    let id = slots[0].pending().unwrap().id();
    assert_eq!(
        check(&slots, 2, 0x1000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
    assert_eq!(check(&slots, 2, 0x50000, 1), Ok(()));
}

#[test]
fn missing_layout_requires_valid_retained_stack_and_no_unlocated_caps() {
    let mut owner = runtime(2, ProcessGeneration::Hosted(7));
    owner.memory = ThreadMemoryResources::empty();
    let slots = [pending(owner)];
    let id = slots[0].pending().unwrap().id();
    assert_eq!(
        check(&slots, 2, 0x10000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
    assert_eq!(check(&slots, 2, 0x50000, 1), Ok(()));
    for cap in [0, 99] {
        let mut owner = runtime(2, ProcessGeneration::Hosted(7));
        owner.memory = ThreadMemoryResources::empty();
        owner.memory.teb_owner = cap;
        if cap == 0 {
            owner.bottom = 0;
            owner.top = 0;
        }
        let slots = [pending(owner)];
        assert!(matches!(
            check(&slots, 2, 0x50000, 1),
            Err(ThreadMemoryAccessError::InvalidOwner(_))
        ));
    }
}

struct Backend {
    id: ThreadRollbackId,
    fail: bool,
}

#[test]
fn journal_preparation_failure_retains_the_same_exclusion() {
    use crate::thread_rollback::ThreadRollbackResourceKind;
    let mut slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    let id = slots[0].pending().unwrap().id();
    let invalid = [ThreadRollbackResource {
        cap: 100,
        kind: ThreadRollbackResourceKind::Frame,
    }];
    assert!(slots[0].prepare_cleanup(id, &invalid).is_err());
    assert!(slots[0].pending().unwrap().cleanup().is_none());
    assert_eq!(
        check(&slots, 2, 0x1000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
    slots[0].prepare_cleanup(id, &[]).unwrap();
    assert_eq!(
        check(&slots, 2, 0x1000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
}
impl ThreadRollbackIo for Backend {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        self.id == id
    }
    fn suspend_tcb(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn delete_tcb(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn revoke_memory_access(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
        if self.fail {
            Err(0xc000009a)
        } else {
            Ok(())
        }
    }
    fn release_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        panic!("empty journal")
    }
    fn commit_rollback(&mut self, _: ThreadRollbackId) {}
}

#[test]
fn failed_and_completed_cleanup_preserve_exclusions_until_retirement() {
    let mut slots = [pending(runtime(2, ProcessGeneration::Hosted(7)))];
    let id = slots[0].pending().unwrap().id();
    slots[0].prepare_cleanup(id, &[]).unwrap();
    let mut backend = Backend { id, fail: true };
    assert!(slots[0].advance_cleanup(id, &mut backend).is_err());
    assert_eq!(
        check(&slots, 2, 0x1000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
    backend.fail = false;
    slots[0].advance_cleanup(id, &mut backend).unwrap();
    assert_eq!(
        check(&slots, 2, 0x1000, 1),
        Err(ThreadMemoryAccessError::Excluded(id))
    );
    assert!(slots[0].take_retired_payload(id).is_some());
    assert_eq!(check(&slots, 2, 0x1000, 1), Ok(()));
}
