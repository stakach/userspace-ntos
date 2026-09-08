use super::*;
use crate::process_identity::ProcessGeneration;
use crate::thread_rollback::{ThreadRollbackIdentity, ThreadRollbackResourceKind as Kind};
use alloc::rc::Rc;
use core::cell::Cell;

const INVENTORY: [ThreadRollbackResource; 2] = [
    ThreadRollbackResource {
        cap: 200,
        kind: Kind::Frame,
    },
    ThreadRollbackResource {
        cap: 100,
        kind: Kind::Alias,
    },
];

struct Runtime {
    registered: super::registered_tests::PublishedMechanisms,
    caps: [u64; 2],
    geometry: (usize, u64, u64),
    ready: Rc<Cell<bool>>,
    handoffs: Rc<Cell<usize>>,
    effects: Rc<Cell<usize>>,
}
super::registered_tests::delegate!(Runtime, registered);

impl RuntimeMemoryHandoff for Runtime {
    fn clear_memory_projections(
        &mut self,
        id: ThreadRollbackId,
        inventory: &[ThreadRollbackResource],
    ) -> Result<(), u32> {
        if id.identity().pi != self.geometry.0
            || !self.ready.get()
            || inventory != INVENTORY
            || self.caps != [200, 100]
        {
            return Err(0xc000_000d);
        }
        self.caps = [0; 2];
        self.handoffs.set(self.handoffs.get() + 1);
        Ok(())
    }
}

fn owner() -> PendingThreadRuntime<Runtime> {
    let runtime = Runtime {
        registered: super::registered_tests::PublishedMechanisms::new(
            ThreadRollbackIdentity {
                pi: 2,
                pid: 8,
                process_generation: ProcessGeneration::Hosted(7),
                tid: 24,
            },
            ThreadRuntimeReservations {
                badge: 4,
                pool_slot: 3,
                window_slot: Some(5),
            },
            10,
        ),
        caps: [200, 100],
        geometry: (2, 0x1000, 0x4000),
        ready: Rc::new(Cell::new(true)),
        handoffs: Rc::new(Cell::new(0)),
        effects: Rc::new(Cell::new(0)),
    };
    match PendingThreadRuntime::retain(
        ThreadRollbackIdentity {
            pi: 2,
            pid: 8,
            process_generation: ProcessGeneration::Hosted(7),
            tid: 24,
        },
        10,
        Some(ThreadRuntimeReservations {
            badge: 4,
            pool_slot: 3,
            window_slot: Some(5),
        }),
        runtime,
    ) {
        Ok(mut owner) => {
            super::registered_tests::finish_pending(&mut owner);
            owner
        }
        Err(_) => panic!("valid retained owner"),
    }
}

struct BorrowedBackend<'a> {
    runtime: &'a Runtime,
    id: ThreadRollbackId,
    fail_finish: bool,
}
impl BorrowedBackend<'_> {
    fn effect(&self) -> Result<(), u32> {
        assert_eq!(self.runtime.caps, [0; 2]);
        self.runtime.effects.set(self.runtime.effects.get() + 1);
        Ok(())
    }
}
impl ThreadRollbackIo for BorrowedBackend<'_> {
    fn is_current(&self, id: ThreadRollbackId) -> bool {
        id == self.id
    }

    fn revoke_memory_access(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
        self.effect()
    }
    fn unmap_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        self.effect()
    }
    fn delete_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        self.effect()
    }
    fn recycle_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        self.effect()
    }
    fn finish_memory_transfers(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
        if self.fail_finish {
            Err(0xc000_009a)
        } else {
            self.effect()
        }
    }
    fn commit_rollback(&mut self, _: ThreadRollbackId) {
        self.effect().unwrap();
    }
}

#[test]
fn unprepared_and_unarmed_owners_refuse_handoff_or_backend_construction() {
    let mut owner = owner();
    let id = owner.id();
    assert_eq!(
        owner.commit_memory_handoff(id),
        Err(MemoryHandoffError::NotPrepared)
    );
    owner.prepare_journal(&INVENTORY).unwrap();
    assert!(!owner.is_memory_handed_off());
    assert_eq!(
        owner.advance_with::<BorrowedBackend<'_>>(|_| panic!("unarmed factory")),
        Err(ThreadRollbackError::NotPrepared)
    );
    let effects = owner.runtime().effects.clone();
    let dummy = Runtime {
        registered: super::registered_tests::PublishedMechanisms::new(
            id.identity(),
            owner.reservations().unwrap(),
            10,
        ),
        caps: [0; 2],
        geometry: (2, 0, 0),
        ready: Rc::new(Cell::new(true)),
        handoffs: Rc::new(Cell::new(0)),
        effects: effects.clone(),
    };
    assert_eq!(
        owner.advance(&mut BorrowedBackend {
            runtime: &dummy,
            id,
            fail_finish: false
        }),
        Err(ThreadRollbackError::NotPrepared)
    );
    assert_eq!(effects.get(), 0);
    assert_eq!(owner.runtime().caps, [200, 100]);
    assert!(owner.try_into_retired_payload().is_err());
}

#[test]
fn failed_and_foreign_handoff_leave_all_projections_and_reservations_intact() {
    let foreign = owner().id();
    let mut owner = owner();
    let id = owner.id();
    let holds = owner.reservations();
    owner.prepare_journal(&INVENTORY).unwrap();
    assert_eq!(
        owner.commit_memory_handoff(foreign),
        Err(MemoryHandoffError::StaleOwner)
    );
    owner.runtime().ready.set(false);
    for _ in 0..2 {
        assert_eq!(
            owner.commit_memory_handoff(id),
            Err(MemoryHandoffError::Projection(0xc000_000d))
        );
        assert!(!owner.is_memory_handed_off());
        assert_eq!(owner.runtime().caps, [200, 100]);
        assert_eq!(owner.reservations(), holds);
        assert_eq!(owner.runtime().handoffs.get(), 0);
    }
    owner.runtime().ready.set(true);
    owner.commit_memory_handoff(id).unwrap();
    owner.commit_memory_handoff(id).unwrap();
    assert_eq!(owner.runtime().caps, [0; 2]);
    assert_eq!(owner.runtime().geometry, (2, 0x1000, 0x4000));
    assert_eq!(owner.runtime().handoffs.get(), 1);
    assert_eq!(owner.reservations(), holds);
    assert_eq!(
        owner.commit_memory_handoff(foreign),
        Err(MemoryHandoffError::StaleOwner)
    );
}

#[test]
fn exact_immutable_inventory_is_required_before_clearing_any_cap() {
    let mut owner = owner();
    let id = owner.id();
    owner.prepare_journal(&INVENTORY[..1]).unwrap();
    assert_eq!(
        owner.commit_memory_handoff(id),
        Err(MemoryHandoffError::Projection(0xc000_000d))
    );
    assert_eq!(owner.runtime().caps, [200, 100]);
    assert!(!owner.is_memory_handed_off());
}

#[test]
fn readonly_backend_factory_retains_owner_through_fallible_terminal_transfer() {
    let mut owner = owner();
    let id = owner.id();
    owner.prepare_journal(&INVENTORY).unwrap();
    owner.commit_memory_handoff(id).unwrap();
    assert!(owner
        .advance_with(|runtime| BorrowedBackend {
            runtime,
            id,
            fail_finish: true
        })
        .is_err());
    let effects = owner.runtime().effects.get();
    let mut owner = match owner.try_into_retired_payload() {
        Err(owner) => owner,
        Ok(_) => panic!("terminal transfer is not acknowledged"),
    };
    owner.commit_memory_handoff(id).unwrap();
    owner
        .advance_with(|runtime| BorrowedBackend {
            runtime,
            id,
            fail_finish: false,
        })
        .unwrap();
    assert_eq!(owner.runtime().effects.get(), effects + 2);
    owner.commit_memory_handoff(id).unwrap();
    owner
        .advance_with(|runtime| BorrowedBackend {
            runtime,
            id,
            fail_finish: false,
        })
        .unwrap();
    assert_eq!(owner.runtime().handoffs.get(), 1);
    assert!(owner.try_into_retired_payload().is_ok());
}
