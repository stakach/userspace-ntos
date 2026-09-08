use super::*;
use nt_user_host::thread_slot::{RuntimeMechanismHandoff, RuntimeTcbProjection};

struct Registered {
    binding: ThreadBinding<u32>,
    publication: ThreadPublicationSlot,
    caps: [u64; 4],
    fail: bool,
}
impl RuntimeIdentity for Registered {
    type Role = u32;
    fn binding(&self) -> ThreadBinding<u32> {
        self.binding
    }
    fn publication(&self) -> &ThreadPublicationSlot {
        &self.publication
    }
}
impl RuntimeTcbProjection for Registered {
    fn clear_retired_tcb_projection(&mut self, cap: u64) -> Result<(), u32> {
        if self.binding.tcb != cap && self.binding.tcb != 1 {
            return Err(1);
        }
        self.binding.tcb = 1;
        Ok(())
    }
}
impl RuntimeMechanismHandoff for Registered {
    fn registered_mechanism_slots(&self) -> Result<[u64; 4], u32> {
        Ok(self.caps)
    }
    fn clear_registered_mechanism_projections(
        &mut self,
        id: ThreadRollbackId,
        expected: [u64; 4],
    ) -> Result<(), u32> {
        if self.fail || id.identity().tid != self.binding.tid || expected != self.caps {
            return Err(123);
        }
        self.caps = [0; 4];
        Ok(())
    }
}
fn slot(fail: bool, caps: [u64; 4]) -> (ThreadRuntimeSlot<Registered>, ThreadRollbackId) {
    let (original, _, _, _) = fixture(None, false);
    let mut binding = original.owner().unwrap().binding;
    binding.tcb = 400;
    let mut slot = ThreadRuntimeSlot::empty();
    assert!(slot
        .insert(Registered {
            binding,
            publication: ThreadPublicationSlot::empty(),
            caps,
            fail
        })
        .is_ok());
    let id = slot.begin_pending(binding).unwrap();
    (slot, id)
}

#[test]
fn registered_handoff_success_and_rejections_allocate_nothing() {
    for (fail, caps) in [
        (false, [200, 300, 400, 500]),
        (true, [200, 300, 400, 500]),
        (false, [200, 300, 400, 200]),
    ] {
        let (mut slot, id) = slot(fail, caps);
        let result = without_allocation(|| slot.handoff_registered_mechanisms(id));
        if !fail && caps[3] == 500 {
            result.unwrap();
            assert_eq!(slot.owner().unwrap().caps, [0; 4]);
            without_allocation(|| slot.handoff_registered_mechanisms(id)).unwrap();
            let mut backend = Backend {
                current: id,
                events: Vec::with_capacity(9),
                fail: None,
            };
            without_allocation(|| slot.advance_registered_mechanism_retirement(id, &mut backend))
                .unwrap();
            assert_eq!(slot.owner().unwrap().binding.tcb, 1);
        } else {
            assert!(result.is_err());
            assert_eq!(slot.owner().unwrap().caps, caps);
            assert!(slot
                .pending()
                .unwrap()
                .registered_mechanism_retirement()
                .is_none());
        }
    }
}

#[test]
fn construction_owner_cannot_use_registered_handoff_or_driver() {
    let (mut slot, ticket, partial, _) = fixture(Some(400), false);
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    // The construction payload does not implement RuntimeMechanismHandoff at all. The generic
    // driver still checks provenance and refuses even though TCB projection clearing is supported.
    let mut backend = Backend {
        current: id,
        events: vec![],
        fail: None,
    };
    assert_eq!(
        slot.advance_registered_mechanism_retirement(id, &mut backend),
        Err(SlotError::Retirement(RetirementError::NotRegistered))
    );
    assert!(backend.events.is_empty());
}
