//! One canonical VSpace owner journal with a read-only, borrow-safe pump observation port.
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;
use nt_memory_manager::ProcessIdentity;

struct Owner {
    process: ProcessIdentity,
    caps: super::img_spawn::HostedProcessVspaceCaps,
}
enum Slot {
    Empty,
    Owned(Owner),
    Updating,
}
type Store = Rc<RefCell<Vec<Slot>>>;

pub(crate) struct HostedProcessVSpaces {
    store: Store,
}
#[derive(Clone)]
pub(crate) struct VSpaceObserver {
    store: Store,
}

impl HostedProcessVSpaces {
    pub(crate) fn new(slots: usize) -> Self {
        let mut rows = Vec::new();
        rows.try_reserve_exact(slots)
            .expect("process VSpace journal allocation failed");
        rows.resize_with(slots, || Slot::Empty);
        Self {
            store: Rc::new(RefCell::new(rows)),
        }
    }
    pub(crate) fn observer(&self) -> VSpaceObserver {
        VSpaceObserver {
            store: Rc::clone(&self.store),
        }
    }
    /// An unavailable slot (including an active update) is distinct from empty ownership.
    pub(crate) fn get(
        &self,
        pi: usize,
    ) -> Option<Option<super::img_spawn::HostedProcessVspaceCaps>> {
        let rows = self.store.try_borrow().ok()?;
        match rows.get(pi)? {
            Slot::Empty => Some(None),
            Slot::Owned(owner) => Some(Some(owner.caps)),
            Slot::Updating => None,
        }
    }
    pub(crate) fn validate_publication(
        &self,
        pi: usize,
        process: ProcessIdentity,
        caps: super::img_spawn::HostedProcessVspaceCaps,
    ) -> Result<(), u32> {
        if !process.is_valid()
            || process.generation != nt_memory_manager::ProcessGeneration::Hosted(caps.generation)
            || caps.pml4 == 0
        {
            return Err(nt_process::STATUS_INVALID_PARAMETER);
        }
        let rows = self
            .store
            .try_borrow()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        let slot = rows.get(pi).ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
        if !matches!(slot, Slot::Empty) {
            return Err(nt_process::STATUS_DEVICE_BUSY);
        }
        Ok(())
    }
    pub(crate) fn publish(
        &self,
        pi: usize,
        process: ProcessIdentity,
        caps: super::img_spawn::HostedProcessVspaceCaps,
    ) -> Result<(), u32> {
        self.validate_publication(pi, process, caps)?;
        let mut rows = self
            .store
            .try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        rows[pi] = Slot::Owned(Owner { process, caps });
        Ok(())
    }
    pub(crate) fn begin_update(
        &self,
        pi: usize,
        process: ProcessIdentity,
    ) -> Result<Option<VSpaceUpdate>, u32> {
        let mut rows = self
            .store
            .try_borrow_mut()
            .map_err(|_| nt_process::STATUS_DEVICE_BUSY)?;
        let slot = rows
            .get_mut(pi)
            .ok_or(nt_process::STATUS_INVALID_PARAMETER)?;
        match slot {
            Slot::Empty => return Ok(None),
            Slot::Owned(owner) if owner.process == process => {}
            _ => return Err(nt_process::STATUS_INVALID_PARAMETER),
        }
        let Slot::Owned(owner) = core::mem::replace(slot, Slot::Updating) else {
            unreachable!()
        };
        // The single owner moves to this guard; no RefCell borrow survives native effects.
        Ok(Some(VSpaceUpdate {
            store: Rc::clone(&self.store),
            pi,
            owner: Some(owner),
        }))
    }
}

impl VSpaceObserver {
    /// Expected root is an untrusted observation; the kernel must compare actual physical roots.
    pub(crate) fn expected_child_root(
        &self,
        binding: nt_user_host::thread_binding::ThreadBinding<super::HostedThreadRole>,
    ) -> Option<u64> {
        let rows = self.store.try_borrow().ok()?;
        let Slot::Owned(owner) = rows.get(binding.pi)? else {
            return None;
        };
        (binding.process == owner.process
            && binding.process.is_valid()
            && binding.process.generation
                == nt_memory_manager::ProcessGeneration::Hosted(owner.caps.generation)
            && owner.caps.pml4 != 0)
            .then_some(owner.caps.pml4)
    }
}

/// Retained cleanup journal. Dropping on refusal restores every acknowledged prefix update.
pub(crate) struct VSpaceUpdate {
    store: Store,
    pi: usize,
    owner: Option<Owner>,
}
impl VSpaceUpdate {
    pub(crate) fn caps_mut(&mut self) -> &mut super::img_spawn::HostedProcessVspaceCaps {
        &mut self.owner.as_mut().expect("live VSpace update owner").caps
    }
    /// Only after checked physical retirement of all caps, including the root.
    pub(crate) fn finish_retirement(mut self) {
        let caps = &self
            .owner
            .as_ref()
            .expect("live VSpace retirement owner")
            .caps;
        assert!(
            caps.pml4 == 0
                && caps.image_pdpt == 0
                && caps.image_pd == 0
                && caps.kuser_pdpt == 0
                && caps.kuser_pd == 0
                && caps.fault_endpoint == 0
                && caps.mapped_len == 0
                && caps.plain_len == 0
                && caps.mapped_unmapped == 0
                && caps.mapped.iter().all(|cap| *cap == 0)
                && caps.plain.iter().all(|cap| *cap == 0)
        );
        let mut rows = self.store.borrow_mut();
        assert!(matches!(rows[self.pi], Slot::Updating));
        rows[self.pi] = Slot::Empty;
        self.owner = None;
    }
}
impl Drop for VSpaceUpdate {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            let mut rows = self.store.borrow_mut();
            assert!(matches!(rows[self.pi], Slot::Updating));
            rows[self.pi] = Slot::Owned(owner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn binding(
        generation: u64,
    ) -> nt_user_host::thread_binding::ThreadBinding<crate::HostedThreadRole> {
        nt_user_host::thread_binding::ThreadBinding {
            pi: 0,
            process: ProcessIdentity {
                pid: 304,
                generation: nt_memory_manager::ProcessGeneration::Hosted(generation),
            },
            tid: 312,
            badge: 614,
            tcb: 80,
            role: crate::HostedThreadRole::Main,
            reservations: None,
        }
    }
    fn caps(generation: u64) -> crate::img_spawn::HostedProcessVspaceCaps {
        crate::img_spawn::HostedProcessVspaceCaps {
            generation,
            pml4: 100,
            image_pdpt: 101,
            image_pd: 102,
            kuser_pdpt: 103,
            kuser_pd: 104,
            fault_endpoint: 105,
            mapped: [0; 64],
            mapped_len: 0,
            mapped_unmapped: 0,
            plain: [0; 16],
            plain_len: 0,
        }
    }
    #[test]
    fn observer_reads_one_shared_store_and_rejects_other_incarnations() {
        let journal = HostedProcessVSpaces::new(1);
        let observer = journal.observer();
        assert!(Rc::ptr_eq(&journal.store, &observer.store));
        assert_eq!(observer.expected_child_root(binding(2)), None);
        journal.publish(0, binding(2).process, caps(2)).unwrap();
        assert_eq!(observer.expected_child_root(binding(2)), Some(100));
        assert_eq!(observer.expected_child_root(binding(3)), None);
        let mut wrong_pid = binding(2);
        wrong_pid.process.pid = 400;
        assert_eq!(observer.expected_child_root(wrong_pid), None);
        let mut wrong_pi = binding(2);
        wrong_pi.pi = 1;
        assert_eq!(observer.expected_child_root(wrong_pi), None);
    }
    #[test]
    fn active_borrow_denies_observation_without_mutation() {
        let journal = HostedProcessVSpaces::new(1);
        journal.publish(0, binding(2).process, caps(2)).unwrap();
        let observer = journal.observer();
        let borrowed = journal.store.borrow_mut();
        assert_eq!(observer.expected_child_root(binding(2)), None);
        drop(borrowed);
        assert_eq!(observer.expected_child_root(binding(2)), Some(100));
    }
    #[test]
    fn native_update_moves_owner_and_restores_acknowledged_prefix_on_refusal() {
        let journal = HostedProcessVSpaces::new(1);
        journal.publish(0, binding(2).process, caps(2)).unwrap();
        let observer = journal.observer();
        let mut update = journal
            .begin_update(0, binding(2).process)
            .unwrap()
            .unwrap();
        assert!(journal.store.try_borrow_mut().is_ok());
        assert_eq!(observer.expected_child_root(binding(2)), None);
        assert!(journal.publish(0, binding(3).process, caps(3)).is_err());
        update.caps_mut().mapped_unmapped = 1;
        drop(update);
        assert_eq!(journal.get(0).flatten().unwrap().mapped_unmapped, 1);
        assert_eq!(observer.expected_child_root(binding(2)), Some(100));
    }
    #[test]
    fn exact_retirement_allows_new_publication_without_borrowing_old_evidence() {
        let journal = HostedProcessVSpaces::new(1);
        journal.publish(0, binding(2).process, caps(2)).unwrap();
        assert!(journal.begin_update(0, binding(3).process).is_err());
        let mut update = journal
            .begin_update(0, binding(2).process)
            .unwrap()
            .unwrap();
        // Model the checked backend's complete retirement receipt, without native effects.
        let retired = update.caps_mut();
        retired.pml4 = 0;
        retired.image_pdpt = 0;
        retired.image_pd = 0;
        retired.kuser_pdpt = 0;
        retired.kuser_pd = 0;
        retired.fault_endpoint = 0;
        update.finish_retirement();
        journal.publish(0, binding(3).process, caps(3)).unwrap();
        let observer = journal.observer();
        assert_eq!(observer.expected_child_root(binding(2)), None);
        assert_eq!(observer.expected_child_root(binding(3)), Some(100));
    }
}
