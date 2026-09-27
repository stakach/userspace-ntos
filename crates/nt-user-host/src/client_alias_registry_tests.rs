use super::*;
use crate::process_identity::{ProcessGeneration, ProcessIdentity};
use alloc::{rc::Rc, vec, vec::Vec};
use core::cell::RefCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Copy(u64),
    Unmap(u64),
    Map(u64, u64),
    Delete(u64),
    Recycle(u64),
}

#[derive(Default)]
struct Effects {
    calls: Vec<Call>,
    fail: Vec<Call>,
}

#[derive(Clone, Default)]
struct Io(Rc<RefCell<Effects>>);

impl Io {
    fn effect(&self, call: Call) -> Result<(), u32> {
        let mut effects = self.0.borrow_mut();
        effects.calls.push(call);
        if effects.fail.contains(&call) {
            Err(77)
        } else {
            Ok(())
        }
    }
}

impl AliasRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Call::Unmap(cap))
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.effect(Call::Delete(cap))
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn recycle_unretyped_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.effect(Call::Recycle(slot))
    }
}

impl AliasTransitionIo for Io {
    fn copy(&mut self) -> (u64, u32) {
        panic!("switch must not create a cap")
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.effect(Call::Map(cap, rights))
    }
}

struct Setup {
    io: Io,
    cap: u64,
}

impl AliasRetirementIo for Setup {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.io.unmap(cap)
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.io.delete(cap)
    }
    fn recycle_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.io.recycle_slot(cap)
    }
    fn recycle_unretyped_slot(&mut self, cap: u64) -> Result<(), u32> {
        self.io.recycle_unretyped_slot(cap)
    }
}

impl AliasTransitionIo for Setup {
    fn copy(&mut self) -> (u64, u32) {
        self.io.effect(Call::Copy(self.cap)).unwrap();
        (self.cap, 0)
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.io.map(cap, rights)
    }
}

impl ReservedAliasTransitionIo for Setup {
    fn copy_into(&mut self, destination_cap: u64) -> Result<(), u32> {
        assert_eq!(destination_cap, self.cap);
        self.io.effect(Call::Copy(destination_cap))
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.io.map(cap, rights)
    }
}

fn owner(pi: usize, generation: u64) -> WindowOwner {
    WindowOwner {
        pi,
        process: ProcessIdentity {
            pid: pi as u32 + 100,
            generation: ProcessGeneration::Hosted(generation),
        },
        vspace: pi as u64 + 500,
    }
}

fn row(page: u64, cap: u64, io: &Io) -> ThreadAliasMapping {
    let mut row = ThreadAliasMapping::new(page).unwrap();
    row.replace(
        3,
        &mut Setup {
            io: io.clone(),
            cap,
        },
    )
    .unwrap();
    row
}

#[test]
fn suspended_caps_remain_owned_across_active_switch() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let old = owner(1, 1);
    let next = owner(2, 1);
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    registry.suspend_active(old, |_| io.clone()).unwrap();
    assert_eq!(registry.active_owner(), None);
    assert!(registry.owns_cap(10));
    assert_eq!(
        registry.page(old, 0x1000).unwrap().suspended(),
        Some((10, 3))
    );
    assert_eq!(
        registry.replacement_target(old, 0x1000).err(),
        Some(RegistryError::Busy)
    );
    assert_eq!(
        registry.retire_page(old, 0x1000, &mut io.clone()),
        Err(RegistryError::Busy)
    );
    registry
        .insert_active(next, &mut vec![row(0x1000, 20, &io)])
        .unwrap();
    assert_eq!(registry.active_owner(), Some(next));
    let mut rejected = vec![row(0x2000, 10, &io)];
    assert_eq!(
        registry.insert_active(owner(3, 1), &mut rejected),
        Err(RegistryError::ActiveOwner(next))
    );
    assert_eq!(rejected.len(), 1);
    assert!(registry.owns_cap(10));
}

#[test]
fn pi_reuse_and_missing_owners_are_distinct() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let original = owner(1, 8);
    registry
        .insert_active(original, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    let reused = owner(1, 9);
    assert_eq!(
        registry.state(reused),
        Err(RegistryError::StaleOwner(original))
    );
    let mut wrong_vspace = original;
    wrong_vspace.vspace += 1;
    assert_eq!(
        registry.page(wrong_vspace, 0x1000).err(),
        Some(RegistryError::StaleOwner(original))
    );
    assert_eq!(
        registry.state(owner(9, 1)),
        Err(RegistryError::MissingOwner)
    );
    assert_eq!(
        registry.insert_active(reused, &mut Vec::new()),
        Err(RegistryError::StaleOwner(original))
    );
}

#[test]
fn duplicate_page_and_cap_are_refused_before_admission() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let first = owner(1, 1);
    registry
        .insert_active(first, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    registry.suspend_active(first, |_| io.clone()).unwrap();
    let mut duplicate_page = vec![row(0x1000, 20, &io), row(0x1000, 21, &io)];
    assert_eq!(
        registry.insert_active(owner(2, 1), &mut duplicate_page),
        Err(RegistryError::DuplicatePage(0x1000))
    );
    assert_eq!(duplicate_page.len(), 2);
    let mut duplicate_cap = vec![row(0x2000, 10, &io)];
    assert_eq!(
        registry.insert_active(owner(2, 1), &mut duplicate_cap),
        Err(RegistryError::SharedCapability(10))
    );
    assert_eq!(duplicate_cap.len(), 1);
    assert_eq!(registry.active_owner(), None);
}

#[test]
fn failed_rollback_blocks_publication_and_keeps_all_caps_visible() {
    let io = Io::default();
    let old = owner(1, 1);
    let mut registry = ClientAliasRegistry::new();
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io), row(0x2000, 20, &io)])
        .unwrap();
    io.0.borrow_mut()
        .fail
        .extend([Call::Unmap(20), Call::Map(10, 3)]);
    assert_eq!(
        registry.suspend_active(old, |_| io.clone()),
        Err(RegistryError::Backend {
            page: 0x2000,
            status: 77
        })
    );
    assert_eq!(registry.state(old), Ok(WindowState::Blocked));
    assert_eq!(registry.active_owner(), None);
    assert_eq!(registry.blocked_owner(), Some(old));
    assert!(registry.owns_cap(10) && registry.owns_cap(20));
    assert_eq!(
        registry.page(old, 0x1000).unwrap().suspended(),
        Some((10, 3))
    );
    assert_eq!(
        registry.insert_active(owner(2, 1), &mut Vec::new()),
        Err(RegistryError::BlockedOwner(old))
    );
    assert_eq!(
        registry.retire_page(old, 0x1000, &mut io.clone()),
        Err(RegistryError::Busy)
    );
    assert_eq!(
        registry.replacement_target(old, 0x1000).err(),
        Some(RegistryError::Busy)
    );
    io.0.borrow_mut().fail.clear();
    registry.restore_owner(old, |_| io.clone()).unwrap();
    assert_eq!(registry.state(old), Ok(WindowState::Active));
}

#[test]
fn failed_target_restore_remains_blocked_and_prevents_other_publication() {
    let io = Io::default();
    let old = owner(1, 1);
    let mut registry = ClientAliasRegistry::new();
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    registry.suspend_active(old, |_| io.clone()).unwrap();
    io.0.borrow_mut().fail.push(Call::Map(10, 3));
    assert_eq!(
        registry.restore_owner(old, |_| io.clone()),
        Err(RegistryError::Backend {
            page: 0x1000,
            status: 77
        })
    );
    assert_eq!(registry.active_owner(), None);
    assert_eq!(registry.blocked_owner(), Some(old));
    assert!(registry.owns_cap(10));
    io.0.borrow_mut().fail.clear();
    registry.restore_owner(old, |_| io.clone()).unwrap();
    assert_eq!(registry.active_owner(), Some(old));
}

#[test]
fn failed_retirement_retains_exact_row_and_cap_for_retry() {
    let io = Io::default();
    let old = owner(1, 1);
    let mut registry = ClientAliasRegistry::new();
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    io.0.borrow_mut().fail.push(Call::Unmap(10));
    assert_eq!(
        registry.retire_page(old, 0x1000, &mut io.clone()),
        Err(RegistryError::Backend {
            page: 0x1000,
            status: 77,
        })
    );
    assert!(registry.owns_cap(10));
    assert!(registry.page(old, 0x1000).is_ok());
    assert_eq!(registry.remove_empty_owner(old), Err(RegistryError::Busy));
    io.0.borrow_mut().fail.clear();
    registry.retire_page(old, 0x1000, &mut io.clone()).unwrap();
    assert!(!registry.owns_cap(10));
    registry.remove_empty_owner(old).unwrap();
    assert_eq!(registry.state(old), Err(RegistryError::MissingOwner));
}

#[test]
fn terminal_retirement_releases_suspended_owner_without_remapping_it() {
    let io = Io::default();
    let old = owner(1, 1);
    let next = owner(2, 1);
    let mut registry = ClientAliasRegistry::new();
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    registry.suspend_active(old, |_| io.clone()).unwrap();
    registry
        .insert_active(next, &mut vec![row(0x1000, 20, &io)])
        .unwrap();
    assert_eq!(
        registry.retire_page(old, 0x1000, &mut io.clone()),
        Err(RegistryError::Busy)
    );
    registry.begin_retirement(old).unwrap();
    assert_eq!(registry.is_retiring(old), Ok(true));
    registry.retire_page(old, 0x1000, &mut io.clone()).unwrap();
    assert!(!registry.owns_cap(10));
    assert!(registry.owns_cap(20));
    registry.suspend_active(next, |_| io.clone()).unwrap();
    assert_eq!(
        registry.restore_owner(old, |_| io.clone()),
        Err(RegistryError::Busy)
    );
    registry.remove_empty_owner(old).unwrap();
    registry.restore_owner(next, |_| io.clone()).unwrap();
    assert_eq!(registry.active_owner(), Some(next));
}

#[test]
fn blocked_owner_can_be_retired_after_quiescence_without_recovery() {
    let io = Io::default();
    let old = owner(1, 1);
    let mut registry = ClientAliasRegistry::new();
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io), row(0x2000, 20, &io)])
        .unwrap();
    io.0.borrow_mut()
        .fail
        .extend([Call::Unmap(20), Call::Map(10, 3)]);
    assert!(registry.suspend_active(old, |_| io.clone()).is_err());
    assert_eq!(registry.blocked_owner(), Some(old));
    registry.begin_retirement(old).unwrap();
    io.0.borrow_mut().fail.clear();
    registry.retire_page(old, 0x1000, &mut io.clone()).unwrap();
    registry.retire_page(old, 0x2000, &mut io.clone()).unwrap();
    assert!(!registry.owns_cap(10) && !registry.owns_cap(20));
    registry.remove_empty_owner(old).unwrap();
    assert_eq!(registry.blocked_owner(), None);
}

#[test]
fn demand_mapping_preflights_every_retained_cap_before_copy() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let old = owner(1, 1);
    let next = owner(2, 1);
    registry
        .insert_active(old, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    registry.suspend_active(old, |_| io.clone()).unwrap();
    registry.insert_active(next, &mut Vec::new()).unwrap();
    let before = io.0.borrow().calls.len();
    let mut reused = Setup {
        io: io.clone(),
        cap: 10,
    };
    assert_eq!(
        registry.admit_active_page(next, 0x2000, 10, 3, &mut reused),
        Err(RegistryError::SharedCapability(10))
    );
    assert_eq!(io.0.borrow().calls.len(), before);
    assert_eq!(
        registry.page(next, 0x2000).err(),
        Some(RegistryError::MissingPage(0x2000))
    );
    let mut fresh = Setup {
        io: io.clone(),
        cap: 20,
    };
    registry
        .admit_active_page(next, 0x2000, 20, 3, &mut fresh)
        .unwrap();
    assert_eq!(registry.page(next, 0x2000).unwrap().live(), Some((20, 3)));
    let before = io.0.borrow().calls.len();
    assert_eq!(
        registry.replace_active_page(next, 0x2000, 10, 7, &mut reused),
        Err(RegistryError::SharedCapability(10))
    );
    assert_eq!(io.0.borrow().calls.len(), before);
}

#[test]
fn failed_replacement_retains_old_and_candidate_until_recovered() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let current = owner(1, 1);
    registry
        .insert_active(current, &mut vec![row(0x1000, 10, &io)])
        .unwrap();
    io.0.borrow_mut().fail.push(Call::Delete(10));
    let mut replacement = Setup {
        io: io.clone(),
        cap: 20,
    };
    assert_eq!(
        registry.replace_active_page(current, 0x1000, 20, 7, &mut replacement),
        Err(RegistryError::Backend {
            page: 0x1000,
            status: 77,
        })
    );
    assert!(registry.owns_cap(10) && registry.owns_cap(20));
    assert_eq!(registry.page(current, 0x1000).unwrap().live(), None);
    let mut duplicate = Setup {
        io: io.clone(),
        cap: 20,
    };
    assert_eq!(
        registry.admit_active_page(current, 0x2000, 20, 3, &mut duplicate),
        Err(RegistryError::SharedCapability(20))
    );
    io.0.borrow_mut().fail.clear();
    let copies_before =
        io.0.borrow()
            .calls
            .iter()
            .filter(|call| **call == Call::Copy(20))
            .count();
    registry
        .recover_page(current, 0x1000, &mut replacement)
        .unwrap();
    assert_eq!(
        registry.page(current, 0x1000).unwrap().live(),
        Some((20, 7))
    );
    assert!(!registry.owns_cap(10));
    assert_eq!(
        io.0.borrow()
            .calls
            .iter()
            .filter(|call| **call == Call::Copy(20))
            .count(),
        copies_before
    );
}

#[test]
fn failed_admission_keeps_candidate_row_until_cleanup() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let current = owner(1, 1);
    registry.insert_active(current, &mut Vec::new()).unwrap();
    io.0.borrow_mut()
        .fail
        .extend([Call::Map(20, 3), Call::Delete(20)]);
    let mut candidate = Setup {
        io: io.clone(),
        cap: 20,
    };
    assert_eq!(
        registry.admit_active_page(current, 0x2000, 20, 3, &mut candidate),
        Err(RegistryError::Backend {
            page: 0x2000,
            status: 77,
        })
    );
    assert!(registry.owns_cap(20));
    assert!(registry.page(current, 0x2000).is_ok());
    assert_eq!(
        registry.admit_active_page(current, 0x2000, 30, 3, &mut candidate),
        Err(RegistryError::DuplicatePage(0x2000))
    );
    io.0.borrow_mut().fail.clear();
    registry
        .recover_page(current, 0x2000, &mut candidate)
        .unwrap();
    assert!(!registry.owns_cap(20));
    assert_eq!(
        registry.page(current, 0x2000).err(),
        Some(RegistryError::MissingPage(0x2000))
    );
}

#[test]
fn failed_copy_recycles_only_the_reserved_empty_slot() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let current = owner(1, 1);
    registry.insert_active(current, &mut Vec::new()).unwrap();
    io.0.borrow_mut().fail.push(Call::Copy(20));
    let mut candidate = Setup {
        io: io.clone(),
        cap: 20,
    };
    assert_eq!(
        registry.admit_active_page(current, 0x2000, 20, 3, &mut candidate),
        Err(RegistryError::Backend {
            page: 0x2000,
            status: 77,
        })
    );
    assert!(!registry.owns_cap(20));
    assert!(registry.page(current, 0x2000).is_err());
    assert!(io.0.borrow().calls.contains(&Call::Recycle(20)));
    assert!(!io.0.borrow().calls.contains(&Call::Delete(20)));
}

#[test]
fn failed_copy_and_recycle_retains_empty_slot_for_retry() {
    let io = Io::default();
    let mut registry = ClientAliasRegistry::new();
    let current = owner(1, 1);
    registry.insert_active(current, &mut Vec::new()).unwrap();
    io.0.borrow_mut()
        .fail
        .extend([Call::Copy(20), Call::Recycle(20)]);
    let mut candidate = Setup {
        io: io.clone(),
        cap: 20,
    };
    assert_eq!(
        registry.admit_active_page(current, 0x2000, 20, 3, &mut candidate),
        Err(RegistryError::Backend {
            page: 0x2000,
            status: 77,
        })
    );
    assert!(registry.owns_cap(20));
    assert!(registry.page(current, 0x2000).is_ok());
    io.0.borrow_mut().fail.clear();
    registry
        .recover_page(current, 0x2000, &mut candidate)
        .unwrap();
    assert!(!registry.owns_cap(20));
    assert!(registry.page(current, 0x2000).is_err());
    assert!(!io.0.borrow().calls.contains(&Call::Delete(20)));
}
