use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Copy(u64),
    Map(u64, u64),
    Unmap(u64),
    Delete(u64),
    Recycle(u64),
}

struct Io {
    next: u64,
    copy_status: u32,
    fail_maps: Vec<(u64, u64)>,
    fail_unmap: Option<u64>,
    fail_delete: Option<u64>,
    fail_recycle: Option<u64>,
    populated: Vec<u64>,
    mapped: Option<(u64, u64)>,
    calls: Vec<Call>,
}

impl Default for Io {
    fn default() -> Self {
        Self {
            next: 42,
            copy_status: 0,
            fail_maps: Vec::new(),
            fail_unmap: None,
            fail_delete: None,
            fail_recycle: None,
            populated: Vec::new(),
            mapped: None,
            calls: Vec::new(),
        }
    }
}

impl AliasRetirementIo for Io {
    fn unmap(&mut self, cap: u64) -> Result<(), u32> {
        self.calls.push(Call::Unmap(cap));
        if self.fail_unmap == Some(cap) {
            return Err(4);
        }
        assert_eq!(self.mapped.map(|(mapped, _)| mapped), Some(cap));
        self.mapped = None;
        Ok(())
    }
    fn delete(&mut self, cap: u64) -> Result<(), u32> {
        self.calls.push(Call::Delete(cap));
        assert_ne!(self.mapped.map(|(mapped, _)| mapped), Some(cap));
        if self.fail_delete == Some(cap) {
            Err(5)
        } else {
            let index = self
                .populated
                .iter()
                .position(|&slot| slot == cap)
                .expect("delete only populated caps once");
            self.populated.swap_remove(index);
            Ok(())
        }
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("copied aliases require strict unretyped recycling")
    }
    fn recycle_unretyped_slot(&mut self, slot: u64) -> Result<(), u32> {
        self.calls.push(Call::Recycle(slot));
        assert!(!self.populated.contains(&slot));
        if self.fail_recycle == Some(slot) {
            Err(6)
        } else {
            Ok(())
        }
    }
}

impl AliasTransitionIo for Io {
    fn copy(&mut self) -> (u64, u32) {
        let cap = self.next;
        self.next += 1;
        self.calls.push(Call::Copy(cap));
        if cap != 0 && self.copy_status == 0 {
            self.populated.push(cap);
        }
        (cap, self.copy_status)
    }
    fn map(&mut self, cap: u64, rights: u64) -> Result<(), u32> {
        self.calls.push(Call::Map(cap, rights));
        if self.fail_maps.contains(&(cap, rights)) {
            return Err(3);
        }
        assert_eq!(
            self.mapped, None,
            "one alias VA may have only one mapped owner"
        );
        self.mapped = Some((cap, rights));
        Ok(())
    }
}

fn live() -> (AliasTransition, Io) {
    let mut owner = AliasTransition::empty();
    let mut io = Io::default();
    owner.replace(1, &mut io).unwrap();
    io.calls.clear();
    (owner, io)
}

#[test]
fn snapshots_observe_live_and_unpublished_caps_without_backend_effects() {
    let (mut owner, mut io) = live();
    let before = owner.snapshot();
    assert_eq!(before.capabilities().collect::<Vec<_>>(), vec![42]);
    assert_eq!(owner.snapshot(), before);
    assert!(io.calls.is_empty());
    io.fail_delete = Some(42);
    assert_eq!(owner.replace(2, &mut io), Err(5));
    let pending = owner.snapshot();
    assert_eq!(pending.capabilities().collect::<Vec<_>>(), vec![42, 43]);
    assert_ne!(pending, before);
    assert!(!pending.old.mapped && pending.new.mapped);
    let calls = io.calls.len();
    assert_eq!(owner.snapshot(), pending);
    assert_eq!(io.calls.len(), calls);
}

#[test]
fn snapshots_distinguish_retirement_and_failed_copy_state_from_empty() {
    let (mut owner, mut io) = live();
    let live = owner.snapshot();
    io.fail_delete = Some(42);
    assert_eq!(owner.retire(&mut io), Err(5));
    let retiring = owner.snapshot();
    assert_ne!(retiring, live);
    assert!(!retiring.old.mapped);
    io.fail_delete = None;
    owner.retire(&mut io).unwrap();
    let empty = owner.snapshot();
    assert_eq!(empty.capabilities().count(), 0);
    io.copy_status = 2;
    io.fail_recycle = Some(43);
    assert_eq!(owner.replace(1, &mut io), Err(2));
    let failed = owner.snapshot();
    assert_ne!(failed, empty);
    assert_eq!(failed.capabilities().collect::<Vec<_>>(), vec![43]);
    assert!(!failed.new.mapped);
}

#[test]
fn initial_copy_is_published_only_after_mapping_and_detach_is_idempotent() {
    let mut owner = AliasTransition::empty();
    let mut io = Io::default();
    assert!(owner.is_empty());
    owner.replace(1, &mut io).unwrap();
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(io.calls, vec![Call::Copy(42), Call::Map(42, 1)]);
    owner.retire(&mut io).unwrap();
    owner.retire(&mut io).unwrap();
    assert!(owner.is_empty());
    assert_eq!(
        &io.calls[2..],
        &[Call::Unmap(42), Call::Delete(42), Call::Recycle(42)]
    );
}

#[test]
fn failed_copy_slot_is_retained_without_attempting_a_map() {
    let mut owner = AliasTransition::empty();
    let mut io = Io {
        copy_status: 2,
        fail_recycle: Some(42),
        ..Io::default()
    };
    assert_eq!(owner.replace(1, &mut io), Err(2));
    assert_eq!(owner.live(), None);
    assert!(!owner.is_empty());
    assert_eq!(io.calls, vec![Call::Copy(42), Call::Recycle(42)]);
    io.fail_recycle = None;
    owner.recover(&mut io).unwrap();
    assert!(owner.is_empty());
    assert_eq!(io.calls.last(), Some(&Call::Recycle(42)));
}

#[test]
fn null_copy_result_is_never_mapped_or_deleted() {
    let mut owner = AliasTransition::empty();
    let mut io = Io {
        next: 0,
        ..Io::default()
    };
    assert_eq!(owner.replace(1, &mut io), Err(RESOURCES));
    assert!(owner.is_empty());
    assert_eq!(io.calls, vec![Call::Copy(0)]);
}

#[test]
fn initial_map_failure_retains_unmapped_cap_until_delete_succeeds() {
    let mut owner = AliasTransition::empty();
    let mut io = Io {
        fail_maps: vec![(42, 1)],
        fail_delete: Some(42),
        ..Io::default()
    };
    assert_eq!(owner.replace(1, &mut io), Err(3));
    assert!(!owner.is_empty());
    io.fail_delete = None;
    owner.recover(&mut io).unwrap();
    assert!(owner.is_empty());
    assert_eq!(
        io.calls,
        vec![
            Call::Copy(42),
            Call::Map(42, 1),
            Call::Delete(42),
            Call::Delete(42),
            Call::Recycle(42)
        ]
    );
}

#[test]
fn replacement_copies_before_unmap_and_deletes_old_before_publication() {
    let (mut owner, mut io) = live();
    owner.replace(2, &mut io).unwrap();
    assert_eq!(owner.live(), Some((43, 2)));
    assert_eq!(
        io.calls,
        vec![
            Call::Copy(43),
            Call::Unmap(42),
            Call::Map(43, 2),
            Call::Delete(42),
            Call::Recycle(42)
        ]
    );
}

#[test]
fn failed_candidate_copy_does_not_detach_old_mapping() {
    let (mut owner, mut io) = live();
    io.copy_status = 2;
    assert_eq!(owner.replace(2, &mut io), Err(2));
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(io.calls, vec![Call::Copy(43), Call::Recycle(43)]);
}

#[test]
fn failed_old_unmap_releases_candidate_and_preserves_old_rights() {
    let (mut owner, mut io) = live();
    io.fail_unmap = Some(42);
    assert_eq!(owner.replace(2, &mut io), Err(4));
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(
        io.calls,
        vec![
            Call::Copy(43),
            Call::Unmap(42),
            Call::Delete(43),
            Call::Recycle(43)
        ]
    );
}

#[test]
fn failed_candidate_recycle_hides_even_the_still_mapped_old_cap() {
    let (mut owner, mut io) = live();
    io.copy_status = 2;
    io.fail_recycle = Some(43);
    assert_eq!(owner.replace(2, &mut io), Err(2));
    assert_eq!(owner.live(), None);
    assert_eq!(io.mapped, Some((42, 1)));
    io.fail_recycle = None;
    owner.recover(&mut io).unwrap();
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(
        io.calls,
        vec![Call::Copy(43), Call::Recycle(43), Call::Recycle(43)]
    );
}

#[test]
fn replacement_map_failure_rolls_back_without_reporting_success() {
    let (mut owner, mut io) = live();
    io.fail_maps.push((43, 2));
    assert_eq!(owner.replace(2, &mut io), Err(3));
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(
        io.calls,
        vec![
            Call::Copy(43),
            Call::Unmap(42),
            Call::Map(43, 2),
            Call::Delete(43),
            Call::Recycle(43),
            Call::Map(42, 1)
        ]
    );
}

#[test]
fn rollback_delete_and_restore_failures_retain_both_stages() {
    let (mut owner, mut io) = live();
    io.fail_maps = vec![(43, 2), (42, 1)];
    io.fail_delete = Some(43);
    assert_eq!(owner.replace(2, &mut io), Err(3));
    assert_eq!(owner.live(), None);
    assert_eq!(io.mapped, None);
    io.fail_delete = None;
    assert_eq!(owner.recover(&mut io), Err(3));
    assert_eq!(owner.live(), None);
    io.fail_maps.clear();
    let before = io.calls.len();
    owner.recover(&mut io).unwrap();
    assert_eq!(&io.calls[before..], &[Call::Map(42, 1)]);
    assert_eq!(owner.live(), Some((42, 1)));
}

#[test]
fn commit_delete_failure_retries_only_old_deletion_not_copy_or_map() {
    let (mut owner, mut io) = live();
    io.fail_delete = Some(42);
    assert_eq!(owner.replace(2, &mut io), Err(5));
    assert_eq!(owner.live(), None);
    assert_eq!(io.mapped, Some((43, 2)));
    io.fail_delete = None;
    let before = io.calls.len();
    owner.recover(&mut io).unwrap();
    assert_eq!(&io.calls[before..], &[Call::Delete(42), Call::Recycle(42)]);
    assert_eq!(owner.live(), Some((43, 2)));
}

#[test]
fn remap_reuses_same_cap_without_copy_or_delete() {
    let (mut owner, mut io) = live();
    owner.remap(2, &mut io).unwrap();
    assert_eq!(owner.live(), Some((42, 2)));
    assert_eq!(io.calls, vec![Call::Unmap(42), Call::Map(42, 2)]);
}

#[test]
fn remap_failure_restores_exact_old_rights_and_returns_failure() {
    let (mut owner, mut io) = live();
    io.fail_maps.push((42, 2));
    assert_eq!(owner.remap(2, &mut io), Err(3));
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(
        io.calls,
        vec![Call::Unmap(42), Call::Map(42, 2), Call::Map(42, 1)]
    );
}

#[test]
fn failed_remap_restore_is_unavailable_and_retries_only_restore() {
    let (mut owner, mut io) = live();
    io.fail_maps = vec![(42, 2), (42, 1)];
    assert_eq!(owner.remap(2, &mut io), Err(3));
    assert_eq!(owner.live(), None);
    let before = io.calls.len();
    assert_eq!(owner.remap(2, &mut io), Err(INVALID));
    assert_eq!(owner.replace(2, &mut io), Err(INVALID));
    assert_eq!(io.calls.len(), before);
    io.fail_maps.clear();
    owner.recover(&mut io).unwrap();
    assert_eq!(&io.calls[before..], &[Call::Map(42, 1)]);
    assert_eq!(owner.live(), Some((42, 1)));
}

#[test]
fn explicit_detach_can_cancel_pending_commit_and_retains_failed_delete() {
    let (mut owner, mut io) = live();
    io.fail_delete = Some(42);
    assert_eq!(owner.replace(2, &mut io), Err(5));
    assert_eq!(owner.retire(&mut io), Err(5));
    assert_eq!(owner.live(), None);
    assert_eq!(io.mapped, None);
    io.fail_delete = None;
    let before = io.calls.len();
    owner.recover(&mut io).unwrap();
    assert_eq!(&io.calls[before..], &[Call::Delete(42), Call::Recycle(42)]);
    assert!(owner.is_empty());
}

#[test]
fn failed_detach_unmap_never_deletes_the_mapped_cap() {
    let (mut owner, mut io) = live();
    io.fail_unmap = Some(42);
    assert_eq!(owner.retire(&mut io), Err(4));
    assert_eq!(owner.live(), None);
    assert_eq!(io.calls, vec![Call::Unmap(42)]);
    io.fail_unmap = None;
    owner.retire(&mut io).unwrap();
    assert_eq!(
        io.calls,
        vec![
            Call::Unmap(42),
            Call::Unmap(42),
            Call::Delete(42),
            Call::Recycle(42)
        ]
    );
    assert!(owner.is_empty());
}

#[test]
fn commit_recycle_failure_retains_deleted_slot_and_candidate_without_replay() {
    let (mut owner, mut io) = live();
    io.fail_delete = Some(42);
    assert_eq!(owner.replace(2, &mut io), Err(5));
    let before_delete = owner.snapshot();
    io.fail_delete = None;
    io.fail_recycle = Some(42);
    assert_eq!(owner.recover(&mut io), Err(6));
    let after_delete = owner.snapshot();
    assert_ne!(before_delete, after_delete);
    assert!(before_delete.old.populated && !after_delete.old.populated);
    assert_eq!(
        after_delete.capabilities().collect::<Vec<_>>(),
        vec![42, 43]
    );
    assert_eq!(owner.live(), None);
    assert_eq!(io.mapped, Some((43, 2)));
    for _ in 0..3 {
        let before = io.calls.len();
        assert_eq!(owner.recover(&mut io), Err(6));
        assert_eq!(&io.calls[before..], &[Call::Recycle(42)]);
        assert_eq!(owner.snapshot(), after_delete);
    }
    io.fail_recycle = None;
    let before = io.calls.len();
    owner.recover(&mut io).unwrap();
    assert_eq!(&io.calls[before..], &[Call::Recycle(42)]);
    assert_eq!(owner.live(), Some((43, 2)));
}

#[test]
fn rollback_recycle_failure_postpones_restore_without_repeating_delete() {
    let (mut owner, mut io) = live();
    io.fail_maps.push((43, 2));
    io.fail_recycle = Some(43);
    assert_eq!(owner.replace(2, &mut io), Err(3));
    assert_eq!(io.mapped, None);
    assert_eq!(owner.live(), None);
    assert!(!owner.snapshot().new.populated);
    for _ in 0..3 {
        let before = io.calls.len();
        assert_eq!(owner.recover(&mut io), Err(6));
        assert_eq!(&io.calls[before..], &[Call::Recycle(43)]);
    }
    io.fail_recycle = None;
    let before = io.calls.len();
    owner.recover(&mut io).unwrap();
    assert_eq!(&io.calls[before..], &[Call::Recycle(43), Call::Map(42, 1)]);
    assert_eq!(owner.live(), Some((42, 1)));
}

#[test]
fn explicit_retirement_cancels_both_recycle_recovery_directions() {
    for rollback in [false, true] {
        let (mut owner, mut io) = live();
        if rollback {
            io.fail_maps.push((43, 2));
        }
        io.fail_recycle = Some(if rollback { 43 } else { 42 });
        assert!(owner.replace(2, &mut io).is_err());
        assert!(!owner.is_empty());
        io.fail_recycle = None;
        let before = io.calls.len();
        owner.retire(&mut io).unwrap();
        owner.retire(&mut io).unwrap();
        assert!(owner.is_empty());
        assert_eq!(io.mapped, None);
        assert!(io.populated.is_empty());
        assert!(!io.calls[before..]
            .iter()
            .any(|call| matches!(call, Call::Copy(_) | Call::Map(_, _))));
        for cap in [42, 43] {
            assert_eq!(
                io.calls
                    .iter()
                    .filter(|call| **call == Call::Delete(cap))
                    .count(),
                1
            );
        }
    }
}
