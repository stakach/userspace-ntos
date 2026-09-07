use super::*;
use alloc::vec;
use alloc::vec::Vec;

#[derive(Debug, PartialEq, Eq)]
enum Call {
    Copy(u64),
    Map(u64, u64),
    Unmap(u64),
    Delete(u64),
}

struct Io {
    next: u64,
    copy_status: u32,
    fail_maps: Vec<(u64, u64)>,
    fail_unmap: Option<u64>,
    fail_delete: Option<u64>,
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
            Ok(())
        }
    }
}

impl AliasTransitionIo for Io {
    fn copy(&mut self) -> (u64, u32) {
        let cap = self.next;
        self.next += 1;
        self.calls.push(Call::Copy(cap));
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
    io.fail_delete = Some(43);
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
    assert_eq!(&io.calls[2..], &[Call::Unmap(42), Call::Delete(42)]);
}

#[test]
fn failed_copy_slot_is_retained_without_attempting_a_map() {
    let mut owner = AliasTransition::empty();
    let mut io = Io {
        copy_status: 2,
        fail_delete: Some(42),
        ..Io::default()
    };
    assert_eq!(owner.replace(1, &mut io), Err(2));
    assert_eq!(owner.live(), None);
    assert!(!owner.is_empty());
    assert_eq!(io.calls, vec![Call::Copy(42), Call::Delete(42)]);
    io.fail_delete = None;
    owner.recover(&mut io).unwrap();
    assert!(owner.is_empty());
    assert_eq!(io.calls.last(), Some(&Call::Delete(42)));
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
            Call::Delete(42)
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
            Call::Delete(42)
        ]
    );
}

#[test]
fn failed_candidate_copy_does_not_detach_old_mapping() {
    let (mut owner, mut io) = live();
    io.copy_status = 2;
    assert_eq!(owner.replace(2, &mut io), Err(2));
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(io.calls, vec![Call::Copy(43), Call::Delete(43)]);
}

#[test]
fn failed_old_unmap_releases_candidate_and_preserves_old_rights() {
    let (mut owner, mut io) = live();
    io.fail_unmap = Some(42);
    assert_eq!(owner.replace(2, &mut io), Err(4));
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(
        io.calls,
        vec![Call::Copy(43), Call::Unmap(42), Call::Delete(43)]
    );
}

#[test]
fn failed_candidate_delete_hides_even_the_still_mapped_old_cap() {
    let (mut owner, mut io) = live();
    io.copy_status = 2;
    io.fail_delete = Some(43);
    assert_eq!(owner.replace(2, &mut io), Err(2));
    assert_eq!(owner.live(), None);
    assert_eq!(io.mapped, Some((42, 1)));
    io.fail_delete = None;
    owner.recover(&mut io).unwrap();
    assert_eq!(owner.live(), Some((42, 1)));
    assert_eq!(
        io.calls,
        vec![Call::Copy(43), Call::Delete(43), Call::Delete(43)]
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
    assert_eq!(&io.calls[before..], &[Call::Delete(42)]);
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
    assert_eq!(&io.calls[before..], &[Call::Delete(42)]);
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
        vec![Call::Unmap(42), Call::Unmap(42), Call::Delete(42)]
    );
    assert!(owner.is_empty());
}
