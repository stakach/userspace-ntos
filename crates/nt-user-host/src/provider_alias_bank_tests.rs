use super::*;
use crate::process_identity::ProcessGeneration;
use alloc::vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Copy(u64),
    Map(u64),
    Segment(usize),
    Move(u64, ChildCap),
    Recycle(u64),
    DeleteRoot(u64),
    DeleteChild(ChildCap),
}

#[derive(Default)]
struct Io {
    calls: Vec<Call>,
    fail: Option<Call>,
    next: u64,
    copy_failure: Option<(u64, u32)>,
    null_segment: bool,
    same_segments: bool,
}

impl Io {
    fn call(&mut self, call: Call) -> Result<(), u32> {
        self.calls.push(call);
        if self.fail == Some(call) {
            self.fail = None;
            Err(99)
        } else {
            Ok(())
        }
    }
}

impl ProviderAliasIo for Io {
    fn copy(&mut self, source: u64) -> (u64, u32) {
        self.calls.push(Call::Copy(source));
        if let Some(result) = self.copy_failure.take() {
            return result;
        }
        self.next += 1;
        (100 + self.next, 0)
    }
    fn map(&mut self, root: u64, _: u64, _: u64, _: u64) -> Result<(), u32> {
        self.call(Call::Map(root))
    }
    fn ensure_segment(&mut self, segment: usize) -> Result<u64, u32> {
        self.call(Call::Segment(segment))?;
        Ok(if self.null_segment {
            0
        } else if self.same_segments {
            1000
        } else {
            1000 + segment as u64
        })
    }
    fn move_to_child(&mut self, root: u64, child: ChildCap) -> Result<(), u32> {
        self.call(Call::Move(root, child))
    }
    fn recycle_empty_root(&mut self, root: u64) -> Result<(), u32> {
        self.call(Call::Recycle(root))
    }
    fn delete_root(&mut self, root: u64) -> Result<(), u32> {
        self.call(Call::DeleteRoot(root))
    }
    fn delete_child(&mut self, child: ChildCap) -> Result<(), u32> {
        self.call(Call::DeleteChild(child))
    }
}

fn request(page: u64) -> ProviderAliasRequest {
    ProviderAliasRequest {
        pi: 300,
        process: ProcessIdentity {
            pid: 99,
            generation: ProcessGeneration::Hosted(7),
        },
        page,
        pml4: 10,
        source_frame: 20,
        rights: 3,
    }
}
fn child(slot: u64) -> ChildCap {
    ChildCap { cnode: 1000, slot }
}
fn bank() -> ProviderAliasBank {
    ProviderAliasBank::new(2, 2).unwrap()
}

#[test]
fn exact_request_is_idempotent_and_has_typed_child_ownership() {
    let mut bank = bank();
    let mut io = Io::default();
    let req = request(4096);
    let handle = bank.map(req, &mut io).unwrap();
    assert_eq!(
        io.calls,
        vec![
            Call::Copy(20),
            Call::Map(101),
            Call::Segment(0),
            Call::Move(101, child(0)),
            Call::Recycle(101)
        ]
    );
    io.calls.clear();
    assert_eq!(bank.map(req, &mut io), Ok(handle));
    assert!(io.calls.is_empty());
    let snapshot = bank.get(handle).unwrap();
    assert_eq!(snapshot.request, req);
    assert_eq!(snapshot.child, Some(child(0)));
    assert_eq!(snapshot.root, None);
    assert_eq!(bank.stats().mapped, 1);
}

#[test]
fn invalid_requests_and_conflicting_lifetimes_have_no_effects() {
    let mut bank = bank();
    let mut io = Io::default();
    let req = request(4096);
    bank.map(req, &mut io).unwrap();
    io.calls.clear();
    for invalid in [
        ProviderAliasRequest { page: 4097, ..req },
        ProviderAliasRequest {
            source_frame: 0,
            ..req
        },
        ProviderAliasRequest { pml4: 0, ..req },
        ProviderAliasRequest {
            page: u64::MAX & !4095,
            ..req
        },
        ProviderAliasRequest {
            process: ProcessIdentity::empty(),
            ..req
        },
    ] {
        assert_eq!(bank.map(invalid, &mut io), Err(BankError::InvalidRequest));
    }
    assert_eq!(
        bank.map(ProviderAliasRequest { rights: 1, ..req }, &mut io),
        Err(BankError::RequestConflict)
    );
    let foreign = ProcessIdentity {
        generation: ProcessGeneration::Hosted(8),
        ..req.process
    };
    assert_eq!(
        bank.map(
            ProviderAliasRequest {
                process: foreign,
                page: 8192,
                ..req
            },
            &mut io
        ),
        Err(BankError::OwnerChanged)
    );
    assert_eq!(
        bank.release_process(req.pi, foreign, &mut io),
        Err(BankError::OwnerChanged)
    );
    assert!(!bank.snapshots().next().unwrap().releasing);
    assert!(io.calls.is_empty());
}

#[test]
fn allocated_empty_copy_failure_recycles_before_retrying_copy() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        copy_failure: Some((50, 17)),
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(17)));
    assert_eq!(
        bank.snapshots().next().unwrap().root,
        Some(RootAliasSnapshot {
            slot: 50,
            populated: false,
            mapped: false
        })
    );
    io.calls.clear();
    io.fail = Some(Call::Recycle(50));
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(99)));
    assert_eq!(io.calls, vec![Call::Recycle(50)]);
    io.calls.clear();
    bank.map(req, &mut io).unwrap();
    assert_eq!(&io.calls[..2], &[Call::Recycle(50), Call::Copy(20)]);
}

#[test]
fn copy_without_acquisition_and_null_success_remain_owned_requests() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        copy_failure: Some((0, 17)),
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(17)));
    assert_eq!(bank.stats().live, 1);
    assert_eq!(bank.snapshots().next().unwrap().root, None);
    io.copy_failure = Some((0, 0));
    assert_eq!(bank.map(req, &mut io), Err(BankError::InvalidBackend));
    assert!(io.calls.iter().all(|call| *call == Call::Copy(20)));
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    assert!(bank.is_empty());
}

#[test]
fn map_failure_retries_mapping_without_copying() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Map(101)),
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(99)));
    assert_eq!(
        bank.snapshots().next().unwrap().root,
        Some(RootAliasSnapshot {
            slot: 101,
            populated: true,
            mapped: false
        })
    );
    io.calls.clear();
    bank.map(req, &mut io).unwrap();
    assert_eq!(io.calls[0], Call::Map(101));
    assert!(!io.calls.contains(&Call::Copy(20)));
}

#[test]
fn segment_failure_retains_mapped_root_without_remapping() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Segment(0)),
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(99)));
    assert!(bank.snapshots().next().unwrap().root.unwrap().mapped);
    io.calls.clear();
    bank.map(req, &mut io).unwrap();
    assert_eq!(
        io.calls,
        vec![
            Call::Segment(0),
            Call::Move(101, child(0)),
            Call::Recycle(101)
        ]
    );
}

#[test]
fn null_segment_is_rejected_without_losing_root() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        null_segment: true,
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::InvalidBackend));
    assert!(bank.snapshots().next().unwrap().root.unwrap().mapped);
    assert!(!io.calls.iter().any(|call| matches!(call, Call::Move(_, _))));
    io.null_segment = false;
    bank.map(req, &mut io).unwrap();
}

#[test]
fn move_failure_keeps_exact_reserved_child_slot_for_retry() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Move(101, child(0))),
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(99)));
    assert_eq!(bank.snapshots().next().unwrap().child, None);
    io.calls.clear();
    bank.map(req, &mut io).unwrap();
    assert_eq!(
        io.calls,
        vec![
            Call::Segment(0),
            Call::Move(101, child(0)),
            Call::Recycle(101)
        ]
    );
}

#[test]
fn moved_child_survives_root_recycle_failure_without_repeat_move() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Recycle(101)),
        ..Io::default()
    };
    assert_eq!(bank.map(req, &mut io), Err(BankError::Backend(99)));
    let snapshot = bank.snapshots().next().unwrap();
    assert_eq!(snapshot.child, Some(child(0)));
    assert_eq!(
        snapshot.root,
        Some(RootAliasSnapshot {
            slot: 101,
            populated: false,
            mapped: false
        })
    );
    io.calls.clear();
    bank.map(req, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(101)]);
    assert_eq!(bank.stats().moves, 1);
}

#[test]
fn release_after_map_failure_deletes_then_recycles_exact_root() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Map(101)),
        ..Io::default()
    };
    assert!(bank.map(req, &mut io).is_err());
    io.calls.clear();
    io.fail = Some(Call::DeleteRoot(101));
    assert_eq!(
        bank.release_process(req.pi, req.process, &mut io),
        Err(BankError::Backend(99))
    );
    assert!(bank.snapshots().next().unwrap().root.unwrap().populated);
    io.calls.clear();
    io.fail = Some(Call::Recycle(101));
    assert!(bank.release_process(req.pi, req.process, &mut io).is_err());
    assert_eq!(io.calls, vec![Call::DeleteRoot(101), Call::Recycle(101)]);
    assert!(!bank.snapshots().next().unwrap().root.unwrap().populated);
    io.calls.clear();
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(101)]);
    assert!(bank.is_empty());
}

#[test]
fn release_empty_copy_destination_never_deletes_it() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        copy_failure: Some((50, 17)),
        ..Io::default()
    };
    assert!(bank.map(req, &mut io).is_err());
    io.calls.clear();
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(50)]);
}

#[test]
fn release_acknowledges_child_deletion_before_retrying_root_recycle() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Recycle(101)),
        ..Io::default()
    };
    assert!(bank.map(req, &mut io).is_err());
    io.calls.clear();
    io.fail = Some(Call::Recycle(101));
    assert!(bank.release_process(req.pi, req.process, &mut io).is_err());
    assert_eq!(
        io.calls,
        vec![Call::DeleteChild(child(0)), Call::Recycle(101)]
    );
    assert_eq!(bank.snapshots().next().unwrap().child, None);
    io.calls.clear();
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(101)]);
}

#[test]
fn partial_process_release_fences_all_remaining_rows_and_preserves_other_process() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io::default();
    bank.map(req, &mut io).unwrap();
    bank.map(request(8192), &mut io).unwrap();
    let other = ProviderAliasRequest {
        pi: 301,
        ..request(4096)
    };
    let other_handle = bank.map(other, &mut io).unwrap();
    io.calls.clear();
    io.fail = Some(Call::DeleteChild(child(1)));
    assert!(bank.release_process(req.pi, req.process, &mut io).is_err());
    assert_eq!(bank.stats().live, 2);
    assert_eq!(bank.stats().releases, 1);
    assert!(bank
        .snapshots()
        .filter(|row| row.request.pi == req.pi)
        .all(|row| row.releasing));
    assert_eq!(bank.map(request(12288), &mut io), Err(BankError::Releasing));
    assert_eq!(bank.map(request(8192), &mut io), Err(BankError::Releasing));
    assert_eq!(bank.map(other, &mut io), Ok(other_handle));
    io.calls.clear();
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::DeleteChild(child(1))]);
    assert!(bank.process_is_empty(req.pi));
    assert!(!bank.process_is_empty(other.pi));
    assert!(bank.get(other_handle).is_some());
}

#[test]
fn child_slot_reuse_changes_generation_and_allows_new_process_lifetime() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io::default();
    let old = bank.map(req, &mut io).unwrap();
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    let newer = ProviderAliasRequest {
        process: ProcessIdentity {
            generation: ProcessGeneration::Hosted(8),
            ..req.process
        },
        ..req
    };
    let new = bank.map(newer, &mut io).unwrap();
    assert_eq!(old.index(), new.index());
    assert_ne!(old.generation(), new.generation());
    assert_eq!(bank.get(old), None);
    assert_eq!(bank.entry_count(), 1);
    assert_eq!(
        bank.release_process(req.pi, req.process, &mut io),
        Err(BankError::OwnerChanged)
    );
}

#[test]
fn slot_capacity_and_segment_boundaries_are_checked_before_copy() {
    assert!(ProviderAliasBank::new(0, 1).is_err());
    assert!(ProviderAliasBank::new(1, 0).is_err());
    assert!(ProviderAliasBank::new(u64::MAX, 2).is_err());
    let mut bank = bank();
    let mut io = Io::default();
    for page in [4096, 8192, 12288, 16384] {
        bank.map(request(page), &mut io).unwrap();
    }
    assert_eq!(
        bank.snapshots().nth(2).unwrap().child,
        Some(ChildCap {
            cnode: 1001,
            slot: 0
        })
    );
    io.calls.clear();
    assert_eq!(
        bank.map(request(20480), &mut io),
        Err(BankError::InsufficientResources)
    );
    assert!(io.calls.is_empty());
    assert_eq!(bank.stats().high_water, 4);
}

#[test]
fn generation_exhaustion_never_reuses_an_old_handle() {
    let mut bank = ProviderAliasBank::new(1, 1).unwrap();
    let req = request(4096);
    let mut io = Io::default();
    bank.map(req, &mut io).unwrap();
    bank.slots[0].generation = u64::MAX;
    bank.processes[0].pages[0].1.generation = u64::MAX;
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    io.calls.clear();
    assert_eq!(
        bank.map(req, &mut io),
        Err(BankError::InsufficientResources)
    );
    assert!(io.calls.is_empty());
}

#[test]
fn released_slots_reused_during_partial_release_are_not_deleted_by_old_owner() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io::default();
    bank.map(req, &mut io).unwrap();
    bank.map(request(8192), &mut io).unwrap();
    io.fail = Some(Call::DeleteChild(child(1)));
    assert!(bank.release_process(req.pi, req.process, &mut io).is_err());
    let other = ProviderAliasRequest { pi: 901, ..req };
    let handle = bank.map(other, &mut io).unwrap();
    assert_eq!(handle.index(), 0);
    io.calls.clear();
    bank.release_process(req.pi, req.process, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::DeleteChild(child(1))]);
    assert!(!bank.get(handle).unwrap().releasing);
    assert_eq!(bank.map(other, &mut io), Ok(handle));
}

#[test]
fn process_admission_and_prefix_require_exact_published_mappings() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io::default();
    assert_eq!(bank.admit_process(req.pi, req.process), Ok(()));
    assert!(bank.mapped_prefix(req.pi, req.process, req.page, 0, 10, 20, 3));
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 1, 10, 20, 3));
    bank.map(req, &mut io).unwrap();
    bank.map(
        ProviderAliasRequest {
            page: 8192,
            source_frame: 21,
            ..req
        },
        &mut io,
    )
    .unwrap();
    assert!(bank.mapped_prefix(req.pi, req.process, req.page, 2, 10, 20, 3));
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 3, 10, 20, 3));
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 2, 11, 20, 3));
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 2, 10, 21, 3));
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 2, 10, 20, 1));
    io.fail = Some(Call::DeleteChild(child(0)));
    assert!(bank.release_process(req.pi, req.process, &mut io).is_err());
    assert_eq!(
        bank.admit_process(req.pi, req.process),
        Err(BankError::Releasing)
    );
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 2, 10, 20, 3));
}

#[test]
fn moved_but_unrecycled_root_does_not_publish_prefix() {
    let mut bank = bank();
    let req = request(4096);
    let mut io = Io {
        fail: Some(Call::Recycle(101)),
        ..Io::default()
    };
    assert!(bank.map(req, &mut io).is_err());
    assert!(!bank.mapped_prefix(req.pi, req.process, req.page, 1, 10, 20, 3));
    bank.map(req, &mut io).unwrap();
    assert!(bank.mapped_prefix(req.pi, req.process, req.page, 1, 10, 20, 3));
}

#[test]
fn child_segment_identity_cannot_alias_another_segment() {
    let mut bank = bank();
    let mut io = Io {
        same_segments: true,
        ..Io::default()
    };
    bank.map(request(4096), &mut io).unwrap();
    bank.map(request(8192), &mut io).unwrap();
    io.calls.clear();
    assert_eq!(
        bank.map(request(12288), &mut io),
        Err(BankError::InvalidBackend)
    );
    assert!(!io.calls.iter().any(|call| matches!(call, Call::Move(_, _))));
    assert_eq!(bank.snapshots().nth(2).unwrap().root.unwrap().slot, 103);
    io.same_segments = false;
    bank.map(request(12288), &mut io).unwrap();
}
