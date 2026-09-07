use super::*;
use crate::process_identity::ProcessGeneration;
use crate::provider_alias_bank::{ChildCap, ProviderAliasRequest, RootAliasSnapshot};
use crate::thread_rollback::{new_rollback_id, ThreadRollbackIdentity};
use alloc::vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Call {
    Copy,
    Map(u64),
    Segment,
    Move(u64),
    Recycle(u64),
    Root(u64),
    Child(ChildCap),
}

#[derive(Default)]
struct Io {
    calls: Vec<Call>,
    failure: Option<Call>,
    next: u64,
    copy_result: Option<(u64, u32)>,
}

impl Io {
    fn call(&mut self, call: Call) -> Result<(), u32> {
        self.calls.push(call);
        if self.failure == Some(call) {
            self.failure = None;
            Err(77)
        } else {
            Ok(())
        }
    }
}

impl ProviderAliasIo for Io {
    fn copy(&mut self, _: u64) -> (u64, u32) {
        self.calls.push(Call::Copy);
        if let Some(result) = self.copy_result.take() {
            return result;
        }
        self.next += 1;
        (100 + self.next, 0)
    }
    fn map(&mut self, cap: u64, _: u64, _: u64, _: u64) -> Result<(), u32> {
        self.call(Call::Map(cap))
    }
    fn ensure_segment(&mut self, segment: usize) -> Result<u64, u32> {
        self.call(Call::Segment)?;
        Ok(1000 + segment as u64)
    }
    fn move_to_child(&mut self, root: u64, _: ChildCap) -> Result<(), u32> {
        self.call(Call::Move(root))
    }
    fn recycle_empty_root(&mut self, root: u64) -> Result<(), u32> {
        self.call(Call::Recycle(root))
    }
    fn delete_root(&mut self, root: u64) -> Result<(), u32> {
        self.call(Call::Root(root))
    }
    fn delete_child(&mut self, child: ChildCap) -> Result<(), u32> {
        self.call(Call::Child(child))
    }
}

fn id() -> ThreadRollbackId {
    new_rollback_id(ThreadRollbackIdentity {
        pi: 2,
        pid: 20,
        tid: 24,
        process_generation: ProcessGeneration::Hosted(7),
    })
    .unwrap()
}
fn layout() -> ThreadMemoryLayout {
    ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x6000, 0xa000).unwrap()
}
fn request(page: u64) -> ProviderAliasRequest {
    ProviderAliasRequest {
        pi: 2,
        process: ProcessIdentity {
            pid: 20,
            generation: ProcessGeneration::Hosted(7),
        },
        page,
        pml4: 30,
        source_frame: 40,
        rights: 3,
    }
}
fn bank() -> ProviderAliasBank {
    ProviderAliasBank::new(16, 2).unwrap()
}
fn child(slot: u64) -> ChildCap {
    ChildCap { cnode: 1000, slot }
}

#[test]
fn preparation_is_read_only_and_retains_both_typed_capability_namespaces() {
    let mut bank = bank();
    let mut io = Io {
        failure: Some(Call::Recycle(101)),
        ..Io::default()
    };
    let owner = id();
    assert!(bank.map(request(0x1000), &mut io).is_err());
    let before = bank.snapshots().collect::<Vec<_>>();
    io.calls.clear();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    assert_eq!(before, bank.snapshots().collect::<Vec<_>>());
    assert_eq!(
        journal.original_capabilities().collect::<Vec<_>>(),
        vec![
            ProviderAliasCapability::Root(101),
            ProviderAliasCapability::Child(child(0))
        ]
    );
    assert_eq!(journal.original_root_caps().collect::<Vec<_>>(), vec![101]);
    assert!(bank.owns_root_cap(101));
    assert!(bank.owns_child_cap(child(0)));
    assert!(!bank.owns_root_cap(40));
    assert!(!bank.owns_root_cap(30));
    assert!(!bank.owns_root_cap(1000));
    journal.claim(owner, &mut bank).unwrap();
    assert_eq!(bank.snapshots().next().unwrap().claim, Some(owner));
    assert!(io.calls.is_empty());
}

#[test]
fn every_operation_requires_the_exact_attempt_and_tagged_process_lifetime() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    let foreign = id();
    io.calls.clear();
    assert_eq!(
        journal.revalidate(foreign, &bank),
        Err(BankError::OwnerChanged)
    );
    assert_eq!(
        journal.claim(foreign, &mut bank),
        Err(BankError::OwnerChanged)
    );
    assert_eq!(
        journal.retire(foreign, &mut bank, &mut io),
        Err(BankError::OwnerChanged)
    );
    let temporary = new_rollback_id(ThreadRollbackIdentity {
        process_generation: ProcessGeneration::Temporary(7),
        ..owner.identity()
    })
    .unwrap();
    assert!(matches!(
        ThreadProviderAliasJournal::prepare(temporary, layout(), &bank),
        Err(BankError::OwnerChanged)
    ));
    assert!(bank.snapshots().all(|row| row.claim.is_none()));
    assert!(io.calls.is_empty());
}

#[test]
fn claims_block_target_retry_and_process_release_without_blocking_unrelated_pages() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0xc000), &mut io).unwrap();
    bank.map(request(0x1000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.calls.clear();
    assert_eq!(bank.map(request(0x1000), &mut io), Err(BankError::Claimed));
    assert_eq!(
        bank.release_process(2, process(owner), &mut io),
        Err(BankError::Claimed)
    );
    assert!(io.calls.is_empty());
    assert!(bank.snapshots().all(|row| !row.releasing));
    assert!(!bank.mapped_prefix(2, process(owner), 0x1000, 1, 30, 40, 3));
    assert!(bank.mapped_prefix(2, process(owner), 0xc000, 1, 30, 40, 3));
    bank.map(request(0xd000), &mut io).unwrap();
    let unrelated = ProviderAliasRequest {
        pi: 3,
        ..request(0x1000)
    };
    bank.map(unrelated, &mut io).unwrap();
    bank.release_process(3, unrelated.process, &mut io).unwrap();
    journal.revalidate(owner, &bank).unwrap();
}

#[test]
fn stale_last_entry_prevents_any_claim_publication() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    io.failure = Some(Call::Map(102));
    assert!(bank.map(request(0x2000), &mut io).is_err());
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    bank.map(request(0x2000), &mut io).unwrap();
    io.calls.clear();
    assert_eq!(journal.claim(owner, &mut bank), Err(BankError::StaleHandle));
    assert!(bank.snapshots().all(|row| row.claim.is_none()));
    assert!(io.calls.is_empty());
}

#[test]
fn changed_selected_coverage_prevents_all_claims() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    bank.map(request(0x2000), &mut io).unwrap();
    assert_eq!(journal.claim(owner, &mut bank), Err(BankError::StaleHandle));
    assert!(bank.snapshots().all(|row| row.claim.is_none()));
}

#[test]
fn recycled_handle_cannot_replace_prepared_coverage() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    let old = bank.map(request(0x1000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    bank.release_process(2, process(owner), &mut io).unwrap();
    let new = bank.map(request(0x1000), &mut io).unwrap();
    assert_eq!(old.index(), new.index());
    assert_ne!(old.generation(), new.generation());
    assert_eq!(journal.claim(owner, &mut bank), Err(BankError::StaleHandle));
    assert!(bank.get(new).unwrap().claim.is_none());
}

#[test]
fn second_preparation_cannot_steal_same_attempt_claims() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    let first = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    let second = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    first.claim(owner, &mut bank).unwrap();
    first.claim(owner, &mut bank).unwrap();
    assert_eq!(second.claim(owner, &mut bank), Err(BankError::Claimed));
    assert!(matches!(
        ThreadProviderAliasJournal::prepare(owner, layout(), &bank),
        Err(BankError::Claimed)
    ));
    first.revalidate(owner, &bank).unwrap();
}

#[test]
fn foreign_claim_on_late_entry_does_not_pin_earlier_entries() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    bank.map(request(0x2000), &mut io).unwrap();
    let all = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    let other = id();
    let narrow = ThreadMemoryLayout::new(0x2000, 1, 0x14000, 0x16000, 0x1a000).unwrap();
    let second = ThreadProviderAliasJournal::prepare(other, narrow, &bank).unwrap();
    second.claim(other, &mut bank).unwrap();
    assert_eq!(all.claim(owner, &mut bank), Err(BankError::Claimed));
    let rows = bank.snapshots().collect::<Vec<_>>();
    assert_eq!(rows[0].claim, None);
    assert_eq!(rows[1].claim, Some(other));
}

#[test]
fn shared_current_root_or_child_is_rejected_before_claims() {
    let mut bank = bank();
    let mut io = Io {
        failure: Some(Call::Map(101)),
        ..Io::default()
    };
    let owner = id();
    assert!(bank.map(request(0x1000), &mut io).is_err());
    io.failure = Some(Call::Map(101));
    io.copy_result = Some((101, 0));
    assert!(bank.map(request(0xc000), &mut io).is_err());
    assert!(matches!(
        ThreadProviderAliasJournal::prepare(owner, layout(), &bank),
        Err(BankError::SharedCapability(ProviderAliasCapability::Root(
            101
        )))
    ));
    assert!(bank.snapshots().all(|row| row.claim.is_none()));

    let mut bank = ProviderAliasBank::new(16, 2).unwrap();
    let mut io = Io::default();
    bank.map(request(0x1000), &mut io).unwrap();
    let other = bank.map(request(0xc000), &mut io).unwrap();
    bank.slots[other.index()].row.as_mut().unwrap().child = Some(child(0));
    assert!(
        matches!(ThreadProviderAliasJournal::prepare(owner, layout(), &bank),
        Err(BankError::SharedCapability(ProviderAliasCapability::Child(cap))) if cap == child(0))
    );
}

#[test]
fn typed_namespaces_and_borrowed_sources_are_not_leaf_capability_conflicts() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0xc000), &mut io).unwrap();
    bank.map(request(0x2000), &mut io).unwrap();
    io.copy_result = Some((1, 0));
    io.failure = Some(Call::Map(1));
    assert!(bank
        .map(
            ProviderAliasRequest {
                source_frame: 1000,
                pml4: 1000,
                ..request(0x1000)
            },
            &mut io
        )
        .is_err());
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    assert_eq!(journal.original_root_caps().collect::<Vec<_>>(), vec![1]);
    assert!(!bank.owns_root_cap(1000));
    assert!(bank.owns_child_cap(child(1)));
    journal.claim(owner, &mut bank).unwrap();
}

#[test]
fn retirement_requires_claims_before_any_backend_call() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    io.calls.clear();
    assert_eq!(
        journal.retire(owner, &mut bank, &mut io),
        Err(BankError::NotClaimed)
    );
    assert!(io.calls.is_empty());
    assert!(!journal.is_complete());
}

#[test]
fn child_deletion_failure_retains_exact_claim_and_retries_once() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.calls.clear();
    io.failure = Some(Call::Child(child(0)));
    assert_eq!(
        journal.retire(owner, &mut bank, &mut io),
        Err(BankError::Backend(77))
    );
    assert_eq!(bank.snapshots().next().unwrap().claim, Some(owner));
    assert_eq!(bank.map(request(0x1000), &mut io), Err(BankError::Claimed));
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Child(child(0)), Call::Child(child(0))]);
    assert!(journal.is_complete());
    assert!(bank.is_empty());
    io.calls.clear();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert!(io.calls.is_empty());
}

#[test]
fn root_deletion_and_recycling_have_separate_retained_acknowledgements() {
    let mut bank = bank();
    let mut io = Io {
        failure: Some(Call::Segment),
        ..Io::default()
    };
    let owner = id();
    assert!(bank.map(request(0x1000), &mut io).is_err());
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.calls.clear();
    io.failure = Some(Call::Root(101));
    assert!(journal.retire(owner, &mut bank, &mut io).is_err());
    assert!(bank.snapshots().next().unwrap().root.unwrap().mapped);
    io.failure = Some(Call::Recycle(101));
    assert!(journal.retire(owner, &mut bank, &mut io).is_err());
    assert_eq!(
        bank.snapshots().next().unwrap().root,
        Some(RootAliasSnapshot {
            slot: 101,
            populated: false,
            mapped: false
        })
    );
    io.calls.clear();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(101)]);
    assert_eq!(journal.original_root_caps().collect::<Vec<_>>(), vec![101]);
}

#[test]
fn moved_child_is_not_deleted_twice_after_empty_root_recycle_failure() {
    let mut bank = bank();
    let mut io = Io {
        failure: Some(Call::Recycle(101)),
        ..Io::default()
    };
    let owner = id();
    assert!(bank.map(request(0x1000), &mut io).is_err());
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.calls.clear();
    io.failure = Some(Call::Recycle(101));
    assert!(journal.retire(owner, &mut bank, &mut io).is_err());
    assert_eq!(io.calls, vec![Call::Child(child(0)), Call::Recycle(101)]);
    assert_eq!(bank.snapshots().next().unwrap().child, None);
    assert!(bank.owns_root_cap(101));
    assert!(!bank.owns_child_cap(child(0)));
    io.calls.clear();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(101)]);
}

#[test]
fn failed_copy_destination_retires_without_deletion() {
    let mut bank = bank();
    let mut io = Io {
        copy_result: Some((500, 19)),
        ..Io::default()
    };
    let owner = id();
    assert!(bank.map(request(0x1000), &mut io).is_err());
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.calls.clear();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Recycle(500)]);
}

#[test]
fn partial_retirement_accepts_slot_reuse_without_touching_the_new_owner() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    let old = bank.map(request(0x1000), &mut io).unwrap();
    bank.map(request(0x2000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.failure = Some(Call::Child(child(1)));
    assert!(journal.retire(owner, &mut bank, &mut io).is_err());
    let new = bank.map(request(0xc000), &mut io).unwrap();
    assert_eq!(old.index(), new.index());
    assert_ne!(old.generation(), new.generation());
    journal.revalidate(owner, &bank).unwrap();
    io.calls.clear();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Child(child(1))]);
    assert!(bank.get(new).is_some());
    assert!(journal.is_complete());
    assert_eq!(
        journal.original_capabilities().collect::<Vec<_>>(),
        vec![
            ProviderAliasCapability::Child(child(0)),
            ProviderAliasCapability::Child(child(1))
        ]
    );
}

#[test]
fn empty_coverage_is_exact_and_requires_caller_admission_exclusions() {
    let mut bank = bank();
    let owner = id();
    let mut io = Io::default();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    bank.map(request(0xc000), &mut io).unwrap();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert!(journal.is_complete());
    assert_eq!(
        journal.revalidate(id(), &bank),
        Err(BankError::OwnerChanged)
    );
    // The native pending-runtime geometry exclusion must prevent this admission. The journal
    // refuses changed coverage rather than silently replacing its originally empty snapshot.
    bank.map(request(0x1000), &mut io).unwrap();
    assert_eq!(
        journal.revalidate(owner, &bank),
        Err(BankError::StaleHandle)
    );
}

#[test]
fn selection_covers_stack_ipc_all_teb_pages_and_trampoline_only() {
    let mut bank = bank();
    let owner = id();
    let mut io = Io::default();
    for page in [
        0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xa000, 0xb000,
    ] {
        bank.map(request(page), &mut io).unwrap();
    }
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    let claimed = bank
        .snapshots()
        .filter(|row| row.claim == Some(owner))
        .map(|row| row.request.page)
        .collect::<Vec<_>>();
    assert_eq!(
        claimed,
        vec![0x1000, 0x2000, 0x4000, 0x6000, 0x7000, 0x8000, 0xa000]
    );
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(
        bank.snapshots()
            .map(|row| row.request.page)
            .collect::<Vec<_>>(),
        vec![0x3000, 0x5000, 0x9000, 0xb000]
    );
}

#[test]
fn late_capability_conflict_prevents_every_claim() {
    let mut bank = bank();
    let mut io = Io::default();
    let owner = id();
    bank.map(request(0x1000), &mut io).unwrap();
    bank.map(request(0x2000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    let unrelated = bank.map(request(0xc000), &mut io).unwrap();
    bank.slots[unrelated.index()].row.as_mut().unwrap().child = Some(child(1));
    assert_eq!(
        journal.claim(owner, &mut bank),
        Err(BankError::SharedCapability(ProviderAliasCapability::Child(
            child(1)
        )))
    );
    assert!(bank.snapshots().all(|row| row.claim.is_none()));
}

#[test]
fn no_capability_row_still_retains_claim_until_journal_commit() {
    let mut bank = bank();
    let owner = id();
    let mut io = Io {
        copy_result: Some((0, 19)),
        ..Io::default()
    };
    assert!(bank.map(request(0x1000), &mut io).is_err());
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    assert_eq!(journal.original_capabilities().count(), 0);
    journal.claim(owner, &mut bank).unwrap();
    io.calls.clear();
    assert_eq!(bank.map(request(0x1000), &mut io), Err(BankError::Claimed));
    assert_eq!(
        bank.release_process(2, process(owner), &mut io),
        Err(BankError::Claimed)
    );
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert!(io.calls.is_empty());
    assert!(bank.is_empty());
    assert!(journal.is_complete());
}

#[test]
fn acknowledged_root_number_reuse_does_not_conflict_with_remaining_claims() {
    let mut bank = bank();
    let owner = id();
    let mut io = Io {
        copy_result: Some((500, 19)),
        ..Io::default()
    };
    assert!(bank.map(request(0x1000), &mut io).is_err());
    bank.map(request(0x2000), &mut io).unwrap();
    let journal = ThreadProviderAliasJournal::prepare(owner, layout(), &bank).unwrap();
    journal.claim(owner, &mut bank).unwrap();
    io.failure = Some(Call::Child(child(1)));
    assert!(journal.retire(owner, &mut bank, &mut io).is_err());
    io.copy_result = Some((500, 0));
    io.failure = Some(Call::Map(500));
    assert!(bank.map(request(0xc000), &mut io).is_err());
    assert!(bank.owns_root_cap(500));
    journal.revalidate(owner, &bank).unwrap();
    io.calls.clear();
    journal.retire(owner, &mut bank, &mut io).unwrap();
    assert_eq!(io.calls, vec![Call::Child(child(1))]);
    assert!(bank.owns_root_cap(500));
    assert_eq!(journal.original_root_caps().collect::<Vec<_>>(), vec![500]);
}
