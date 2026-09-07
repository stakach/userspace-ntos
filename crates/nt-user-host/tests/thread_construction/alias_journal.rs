use super::*;
use nt_memory_manager::alias_transition::AliasTransitionIo;
use nt_memory_manager::retained_alias::AliasRetirementIo;
use nt_user_host::thread_alias_journal::{JournalError, ThreadAliasJournal, ThreadAliasMapping};

struct Io<'a>(&'a Cell<usize>);
impl AliasRetirementIo for Io<'_> {
    fn unmap(&mut self, _: u64) -> Result<(), u32> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
    fn delete(&mut self, _: u64) -> Result<(), u32> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("strict recycling required")
    }
    fn recycle_unretyped_slot(&mut self, _: u64) -> Result<(), u32> {
        self.0.set(self.0.get() + 1);
        Ok(())
    }
}
impl AliasTransitionIo for Io<'_> {
    fn copy(&mut self) -> (u64, u32) {
        (701, 0)
    }
    fn map(&mut self, _: u64, _: u64) -> Result<(), u32> {
        Ok(())
    }
}

#[test]
fn alias_preparation_oom_preserves_pending_owner_and_unclaimed_mapping() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_ALLOCATIONS.with(|flag| flag.set(false));
        }
    }
    let (mut slot, ticket, partial, _) = fixture(None, true);
    let layout = partial.memory.layout().unwrap();
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let effects = Cell::new(0);
    let mut row = ThreadAliasMapping::new(layout.stack().base).unwrap();
    row.replace(1, &mut Io(&effects)).unwrap();
    let rows = vec![row];
    FAIL_ALLOCATIONS.with(|flag| flag.set(true));
    let reset = Reset;
    let result = ThreadAliasJournal::prepare(id, layout, 2, &rows);
    drop(reset);
    assert!(matches!(result, Err(JournalError::InsufficientResources)));
    assert!(!rows[0].is_claimed());
    assert_eq!(rows[0].live(), Some((701, 1)));
    assert_eq!(effects.get(), 0);
    assert_protected(&mut slot, id);
    assert!(ThreadAliasJournal::prepare(id, layout, 2, &rows).is_ok());
}

#[test]
fn claim_and_complete_alias_retirement_allocate_nothing_and_do_not_release_runtime() {
    let (mut slot, ticket, partial, _) = fixture(None, true);
    let layout = partial.memory.layout().unwrap();
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let effects = Cell::new(0);
    let mut row = ThreadAliasMapping::new(layout.stack().base).unwrap();
    row.replace(1, &mut Io(&effects)).unwrap();
    let mut rows = vec![row];
    let journal = ThreadAliasJournal::prepare(id, layout, 2, &rows).unwrap();
    without_allocation(|| journal.claim(id, 2, &mut rows)).unwrap();
    without_allocation(|| journal.revalidate(id, 2, &rows)).unwrap();
    without_allocation(|| journal.retire(id, 2, &mut rows, |_| Io(&effects))).unwrap();
    assert_eq!(effects.get(), 3);
    assert!(journal.is_complete() && rows.is_empty());
    assert_protected(&mut slot, id);
}
