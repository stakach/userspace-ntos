use super::*;
use nt_memory_manager::prefetch::{
    PrefetchFrames, PrefetchIo, PrefetchJournalError, PrefetchProcess,
};
use nt_memory_manager::retained_alias::AliasRetirementIo;
use nt_user_host::thread_prefetch_journal::ThreadPrefetchJournal;

const PROCESS: PrefetchProcess = PrefetchProcess {
    pi: 2,
    generation: 7,
};
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
        self.0.set(self.0.get() + 1);
        Ok(())
    }
    fn recycle_unretyped_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("mapped prefetch owns retype bytes")
    }
}
impl PrefetchIo for Io<'_> {
    fn allocate(&mut self) -> (u64, u32) {
        (701, 0)
    }
    fn map(&mut self, _: u64, _: u64) -> Result<(), u32> {
        Ok(())
    }
    fn fill(&mut self, _: u64) -> Result<(), u32> {
        Ok(())
    }
}

#[test]
fn prefetch_preparation_oom_keeps_runtime_and_prefetch_owners_without_claim() {
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
    let mut frames = PrefetchFrames::new();
    let reservation = frames
        .reserve(PROCESS, layout.stack().base, |_| Some(0x100000))
        .unwrap();
    frames.build(reservation, &mut Io(&effects)).unwrap();
    FAIL_ALLOCATIONS.with(|flag| flag.set(true));
    let reset = Reset;
    let result = ThreadPrefetchJournal::prepare(id, layout, Some(PROCESS), &frames);
    drop(reset);
    assert!(matches!(
        result,
        Err(PrefetchJournalError::InsufficientResources)
    ));
    assert!(frames.can_retire_process(PROCESS, |_| true));
    assert_eq!(
        frames
            .lookup(PROCESS, layout.stack().base)
            .unwrap()
            .unwrap()
            .frame,
        701
    );
    assert_eq!(effects.get(), 0);
    assert_protected(&mut slot, id);
    assert!(ThreadPrefetchJournal::prepare(id, layout, Some(PROCESS), &frames).is_ok());
}

#[test]
fn prefetch_claim_revalidation_and_retirement_do_not_allocate_or_release_pending_runtime() {
    let (mut slot, ticket, partial, _) = fixture(None, true);
    let layout = partial.memory.layout().unwrap();
    let id = slot.retain_failed_construction(ticket, partial).unwrap();
    let effects = Cell::new(0);
    let mut frames = PrefetchFrames::new();
    let reservation = frames
        .reserve(PROCESS, layout.stack().base, |_| Some(0x100000))
        .unwrap();
    frames.build(reservation, &mut Io(&effects)).unwrap();
    let journal = ThreadPrefetchJournal::prepare(id, layout, Some(PROCESS), &frames).unwrap();
    without_allocation(|| journal.claim(id, Some(PROCESS), &mut frames)).unwrap();
    without_allocation(|| journal.revalidate(id, Some(PROCESS), &frames)).unwrap();
    without_allocation(|| journal.retire(id, Some(PROCESS), &mut frames, &mut Io(&effects)))
        .unwrap();
    assert_eq!(effects.get(), 3);
    assert!(journal.is_complete() && frames.process_is_empty(2));
    assert_protected(&mut slot, id);
}
