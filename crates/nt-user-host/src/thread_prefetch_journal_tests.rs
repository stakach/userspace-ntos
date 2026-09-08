use super::*;
use crate::thread_rollback::{new_rollback_id, ThreadRollbackIdentity};

fn id(generation: ProcessGeneration) -> ThreadRollbackId {
    new_rollback_id(ThreadRollbackIdentity {
        pi: 2,
        pid: 8,
        tid: 12,
        process_generation: generation,
    })
    .unwrap()
}
fn layout() -> ThreadMemoryLayout {
    ThreadMemoryLayout::new(0x1000, 2, 0x4000, 0x6000, 0xa000).unwrap()
}
const PROCESS: PrefetchProcess = PrefetchProcess {
    pi: 2,
    generation: 7,
};

struct NoEffects;
impl AliasRetirementIo for NoEffects {
    fn unmap(&mut self, _: u64) -> Result<(), u32> {
        panic!("unexpected unmap")
    }
    fn delete(&mut self, _: u64) -> Result<(), u32> {
        panic!("unexpected delete")
    }
    fn recycle_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("unexpected recycle")
    }
    fn recycle_unretyped_slot(&mut self, _: u64) -> Result<(), u32> {
        panic!("unexpected recycle")
    }
}

#[test]
fn exact_attempt_and_current_process_are_required_for_every_projection() {
    let owner = id(ProcessGeneration::Hosted(7));
    let mut frames = PrefetchFrames::new();
    frames.reserve(PROCESS, 0x1000, |_| Some(0x100000)).unwrap();
    let journal = ThreadPrefetchJournal::prepare(owner, layout(), Some(PROCESS), &frames).unwrap();
    let foreign = id(ProcessGeneration::Hosted(7));
    for current in [
        None,
        Some(PrefetchProcess {
            pi: 2,
            generation: 8,
        }),
        Some(PrefetchProcess {
            pi: 3,
            generation: 7,
        }),
    ] {
        assert_eq!(
            journal.claim(owner, current, &mut frames),
            Err(PrefetchJournalError::OwnerChanged)
        );
    }
    assert_eq!(
        journal.claim(foreign, Some(PROCESS), &mut frames),
        Err(PrefetchJournalError::OwnerChanged)
    );
    journal.claim(owner, Some(PROCESS), &mut frames).unwrap();
    assert_eq!(
        journal.retire(foreign, Some(PROCESS), &mut frames, &mut NoEffects),
        Err(PrefetchJournalError::OwnerChanged)
    );
    journal
        .retire(owner, Some(PROCESS), &mut frames, &mut NoEffects)
        .unwrap();
    assert!(journal.is_complete());
}

#[test]
fn temporary_process_requires_prefetch_absence_not_a_numeric_generation_substitute() {
    let owner = id(ProcessGeneration::Temporary(7));
    let mut frames = PrefetchFrames::new();
    assert!(ThreadPrefetchJournal::prepare(owner, layout(), Some(PROCESS), &frames).is_err());
    let journal = ThreadPrefetchJournal::prepare(owner, layout(), None, &frames).unwrap();
    journal.claim(owner, None, &mut frames).unwrap();
    frames.reserve(PROCESS, 0xb000, |_| Some(0x100000)).unwrap();
    assert_eq!(
        journal.revalidate(owner, None, &frames),
        Err(PrefetchJournalError::OwnerChanged)
    );
    assert!(ThreadPrefetchJournal::prepare(owner, layout(), None, &frames).is_err());
}

#[test]
fn complete_empty_journal_keeps_its_exact_attempt_boundary() {
    let owner = id(ProcessGeneration::Hosted(7));
    let mut frames = PrefetchFrames::new();
    let journal = ThreadPrefetchJournal::prepare(owner, layout(), Some(PROCESS), &frames).unwrap();
    journal.claim(owner, Some(PROCESS), &mut frames).unwrap();
    journal
        .retire(owner, Some(PROCESS), &mut frames, &mut NoEffects)
        .unwrap();
    assert!(journal.is_complete());
    assert_eq!(
        journal.retire(
            id(ProcessGeneration::Hosted(7)),
            Some(PROCESS),
            &mut frames,
            &mut NoEffects
        ),
        Err(PrefetchJournalError::OwnerChanged)
    );
}

#[test]
fn main_transport_journal_retires_only_real_ranges_not_private_stack() {
    let owner = id(ProcessGeneration::Hosted(7));
    let layout = ThreadMemoryLayout::without_stack(0x4000, 0x6000, 0xa000).unwrap();
    let mut frames = PrefetchFrames::new();
    for (index, page) in [0x1000, 0x4000, 0x6000, 0x7000, 0x8000, 0xa000]
        .into_iter()
        .enumerate()
    {
        frames
            .reserve(PROCESS, page, |_| Some(0x100000 + index as u64 * 4096))
            .unwrap();
    }
    let journal = ThreadPrefetchJournal::prepare(owner, layout, Some(PROCESS), &frames).unwrap();
    assert_eq!(journal.original_capabilities().count(), 0);
    journal.claim(owner, Some(PROCESS), &mut frames).unwrap();
    journal
        .retire(owner, Some(PROCESS), &mut frames, &mut NoEffects)
        .unwrap();
    assert!(journal.is_complete());
    for page in [0x4000, 0x6000, 0x7000, 0x8000, 0xa000] {
        assert_eq!(frames.lookup(PROCESS, page).unwrap(), None);
    }
    // The distinct private-stack reservation remains held, not selected or released.
    assert!(frames.lookup(PROCESS, 0x1000).is_err());
    assert!(frames.reserve(PROCESS, 0x1000, |_| Some(0x200000)).is_err());
    journal.revalidate(owner, Some(PROCESS), &frames).unwrap();
}
