use super::*;
use nt_memory_manager::section_scratch::{SectionAliasAccess, SectionScratch, SectionScratchIo};
use nt_user_host::slot_recycle::SlotRecycleState;

#[derive(Default)]
struct Io {
    live: [u64; 1],
    pinned: [u64; 1],
    bytes: [u32; 1],
    free: [u64; 1],
    count: u64,
    live_bytes: u64,
    released_bytes: u64,
    copy_status: u32,
    copies: usize,
    deletes: usize,
    mapped: bool,
    populated: bool,
}
impl SectionScratchIo for Io {
    fn copy_frame(&mut self, _: u64) -> (u64, u32) {
        assert_eq!(self.live[0], 0);
        self.live[0] = 1;
        self.copies += 1;
        self.populated = self.copy_status == 0;
        (70, self.copy_status)
    }
    fn map_alias(&mut self, cap: u64, _: u64, _: SectionAliasAccess) -> Result<(), u32> {
        assert_eq!(cap, 70);
        assert!(self.populated && !self.mapped);
        self.mapped = true;
        Ok(())
    }
    fn delete_alias(&mut self, cap: u64) -> Result<(), u32> {
        assert_eq!(cap, 70);
        assert!(self.populated, "delete acknowledged exactly once");
        self.deletes += 1;
        self.populated = false;
        self.mapped = false;
        Ok(())
    }
    fn recycle_alias_slot(&mut self, slot: u64) -> Result<(), u32> {
        assert!(!self.populated && !self.mapped);
        let mut state = SlotRecycleState {
            start: 70,
            end: 71,
            live: &mut self.live,
            pinned: &self.pinned,
            retype_bytes: &mut self.bytes,
            free: &mut self.free,
            count: self.count,
            live_bytes: self.live_bytes,
            released_bytes: self.released_bytes,
        };
        state.publish_unretyped(slot).map_err(|_| 99u32)?;
        self.count = state.count;
        self.live_bytes = state.live_bytes;
        self.released_bytes = state.released_bytes;
        Ok(())
    }
}

#[test]
fn scratch_recycle_refusal_retains_deleted_slot_and_retries_allocation_free() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    owner.begin(&mut io).unwrap();
    let handle = owner
        .prepare(50, 0x1000, SectionAliasAccess::ReadOnly, &mut io)
        .unwrap();
    io.pinned[0] = 1;
    assert_eq!(without_allocation(|| owner.finish(&mut io)), Err(99));
    assert_eq!(io.live, [1]);
    assert_eq!(io.count, 0);
    assert_eq!(io.deletes, 1);
    assert!(owner
        .resolve(handle, 0, 1, SectionAliasAccess::ReadOnly)
        .is_err());
    assert_eq!(without_allocation(|| owner.begin(&mut io)), Err(99));
    assert_eq!(io.copies, 1);
    assert_eq!(io.deletes, 1);
    io.pinned[0] = 0;
    without_allocation(|| owner.drain(&mut io)).unwrap();
    without_allocation(|| owner.drain(&mut io)).unwrap();
    assert_eq!(io.free, [70]);
    assert_eq!(io.count, 1);
    assert_eq!(io.deletes, 1);
    assert_eq!(io.live, [0]);
}

#[test]
fn failed_scratch_copy_cannot_discard_or_release_unexpected_retype_bytes() {
    let mut owner = SectionScratch::new();
    let mut io = Io {
        copy_status: 7,
        bytes: [4096],
        live_bytes: 4096,
        ..Io::default()
    };
    owner.begin(&mut io).unwrap();
    assert_eq!(
        owner.prepare(50, 0x1000, SectionAliasAccess::ReadOnly, &mut io),
        Err(7)
    );
    assert_eq!(without_allocation(|| owner.finish(&mut io)), Err(99));
    assert_eq!(io.deletes, 0);
    assert_eq!(
        (io.bytes, io.live_bytes, io.released_bytes),
        ([4096], 4096, 0)
    );
    assert_eq!(io.live, [1]);
    io.bytes[0] = 0; // Repair contradictory external metadata, not the cleanup owner's action.
    without_allocation(|| owner.drain(&mut io)).unwrap();
    assert_eq!(io.deletes, 0);
    assert_eq!((io.live_bytes, io.released_bytes), (4096, 0));
    assert_eq!(io.count, 1);
}

#[test]
fn scratch_metadata_oom_happens_before_copy_or_slot_acquisition() {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            FAIL_ALLOCATIONS.with(|flag| flag.set(false));
        }
    }
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    owner.begin(&mut io).unwrap();
    FAIL_ALLOCATIONS.with(|flag| flag.set(true));
    let reset = Reset;
    let result = owner.prepare(50, 0x1000, SectionAliasAccess::ReadOnly, &mut io);
    drop(reset);
    assert_eq!(result, Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES));
    assert_eq!(io.copies, 0);
    assert_eq!(io.live, [0]);
    without_allocation(|| owner.finish(&mut io)).unwrap();
}
