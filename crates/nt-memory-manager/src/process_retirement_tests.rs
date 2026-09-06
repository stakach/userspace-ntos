use super::*;
use crate::image_section::{
    ImageAcquire, ImageAreaId, ImageFlushError, ImageSectionPurge, ImageSectionTable, ImageViewRef,
};
use crate::{SectionFileIdentity, SectionMountIds};
use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stage {
    Leaves,
    PageTables,
    Vspace,
    Metadata,
}

struct Backend {
    quiescent: bool,
    events: Vec<Stage>,
    remaining: [usize; 3],
    fail: Option<(usize, usize)>,
    committed: usize,
    image: ImageSectionTable,
    view: Option<ImageViewRef>,
    file: SectionFileIdentity,
    cow_bytes: [u8; 4],
}

impl Backend {
    fn new() -> Self {
        let file = SectionFileIdentity {
            mount: SectionMountIds::new().allocate().unwrap(),
            file_id: 17,
        };
        let mut image = ImageSectionTable::new();
        let ImageAcquire::Create(creation) = image.acquire(file).unwrap() else {
            panic!()
        };
        let section = image.publish(creation).unwrap();
        let view = image.reference_view(section).unwrap();
        image.close_section(section).unwrap();
        Self {
            quiescent: true,
            events: Vec::new(),
            remaining: [4, 3, 2],
            fail: None,
            committed: 0,
            image,
            view: Some(view),
            file,
            cow_bytes: [1, 2, 3, 4],
        }
    }

    fn drain(&mut self, index: usize, stage: Stage) -> bool {
        assert!(self.remaining[..index].iter().all(|&count| count == 0));
        assert_eq!(self.committed, 0);
        assert_eq!(self.cow_bytes, [1, 2, 3, 4]);
        self.events.push(stage);
        while self.remaining[index] != 0 {
            if self.fail == Some((index, self.remaining[index])) {
                return false;
            }
            self.remaining[index] -= 1;
        }
        true
    }
}

impl ProcessVmRetirementIo for Backend {
    fn is_quiescent(&self) -> bool {
        self.quiescent
    }
    fn retire_leaves(&mut self) -> bool {
        self.drain(0, Stage::Leaves)
    }
    fn retire_page_tables(&mut self) -> bool {
        self.drain(1, Stage::PageTables)
    }
    fn retire_vspace(&mut self) -> bool {
        self.drain(2, Stage::Vspace)
    }
    fn commit_metadata(&mut self) {
        assert_eq!(self.remaining, [0; 3]);
        assert_eq!(self.committed, 0);
        self.image.release_view(self.view.take().unwrap()).unwrap();
        self.cow_bytes = [0; 4];
        self.events.push(Stage::Metadata);
        self.committed += 1;
    }
}

#[derive(Default)]
struct Purge(usize);
impl ImageSectionPurge for Purge {
    fn purge_image(&mut self, _: ImageAreaId, _: SectionFileIdentity) -> Result<(), u32> {
        self.0 += 1;
        Ok(())
    }
}

#[test]
fn nonquiescent_process_has_no_cleanup_effects() {
    let mut io = Backend::new();
    io.quiescent = false;
    assert_eq!(
        retire_process_vm(&mut io),
        ProcessVmRetirement::NotQuiescent
    );
    assert!(io.events.is_empty());
    assert_eq!(io.remaining, [4, 3, 2]);
    assert_eq!(io.committed, 0);
}

#[test]
fn metadata_and_image_ownership_commit_only_after_root_release() {
    let mut io = Backend::new();
    let mut purge = Purge::default();
    assert_eq!(
        io.image.flush_for_write(io.file, &mut purge),
        Err(ImageFlushError::InUse)
    );
    assert_eq!(retire_process_vm(&mut io), ProcessVmRetirement::Complete);
    assert_eq!(
        io.events,
        [
            Stage::Leaves,
            Stage::PageTables,
            Stage::Vspace,
            Stage::Metadata
        ]
    );
    assert_eq!(io.committed, 1);
    io.image.flush_for_write(io.file, &mut purge).unwrap();
    assert_eq!(purge.0, 1);
}

fn failure_case(index: usize, remaining: usize) {
    let mut io = Backend::new();
    io.fail = Some((index, remaining));
    let outcome = [
        ProcessVmRetirement::LeavesPending,
        ProcessVmRetirement::PageTablesPending,
        ProcessVmRetirement::VspacePending,
    ][index];
    for _ in 0..2 {
        io.events.clear();
        assert_eq!(retire_process_vm(&mut io), outcome);
        assert_eq!(
            io.events,
            [Stage::Leaves, Stage::PageTables, Stage::Vspace][..=index]
        );
        assert_eq!(io.remaining[index], remaining);
        assert_eq!(io.committed, 0);
        assert_eq!(io.cow_bytes, [1, 2, 3, 4]);
        let mut purge = Purge::default();
        assert_eq!(
            io.image.flush_for_write(io.file, &mut purge),
            Err(ImageFlushError::InUse)
        );
        assert_eq!(purge.0, 0);
    }
    // A retry must recheck quiescence before continuing even partially completed teardown.
    io.quiescent = false;
    io.events.clear();
    assert_eq!(
        retire_process_vm(&mut io),
        ProcessVmRetirement::NotQuiescent
    );
    assert!(io.events.is_empty());
    io.quiescent = true;
    io.fail = None;
    assert_eq!(retire_process_vm(&mut io), ProcessVmRetirement::Complete);
    assert_eq!(io.committed, 1);
}

#[test]
fn first_leaf_failure_retains_all_metadata() {
    failure_case(0, 4);
}
#[test]
fn partial_leaf_failure_retains_all_metadata() {
    failure_case(0, 2);
}
#[test]
fn last_leaf_failure_blocks_page_tables() {
    failure_case(0, 1);
}
#[test]
fn first_page_table_failure_retains_all_metadata() {
    failure_case(1, 3);
}
#[test]
fn partial_page_table_failure_retains_all_metadata() {
    failure_case(1, 2);
}
#[test]
fn last_page_table_failure_blocks_root() {
    failure_case(1, 1);
}
#[test]
fn first_root_resource_failure_retains_all_metadata() {
    failure_case(2, 2);
}
#[test]
fn final_root_failure_retains_all_metadata() {
    failure_case(2, 1);
}

#[test]
fn already_empty_physical_owners_still_commit_logical_retirement() {
    let mut io = Backend::new();
    io.remaining = [0; 3];
    assert_eq!(retire_process_vm(&mut io), ProcessVmRetirement::Complete);
    assert_eq!(io.committed, 1);
    assert!(io.view.is_none());
}
