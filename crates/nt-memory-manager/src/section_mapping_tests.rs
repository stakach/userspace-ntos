use super::*;
use alloc::{collections::BTreeMap, vec};

#[derive(Default)]
struct Io {
    next: u64,
    caps: BTreeMap<u64, Option<u64>>,
    copied: Vec<u64>,
    deleted: Vec<u64>,
    recycled: Vec<u64>,
    fail_copy: Option<u64>,
    fail_map: Option<u64>,
    fail_delete: Option<u64>,
    fail_recycle: Option<u64>,
}
impl SectionScratchIo for Io {
    fn copy_frame(&mut self, frame: u64) -> (u64, u32) {
        self.copied.push(frame);
        if self.fail_copy == Some(frame) {
            return (0, RESOURCES);
        }
        self.next += 1;
        assert!(self.caps.insert(self.next, None).is_none());
        (self.next, 0)
    }
    fn map_alias(&mut self, alias: u64, address: u64, _: SectionAliasAccess) -> Result<(), u32> {
        if self.fail_map == Some(alias) {
            return Err(RESOURCES);
        }
        assert!(!self.caps.values().any(|prior| *prior == Some(address)));
        *self.caps.get_mut(&alias).unwrap() = Some(address);
        Ok(())
    }
    fn delete_alias(&mut self, alias: u64) -> Result<(), u32> {
        if self.fail_delete == Some(alias) {
            return Err(RESOURCES);
        }
        assert!(self.caps.remove(&alias).is_some());
        self.deleted.push(alias);
        Ok(())
    }
    fn recycle_alias_slot(&mut self, slot: u64) -> Result<(), u32> {
        assert!(!self.caps.contains_key(&slot));
        assert!(self.deleted.contains(&slot));
        assert!(!self.recycled.contains(&slot));
        if self.fail_recycle == Some(slot) {
            return Err(RESOURCES);
        }
        self.recycled.push(slot);
        Ok(())
    }
}

fn prepare(owner: &mut SectionScratch, io: &mut Io, count: u64) -> Vec<SectionAliasHandle> {
    owner.begin(io).unwrap();
    (0..count)
        .map(|i| {
            owner
                .prepare(
                    50 + i,
                    0x10000 + i * 4096,
                    SectionAliasAccess::ReadWrite,
                    io,
                )
                .unwrap()
        })
        .collect()
}

#[test]
fn batch_maps_all_pages_and_resolves_them_until_finish() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    let handles = prepare(&mut owner, &mut io, 3);
    assert_eq!(io.caps.len(), 3);
    for (i, handle) in handles.iter().enumerate() {
        assert_eq!(
            owner.resolve(*handle, 7, 9, SectionAliasAccess::ReadOnly),
            Ok(0x10007 + i as u64 * 4096)
        );
        assert_eq!(
            owner.resolve(*handle, 0, 4096, SectionAliasAccess::ReadWrite),
            Ok(0x10000 + i as u64 * 4096)
        );
    }
    owner.finish(&mut io).unwrap();
    assert_eq!(io.deleted, [3, 2, 1]);
    assert!(io.caps.is_empty());
}

#[test]
fn partial_recycling_keeps_batch_handles_invalid_and_does_not_repeat_deletion() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    let handles = prepare(&mut owner, &mut io, 3);
    io.fail_recycle = Some(2);
    assert_eq!(owner.finish(&mut io), Err(RESOURCES));
    assert_eq!(io.deleted, [3, 2]);
    assert_eq!(io.recycled, [3]);
    assert_eq!(owner.entries.len(), 2);
    assert!(!owner.entries[1].mapped && !owner.entries[1].populated);
    for handle in handles {
        assert!(owner
            .resolve(handle, 0, 1, SectionAliasAccess::ReadOnly)
            .is_err());
    }
    assert_eq!(owner.begin(&mut io), Err(RESOURCES));
    assert_eq!(io.deleted, [3, 2]);
    io.fail_recycle = None;
    owner.begin(&mut io).unwrap();
    assert_eq!(io.deleted, [3, 2, 1]);
    assert_eq!(io.recycled, [3, 2, 1]);
    owner.finish(&mut io).unwrap();
}

#[test]
fn last_copy_failure_does_not_lose_prior_preparations() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    prepare(&mut owner, &mut io, 2);
    io.fail_copy = Some(52);
    assert_eq!(
        owner.prepare(52, 0x12000, SectionAliasAccess::ReadWrite, &mut io),
        Err(RESOURCES)
    );
    assert_eq!(owner.entries.len(), 2);
    owner.finish(&mut io).unwrap();
    assert_eq!(io.deleted, [2, 1]);
}

#[test]
fn failed_last_map_is_owned_before_mapping_and_blocks_new_batches_until_deleted() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    let handles = prepare(&mut owner, &mut io, 2);
    io.fail_map = Some(3);
    io.fail_delete = Some(3);
    assert_eq!(
        owner.prepare(52, 0x12000, SectionAliasAccess::ReadWrite, &mut io),
        Err(RESOURCES)
    );
    assert_eq!(owner.entries.len(), 3);
    assert_eq!(owner.finish(&mut io), Err(RESOURCES));
    for handle in handles {
        assert_eq!(
            owner.resolve(handle, 0, 1, SectionAliasAccess::ReadOnly),
            Err(crate::STATUS_INVALID_HANDLE)
        );
    }
    let copies = io.copied.clone();
    assert_eq!(owner.begin(&mut io), Err(RESOURCES));
    assert_eq!(io.copied, copies);
    io.fail_delete = None;
    owner.begin(&mut io).unwrap();
    assert_eq!(io.deleted, [3, 2, 1]);
    owner.finish(&mut io).unwrap();
}

#[test]
fn partial_cleanup_never_replays_successful_deletions() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    let handles = prepare(&mut owner, &mut io, 3);
    io.fail_delete = Some(2);
    assert_eq!(owner.finish(&mut io), Err(RESOURCES));
    assert_eq!(io.deleted, [3]);
    assert_eq!(
        owner.resolve(handles[0], 0, 1, SectionAliasAccess::ReadWrite),
        Err(crate::STATUS_INVALID_HANDLE)
    );
    io.fail_delete = None;
    owner.drain(&mut io).unwrap();
    owner.drain(&mut io).unwrap();
    assert_eq!(io.deleted, [3, 2, 1]);
}

#[test]
fn handles_reject_old_generations_reused_caps_and_other_owners() {
    let mut a = SectionScratch::new();
    let mut b = SectionScratch::new();
    let mut io_a = Io::default();
    let mut io_b = Io::default();
    let old = prepare(&mut a, &mut io_a, 1)[0];
    let other = prepare(&mut b, &mut io_b, 1)[0];
    assert_eq!(
        b.resolve(old, 0, 1, SectionAliasAccess::ReadOnly),
        Err(crate::STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        a.resolve(other, 0, 1, SectionAliasAccess::ReadOnly),
        Err(crate::STATUS_INVALID_HANDLE)
    );
    a.finish(&mut io_a).unwrap();
    io_a.next = 0;
    let new = prepare(&mut a, &mut io_a, 1)[0];
    assert_eq!(
        a.resolve(old, 0, 1, SectionAliasAccess::ReadOnly),
        Err(crate::STATUS_INVALID_HANDLE)
    );
    assert_eq!(
        a.resolve(new, 0, 1, SectionAliasAccess::ReadOnly),
        Ok(0x10000)
    );
}

#[test]
fn rights_bounds_and_active_batch_cannot_be_bypassed() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    owner.begin(&mut io).unwrap();
    let handle = owner
        .prepare(50, 0x10000, SectionAliasAccess::ReadOnly, &mut io)
        .unwrap();
    assert_eq!(
        owner.resolve(handle, 0, 1, SectionAliasAccess::ReadWrite),
        Err(crate::STATUS_ACCESS_VIOLATION)
    );
    for (offset, length) in [(4096, 1), (4097, 0), (usize::MAX, 2)] {
        assert_eq!(
            owner.resolve(handle, offset, length, SectionAliasAccess::ReadOnly),
            Err(INVALID_PARAMETER)
        );
    }
    assert_eq!(owner.begin(&mut io), Err(RESOURCES));
    assert_eq!(owner.drain(&mut io), Err(RESOURCES));
    assert!(io.deleted.is_empty());
    owner.finish(&mut io).unwrap();
    assert_eq!(
        owner.prepare(50, 0x10000, SectionAliasAccess::ReadOnly, &mut io),
        Err(crate::STATUS_INVALID_HANDLE)
    );
}

#[test]
fn malformed_and_duplicate_addresses_fail_before_cap_copy() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    prepare(&mut owner, &mut io, 1);
    for address in [0x10001, u64::MAX - 4095, 0x10000] {
        assert_eq!(
            owner.prepare(51, address, SectionAliasAccess::ReadWrite, &mut io),
            Err(INVALID_PARAMETER)
        );
    }
    assert_eq!(io.copied, [50]);
}

#[test]
fn exhausted_generation_never_reuses_tokens_or_acquires_caps() {
    let mut owner = SectionScratch::new();
    owner.generation = u64::MAX;
    let mut io = Io::default();
    assert_eq!(owner.begin(&mut io), Err(RESOURCES));
    assert!(io.copied.is_empty());
    assert!(!owner.active);
}

#[test]
fn revoked_empty_mapping_is_still_acknowledged_exactly_once() {
    let mut owner = SectionScratch::new();
    let mut io = Io::default();
    prepare(&mut owner, &mut io, 2);
    io.caps.insert(2, None);
    owner.finish(&mut io).unwrap();
    owner.drain(&mut io).unwrap();
    assert_eq!(io.deleted, [2, 1]);
}

struct WriteIo {
    owner: SectionScratch,
    maps: Io,
    handles: Vec<(crate::SectionFilePage, SectionAliasHandle)>,
    wrote: bool,
}
impl crate::SectionFileWriteIo for WriteIo {
    fn begin(&mut self) -> Result<(), u32> {
        self.owner.begin(&mut self.maps)
    }
    fn rearm_alias(&mut self, _: crate::writeback::SectionPageAlias) -> Result<(), u32> {
        Ok(())
    }
    fn prepare_page(&mut self, page: crate::SectionFilePage) -> Result<(), u32> {
        let handle = self.owner.prepare(
            page.frame,
            0x10000 + self.handles.len() as u64 * 4096,
            SectionAliasAccess::ReadWrite,
            &mut self.maps,
        )?;
        self.handles.push((page, handle));
        Ok(())
    }
    fn write_backing(&mut self, _: u64, data: &[u8]) -> (u32, usize) {
        assert_eq!(self.maps.caps.len(), 3);
        self.wrote = true;
        (0, data.len())
    }
    fn copy_resident(&mut self, page: crate::SectionFilePage, offset: usize, data: &[u8]) {
        assert!(self.wrote);
        let handle = self
            .handles
            .iter()
            .find(|(prior, _)| *prior == page)
            .unwrap()
            .1;
        self.owner
            .resolve(handle, offset, data.len(), SectionAliasAccess::ReadWrite)
            .unwrap();
    }
    fn zero_resident(&mut self, _: crate::SectionFilePage, _: usize, _: usize) {
        panic!("no EOF gap");
    }
    fn finish(&mut self) -> Result<(), u32> {
        self.handles.clear();
        self.owner.finish(&mut self.maps)
    }
}

#[test]
fn real_transaction_does_not_write_when_the_last_alias_cannot_be_prepared() {
    for fail in [false, true] {
        let mut table = crate::GenericSectionTable::new();
        let backing = crate::GenericSectionBacking::overlay(
            1,
            crate::SectionFileIdentity {
                mount: crate::SectionMountIds::new().allocate().unwrap(),
                file_id: 10,
            },
            0x3000,
        );
        let section = table
            .create(
                1,
                4,
                0x3000,
                crate::PAGE_READWRITE,
                crate::SECTION_ATTR_SEC_COMMIT,
                backing,
            )
            .unwrap();
        for page in 0..3 {
            table.set_page_frame(section, page, 50 + page);
        }
        let mut io = WriteIo {
            owner: SectionScratch::new(),
            maps: Io {
                fail_map: fail.then_some(3),
                ..Io::default()
            },
            handles: Vec::new(),
            wrote: false,
        };
        let result = table.write_file_coherent(backing, 0, &vec![1; 0x3000], &mut io);
        assert_eq!(result, if fail { (RESOURCES, 0) } else { (0, 0x3000) });
        assert_eq!(io.wrote, !fail);
        assert!(io.maps.caps.is_empty());
    }
}
