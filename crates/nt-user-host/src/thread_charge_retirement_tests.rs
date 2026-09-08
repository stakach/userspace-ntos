use super::*;
use crate::process_identity::ProcessGeneration;
use crate::thread_rollback::{
    new_rollback_id, ThreadRollbackIdentity, ThreadRollbackIo, ThreadRollbackResource,
};
use alloc::vec;
use nt_address_space::{VmCommittedRange, PAGE_READONLY, PAGE_READWRITE};

const FIXED: ThreadMemoryRange = ThreadMemoryRange {
    base: 0x80000,
    size: 0x2000,
};
const STACK: ThreadMemoryRange = ThreadMemoryRange {
    base: 0x10000,
    size: 0x4000,
};
const FAILURE: u32 = 0xc0000001;

struct Fixture {
    pm: ProcessManager,
    mm: ProcessCommitLedger,
    process: ProcessIdentity,
    thread: ThreadLifetime,
    id: ThreadRollbackId,
    fixed: VmCommittedRangeTable<16>,
    private: VmRegionMap<16>,
}

impl Fixture {
    fn new() -> Self {
        let mut pm = ProcessManager::new();
        let pid = pm.create_process("charge.exe", None, None);
        let tid = pm.create_thread(pid, 0x1000, 0, false).unwrap();
        let thread = pm.thread_lifetime(tid).unwrap();
        let process = ProcessIdentity {
            pid,
            generation: ProcessGeneration::Hosted(7),
        };
        let id = new_rollback_id(ThreadRollbackIdentity {
            pi: 3,
            pid,
            process_generation: process.generation,
            tid: u64::from(tid),
        })
        .unwrap();
        let mut fixed = VmCommittedRangeTable::new();
        fixed
            .register(VmCommittedRange::private(
                FIXED.base,
                FIXED.size,
                PAGE_READWRITE,
            ))
            .unwrap();
        let mut private = VmRegionMap::new(0x10000, 0x100000);
        private
            .allocate(Some(STACK.base), STACK.size, MEM_RESERVE, PAGE_READWRITE)
            .unwrap();
        private
            .allocate(
                Some(STACK.base + PAGE_SIZE),
                2 * PAGE_SIZE,
                MEM_COMMIT,
                PAGE_READWRITE,
            )
            .unwrap();
        let mut mm = ProcessCommitLedger::new();
        mm.register(pid, 4 * PAGE_SIZE).unwrap();
        Self {
            pm,
            mm,
            process,
            thread,
            id,
            fixed,
            private,
        }
    }

    fn prepare(&self) -> ThreadChargeRetirement {
        ThreadChargeRetirement::prepare(
            self.id,
            self.process,
            self.thread,
            &[FIXED],
            Some(STACK),
            &self.fixed,
            &self.private,
        )
        .unwrap()
    }

    fn commit(&mut self, owner: &mut ThreadChargeRetirement) -> Result<(), u32> {
        let mut fixed_scratch = VmCommittedRangeTable::new();
        let mut private_scratch = VmRegionMap::new(0x10000, 0x100000);
        owner.commit(
            self.id,
            self.process,
            self.thread,
            ThreadChargeTables {
                fixed: &mut self.fixed,
                private: &mut self.private,
                fixed_scratch: &mut fixed_scratch,
                private_scratch: &mut private_scratch,
            },
            &mut self.mm,
            &mut self.pm,
        )
    }

    fn physical_complete(&self, owner: &mut ThreadChargeRetirement) -> Pages {
        let mut rollback = ThreadRollback::prepare_with_id(self.id, &[]).unwrap();
        rollback.advance(&mut RollbackIo).unwrap();
        owner.acknowledge_fixed_retirement(&rollback).unwrap();
        let mut pages = Pages::default();
        assert_eq!(
            owner.advance_dynamic(
                self.id,
                self.process,
                self.thread,
                &self.private,
                usize::MAX,
                &mut pages
            ),
            Ok(true)
        );
        pages
    }
}

struct RollbackIo;
impl ThreadRollbackIo for RollbackIo {
    fn is_current(&self, _: ThreadRollbackId) -> bool {
        true
    }
    fn revoke_memory_access(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
        Ok(())
    }
    fn unmap_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        Ok(())
    }
    fn delete_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        Ok(())
    }
    fn recycle_resource(&mut self, _: ThreadRollbackResource) -> Result<(), u32> {
        Ok(())
    }
    fn finish_memory_transfers(&mut self, _: ThreadRollbackId) -> Result<(), u32> {
        Ok(())
    }
    fn commit_rollback(&mut self, _: ThreadRollbackId) {}
}

#[derive(Default)]
struct Pages {
    accepted: Vec<u64>,
    fail: Option<u64>,
    stale: bool,
}
impl ThreadChargeRetirementIo for Pages {
    fn is_current(&self, _: ThreadRollbackId, _: ProcessIdentity, _: ThreadLifetime) -> bool {
        !self.stale
    }
    fn retire_dynamic_page(&mut self, page: u64) -> Result<(), u32> {
        if self.fail == Some(page) {
            return Err(FAILURE);
        }
        assert!(
            !self.accepted.contains(&page),
            "accepted page must not be replayed"
        );
        self.accepted.push(page);
        Ok(())
    }
}

#[test]
fn exact_two_page_teb_and_mixed_stack_retire_once_including_reserved_pages() {
    let mut f = Fixture::new();
    let mut owner = f.prepare();
    assert_eq!(owner.charged_bytes(), 4 * PAGE_SIZE);
    assert_eq!(f.commit(&mut owner), Err(STATUS_INVALID_PARAMETER));
    let pages = f.physical_complete(&mut owner);
    assert_eq!(pages.accepted, vec![0x10000, 0x11000, 0x12000, 0x13000]);
    f.commit(&mut owner).unwrap();
    assert!(owner.is_complete());
    assert!(f.fixed.query_basic(FIXED.base).is_none());
    assert!(f.private.extent_at(STACK.base).is_none());
    assert_eq!(f.mm.accounting(f.process.pid).unwrap().current_bytes, 0);
    assert_eq!(
        f.mm.accounting(f.process.pid).unwrap().peak_bytes,
        4 * PAGE_SIZE
    );
    f.commit(&mut owner).unwrap();
    assert_eq!(f.mm.accounting(f.process.pid).unwrap().current_bytes, 0);
}

#[test]
fn bounded_page_retry_preserves_successes_and_failed_page_cursor() {
    let f = Fixture::new();
    let mut owner = f.prepare();
    let mut pages = Pages {
        fail: Some(0x11000),
        ..Pages::default()
    };
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, f.thread, &f.private, 0, &mut pages),
        Ok(false)
    );
    assert!(pages.accepted.is_empty());
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, f.thread, &f.private, 2, &mut pages),
        Err(FAILURE)
    );
    assert_eq!(pages.accepted, vec![0x10000]);
    pages.fail = None;
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, f.thread, &f.private, 1, &mut pages),
        Ok(false)
    );
    assert_eq!(pages.accepted, vec![0x10000, 0x11000]);
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, f.thread, &f.private, 2, &mut pages),
        Ok(true)
    );
    assert_eq!(pages.accepted.len(), 4);
}

#[test]
fn wrong_attempt_process_thread_and_backend_admission_have_no_effects() {
    let mut f = Fixture::new();
    let mut owner = f.prepare();
    let other = new_rollback_id(f.id.identity()).unwrap();
    let mut pages = Pages::default();
    assert_eq!(
        owner.advance_dynamic(other, f.process, f.thread, &f.private, 4, &mut pages),
        Err(STATUS_INVALID_PARAMETER)
    );
    let wrong_process = ProcessIdentity {
        generation: ProcessGeneration::Hosted(8),
        ..f.process
    };
    assert_eq!(
        owner.advance_dynamic(f.id, wrong_process, f.thread, &f.private, 4, &mut pages),
        Err(STATUS_INVALID_PARAMETER)
    );
    let other_tid = f.pm.create_thread(f.process.pid, 0x2000, 0, false).unwrap();
    let other_thread = f.pm.thread_lifetime(other_tid).unwrap();
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, other_thread, &f.private, 4, &mut pages),
        Err(STATUS_INVALID_PARAMETER)
    );
    pages.stale = true;
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, f.thread, &f.private, 4, &mut pages),
        Err(STATUS_INVALID_PARAMETER)
    );
    assert!(pages.accepted.is_empty());
    let mut wrong_rollback = ThreadRollback::prepare_with_id(other, &[]).unwrap();
    wrong_rollback.advance(&mut RollbackIo).unwrap();
    assert_eq!(
        owner.acknowledge_fixed_retirement(&wrong_rollback),
        Err(STATUS_INVALID_PARAMETER)
    );
    let early = ThreadRollback::prepare_with_id(f.id, &[]).unwrap();
    assert_eq!(
        owner.acknowledge_fixed_retirement(&early),
        Err(STATUS_INVALID_PARAMETER)
    );
}

#[test]
fn capture_rejects_missing_overlapping_misaligned_overflow_and_partial_allocations() {
    let f = Fixture::new();
    for (fixed, dynamic) in [
        (vec![FIXED, FIXED], Some(STACK)),
        (
            vec![ThreadMemoryRange {
                base: FIXED.base,
                size: 3 * PAGE_SIZE,
            }],
            Some(STACK),
        ),
        (
            vec![FIXED],
            Some(ThreadMemoryRange {
                base: STACK.base,
                size: 3 * PAGE_SIZE,
            }),
        ),
        (
            vec![FIXED],
            Some(ThreadMemoryRange {
                base: STACK.base + PAGE_SIZE,
                size: 3 * PAGE_SIZE,
            }),
        ),
        (
            vec![FIXED],
            Some(ThreadMemoryRange {
                base: u64::MAX - PAGE_SIZE + 1,
                size: PAGE_SIZE,
            }),
        ),
        (
            vec![ThreadMemoryRange {
                base: FIXED.base + 1,
                size: PAGE_SIZE,
            }],
            None,
        ),
        (vec![FIXED], Some(FIXED)),
    ] {
        assert!(ThreadChargeRetirement::prepare(
            f.id, f.process, f.thread, &fixed, dynamic, &f.fixed, &f.private
        )
        .is_err());
    }
    assert_eq!(f.fixed.process_commit_bytes(), 2 * PAGE_SIZE);
    assert_eq!(f.private.private_committed_bytes(), 2 * PAGE_SIZE);
}

#[test]
fn selected_protection_change_blocks_cleanup_and_commit_without_table_mutation() {
    let mut f = Fixture::new();
    let mut owner = f.prepare();
    f.private
        .protect(0x11000, PAGE_SIZE, PAGE_READONLY)
        .unwrap();
    let mut pages = Pages::default();
    assert_eq!(
        owner.advance_dynamic(f.id, f.process, f.thread, &f.private, 4, &mut pages),
        Err(STATUS_CONFLICTING_ADDRESSES)
    );
    assert!(pages.accepted.is_empty());
    f.private
        .protect(0x11000, PAGE_SIZE, PAGE_READWRITE)
        .unwrap();
    f.physical_complete(&mut owner);
    f.fixed
        .protect(FIXED.base, PAGE_SIZE, PAGE_READONLY)
        .unwrap();
    assert_eq!(f.commit(&mut owner), Err(STATUS_CONFLICTING_ADDRESSES));
    assert_eq!(
        f.mm.accounting(f.process.pid).unwrap().current_bytes,
        4 * PAGE_SIZE
    );
    assert!(f.private.extent_at(STACK.base).is_some());
}

#[test]
fn unrelated_table_edits_survive_commit_from_current_tables() {
    let mut f = Fixture::new();
    let mut owner = f.prepare();
    f.physical_complete(&mut owner);
    f.fixed
        .register(VmCommittedRange::private(0x90000, PAGE_SIZE, PAGE_READONLY))
        .unwrap();
    f.private
        .allocate(
            Some(0x30000),
            PAGE_SIZE,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_READWRITE,
        )
        .unwrap();
    let charge = f.mm.prepare_charge(f.process.pid, 2 * PAGE_SIZE).unwrap();
    f.mm.commit_charge(charge).unwrap();
    f.commit(&mut owner).unwrap();
    assert_eq!(f.fixed.query_basic(0x90000).unwrap().protect, PAGE_READONLY);
    assert!(f.private.extent_at(0x30000).is_some());
    assert_eq!(
        f.mm.accounting(f.process.pid).unwrap().current_bytes,
        2 * PAGE_SIZE
    );
}

#[test]
fn paired_accounting_refusal_retains_ranges_and_owner_for_retry() {
    let mut f = Fixture::new();
    let job = f.pm.create_job(0).unwrap();
    f.pm.assign_process_to_job_with_commit(job, f.process.pid, 3 * PAGE_SIZE)
        .unwrap();
    let mut owner = f.prepare();
    f.physical_complete(&mut owner);
    for _ in 0..2 {
        assert_eq!(f.commit(&mut owner), Err(STATUS_INVALID_PARAMETER));
        assert!(!owner.is_complete());
        assert!(f.fixed.query_basic(FIXED.base).is_some());
        assert!(f.private.extent_at(STACK.base).is_some());
        assert_eq!(
            f.mm.accounting(f.process.pid).unwrap().current_bytes,
            4 * PAGE_SIZE
        );
    }
    let charge =
        f.pm.prepare_job_memory_charge(f.process.pid, PAGE_SIZE)
            .unwrap()
            .unwrap();
    f.pm.commit_job_memory_charge(charge).unwrap();
    f.commit(&mut owner).unwrap();
    assert_eq!(f.pm.job_memory_usage(f.process.pid), Ok((0, 0)));
}

#[test]
fn no_dynamic_stack_is_explicit_and_fixed_cleanup_still_requires_ack() {
    let mut f = Fixture::new();
    let mut owner = ThreadChargeRetirement::prepare(
        f.id,
        f.process,
        f.thread,
        &[FIXED],
        None,
        &f.fixed,
        &f.private,
    )
    .unwrap();
    assert!(owner.dynamic_pages_complete());
    assert_eq!(owner.charged_bytes(), 2 * PAGE_SIZE);
    assert_eq!(f.commit(&mut owner), Err(STATUS_INVALID_PARAMETER));
    f.physical_complete(&mut owner);
    f.commit(&mut owner).unwrap();
    assert!(f.private.extent_at(STACK.base).is_some());
    assert_eq!(
        f.mm.accounting(f.process.pid).unwrap().current_bytes,
        2 * PAGE_SIZE
    );
}

#[test]
fn effective_equivalent_protection_splits_do_not_invalidate_owned_geometry() {
    let mut f = Fixture::new();
    let mut owner = f.prepare();
    f.fixed
        .protect(FIXED.base, PAGE_SIZE, PAGE_READONLY)
        .unwrap();
    f.fixed
        .protect(FIXED.base, PAGE_SIZE, PAGE_READWRITE)
        .unwrap();
    f.private
        .protect(0x11000, PAGE_SIZE, PAGE_READONLY)
        .unwrap();
    f.private
        .protect(0x11000, PAGE_SIZE, PAGE_READWRITE)
        .unwrap();
    f.physical_complete(&mut owner);
    f.commit(&mut owner).unwrap();
    assert_eq!(f.mm.accounting(f.process.pid).unwrap().current_bytes, 0);
}

#[test]
fn mm_refusal_preserves_job_and_ranges_until_exact_retry() {
    let mut f = Fixture::new();
    let job = f.pm.create_job(0).unwrap();
    f.pm.assign_process_to_job_with_commit(job, f.process.pid, 4 * PAGE_SIZE)
        .unwrap();
    f.mm.release(f.process.pid, PAGE_SIZE).unwrap();
    let mut owner = f.prepare();
    f.physical_complete(&mut owner);
    assert_eq!(f.commit(&mut owner), Err(STATUS_INVALID_PARAMETER));
    assert_eq!(
        f.pm.job_memory_usage(f.process.pid),
        Ok((4 * PAGE_SIZE, 4 * PAGE_SIZE))
    );
    assert!(f.fixed.query_basic(FIXED.base).is_some());
    assert!(f.private.extent_at(STACK.base).is_some());
    let charge = f.mm.prepare_charge(f.process.pid, PAGE_SIZE).unwrap();
    f.mm.commit_charge(charge).unwrap();
    f.commit(&mut owner).unwrap();
    assert_eq!(f.pm.job_memory_usage(f.process.pid), Ok((0, 0)));
}
