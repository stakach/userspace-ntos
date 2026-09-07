//! Native capability operations for generation-exact provider arena leaf mappings.
use super::*;
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_alias_bank::{
    BankError, ChildCap, ProviderAliasBank, ProviderAliasIo, ProviderAliasRequest,
};

const RADIX: u32 = 12;
const SEGMENT_SLOTS: u64 = 1u64 << RADIX;
const SEGMENTS: usize = 24;
const GUARD_BADGE: u64 = 64 - RADIX as u64;
static RAW: [AtomicU64; SEGMENTS] = [const { AtomicU64::new(0) }; SEGMENTS];
static CNODE: [AtomicU64; SEGMENTS] = [const { AtomicU64::new(0) }; SEGMENTS];
static mut BANK: Option<ProviderAliasBank> = None;
static BORROWED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);

struct Borrow;
impl Borrow {
    fn acquire() -> Result<Self, BankError> {
        BORROWED
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .map(|_| Self)
            .map_err(|_| BankError::InsufficientResources)
    }
}
impl Drop for Borrow {
    fn drop(&mut self) {
        BORROWED.store(false, Ordering::Release);
    }
}

unsafe fn ensure_segment(segment: usize) -> Option<u64> {
    if segment >= SEGMENTS {
        return None;
    }
    let existing = CNODE[segment].load(Ordering::Relaxed);
    if existing != 0 {
        return Some(existing);
    }
    let raw = try_alloc_slot()?;
    if untyped_retype_r(CAP_INIT_UNTYPED, OBJ_CNODE, RADIX, 1, raw) != 0 {
        recycle_deleted_root_slot(raw);
        return None;
    }
    let Some(cnode) = try_alloc_slot() else {
        let _ = cnode_delete_recycle_r(raw);
        return None;
    };
    if cnode_mint_r(CAP_INIT_THREAD_CNODE, cnode, raw, GUARD_BADGE) != 0 {
        recycle_deleted_root_slot(cnode);
        let _ = cnode_delete_recycle_r(raw);
        return None;
    }
    RAW[segment].store(raw, Ordering::Relaxed);
    CNODE[segment].store(cnode, Ordering::Relaxed);
    Some(cnode)
}

struct Io;
fn status(error: u64) -> Result<(), u32> {
    if error == 0 {
        Ok(())
    } else {
        Err(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
}
impl ProviderAliasIo for Io {
    fn copy(&mut self, source: u64) -> (u64, u32) {
        let Some(cap) = try_alloc_slot() else {
            return (0, nt_address_space::STATUS_INSUFFICIENT_RESOURCES);
        };
        (
            cap,
            status(unsafe { copy_cap_into_r(source, cap) })
                .err()
                .unwrap_or(0),
        )
    }
    fn map(&mut self, root: u64, page: u64, rights: u64, pml4: u64) -> Result<(), u32> {
        status(unsafe { page_map_r(root, page, rights, pml4) })
    }
    fn ensure_segment(&mut self, segment: usize) -> Result<u64, u32> {
        unsafe { ensure_segment(segment) }.ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn move_to_child(&mut self, root: u64, child: ChildCap) -> Result<(), u32> {
        status(unsafe { cnode_move_root_to_cnode_r(child.cnode, child.slot, root) })
    }
    fn recycle_empty_root(&mut self, root: u64) -> Result<(), u32> {
        unsafe { root_slot_recycle::publish_unretyped(root) }
            .map_err(|_| nt_address_space::STATUS_INSUFFICIENT_RESOURCES)
    }
    fn delete_root(&mut self, root: u64) -> Result<(), u32> {
        status(unsafe { cnode_delete_r(root) })
    }
    fn delete_child(&mut self, child: ChildCap) -> Result<(), u32> {
        status(unsafe { cnode_delete_in_cnode_r(child.cnode, child.slot) })
    }
}

unsafe fn map_inner(request: ProviderAliasRequest) -> Result<(), BankError> {
    let _borrow = Borrow::acquire()?;
    let _durable = allocator::enter_durable();
    let slot = &mut *core::ptr::addr_of_mut!(BANK);
    if slot.is_none() {
        *slot = Some(ProviderAliasBank::new(SEGMENT_SLOTS, SEGMENTS)?);
    }
    slot.as_mut().unwrap().map(request, &mut Io).map(|_| ())
}

pub(super) unsafe fn map(request: ProviderAliasRequest) -> Result<(), BankError> {
    let result = map_inner(request);
    if let Err(error) = result {
        note_error(b"map", request.pi, request.process, error);
    }
    result
}

pub(super) fn is_empty(pi: usize) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe {
        (&*core::ptr::addr_of!(BANK))
            .as_ref()
            .is_none_or(|bank| bank.process_is_empty(pi))
    }
}

pub(super) fn all_empty() -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe {
        (&*core::ptr::addr_of!(BANK))
            .as_ref()
            .is_none_or(|bank| bank.is_empty())
    }
}

pub(super) fn admit_process(pi: usize, process: ProcessIdentity) -> Result<(), BankError> {
    let _borrow = Borrow::acquire()?;
    match unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() } {
        Some(bank) => bank.admit_process(pi, process),
        None if process.is_valid() => Ok(()),
        None => Err(BankError::InvalidRequest),
    }
}

pub(super) fn mapped_prefix(
    pi: usize,
    process: ProcessIdentity,
    base: u64,
    count: u64,
    pml4: u64,
    source_base: u64,
    rights: u64,
) -> bool {
    let Ok(_borrow) = Borrow::acquire() else {
        return false;
    };
    unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() }
        .is_some_and(|bank| bank.mapped_prefix(pi, process, base, count, pml4, source_base, rights))
}

unsafe fn release_inner(
    candidate: nt_user_host::ProcessDeletionCandidate,
) -> Result<(), BankError> {
    let _borrow = Borrow::acquire()?;
    let Some(bank) = (&mut *core::ptr::addr_of_mut!(BANK)).as_mut() else {
        return Ok(());
    };
    bank.release_process(
        candidate.pi,
        ProcessIdentity {
            pid: candidate.pid,
            generation: ProcessGeneration::Hosted(candidate.generation),
        },
        &mut Io,
    )
}

pub(super) unsafe fn release(
    candidate: nt_user_host::ProcessDeletionCandidate,
) -> Result<(), BankError> {
    let result = release_inner(candidate);
    if let Err(error) = result {
        note_error(
            b"release",
            candidate.pi,
            ProcessIdentity {
                pid: candidate.pid,
                generation: ProcessGeneration::Hosted(candidate.generation),
            },
            error,
        );
    }
    result
}

fn note_error(operation: &[u8], pi: usize, process: ProcessIdentity, error: BankError) {
    static REPORTS: AtomicU64 = AtomicU64::new(0);
    let count = REPORTS.fetch_add(1, Ordering::Relaxed).saturating_add(1);
    if count > 16 && !count.is_power_of_two() {
        return;
    }
    let held = {
        let Ok(_borrow) = Borrow::acquire() else {
            return;
        };
        unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() }
            .map(|bank| bank.stats())
            .unwrap_or_default()
    };
    {
        print_str(b"[w32-bank] ");
        print_str(operation);
        print_str(b" error pi=");
        print_u64(pi as u64);
        print_str(b" pid=");
        print_u64(process.pid as u64);
        let (kind, generation): (&[u8], u64) = match process.generation {
            ProcessGeneration::Hosted(value) => (b"hosted", value),
            ProcessGeneration::Temporary(value) => (b"temporary", value),
        };
        print_str(b" owner=");
        print_str(kind);
        print_str(b"/");
        print_u64(generation);
        print_str(b" reason=");
        print_str(match error {
            BankError::InvalidRequest => b"invalid-request",
            BankError::OwnerChanged => b"owner-changed",
            BankError::RequestConflict => b"request-conflict",
            BankError::Releasing => b"releasing",
            BankError::InsufficientResources => b"resources",
            BankError::StaleHandle => b"stale-handle",
            BankError::InvalidBackend => b"invalid-backend",
            BankError::Backend(_) => b"backend",
        });
        if let BankError::Backend(status) = error {
            print_str(b" status=0x");
            print_hex(status);
        }
        print_str(b" live/mapped/released=");
        print_u64(held.live as u64);
        print_str(b"/");
        print_u64(held.mapped as u64);
        print_str(b"/");
        print_u64(held.releases);
        print_str(b" failures=");
        print_u64(held.failures);
        print_str(b"\n");
    }
}

pub(super) fn stats() -> (u64, u64, u64, u64, u64) {
    let Ok(_borrow) = Borrow::acquire() else {
        return (0, 0, 0, 0, 1);
    };
    let bank = unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() };
    let segments = CNODE
        .iter()
        .filter(|entry| entry.load(Ordering::Relaxed) != 0)
        .count() as u64;
    let Some(bank) = bank else {
        return (0, 0, 0, segments, 0);
    };
    let stats = bank.stats();
    let mut processes = 0u64;
    for pi in 0..MAX_PI {
        if !bank.process_is_empty(pi) {
            processes += 1;
        }
    }
    (
        stats.live as u64,
        stats.entries as u64,
        processes,
        segments,
        stats.failures,
    )
}
