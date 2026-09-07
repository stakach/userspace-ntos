//! Native capability operations for generation-exact provider arena leaf mappings.
use super::*;
use nt_user_host::process_identity::{ProcessGeneration, ProcessIdentity};
use nt_user_host::provider_alias_bank::segment::{ProviderAliasSegment, ProviderAliasSegmentIo};
use nt_user_host::provider_alias_bank::{
    BankError, ChildCap, ProviderAliasBank, ProviderAliasIo, ProviderAliasRequest,
};

const RADIX: u32 = 12;
const SEGMENT_SLOTS: u64 = 1u64 << RADIX;
const SEGMENTS: usize = 24;
static mut SEGMENT_OWNERS: [ProviderAliasSegment; SEGMENTS] =
    [const { ProviderAliasSegment::new(RADIX) }; SEGMENTS];
static mut BANK: Option<ProviderAliasBank> = None;
static BORROWED: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
#[path = "win32k_thread_provider_aliases.rs"]
mod thread_aliases;
pub(crate) use thread_aliases::ThreadProviderAliasCleanup;

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

struct SegmentIo;
impl ProviderAliasSegmentIo for SegmentIo {
    fn reserve_slot(&mut self) -> Result<u64, u32> {
        let slot = try_alloc_slot().ok_or(nt_address_space::STATUS_INSUFFICIENT_RESOURCES)?;
        // Segment CNodes live for the executive lifetime; unlike leaf/scratch slots, these
        // capabilities never need deletion. Pinning protects both partial and ready owners.
        unsafe {
            root_slot_pin(slot);
        }
        Ok(slot)
    }
    fn retype(&mut self, raw: u64, radix: u32) -> Result<(), u32> {
        status(unsafe { untyped_retype_r(CAP_INIT_UNTYPED, OBJ_CNODE, radix, 1, raw) })
    }
    fn mint(&mut self, raw: u64, guarded: u64, guard_bits: u64) -> Result<(), u32> {
        status(unsafe { cnode_mint_r(CAP_INIT_THREAD_CNODE, guarded, raw, guard_bits) })
    }
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
        let owner = unsafe { (&mut *core::ptr::addr_of_mut!(SEGMENT_OWNERS)).get_mut(segment) }
            .ok_or(nt_address_space::STATUS_INVALID_PARAMETER)?;
        owner.ensure(&mut SegmentIo).map_err(|error| match error {
            BankError::Backend(status) => status,
            _ => nt_address_space::STATUS_INVALID_PARAMETER,
        })
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

pub(super) fn owns_root_cap(cap: u64) -> bool {
    if cap == 0 {
        return false;
    }
    let Ok(_borrow) = Borrow::acquire() else {
        return true;
    };
    (unsafe { segment_owns_root_cap(cap) })
    || unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() }.is_some_and(|bank| bank.owns_root_cap(cap))
}

/// The caller holds Borrow; these queries must not reacquire it or perform backend operations.
unsafe fn segment_owns_root_cap(cap: u64) -> bool {
    cap != 0
        && (&*core::ptr::addr_of!(SEGMENT_OWNERS)).iter().any(|owner| {
            let held = owner.snapshot();
            held.raw == cap || held.guarded == cap
        })
}

unsafe fn segment_owns_child(child: ChildCap) -> bool {
    child.slot < SEGMENT_SLOTS
        && (&*core::ptr::addr_of!(SEGMENT_OWNERS))
            .iter()
            .any(|owner| owner.ready() == Some(child.cnode))
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
    let (held, constructing) = {
        let Ok(_borrow) = Borrow::acquire() else {
            return;
        };
        let held = unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() }
            .map(|bank| bank.stats())
            .unwrap_or_default();
        let constructing = unsafe { &*core::ptr::addr_of!(SEGMENT_OWNERS) }
            .iter()
            .map(ProviderAliasSegment::snapshot)
            .find(|segment| segment.raw != 0 && !segment.guarded_minted);
        (held, constructing)
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
            BankError::Claimed => b"claimed",
            BankError::NotClaimed => b"not-claimed",
            BankError::SharedCapability(_) => b"shared-capability",
            BankError::InvalidBackend => b"invalid-backend",
            BankError::Backend(_) => b"backend",
        });
        if let BankError::Backend(status) = error {
            print_str(b" status=0x");
            print_hex(status);
        }
        if let BankError::SharedCapability(capability) = error {
            use nt_user_host::provider_alias_bank::ProviderAliasCapability;
            match capability {
                ProviderAliasCapability::Root(slot) => {
                    print_str(b" root-slot=0x");
                    print_hex_u64(slot);
                }
                ProviderAliasCapability::Child(child) => {
                    print_str(b" child-cnode/slot=0x");
                    print_hex_u64(child.cnode);
                    print_str(b"/0x");
                    print_hex_u64(child.slot);
                }
            }
        }
        print_str(b" live/mapped/released=");
        print_u64(held.live as u64);
        print_str(b"/");
        print_u64(held.mapped as u64);
        print_str(b"/");
        print_u64(held.releases);
        print_str(b" failures=");
        print_u64(held.failures);
        if let Some(segment) = constructing {
            print_str(b" segment-raw/guarded=0x");
            print_hex_u64(segment.raw);
            print_str(b"/0x");
            print_hex_u64(segment.guarded);
            print_str(b" retyped=");
            print_u64(segment.raw_retyped as u64);
        }
        print_str(b"\n");
    }
}

pub(super) fn stats() -> (u64, u64, u64, u64, u64) {
    let Ok(_borrow) = Borrow::acquire() else {
        return (0, 0, 0, 0, 1);
    };
    let bank = unsafe { (&*core::ptr::addr_of!(BANK)).as_ref() };
    let segments = unsafe { &*core::ptr::addr_of!(SEGMENT_OWNERS) }
        .iter()
        .filter(|entry| entry.ready().is_some())
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
