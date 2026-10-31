//! Demand-mapped, session-owned physical backing for checked Win32k bulk argument leases.
//!
//! The pure lease ledger owns virtual extents. This module owns the frame identity and its two
//! aliases. A page is published only when both VSpaces map copies of the same canonical cap.
//! Mappings stay live for the session; known completed virtual leases may reuse their bytes after
//! the next caller zeroes its touched extent. An uncertain map fences the whole backing arena.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, Ordering};
use core::sync::atomic::AtomicU64;

use nt_hosted_runtime::{Win32kBulkDispatchIdentity, Win32kBulkLayout, Win32kBulkLease,
    Win32kBulkMapFailure, Win32kBulkOwner, Win32kBulkStages};

use crate::*;

#[derive(Clone, Copy)]
struct PageCaps {
    address: u64,
    canonical: u64,
    executive: u64,
    provider: u64,
    published: bool,
}

static BUSY: AtomicBool = AtomicBool::new(false);
static POISONED: AtomicBool = AtomicBool::new(false);
static mut PAGES: Vec<PageCaps> = Vec::new();
static mut STAGES: Option<Win32kBulkStages<64>> = None;
static NEXT_REQUEST: AtomicU64 = AtomicU64::new(1);

#[derive(Clone, Copy)]
pub(crate) struct BulkStage {
    lease: Win32kBulkLease,
    owner: Win32kBulkOwner,
}

impl BulkStage {
    pub(crate) fn base(self) -> u64 { self.lease.base() }
    pub(crate) fn bytes(self) -> u64 { self.lease.layout().bytes }
    pub(crate) fn capacity(self) -> u64 { self.lease.mapped_bytes() }
}

unsafe fn stages(domain: nt_provider_wait::ProviderDomainIdentity) -> Option<&'static mut Win32kBulkStages<64>> {
    let slot = &mut *core::ptr::addr_of_mut!(STAGES);
    if slot.is_none() {
        *slot = Win32kBulkStages::new(
            win32k_subsystem::WIN32K_BULK_ARENA_VADDR,
            win32k_subsystem::WIN32K_BULK_ARENA_BYTES,
            domain.domain,
            domain.generation,
        ).ok();
    }
    slot.as_mut()
}

/// Reserve disjoint provider-visible bytes, then prove and zero both aliases before publication.
pub(crate) unsafe fn reserve(requester_index: u32, requester_generation: u64,
    layout: Win32kBulkLayout) -> Option<BulkStage> {
    let _guard = MappingGuard::acquire();
    let domain = current_win32k_provider_domain()?;
    let request = NEXT_REQUEST.fetch_add(1, Ordering::Relaxed);
    let owner = Win32kBulkOwner::new(domain.domain, domain.generation,
        requester_index, requester_generation, request)?;
    let lease = stages(domain)?.reserve(owner, layout).ok()?;
    if let Err(failure) = ensure_mapped_locked(lease.base(), lease.mapped_bytes()) {
        // A definitive refusal before any map can release the row. Once mapping may have
        // changed either VSpace, retain the exact row and fence the backing arena.
        if stages(domain)?.reject_mapping(lease, owner, failure).is_err() {
            park();
        }
        return None;
    }
    core::ptr::write_bytes(lease.base() as *mut u8, 0, lease.mapped_bytes() as usize);
    Some(BulkStage { lease, owner })
}

/// Settle the exact lease after the native dispatch reports whether it entered and whether its
/// authenticated provider return completed. Uncertain effects retain their virtual extent.
pub(crate) unsafe fn settle(stage: BulkStage, entered: bool, completed: bool) -> bool {
    let _guard = MappingGuard::acquire();
    let Some(domain) = current_win32k_provider_domain() else { return false; };
    let Some(stages) = stages(domain) else { return false; };
    let result = if !entered {
        stages.cancel(stage.lease, stage.owner)
    } else if stages.enter(stage.lease, stage.owner).is_err() {
        return false;
    } else if completed {
        stages.complete(stage.lease, stage.owner)
            .and_then(|()| stages.retire(stage.lease, stage.owner))
    } else {
        stages.mark_uncertain(stage.lease, stage.owner)
    };
    result.is_ok()
}

pub(crate) fn dispatch_identity(context: nt_user_callback::DispatchContext)
    -> Option<Win32kBulkDispatchIdentity>
{
    Win32kBulkDispatchIdentity::new(
        context.lane.index, context.lane.generation, context.dispatch_id, context.ssn,
    )
}

/// Parked dispatches keep their claim until the same physical handler returns. The stage owner
/// came from the authenticated client before dispatch, and the native dispatch context came from
/// the provider lane rather than a transport reply.
pub(crate) unsafe fn retain(stage: BulkStage, context: nt_user_callback::DispatchContext,
    requester_index: u32, requester_generation: u64) -> bool
{
    if !stage.owner.matches_requester(requester_index, requester_generation) { return false; }
    let Some(identity) = dispatch_identity(context) else { return false; };
    let _guard = MappingGuard::acquire();
    let Some(domain) = current_win32k_provider_domain() else { return false; };
    let Some(stages) = stages(domain) else { return false; };
    if stages.state(stage.lease) == Some(nt_hosted_runtime::Win32kBulkLeaseState::Reserved)
        && stages.enter(stage.lease, stage.owner).is_err()
    {
        return false;
    }
    stages.retain_for_dispatch(stage.lease, stage.owner, identity).is_ok()
}

/// Native terminal ownership and the authenticated handler return jointly authorize reuse.
/// A failed or incomplete return keeps the exact row fenced; unrelated dispatches are ignored.
pub(crate) unsafe fn complete_dispatch(context: nt_user_callback::DispatchContext,
    requester_index: u32, requester_generation: u64,
    returned: Option<nt_user_callback::DispatchReturn>, result: u64) -> bool
{
    let Some(identity) = dispatch_identity(context) else { return true; };
    let _guard = MappingGuard::acquire();
    let Some(domain) = current_win32k_provider_domain() else { return false; };
    let Some(stages) = stages(domain) else { return false; };
    let lease = match stages.retained_for_dispatch(identity) {
        Ok(Some(lease)) => lease,
        Ok(None) => return true,
        Err(_) => return false,
    };
    let owner = lease.owner();
    if !owner.matches_requester(requester_index, requester_generation) { return false; }
    if returned.and_then(|receipt| receipt.handler_value()) != Some(result) {
        return true;
    }
    let receipt = nt_user_callback::DispatchReturnReceipt::handler_returned(
        context.dispatch_id, context.ssn, result,
    );
    stages.complete_retained_dispatch(lease, owner, identity, receipt, result, true).is_ok()
}

struct MappingGuard;

impl MappingGuard {
    fn acquire() -> Self {
        while BUSY.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
            crate::yield_now();
        }
        Self
    }
}

impl Drop for MappingGuard {
    fn drop(&mut self) {
        BUSY.store(false, Ordering::Release);
    }
}

/// Ensure a checked virtual lease has identical physical backing in the executive and provider.
/// No caller may dereference the lease until this succeeds. Partial effects remain recorded and
/// poison further mapping attempts, so no cap or VA is reused on an uncertain result.
unsafe fn ensure_mapped_locked(base: u64, bytes: u64) -> Result<(), Win32kBulkMapFailure> {
    const PAGE: u64 = 4096;
    let arena = win32k_subsystem::WIN32K_BULK_ARENA_VADDR;
    let limit = arena + win32k_subsystem::WIN32K_BULK_ARENA_BYTES;
    if base < arena || base & (PAGE - 1) != 0 || bytes == 0 || bytes & (PAGE - 1) != 0 {
        return Err(Win32kBulkMapFailure::NoEffect);
    }
    let Some(end) = base.checked_add(bytes) else { return Err(Win32kBulkMapFailure::NoEffect); };
    if end > limit || POISONED.load(Ordering::Acquire) {
        return Err(Win32kBulkMapFailure::NoEffect);
    }
    let pml4 = WIN32K_HOST_PML4.load(Ordering::Acquire);
    if pml4 == 0 {
        return Err(Win32kBulkMapFailure::NoEffect);
    }
    let pages = &mut *core::ptr::addr_of_mut!(PAGES);
    let end_page = (end - arena) / PAGE;
    let original_page_count = pages.len();
    while (pages.len() as u64) < end_page {
        if pages.try_reserve(1).is_err() {
            if pages.len() != original_page_count {
                POISONED.store(true, Ordering::Release);
                return Err(Win32kBulkMapFailure::Indeterminate);
            }
            return Err(Win32kBulkMapFailure::NoEffect);
        }
        let address = arena + pages.len() as u64 * PAGE;
        pages.push(PageCaps { address, canonical: 0, executive: 0, provider: 0, published: false });
        let row = pages.last_mut().expect("just reserved mapping row");
        if !ensure_executive_paging(address)
            || !win32k_glue::ensure_w32_client_paging(address, pml4)
        {
            POISONED.store(true, Ordering::Release);
            return Err(Win32kBulkMapFailure::Indeterminate);
        }
        let (canonical, retype) = alloc_frame_r();
        row.canonical = canonical;
        if canonical == 0 || retype != 0 {
            POISONED.store(true, Ordering::Release);
            return Err(Win32kBulkMapFailure::Indeterminate);
        }
        let (executive, exec_copy) = copy_cap_r(canonical);
        row.executive = executive;
        if executive == 0 || exec_copy != 0 {
            POISONED.store(true, Ordering::Release);
            return Err(Win32kBulkMapFailure::Indeterminate);
        }
        let (provider, provider_copy) = copy_cap_r(canonical);
        row.provider = provider;
        if provider == 0 || provider_copy != 0 {
            POISONED.store(true, Ordering::Release);
            return Err(Win32kBulkMapFailure::Indeterminate);
        }
        if page_map_r(executive, address, RW_NX, CAP_INIT_THREAD_VSPACE) != 0
            || page_map_r(provider, address, RW_NX, pml4) != 0
        {
            POISONED.store(true, Ordering::Release);
            return Err(Win32kBulkMapFailure::Indeterminate);
        }
        row.published = true;
    }
    if !pages.iter().take(end_page as usize).all(|page| {
        page.published && page.address >= arena && page.canonical != 0
            && page.executive != 0 && page.provider != 0
    }) {
        POISONED.store(true, Ordering::Release);
        return Err(Win32kBulkMapFailure::Indeterminate);
    }
    Ok(())
}
