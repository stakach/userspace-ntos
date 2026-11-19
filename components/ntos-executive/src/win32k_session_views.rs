//! Root owner of win32k's reserve-only session views (`SEC_RESERVE` Section views).
//!
//! The pure ledger is [`nt_memory_manager::session_view_band`]. This adapter performs the native
//! effects of each ledger step: a committed page gets one frame, mapped read-write at the same
//! address in the root and in the win32k provider, and a read-only alias in every admitted GUI
//! client. Every uncertain effect quarantines its page, so its address and frame are never reused.
//! Nothing here runs in the provider: it reaches the ledger only through [`service`].

use crate::*;
use nt_memory_manager::session_view_band::{
    wire, BandError, CommitRange, CommittedPage, PageAccess, SessionViewBand, ViewReservation,
};

pub(crate) const BASE: u64 = nt_executive_layout::root::WIN32K_SESSION_VIEWS.base;
pub(crate) const BYTES: u64 = nt_executive_layout::root::WIN32K_SESSION_VIEWS.len;
/// GUI clients project the band read-only at this address.
pub(crate) const CLIENT_BASE: u64 = win32k_subsystem::CSRSS_W32_SHARED_VA;
/// Server address minus client address for every page of the band.
pub(crate) const CLIENT_DELTA: u64 = BASE - CLIENT_BASE;
// The client window ends below the NLS section.
const _: () = assert!(CLIENT_BASE + BYTES <= 0xA000_0000);

static mut BAND: SessionViewBand = SessionViewBand::new(BASE, BYTES);
static COMMIT_TRACES: AtomicU64 = AtomicU64::new(0);
static DENIAL_TRACES: AtomicU64 = AtomicU64::new(0);
const TRACE_LIMIT: u64 = 64;

/// Root-only: the provider never dereferences this static.
unsafe fn band() -> &'static mut SessionViewBand {
    &mut *core::ptr::addr_of_mut!(BAND)
}

pub(crate) fn contains(address: u64) -> bool {
    address >= BASE && address - BASE < BYTES
}

fn trace_denial(stage: &[u8], first: u64, second: u64, status: u32) {
    if DENIAL_TRACES.fetch_add(1, Ordering::Relaxed) >= TRACE_LIMIT {
        return;
    }
    print_str(b"[win32k-session-view] refused stage=");
    print_str(stage);
    print_str(b" first=0x");
    print_hex_u64(first);
    print_str(b" second=0x");
    print_hex_u64(second);
    print_str(b" status=0x");
    print_hex(status);
    print_str(b"\n");
}

/// One provider request: `(status, first, second, third)`. Only the exact physical win32k lane,
/// with its current Reply, may reserve, commit or release; DriverEntry's lane qualifies before any
/// GUI client exists.
pub(crate) unsafe fn service(
    ch: &spawn_hosts::PumpChannel,
    reply_cap: u64,
    badge: u64,
    mi: u64,
    [op, first, second, spare]: [u64; 4],
) -> (i32, u64, u64, u64) {
    let authenticated = provider_service_ingress::authenticate(
        ch, reply_cap, badge, mi, (win32k_subsystem::W32_SESSION_VIEW_LABEL << 12) | 4,
    ).and_then(|(route, dispatch)| {
        provider_service_ingress::physical_win32k_provider(ch, route, dispatch)
    });
    if let Err(status) = authenticated {
        trace_denial(b"authentication", op, first, status);
        return (status as i32, 0, 0, 0);
    }
    if spare != 0 {
        return (nt_process::STATUS_INVALID_PARAMETER as i32, 0, 0, 0);
    }
    let result = match op {
        wire::OP_RESERVE => band().reserve(first)
            .map(|view| (view.base, view.generation))
            .map_err(BandError::status),
        wire::OP_COMMIT => commit(ch, first, second),
        wire::OP_RELEASE => release(first, second).map(|()| (0, 0)),
        _ => Err(nt_process::STATUS_INVALID_PARAMETER),
    };
    match result {
        Ok((out1, out2)) => (0, out1, out2, 0),
        Err(status) => {
            trace_denial(b"request", first, second, status);
            (status as i32, 0, 0, 0)
        }
    }
}

/// `MEM_COMMIT` of Section pages: every page of the range is backed once, for every view.
unsafe fn commit(ch: &spawn_hosts::PumpChannel, address: u64, bytes: u64) -> Result<(u64, u64), u32> {
    let range = band().commit_range(address, bytes).map_err(BandError::status)?;
    while let Some(page) = band().next_uncommitted(range).map_err(BandError::status)? {
        commit_page(ch, range, page)?;
    }
    let count = COMMIT_TRACES.fetch_add(1, Ordering::Relaxed) + 1;
    if count <= TRACE_LIMIT || count.is_power_of_two() {
        print_str(b"[win32k-host] session view commit base=0x");
        print_hex_u64(range.base);
        print_str(b" bytes=0x");
        print_hex_u64(range.bytes);
        print_str(b" view=0x");
        print_hex_u64(range.reservation.base);
        print_str(b" reserve=0x");
        print_hex_u64(range.reservation.bytes);
        print_str(b" committed-pages=");
        print_u64(band().committed_pages());
        print_str(b"\n");
    }
    Ok((range.base, range.bytes))
}

unsafe fn commit_page(ch: &spawn_hosts::PumpChannel, range: CommitRange, page: u64) -> Result<(), u32> {
    let owner = ch.root_image_map_owner;
    if ch.pml4 == 0 || owner == 0 {
        return Err(nt_process::STATUS_INVALID_HANDLE);
    }
    band().begin_commit(range.reservation, page).map_err(BandError::status)?;
    let frame = match frame_acquisition::acquire(EXECUTIVE_WIN32K_SCRATCH_BASE) {
        Ok(frame) => frame,
        Err(status) => {
            // No native effect: the page returns to reserved.
            band().abort_commit(range.reservation, page).map_err(BandError::status)?;
            return Err(status);
        }
    };
    if !ensure_executive_paging(page) || page_map_r(frame, page, RW_NX, CAP_INIT_THREAD_VSPACE) != 0 {
        quarantine(b"root-map", page, frame);
        return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
    }
    let (provider, copy_error) = copy_cap_r(frame);
    if copy_error != 0 || provider == 0
        || !spawn_hosts::component_map_cap_bank_tag(owner, provider)
        || !win32k_glue::ensure_w32_client_paging(page, ch.pml4)
        || page_map_r(provider, page, RW_NX, ch.pml4) != 0
    {
        quarantine(b"provider-map", page, frame);
        return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
    }
    let committed = band().complete_commit(range.reservation, page, frame, provider)
        .map_err(BandError::status)?;
    push_to_clients(committed);
    Ok(())
}

unsafe fn quarantine(stage: &[u8], page: u64, frame: u64) {
    band().quarantine(page);
    trace_denial(stage, page, frame, nt_process::STATUS_INSUFFICIENT_RESOURCES);
}

/// Alias a newly committed page in every admitted client. A client that cannot take the alias
/// keeps it missing; its next refresh retries before it resumes.
unsafe fn push_to_clients(page: CommittedPage) {
    let mut missing = band().clients_missing(page.address);
    if missing == 0 {
        return;
    }
    let Ok(handler) = service_sec_image::registry_live_handler() else { return; };
    while missing != 0 {
        let pi = missing.trailing_zeros() as usize;
        missing &= missing - 1;
        if win32k_glue::map_session_view_page_into_client(handler, pi, page) {
            let _ = band().record_client_mapping(page.address, pi);
        }
    }
}

/// Admit client `pi` and alias every page committed before it connected. Returns the
/// server-to-client delta only when every committed page is aliased.
pub(crate) unsafe fn map_into_client(handler: &mut ExecNtHandler, pi: usize) -> Option<u64> {
    band().admit_client(pi).ok()?;
    let mut from = BASE;
    while let Some(page) = band().next_unmapped_for_client(pi, from) {
        if !win32k_glue::map_session_view_page_into_client(handler, pi, page) {
            return None;
        }
        band().record_client_mapping(page.address, pi).ok()?;
        from = page.address + nt_memory_manager::session_view_band::PAGE_SIZE;
    }
    Some(CLIENT_DELTA)
}

/// The client's address space is gone, and its aliases with it.
pub(crate) unsafe fn forget_client(pi: usize) {
    band().forget_client(pi);
}

/// Section deletion: retire every committed page, then free the view's addresses.
unsafe fn release(base: u64, generation: u64) -> Result<(), u32> {
    let view = band().reservation_at(base)
        .filter(|view| view.base == base && view.generation == generation)
        .ok_or(nt_process::STATUS_INVALID_HANDLE)?;
    band().begin_release(view).map_err(BandError::status)?;
    while let Some(page) = band().next_retirement(view).map_err(BandError::status)? {
        retire_page(view, page)?;
    }
    band().complete_release(view).map_err(BandError::status)
}

unsafe fn retire_page(view: ViewReservation, page: CommittedPage) -> Result<(), u32> {
    let mut clients = page.clients;
    while clients != 0 {
        let pi = clients.trailing_zeros() as usize;
        clients &= clients - 1;
        if !win32k_glue::release_session_view_page_from_client(pi, page) {
            quarantine(b"client-release", page.address, page.frame);
            return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
        }
        band().clear_client_mapping(page.address, pi).map_err(BandError::status)?;
    }
    let owner = WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Acquire) as u16;
    if frame_recycle::prepare(page.frame).is_err()
        || !spawn_hosts::component_map_cap_bank_release_page(owner, page.provider)
        || page_unmap_r(page.frame) != 0
        || cnode_revoke_r(page.frame) != 0
        || frame_recycle::publish(page.frame).is_err()
    {
        quarantine(b"page-release", page.address, page.frame);
        return Err(nt_process::STATUS_INSUFFICIENT_RESOURCES);
    }
    band().complete_page_retirement(view, page.address).map_err(BandError::status)
}

/// A provider fault in the band. A committed page is mapped before its commit returns, so any
/// fault here touched a reserved page that was never committed: NT raises an access violation,
/// and nothing may demand-fill it.
pub(crate) unsafe fn service_fault(address: u64, fault_status: u64) -> Option<bool> {
    if !contains(address) {
        return None;
    }
    let access = band().access(address);
    trace_denial(
        match access {
            PageAccess::Unreserved => b"fault-unreserved",
            PageAccess::Uncommitted => b"fault-uncommitted",
            PageAccess::Committed => b"fault-committed",
            PageAccess::Unavailable => b"fault-unavailable",
        },
        address,
        fault_status,
        0xC000_0005,
    );
    Some(false)
}

pub(crate) unsafe fn committed_pages() -> u64 {
    band().committed_pages()
}
