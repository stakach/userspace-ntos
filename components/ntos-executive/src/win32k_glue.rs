//! `win32k_glue` — the executive-side win32k client plumbing: RO-map win32k's
//! USER/session arenas into GUI clients, per-client cross-AS page attach (w32_*), the GDI/display
//! driver loaders, and the win32k syscall dispatch + backtrace.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;
use alloc::vec::Vec;
use core::sync::atomic::AtomicU8;

const WINDOWPROC_LPARAM_OFFSET: u64 = 0x28;
const WINDOWPROC_PAYLOAD_OFFSET: u32 = 0x40;
const WND_DWUSERDATA_OFFSET: u64 = 0x110;
const WM_GETMINMAXINFO: u32 = 0x0024;
const WM_NCCREATE: u32 = 0x0081;
const EXPLORER_ATL_START_WINDOW_PROC: u64 = crate::PE_LOAD_BASE + 0x13060;
const EXPLORER_ATL_WIN_MODULE_RVA: u64 = 0x446b8;
const ATL_CREATE_WND_LIST_OFFSET: u64 = 0x30;
const ATL_CREATE_WND_DATA_THIS_OFFSET: u64 = 0x00;
const ATL_CREATE_WND_DATA_TID_OFFSET: u64 = 0x08;
const ATL_CREATE_WND_DATA_NEXT_OFFSET: u64 = 0x10;

static USER_CALLBACK_DISPATCH_IDS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_RENDEZVOUS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_WINLOGON_API0: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_API0_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_FAILURES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_DEAD_FAILURES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_NCCREATE_FALSES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_NCCREATE_TRACES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_ATL_CREATE_DATA_TRACES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_TABLE_VALID: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_RETURNS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_RESUME_IP_REPAIRS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_RESUME_IP_REJECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTEXT_TRACES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_RESOURCE_STARTED: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_PUSHES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_UNWINDS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_OVERFLOWS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_NESTED_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_NESTED_SSN_1298: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_NESTED_SSN_126B: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_SEQUENCE_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
/// Bitmask of client `pi`s whose callback-running thread has DIED (crash-park / critical
/// termination). A dead client can never reach `NtCallbackReturn`, so every further callback win32k
/// requests for it must fail closed instead of being redirected into a thread that will never run.
static USER_CALLBACK_DEAD_CLIENTS: AtomicU64 = AtomicU64::new(0);
/// Callback continuation frames unwound because their client died mid-callback (the durable proof
/// the dead-client unwind ran; see [`unwind_dead_client_user_callbacks`]).
static USER_CALLBACK_DEAD_CLIENT_UNWINDS: AtomicU64 = AtomicU64::new(0);
/// Of those, the frames that had already been REDIRECTED into the client (a real reverse transition
/// that will never be answered by an `NtCallbackReturn`). A dead-client unwind is deliberately NOT a
/// `real-return` — it is a failure completion — so this counter is what keeps the redirect ledger
/// exact: `real-returns + dead-client-unwind-redirects == real-redirects` (every real redirect is
/// either returned by the client or torn down because the client died).
static USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CANCEL_CHAINED: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_WM_PAINT_RETURNS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_LAST_REAL_WM_PAINT_HWND: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_OWNER_MISMATCHES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_LOOKUP_FAILURES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_INVALID_REQUEST_TRACES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DISPATCHER: AtomicU64 = AtomicU64::new(0);
static WIN32K_MESSAGE_STAGE_LEASES: AtomicU64 = AtomicU64::new(0);
const _: () = assert!(
    nt_user_callback::CLIENT_TOKEN_USER_SID_MAX == win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX
);
// Win32k shared views carry thousands of mapped frame/page-table caps across GUI clients. Keep the
// root CSpace to process-global names and move these high-volume mapping caps into lazy global
// child-CNode segments; a small ownership index keeps per-process teardown exact.
const WIN32K_CLIENT_CAP_BANK_RADIX: u32 = 12;
const WIN32K_CLIENT_CAP_BANK_SEGMENT_SLOTS: u64 = 1u64 << WIN32K_CLIENT_CAP_BANK_RADIX;
const WIN32K_CLIENT_CAP_BANK_SEGMENTS: usize = 24;
const WIN32K_CLIENT_CAP_BANK_SLOTS: u64 =
    WIN32K_CLIENT_CAP_BANK_SEGMENT_SLOTS * WIN32K_CLIENT_CAP_BANK_SEGMENTS as u64;
const WIN32K_CLIENT_CAP_BANK_GUARD_BADGE: u64 = 64 - WIN32K_CLIENT_CAP_BANK_RADIX as u64;
static WIN32K_CLIENT_CAP_BANK_RAW: [AtomicU64; WIN32K_CLIENT_CAP_BANK_SEGMENTS] =
    [const { AtomicU64::new(0) }; WIN32K_CLIENT_CAP_BANK_SEGMENTS];
static WIN32K_CLIENT_CAP_BANK_CNODE: [AtomicU64; WIN32K_CLIENT_CAP_BANK_SEGMENTS] =
    [const { AtomicU64::new(0) }; WIN32K_CLIENT_CAP_BANK_SEGMENTS];
static WIN32K_CLIENT_CAP_BANK_NEXT: AtomicU64 = AtomicU64::new(0);
static mut WIN32K_CLIENT_CAP_BANK_LIVE_BY_PI: Vec<AtomicU64> = Vec::new();
static WIN32K_CLIENT_CAP_BANK_LIVE_TOTAL: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CAP_BANK_LIVE_HW: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CAP_BANK_TO_BANK: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CAP_BANK_RELEASES: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CAP_BANK_FAILS: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CAP_BANK_FREE_HEAD: AtomicU64 = AtomicU64::new(0);
static WIN32K_CLIENT_CAP_BANK_OWNER: [AtomicU8; WIN32K_CLIENT_CAP_BANK_SLOTS as usize] =
    [const { AtomicU8::new(0) }; WIN32K_CLIENT_CAP_BANK_SLOTS as usize];
static WIN32K_CLIENT_CAP_BANK_FREE_NEXT: [AtomicU64; WIN32K_CLIENT_CAP_BANK_SLOTS as usize] =
    [const { AtomicU64::new(0) }; WIN32K_CLIENT_CAP_BANK_SLOTS as usize];
static WIN32K_CLIENT_PROCESS_ROW_ALLOCATION_FAILURES: AtomicU64 = AtomicU64::new(0);
static mut WIN32K_USER_HEAP_CLIENT_MAPPED_FRAMES: Vec<AtomicU64> = Vec::new();
static mut WIN32K_POOL_CLIENT_MAPPED_FRAMES: Vec<AtomicU64> = Vec::new();
static mut GDI_USERVM_CLIENT_MAPPED_FRAMES: Vec<AtomicU64> = Vec::new();
static mut USER_CALLBACK_CONTINUATIONS: nt_user_callback::ContinuationStack =
    nt_user_callback::ContinuationStack::new();
static mut USER_CALLBACK_ACTIVE: nt_user_callback::ActiveCallbackStack =
    nt_user_callback::ActiveCallbackStack::new();

unsafe fn reset_win32k_atomic_process_rows(rows: &mut Vec<AtomicU64>, slots: usize) -> bool {
    rows.clear();
    if rows.try_reserve(slots).is_err() {
        WIN32K_CLIENT_PROCESS_ROW_ALLOCATION_FAILURES.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    while rows.len() < slots {
        rows.push(AtomicU64::new(0));
    }
    for row in rows.iter() {
        row.store(0, Ordering::Relaxed);
    }
    true
}

pub(crate) fn reset_win32k_client_process_rows(slots: usize) -> bool {
    unsafe {
        let cap_rows = reset_win32k_atomic_process_rows(
            &mut *core::ptr::addr_of_mut!(WIN32K_CLIENT_CAP_BANK_LIVE_BY_PI),
            slots,
        );
        let heap_rows = reset_win32k_atomic_process_rows(
            &mut *core::ptr::addr_of_mut!(WIN32K_USER_HEAP_CLIENT_MAPPED_FRAMES),
            slots,
        );
        let pool_rows = reset_win32k_atomic_process_rows(
            &mut *core::ptr::addr_of_mut!(WIN32K_POOL_CLIENT_MAPPED_FRAMES),
            slots,
        );
        let uservm_rows = reset_win32k_atomic_process_rows(
            &mut *core::ptr::addr_of_mut!(GDI_USERVM_CLIENT_MAPPED_FRAMES),
            slots,
        );
        cap_rows && heap_rows && pool_rows && uservm_rows
    }
}

unsafe fn win32k_client_cap_bank_live_row(pi: usize) -> Option<&'static AtomicU64> {
    (&*core::ptr::addr_of!(WIN32K_CLIENT_CAP_BANK_LIVE_BY_PI)).get(pi)
}

unsafe fn win32k_user_heap_mapped_row(pi: usize) -> Option<&'static AtomicU64> {
    (&*core::ptr::addr_of!(WIN32K_USER_HEAP_CLIENT_MAPPED_FRAMES)).get(pi)
}

unsafe fn win32k_pool_mapped_row(pi: usize) -> Option<&'static AtomicU64> {
    (&*core::ptr::addr_of!(WIN32K_POOL_CLIENT_MAPPED_FRAMES)).get(pi)
}

unsafe fn gdi_uservm_mapped_row(pi: usize) -> Option<&'static AtomicU64> {
    (&*core::ptr::addr_of!(GDI_USERVM_CLIENT_MAPPED_FRAMES)).get(pi)
}

unsafe fn win32k_user_heap_mapped_rows() -> &'static [AtomicU64] {
    (&*core::ptr::addr_of!(WIN32K_USER_HEAP_CLIENT_MAPPED_FRAMES)).as_slice()
}

unsafe fn win32k_pool_mapped_rows() -> &'static [AtomicU64] {
    (&*core::ptr::addr_of!(WIN32K_POOL_CLIENT_MAPPED_FRAMES)).as_slice()
}

unsafe fn gdi_uservm_mapped_rows() -> &'static [AtomicU64] {
    (&*core::ptr::addr_of!(GDI_USERVM_CLIENT_MAPPED_FRAMES)).as_slice()
}

pub(crate) fn win32k_client_process_row_stats(
) -> (usize, usize, usize, usize, usize, usize, usize, usize, u64) {
    unsafe {
        let cap_rows = &*core::ptr::addr_of!(WIN32K_CLIENT_CAP_BANK_LIVE_BY_PI);
        let heap_rows = &*core::ptr::addr_of!(WIN32K_USER_HEAP_CLIENT_MAPPED_FRAMES);
        let pool_rows = &*core::ptr::addr_of!(WIN32K_POOL_CLIENT_MAPPED_FRAMES);
        let uservm_rows = &*core::ptr::addr_of!(GDI_USERVM_CLIENT_MAPPED_FRAMES);
        (
            cap_rows.len(),
            cap_rows.capacity(),
            heap_rows.len(),
            heap_rows.capacity(),
            pool_rows.len(),
            pool_rows.capacity(),
            uservm_rows.len(),
            uservm_rows.capacity(),
            WIN32K_CLIENT_PROCESS_ROW_ALLOCATION_FAILURES.load(Ordering::Relaxed),
        )
    }
}

#[derive(Clone, Copy)]
struct UserCallbackClientRecord {
    dispatch_id: u64,
    client: crate::spawn_hosts::UserCallbackClient,
}

static mut USER_CALLBACK_CLIENT_REGISTRY: Option<Vec<UserCallbackClientRecord>> = None;

unsafe fn user_callback_client_registry_mut() -> &'static mut Vec<UserCallbackClientRecord> {
    let slot = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CLIENT_REGISTRY);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn user_callback_client_registry() -> Option<&'static Vec<UserCallbackClientRecord>> {
    (&*core::ptr::addr_of!(USER_CALLBACK_CLIENT_REGISTRY)).as_ref()
}

static mut USER_CALLBACK_SAS_SEQUENCE: nt_user_callback::SasWmCreateNestedSequence =
    nt_user_callback::SasWmCreateNestedSequence::new();
static USER_CALLBACK_SAS_SEQUENCE_ACTIVE: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID: AtomicU64 = AtomicU64::new(0);
static WIN32K_GDI_LOADER_PML4: AtomicU64 = AtomicU64::new(0);
static DXGTHK_DRIVER_LOADED: AtomicU64 = AtomicU64::new(0);
static WIN32K_STATIC_IMPORT_DEPENDENCIES: AtomicU64 = AtomicU64::new(0);
static WIN32K_STATIC_IMPORTS_LOADED: AtomicU64 = AtomicU64::new(0);
static WIN32K_STATIC_IMPORT_IAT_PATCHES: AtomicU64 = AtomicU64::new(0);
static WIN32K_STATIC_IMPORT_FAILURES: AtomicU64 = AtomicU64::new(0);

const WIN32K_STATIC_IMPORT_BASE_VA: u64 = 0x0000_0100_0870_0000;
const WIN32K_STATIC_IMPORT_LIMIT_VA: u64 = win32k_subsystem::FRAMEBUF_VA;
const WIN32K_STATIC_IMPORT_ALIGN: u64 = 0x0010_0000;

#[derive(Clone, Copy)]
pub(crate) struct CompletedWin32kDispatch {
    pub ssn: u64,
    pub args: [u64; 4],
    pub caller_sp: u64,
    pub status: u64,
    pub provider_output_len: u32,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(crate) const COMPLETED_ARG_SNAPSHOT_BYTES: usize =
    nt_user_callback::DISPATCH_ARG_SNAPSHOT_BYTES;
pub(crate) const COMPLETED_MSG_SNAPSHOT_BYTES: usize = 48;

impl CompletedWin32kDispatch {
    pub(crate) const fn new(ssn: u64, args: [u64; 4], caller_sp: u64, status: u64) -> Self {
        Self {
            ssn,
            args,
            caller_sp,
            status,
            provider_output_len: 0,
            arg_snapshot_len: 0,
            arg_snapshot: [0; COMPLETED_ARG_SNAPSHOT_BYTES],
        }
    }

    pub(crate) unsafe fn capture_arg_snapshot(&mut self, len: u64) -> bool {
        self.capture_arg_snapshot_from(win32k_subsystem::WIN32K_ARG_VADDR, len)
    }

    pub(crate) unsafe fn capture_arg_snapshot_from(&mut self, source: u64, len: u64) -> bool {
        if len == 0 || len as usize > COMPLETED_ARG_SNAPSHOT_BYTES {
            self.arg_snapshot_len = 0;
            return false;
        }
        core::ptr::copy_nonoverlapping(
            source as *const u8,
            self.arg_snapshot.as_mut_ptr(),
            len as usize,
        );
        self.arg_snapshot_len = len as u32;
        true
    }

    pub(crate) fn set_arg_snapshot(&mut self, snapshot: &[u8]) -> bool {
        if snapshot.is_empty() || snapshot.len() > COMPLETED_ARG_SNAPSHOT_BYTES {
            self.arg_snapshot_len = 0;
            return false;
        }
        self.arg_snapshot_len = snapshot.len() as u32;
        self.arg_snapshot[..snapshot.len()].copy_from_slice(snapshot);
        self.arg_snapshot[snapshot.len()..].fill(0);
        true
    }
}

pub(crate) fn acquire_win32k_message_stage() -> Option<nt_user_callback::DispatchOutputStage> {
    let mut leases = WIN32K_MESSAGE_STAGE_LEASES.load(Ordering::Acquire);
    loop {
        let free = (!leases).trailing_zeros() as u64;
        if free >= win32k_subsystem::WIN32K_MESSAGE_STAGE_SLOTS {
            return None;
        }
        let bit = 1u64 << free;
        match WIN32K_MESSAGE_STAGE_LEASES.compare_exchange_weak(
            leases,
            leases | bit,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => {
                let stage = nt_user_callback::DispatchOutputStage {
                    provider_pointer: win32k_subsystem::WIN32K_MESSAGE_STAGE_BASE
                        + free * win32k_subsystem::WIN32K_MESSAGE_STAGE_SLOT_BYTES,
                    capacity: nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES,
                };
                unsafe {
                    core::ptr::write_volatile(
                        (stage.provider_pointer
                            + win32k_subsystem::WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET)
                            as *mut u64,
                        u64::MAX,
                    );
                }
                return Some(stage);
            }
            Err(current) => leases = current,
        }
    }
}

pub(crate) fn release_win32k_message_stage(stage: nt_user_callback::DispatchOutputStage) -> bool {
    let Some(offset) = stage
        .provider_pointer
        .checked_sub(win32k_subsystem::WIN32K_MESSAGE_STAGE_BASE)
    else {
        return false;
    };
    if stage.capacity != nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES
        || offset % win32k_subsystem::WIN32K_MESSAGE_STAGE_SLOT_BYTES != 0
    {
        return false;
    }
    let index = offset / win32k_subsystem::WIN32K_MESSAGE_STAGE_SLOT_BYTES;
    if index >= win32k_subsystem::WIN32K_MESSAGE_STAGE_SLOTS {
        return false;
    }
    let bit = 1u64 << index;
    WIN32K_MESSAGE_STAGE_LEASES.fetch_and(!bit, Ordering::AcqRel) & bit != 0
}

pub(crate) unsafe fn published_win32k_output_length(
    stage: nt_user_callback::DispatchOutputStage,
) -> Option<u32> {
    let len = core::ptr::read_volatile(
        (stage.provider_pointer + win32k_subsystem::WIN32K_MESSAGE_STAGE_OUTPUT_LENGTH_OFFSET)
            as *const u64,
    );
    (len <= u64::from(stage.capacity)).then_some(len as u32)
}

unsafe fn release_dispatch_output_stage(context: nt_user_callback::DispatchContext) {
    if let Some(stage) = context.output_stage {
        let _ = release_win32k_message_stage(stage);
    }
}

#[derive(Clone, Copy)]
pub(crate) struct CompletedUserCallback {
    pub outer_dispatch: Option<CompletedWin32kDispatch>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum UserCallbackReturnReadiness {
    Missing,
    Ready,
    Deferred,
}

/// The win32k dispatch currently being serviced. The dispatch a SUSPENDED callback belongs to is
/// carried by that callback's own frame ([`nt_user_callback::ActiveCallbackFrame::dispatch_context`])
/// — it used to live in a glue-side array indexed in lockstep with the callback stack, which is only
/// sound while frames are removed strictly top-first (they are not: the stack interleaves the
/// chains of several client threads).
type UserCallbackDispatchContext = nt_user_callback::DispatchContext;

static mut USER_CALLBACK_CURRENT_DISPATCH: UserCallbackDispatchContext =
    UserCallbackDispatchContext::EMPTY;
static WIN32K_NEXT_DISPATCH_DEBUG_FLAGS: AtomicU64 = AtomicU64::new(0);
/// Times the bridge invariant was re-asserted, and times it had actually been CLOBBERED (a foreign
/// writer had replaced the bridged `PWND`) — the durable proof this is a live correctness fix.
static USER_CALLBACK_WINDOW_REASSERTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_WINDOW_REPAIRS: AtomicU64 = AtomicU64::new(0);
const SYSTEM_TOKEN_AUTHENTICATION_ID: u64 = nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_LOW
    as u64
    | ((nt_security::se_exports::SYSTEM_AUTHENTICATION_LUID_HIGH as u32 as u64) << 32);

fn local_system_sid_native() -> ([u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX], u32) {
    let mut sid = [0u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX];
    let len = nt_security::Sid::local_system()
        .write_native(&mut sid)
        .unwrap_or(0);
    (sid, len as u32)
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum UserCallbackDisposition {
    ReplyImmediately,
    SuspendComponent,
}

#[derive(Clone, Copy)]
pub(crate) struct Win32kClientContext {
    pub pi: u32,
    pub generation: u64,
    pub pid: u64,
    pub badge: u64,
    pub tid: u64,
    pub tcb: u64,
    pub eprocess: u64,
    pub ethread: u64,
    pub role: Option<HostedThreadRole>,
    pub process_role: Option<nt_exe_image::HostedProcessRole>,
    pub top_badge: u64,
    pub teb: u64,
    pub peb_mirror: u64,
    pub scratch_base: u64,
    pub token_authentication_id: u64,
    pub token_user_sid: [u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX],
    pub token_user_sid_len: u32,
}

impl Win32kClientContext {
    fn callback_client(self) -> crate::spawn_hosts::UserCallbackClient {
        crate::spawn_hosts::UserCallbackClient {
            pi: self.pi,
            generation: self.generation,
            pid: self.pid,
            badge: self.badge,
            tid: self.tid,
            tcb: self.tcb,
            teb: self.teb,
            eprocess: self.eprocess,
            ethread: self.ethread,
            role: self.role,
            process_role: self.process_role,
            top_badge: self.top_badge,
            peb_mirror: self.peb_mirror,
            scratch_base: self.scratch_base,
            token_authentication_id: self.token_authentication_id,
            token_user_sid: self.token_user_sid,
            token_user_sid_len: self.token_user_sid_len,
        }
    }
}

fn win32k_client_context_from_callback_client(
    client: crate::spawn_hosts::UserCallbackClient,
) -> Win32kClientContext {
    Win32kClientContext {
        pi: client.pi,
        generation: client.generation,
        pid: client.pid,
        badge: client.badge,
        tid: client.tid,
        tcb: client.tcb,
        eprocess: client.eprocess,
        ethread: client.ethread,
        role: client.role,
        process_role: client.process_role,
        top_badge: client.top_badge,
        teb: client.teb,
        peb_mirror: client.peb_mirror,
        scratch_base: client.scratch_base,
        token_authentication_id: client.token_authentication_id,
        token_user_sid: client.token_user_sid,
        token_user_sid_len: client.token_user_sid_len,
    }
}

fn user_callback_client_record_matches(
    record: &UserCallbackClientRecord,
    dispatch_id: u64,
    client_pi: u32,
    client_tid: u64,
    client_badge: u64,
) -> bool {
    record.dispatch_id == dispatch_id
        && record.client.pi == client_pi
        && record.client.tid == client_tid
        && record.client.badge == client_badge
}

fn user_callback_client_can_register(client: crate::spawn_hosts::UserCallbackClient) -> bool {
    client.pi != 0 && client.tid != 0 && client.badge != 0 && client.tcb > 1
}

unsafe fn register_user_callback_client_for_dispatch(
    dispatch_id: u64,
    client: crate::spawn_hosts::UserCallbackClient,
) -> bool {
    if dispatch_id == 0 || !user_callback_client_can_register(client) {
        return false;
    }
    let registry = user_callback_client_registry_mut();
    for record in registry.iter_mut() {
        if user_callback_client_record_matches(
            record,
            dispatch_id,
            client.pi,
            client.tid,
            client.badge,
        ) {
            record.client = client;
            return true;
        }
    }
    registry.push(UserCallbackClientRecord {
        dispatch_id,
        client,
    });
    true
}

unsafe fn unregister_user_callback_client_for_dispatch(
    dispatch_id: u64,
    client_pi: u32,
    client_tid: u64,
    client_badge: u64,
) {
    let registry = user_callback_client_registry_mut();
    let mut index = 0usize;
    while index < registry.len() {
        if user_callback_client_record_matches(
            &registry[index],
            dispatch_id,
            client_pi,
            client_tid,
            client_badge,
        ) {
            registry.swap_remove(index);
            return;
        }
        index += 1;
    }
}

unsafe fn user_callback_client_for_request(
    request: &nt_user_callback::CallbackHeader,
) -> Option<crate::spawn_hosts::UserCallbackClient> {
    let registry = user_callback_client_registry()?;
    registry.iter().find_map(|record| {
        user_callback_client_record_matches(
            record,
            request.dispatch_id,
            request.client_pi,
            request.client_tid,
            request.client_badge,
        )
        .then_some(record.client)
    })
}

unsafe fn clear_user_callback_client_registry() {
    if let Some(registry) = (*core::ptr::addr_of_mut!(USER_CALLBACK_CLIENT_REGISTRY)).as_mut() {
        registry.clear();
    }
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Win32kPublishedContext {
    pub pid: u64,
    pub tid: u64,
    pub eprocess: u64,
    pub ethread: u64,
    pub w32process: u64,
    pub w32thread: u64,
}

#[derive(Clone, Copy)]
struct SuspendedPublishedContext {
    pi: u32,
    pid: u64,
    tid: u64,
    published: Win32kPublishedContext,
}

static mut SUSPENDED_PUBLISHED_CONTEXTS: Option<Vec<SuspendedPublishedContext>> = None;
static USER_CALLBACK_SUSPENDED_CONTEXT_CAPTURES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_SUSPENDED_CONTEXT_DROPS: AtomicU64 = AtomicU64::new(0);

unsafe fn suspended_published_contexts_mut() -> &'static mut Vec<SuspendedPublishedContext> {
    let slot = &mut *core::ptr::addr_of_mut!(SUSPENDED_PUBLISHED_CONTEXTS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

fn published_context_has_data(context: Win32kPublishedContext) -> bool {
    context.pid != 0
        || context.tid != 0
        || context.eprocess != 0
        || context.ethread != 0
        || context.w32process != 0
        || context.w32thread != 0
}

fn published_context_matches_client(
    context: Win32kPublishedContext,
    client: crate::spawn_hosts::UserCallbackClient,
) -> bool {
    published_context_matches_ids(context, client.pid, client.tid)
}

fn published_context_matches_ids(
    context: Win32kPublishedContext,
    expected_pid: u64,
    expected_tid: u64,
) -> bool {
    (expected_pid == 0 || (context.pid != 0 && context.pid == expected_pid))
        && (expected_tid == 0 || (context.tid != 0 && context.tid == expected_tid))
}

unsafe fn capture_suspended_published_win32k_context(
    client: crate::spawn_hosts::UserCallbackClient,
) {
    let published = published_win32k_context();
    if !published_context_has_data(published) {
        return;
    }
    if !published_context_matches_client(published, client) {
        let n = USER_CALLBACK_SUSPENDED_CONTEXT_DROPS.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[win32k-context] suspended publication mismatch client-pid=");
            print_u64(client.pid);
            print_str(b" actual-pid=");
            print_u64(published.pid);
            print_str(b" client-tid=");
            print_u64(client.tid);
            print_str(b" actual-tid=");
            print_u64(published.tid);
            print_str(b" -> retained for owner\n");
        }
        return;
    }
    clear_published_win32k_context();

    let contexts = suspended_published_contexts_mut();
    let mut i = 0usize;
    while i < contexts.len() {
        let slot = contexts[i];
        if slot.pi == client.pi
            && slot.pid == client.pid
            && (slot.tid == client.tid || slot.tid == 0 || client.tid == 0)
        {
            contexts[i] = SuspendedPublishedContext {
                pi: client.pi,
                pid: client.pid,
                tid: client.tid,
                published,
            };
            USER_CALLBACK_SUSPENDED_CONTEXT_CAPTURES.fetch_add(1, Ordering::Relaxed);
            return;
        }
        i += 1;
    }

    contexts.push(SuspendedPublishedContext {
        pi: client.pi,
        pid: client.pid,
        tid: client.tid,
        published,
    });
    USER_CALLBACK_SUSPENDED_CONTEXT_CAPTURES.fetch_add(1, Ordering::Relaxed);
}

pub(crate) unsafe fn take_suspended_published_win32k_context(
    pi: u32,
    pid: u64,
    tid: u64,
) -> Option<Win32kPublishedContext> {
    let contexts = suspended_published_contexts_mut();
    let mut i = 0usize;
    while i < contexts.len() {
        let slot = contexts[i];
        if slot.pi == pi
            && (pid == 0 || slot.pid == pid)
            && (tid == 0 || slot.tid == tid)
            && (pid == 0 || slot.published.pid == 0 || slot.published.pid == pid)
            && (tid == 0 || slot.published.tid == 0 || slot.published.tid == tid)
        {
            let published = slot.published;
            contexts.remove(i);
            return Some(published);
        }
        i += 1;
    }
    None
}

pub(crate) unsafe fn published_win32k_context() -> Win32kPublishedContext {
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    Win32kPublishedContext {
        pid: core::ptr::read_volatile((sh + win32k_subsystem::SH_CTX_PROCESS_ID) as *const u64),
        tid: core::ptr::read_volatile((sh + win32k_subsystem::SH_CTX_THREAD_ID) as *const u64),
        eprocess: core::ptr::read_volatile((sh + win32k_subsystem::SH_CTX_EPROCESS) as *const u64),
        ethread: core::ptr::read_volatile((sh + win32k_subsystem::SH_CTX_ETHREAD) as *const u64),
        w32process: core::ptr::read_volatile(
            (sh + win32k_subsystem::SH_CTX_W32PROCESS) as *const u64,
        ),
        w32thread: core::ptr::read_volatile(
            (sh + win32k_subsystem::SH_CTX_W32THREAD) as *const u64,
        ),
    }
}

pub(crate) unsafe fn clear_published_win32k_context() {
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    for offset in [
        win32k_subsystem::SH_CTX_PROCESS_ID,
        win32k_subsystem::SH_CTX_THREAD_ID,
        win32k_subsystem::SH_CTX_EPROCESS,
        win32k_subsystem::SH_CTX_ETHREAD,
        win32k_subsystem::SH_CTX_W32PROCESS,
        win32k_subsystem::SH_CTX_W32THREAD,
    ] {
        core::ptr::write_volatile((sh + offset) as *mut u64, 0);
    }
}

pub(crate) unsafe fn take_matching_published_win32k_context(
    expected_pid: u64,
    expected_tid: u64,
) -> Option<Win32kPublishedContext> {
    let context = published_win32k_context();
    if !published_context_has_data(context) {
        return None;
    }
    if !published_context_matches_ids(context, expected_pid, expected_tid) {
        return None;
    }
    clear_published_win32k_context();
    Some(context)
}

const CALLBACK_ROLE_NONE: u32 = 0;
const CALLBACK_ROLE_MAIN: u32 = 1;
const CALLBACK_ROLE_CSR_API: u32 = 3;
const CALLBACK_ROLE_CSR_SB_API: u32 = 4;
const CALLBACK_ROLE_WINLOGON_LISTENER: u32 = 5;
const CALLBACK_ROLE_SERVICES_LISTENER: u32 = 6;
const CALLBACK_ROLE_LSASS_LISTENER: u32 = 8;
const CALLBACK_ROLE_LSASS_LISTENER2: u32 = 9;
const CALLBACK_ROLE_LSASS_LISTENER3: u32 = 10;
const CALLBACK_ROLE_TP_WORKER_BASE: u32 = 0x1000;
const CALLBACK_ROLE_WINLOGON_WORKER_BASE: u32 = 0x2000;
const CALLBACK_ROLE_SCM_WORKER_SLOT_BASE: u32 = 0x3000;
const CALLBACK_ROLE_LSA_WORKER_SLOT_BASE: u32 = 0x4000;
const CALLBACK_ROLE_SLOT_MASK: u32 = 0x0fff;

fn callback_runtime_role_code(role: Option<HostedThreadRole>) -> u32 {
    match role {
        Some(HostedThreadRole::Main) => CALLBACK_ROLE_MAIN,
        Some(HostedThreadRole::TpWorker { slot }) if slot <= CALLBACK_ROLE_SLOT_MASK as usize => {
            CALLBACK_ROLE_TP_WORKER_BASE | slot as u32
        }
        Some(HostedThreadRole::ScmWorkerSlot { slot })
            if slot <= CALLBACK_ROLE_SLOT_MASK as usize =>
        {
            CALLBACK_ROLE_SCM_WORKER_SLOT_BASE | slot as u32
        }
        Some(HostedThreadRole::LsaWorkerSlot { slot })
            if slot <= CALLBACK_ROLE_SLOT_MASK as usize =>
        {
            CALLBACK_ROLE_LSA_WORKER_SLOT_BASE | slot as u32
        }
        Some(HostedThreadRole::CsrApi) => CALLBACK_ROLE_CSR_API,
        Some(HostedThreadRole::CsrSbApi) => CALLBACK_ROLE_CSR_SB_API,
        Some(HostedThreadRole::WinlogonListener) => CALLBACK_ROLE_WINLOGON_LISTENER,
        Some(HostedThreadRole::WinlogonWorker { slot })
            if slot <= CALLBACK_ROLE_SLOT_MASK as usize =>
        {
            CALLBACK_ROLE_WINLOGON_WORKER_BASE | slot as u32
        }
        Some(HostedThreadRole::ServicesListener) => CALLBACK_ROLE_SERVICES_LISTENER,
        Some(HostedThreadRole::LsassListener) => CALLBACK_ROLE_LSASS_LISTENER,
        Some(HostedThreadRole::LsassListener2) => CALLBACK_ROLE_LSASS_LISTENER2,
        Some(HostedThreadRole::LsassListener3) => CALLBACK_ROLE_LSASS_LISTENER3,
        _ => CALLBACK_ROLE_NONE,
    }
}

fn callback_runtime_role_from_code(code: u32) -> Option<HostedThreadRole> {
    match code {
        CALLBACK_ROLE_MAIN => Some(HostedThreadRole::Main),
        CALLBACK_ROLE_CSR_API => Some(HostedThreadRole::CsrApi),
        CALLBACK_ROLE_CSR_SB_API => Some(HostedThreadRole::CsrSbApi),
        CALLBACK_ROLE_WINLOGON_LISTENER => Some(HostedThreadRole::WinlogonListener),
        CALLBACK_ROLE_SERVICES_LISTENER => Some(HostedThreadRole::ServicesListener),
        CALLBACK_ROLE_LSASS_LISTENER => Some(HostedThreadRole::LsassListener),
        CALLBACK_ROLE_LSASS_LISTENER2 => Some(HostedThreadRole::LsassListener2),
        CALLBACK_ROLE_LSASS_LISTENER3 => Some(HostedThreadRole::LsassListener3),
        code if code & !CALLBACK_ROLE_SLOT_MASK == CALLBACK_ROLE_TP_WORKER_BASE => {
            Some(HostedThreadRole::TpWorker {
                slot: (code & CALLBACK_ROLE_SLOT_MASK) as usize,
            })
        }
        code if code & !CALLBACK_ROLE_SLOT_MASK == CALLBACK_ROLE_SCM_WORKER_SLOT_BASE => {
            Some(HostedThreadRole::ScmWorkerSlot {
                slot: (code & CALLBACK_ROLE_SLOT_MASK) as usize,
            })
        }
        code if code & !CALLBACK_ROLE_SLOT_MASK == CALLBACK_ROLE_LSA_WORKER_SLOT_BASE => {
            Some(HostedThreadRole::LsaWorkerSlot {
                slot: (code & CALLBACK_ROLE_SLOT_MASK) as usize,
            })
        }
        code if code & !CALLBACK_ROLE_SLOT_MASK == CALLBACK_ROLE_WINLOGON_WORKER_BASE => {
            Some(HostedThreadRole::WinlogonWorker {
                slot: (code & CALLBACK_ROLE_SLOT_MASK) as usize,
            })
        }
        _ => None,
    }
}

fn callback_process_role_code(role: Option<nt_exe_image::HostedProcessRole>) -> u32 {
    match role {
        Some(nt_exe_image::HostedProcessRole::NativeSession) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_NATIVE_SESSION as u32
        }
        Some(nt_exe_image::HostedProcessRole::Win32Subsystem) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_WIN32_SUBSYSTEM as u32
        }
        Some(nt_exe_image::HostedProcessRole::InteractiveLogon) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_INTERACTIVE_LOGON as u32
        }
        Some(nt_exe_image::HostedProcessRole::ServiceControlManager) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_SERVICE_CONTROL_MANAGER as u32
        }
        Some(nt_exe_image::HostedProcessRole::LocalSecurityAuthority) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_LOCAL_SECURITY_AUTHORITY as u32
        }
        Some(nt_exe_image::HostedProcessRole::NonInteractiveService) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE as u32
        }
        Some(nt_exe_image::HostedProcessRole::InteractiveShellBootstrap) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL_BOOTSTRAP as u32
        }
        Some(nt_exe_image::HostedProcessRole::InteractiveShell) => {
            win32k_subsystem::HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL as u32
        }
        None => win32k_subsystem::HOSTED_PROCESS_ROLE_NONE as u32,
    }
}

fn callback_process_role_from_code(code: u32) -> Option<nt_exe_image::HostedProcessRole> {
    match code as u64 {
        win32k_subsystem::HOSTED_PROCESS_ROLE_NATIVE_SESSION => {
            Some(nt_exe_image::HostedProcessRole::NativeSession)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_WIN32_SUBSYSTEM => {
            Some(nt_exe_image::HostedProcessRole::Win32Subsystem)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_INTERACTIVE_LOGON => {
            Some(nt_exe_image::HostedProcessRole::InteractiveLogon)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_SERVICE_CONTROL_MANAGER => {
            Some(nt_exe_image::HostedProcessRole::ServiceControlManager)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_LOCAL_SECURITY_AUTHORITY => {
            Some(nt_exe_image::HostedProcessRole::LocalSecurityAuthority)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_NONINTERACTIVE_SERVICE => {
            Some(nt_exe_image::HostedProcessRole::NonInteractiveService)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL_BOOTSTRAP => {
            Some(nt_exe_image::HostedProcessRole::InteractiveShellBootstrap)
        }
        win32k_subsystem::HOSTED_PROCESS_ROLE_INTERACTIVE_SHELL => {
            Some(nt_exe_image::HostedProcessRole::InteractiveShell)
        }
        _ => None,
    }
}

pub(crate) fn user_callback_proofs() -> (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64) {
    (
        USER_CALLBACK_RENDEZVOUS.load(Ordering::Relaxed),
        USER_CALLBACK_WINLOGON_API0.load(Ordering::Relaxed),
        USER_CALLBACK_TABLE_VALID.load(Ordering::Relaxed),
        USER_CALLBACK_REAL_REDIRECTS.load(Ordering::Relaxed),
        USER_CALLBACK_REAL_RETURNS.load(Ordering::Relaxed),
        USER_CALLBACK_CONTINUATION_PUSHES.load(Ordering::Relaxed),
        USER_CALLBACK_CONTINUATION_UNWINDS.load(Ordering::Relaxed),
        USER_CALLBACK_NESTED_DISPATCHES.load(Ordering::Relaxed),
        USER_CALLBACK_NESTED_SSN_1298.load(Ordering::Relaxed),
        USER_CALLBACK_NESTED_SSN_126B.load(Ordering::Relaxed),
        USER_CALLBACK_SEQUENCE_COMPLETIONS.load(Ordering::Relaxed),
    )
}

pub(crate) fn explorer_user_callback_proofs() -> (u64, u64, u64, u64) {
    (
        USER_CALLBACK_EXPLORER_API0_REDIRECTS.load(Ordering::Relaxed),
        USER_CALLBACK_EXPLORER_FAILURES.load(Ordering::Relaxed),
        USER_CALLBACK_EXPLORER_DEAD_FAILURES.load(Ordering::Relaxed),
        USER_CALLBACK_EXPLORER_NCCREATE_FALSES.load(Ordering::Relaxed),
    )
}

/// Frames unwound by [`unwind_dead_client_user_callbacks`] over the whole boot.
pub(crate) fn dead_client_callback_unwinds() -> u64 {
    USER_CALLBACK_DEAD_CLIENT_UNWINDS.load(Ordering::Relaxed)
}

/// Of the unwound frames, those that had already been REDIRECTED — i.e. real redirects that will
/// never produce a `real-return`. See [`USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS`].
pub(crate) fn dead_client_callback_unwind_redirects() -> u64 {
    USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS.load(Ordering::Relaxed)
}

pub(crate) fn user_callback_continuation_overflows() -> u64 {
    USER_CALLBACK_CONTINUATION_OVERFLOWS.load(Ordering::Relaxed)
}

/// `(active callback depth, continuation-stack depth)`. Both ZERO = win32k holds no suspended
/// callback/dispatch continuation, i.e. it is idle in its normal dispatch receive loop.
pub(crate) fn user_callback_stack_depths() -> (usize, usize) {
    unsafe {
        (
            (*core::ptr::addr_of!(USER_CALLBACK_ACTIVE)).len(),
            (*core::ptr::addr_of!(USER_CALLBACK_CONTINUATIONS)).len(),
        )
    }
}

pub(crate) unsafe fn active_user_callback_global_top_identity() -> Option<(u32, u64, u64)> {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let request = active.top()?.request();
    Some((request.client_pi, request.client_badge, request.client_tid))
}

pub(crate) unsafe fn user_callback_return_readiness(
    client_pi: u32,
    client_badge: u64,
    client_tid: u64,
) -> UserCallbackReturnReadiness {
    let identity = nt_user_callback::ClientThreadIdentity::new(client_pi, client_tid, client_badge);
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let Some(frame) = active.top_for(&identity) else {
        return UserCallbackReturnReadiness::Missing;
    };
    if !frame.is_redirected() {
        return UserCallbackReturnReadiness::Missing;
    }
    let correlation = nt_user_callback::CallbackCorrelation::from_request(frame.request());
    match active.is_global_top(correlation) {
        Ok(true) => UserCallbackReturnReadiness::Ready,
        Ok(false) => UserCallbackReturnReadiness::Deferred,
        Err(_) => UserCallbackReturnReadiness::Missing,
    }
}

/// `(re-asserts, repairs)` of the callback-window bridge invariant — see
/// [`reassert_top_client_callback_window`]. `repairs > 0` means a foreign writer really had clobbered
/// the client's `CLIENTINFO.CallbackWnd`.
pub(crate) fn client_callback_window_bridge_proofs() -> (u64, u64) {
    (
        USER_CALLBACK_WINDOW_REASSERTS.load(Ordering::Relaxed),
        USER_CALLBACK_WINDOW_REPAIRS.load(Ordering::Relaxed),
    )
}

/// Does this client currently own ANY outstanding user-mode callback frame?
///
/// A thread that faults OUTSIDE a callback strands nothing: win32k is not suspended in
/// `KeUserModeCallback` on its behalf, so there is nothing to unwind — and latching the whole `pi`
/// as a dead callback client would be actively wrong, because a hosted process' OTHER threads are
/// still live callback clients. Park sites use this to tell the two cases apart.
pub(crate) unsafe fn client_has_active_callback_frames(client_pi: u32) -> bool {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    (0..active.len()).any(|index| {
        active
            .frame(index)
            .is_some_and(|frame| frame.request().client_pi == client_pi)
    })
}

/// Has this client's callback thread died? (Latched by [`unwind_dead_client_user_callbacks`].)
fn user_callback_client_dead(client_pi: u32) -> bool {
    client_pi < 64 && USER_CALLBACK_DEAD_CLIENTS.load(Ordering::Relaxed) & (1u64 << client_pi) != 0
}

/// Is this incoming win32k dispatch NESTED inside a user-mode callback of the SAME client thread?
///
/// ★ THE NESTING QUESTION IS PER-CLIENT-THREAD. In NT a `KeUserModeCallback` runs on the very
/// thread that entered win32k, so only a syscall from THAT thread is nested inside it. A hosted
/// process is multi-threaded (winlogon runs its main thread plus real RPC/logon workers), and a
/// win32k call arriving from a DIFFERENT thread while another thread sits redirected in a callback
/// is a *concurrent root* dispatch, not a nested one. This used to compare the incoming identity
/// against the callback stack's GLOBAL top and reject a mismatch as
/// `ContinuationError::Client` — measured on the post-logon path as winlogon's main thread
/// (`badge 4/tid 6`) issuing `NtGdiGetTextMetricsW` while worker `badge 13/tid 21` was redirected in
/// `WM_WINDOWPOSCHANGING`, walled `0xC000000D`, and killed winlogon as a dead callback client. The
/// lookup is now scoped to the incoming thread's own chain: "no callback frame for THIS thread"
/// means root dispatch, not error. Cross-thread misrouting is still impossible — the parent is
/// selected BY identity, so a nested dispatch can only ever be pushed onto its own thread's chain.
pub(crate) unsafe fn begin_nested_user_callback_dispatch(
    client: Win32kClientContext,
    dispatch_id: u64,
    ssn: u64,
) -> Result<bool, nt_user_callback::ContinuationError> {
    let identity = nt_user_callback::ClientThreadIdentity::new(client.pi, client.tid, client.badge);
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let Some(parent) = active.top_for(&identity) else {
        return Ok(false);
    };
    if !parent.is_redirected() {
        return Err(nt_user_callback::ContinuationError::State);
    }
    let stack = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS);
    stack.push_dispatch(identity, dispatch_id)?;
    if USER_CALLBACK_SAS_SEQUENCE_ACTIVE.load(Ordering::Relaxed) != 0 {
        let mut sequence = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_SAS_SEQUENCE));
        if sequence.accept(ssn).is_ok() {
            core::ptr::write(
                core::ptr::addr_of_mut!(USER_CALLBACK_SAS_SEQUENCE),
                sequence,
            );
        }
    }
    USER_CALLBACK_CONTINUATION_PUSHES.fetch_add(1, Ordering::Relaxed);
    USER_CALLBACK_NESTED_DISPATCHES.fetch_add(1, Ordering::Relaxed);
    USER_CALLBACK_NESTED_SSN_1298.fetch_add(
        (ssn == nt_user_callback::NTUSER_SET_WINDOW_LONG_PTR_SSN) as u64,
        Ordering::Relaxed,
    );
    USER_CALLBACK_NESTED_SSN_126B.fetch_add(
        (ssn == nt_user_callback::NTUSER_REGISTER_HOT_KEY_SSN) as u64,
        Ordering::Relaxed,
    );
    print_str(b"[user-callback] nested win32k dispatch ssn=0x");
    print_hex(ssn as u32);
    print_str(b" pushed above api0 callback\n");
    Ok(true)
}

pub(crate) unsafe fn complete_nested_user_callback_dispatch(
    client: Win32kClientContext,
    dispatch_id: u64,
) -> bool {
    let identity = nt_user_callback::ClientThreadIdentity::new(client.pi, client.tid, client.badge);
    let stack = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS);
    if stack.complete_dispatch(identity, dispatch_id).is_err() {
        return false;
    }
    USER_CALLBACK_CONTINUATION_UNWINDS.fetch_add(1, Ordering::Relaxed);
    // The client is about to resume inside its callback thunk with this syscall's result — win32k may
    // have rewritten CLIENTINFO.CallbackWnd during the nested dispatch, so restate the bridge.
    reassert_top_client_callback_window(&identity);
    true
}

unsafe fn write_callback_failure_reply(request: nt_user_callback::CallbackHeader, status: i32) {
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let mut reply = request;
    reply.state = nt_user_callback::CallbackState::Reply as u32;
    reply.output_length = 0;
    reply.status = status;
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).header), reply);
}

unsafe fn begin_controlled_continuation(
    request: nt_user_callback::CallbackHeader,
    callback_client: crate::spawn_hosts::UserCallbackClient,
) -> bool {
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
    let client = nt_user_callback::ClientThreadIdentity::new(
        request.client_pi,
        request.client_tid,
        request.client_badge,
    );
    let stack = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS);
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    if active.len() >= nt_user_callback::MAX_ACTIVE_CALLBACK_DEPTH {
        return false;
    }
    if callback_client.tcb <= 1 {
        return false;
    }
    let mut token_user_sid = [0u8; nt_user_callback::CLIENT_TOKEN_USER_SID_MAX];
    token_user_sid.copy_from_slice(&callback_client.token_user_sid);
    let active_client = nt_user_callback::ActiveCallbackClient::new(
        callback_client.tcb,
        callback_runtime_role_code(callback_client.role),
        callback_process_role_code(callback_client.process_role),
        callback_client.top_badge,
    )
    .with_process_identity(
        callback_client.pid,
        callback_client.teb,
        callback_client.peb_mirror,
        callback_client.scratch_base,
        callback_client.eprocess,
        callback_client.ethread,
    )
    .with_token(
        callback_client.token_authentication_id,
        token_user_sid,
        callback_client.token_user_sid_len,
    );
    // "Root" is per client thread: this thread holds no continuation yet, so the win32k dispatch
    // this callback was raised inside has to be recorded first. Another thread's chain being live
    // is irrelevant.
    let root = stack.is_empty_for(&client);
    if (root && stack.push_dispatch(client, request.dispatch_id).is_err())
        || stack.push_callback(correlation).is_err()
        || active
            .push_with_active_client_metadata(request, active_client)
            .is_err()
    {
        abort_controlled_user_callbacks();
        return false;
    }
    USER_CALLBACK_CONTINUATION_PUSHES.fetch_add(if root { 2 } else { 1 }, Ordering::Relaxed);
    true
}

unsafe fn unwind_controlled_callback(request: nt_user_callback::CallbackHeader) -> bool {
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
    let stack = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS);
    if stack.return_callback(correlation).is_err() {
        return false;
    }
    USER_CALLBACK_CONTINUATION_UNWINDS.fetch_add(1, Ordering::Relaxed);
    true
}

unsafe fn unwind_controlled_dispatch(request: nt_user_callback::CallbackHeader) -> bool {
    let client = nt_user_callback::ClientThreadIdentity::new(
        request.client_pi,
        request.client_tid,
        request.client_badge,
    );
    let stack = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS);
    if stack
        .complete_dispatch(client, request.dispatch_id)
        .is_err()
    {
        return false;
    }
    USER_CALLBACK_CONTINUATION_UNWINDS.fetch_add(1, Ordering::Relaxed);
    true
}

pub(crate) fn take_user_callback_pump_suspended() -> bool {
    USER_CALLBACK_LAST_PUMP_SUSPENDED.swap(0, Ordering::AcqRel) != 0
}

pub(crate) fn real_wm_paint_callback_returns() -> u64 {
    USER_CALLBACK_REAL_WM_PAINT_RETURNS.load(Ordering::Relaxed)
}

pub(crate) fn real_resource_callback_started() -> bool {
    USER_CALLBACK_REAL_RESOURCE_STARTED.load(Ordering::Relaxed) != 0
}

pub(crate) fn last_real_wm_paint_hwnd() -> u64 {
    USER_CALLBACK_LAST_REAL_WM_PAINT_HWND.load(Ordering::Relaxed)
}

/// Attach the win32k dispatch this callback suspended to the callback's OWN frame, so it travels
/// with the frame however the interleaved stack is later unwound.
unsafe fn remember_active_dispatch(request: &nt_user_callback::CallbackHeader) -> bool {
    let context = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    (&mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE))
        .record_dispatch_context(
            nt_user_callback::CallbackCorrelation::from_request(request),
            context,
        )
        .is_ok()
}

fn staged_userconnect_u64(offset: u64) -> u64 {
    unsafe {
        core::ptr::read_unaligned((win32k_subsystem::WIN32K_ARG_VADDR + offset) as *const u64)
    }
}

fn staged_userconnect_has_sharedinfo(len: u64) -> bool {
    len >= win32k_subsystem::UC_SI_DELTA + 8
        && staged_userconnect_u64(win32k_subsystem::UC_SI_PSI) != 0
        && staged_userconnect_u64(win32k_subsystem::UC_SI_AHELIST) != 0
}

/// If the dispatch currently parked behind this callback has materialized arguments in the shared
/// dispatch page, bind them to the callback frame before a nested win32k dispatch can reuse that
/// page.
unsafe fn remember_active_dispatch_arg_snapshot(
    request: &nt_user_callback::CallbackHeader,
) -> bool {
    let context = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    let len = match context.ssn {
        win32k_subsystem::SSN_NT_USER_INITIALIZE => context.args[2],
        nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN => {
            u64::from(nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES)
        }
        _ => return true,
    }
    .min(win32k_subsystem::WIN32K_ARG_GENERAL_BYTES);
    if len == 0 || len as usize > nt_user_callback::DISPATCH_ARG_SNAPSHOT_BYTES {
        return false;
    }
    if context.ssn == win32k_subsystem::SSN_NT_USER_INITIALIZE
        && !staged_userconnect_has_sharedinfo(len)
    {
        return true;
    }
    let snapshot = core::slice::from_raw_parts(
        win32k_subsystem::WIN32K_ARG_VADDR as *const u8,
        len as usize,
    );
    (&mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE))
        .record_arg_snapshot(
            nt_user_callback::CallbackCorrelation::from_request(request),
            snapshot,
        )
        .is_ok()
}

fn winlogon_callback_teb_alias(client: crate::spawn_hosts::UserCallbackClient) -> Option<u64> {
    let winlogon_pi = callback_client_owner_pi(client)?;
    if !callback_client_is_winlogon(client) || client.tid == 0 {
        return None;
    }
    let alias = match client.role {
        Some(HostedThreadRole::Main) => WINLOGON_MAIN_TEB_MIRROR_VA,
        Some(HostedThreadRole::WinlogonListener) => {
            WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000
        }
        Some(HostedThreadRole::WinlogonWorker { slot: 1 }) => {
            WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000
        }
        Some(HostedThreadRole::WinlogonWorker { slot: 2 }) => {
            WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000
        }
        Some(HostedThreadRole::TpWorker { slot }) => tp_worker_teb_mirror_va(winlogon_pi, slot),
        _ => return None,
    };
    Some(alias)
}

fn main_gui_callback_teb_alias(client: crate::spawn_hosts::UserCallbackClient) -> Option<u64> {
    let pi = callback_client_owner_pi(client)?;
    if client.tid == 0
        || !client
            .process_role
            .is_some_and(nt_exe_image::HostedProcessRole::uses_win32_client_gdi)
    {
        return None;
    }
    match client.role {
        Some(HostedThreadRole::Main)
            if client.top_badge != 0 && client.badge == client.top_badge =>
        {
            let alias = crate::env_scratch_base_for_pi(pi);
            (alias != 0).then_some(alias)
        }
        Some(HostedThreadRole::TpWorker { slot })
            if tp_worker_identity_from_badge(client.badge) == Some((pi, slot)) =>
        {
            Some(tp_worker_teb_mirror_va(pi, slot))
        }
        _ => None,
    }
}

fn callback_client_owner_pi(client: crate::spawn_hosts::UserCallbackClient) -> Option<usize> {
    let pi = client.pi as usize;
    if pi >= MAX_PI {
        return None;
    }
    if let Some((pi, _)) = tp_worker_identity_from_badge(client.badge) {
        return (pi == client.pi as usize).then_some(pi);
    }
    if client.top_badge != 0 && client.badge == client.top_badge {
        return Some(pi);
    }
    match client.role {
        Some(
            HostedThreadRole::Main
            | HostedThreadRole::CsrApi
            | HostedThreadRole::CsrSbApi
            | HostedThreadRole::WinlogonListener
            | HostedThreadRole::WinlogonWorker { .. }
            | HostedThreadRole::ServicesListener
            | HostedThreadRole::ScmWorkerSlot { .. }
            | HostedThreadRole::LsassListener
            | HostedThreadRole::LsassListener2
            | HostedThreadRole::LsassListener3
            | HostedThreadRole::LsaWorkerSlot { .. },
        ) => Some(pi),
        _ => None,
    }
}

fn callback_client_has_process_role(
    client: crate::spawn_hosts::UserCallbackClient,
    role: nt_exe_image::HostedProcessRole,
) -> bool {
    client.process_role == Some(role)
}

fn callback_client_is_winlogon(client: crate::spawn_hosts::UserCallbackClient) -> bool {
    callback_client_has_process_role(client, nt_exe_image::HostedProcessRole::InteractiveLogon)
}

fn callback_client_is_explorer(client: crate::spawn_hosts::UserCallbackClient) -> bool {
    callback_client_has_process_role(client, nt_exe_image::HostedProcessRole::InteractiveShell)
}

fn callback_context_trace_enabled(client: Win32kClientContext) -> bool {
    matches!(
        client.process_role,
        Some(
            nt_exe_image::HostedProcessRole::InteractiveLogon
                | nt_exe_image::HostedProcessRole::InteractiveShell
        )
    )
}

unsafe fn trace_user_callback_context(
    phase: &[u8],
    client: Win32kClientContext,
    api_index: u32,
    redirect_context: &[u64; 20],
    completion_context: &[u64; 20],
    output_context: &[u64; 20],
    resume_ip: u64,
    callout_rsp: u64,
) {
    if !callback_context_trace_enabled(client) {
        return;
    }
    let n = USER_CALLBACK_CONTEXT_TRACES.fetch_add(1, Ordering::Relaxed);
    if n >= 96 {
        return;
    }
    print_str(b"[user-callback-ctx] #");
    print_u64(n);
    print_str(b" phase=");
    print_str(phase);
    print_str(b" api=");
    print_u64(api_index as u64);
    print_str(b" pi=");
    print_u64(client.pi as u64);
    print_str(b" tid=");
    print_u64(client.tid);
    print_str(b" from-rip=0x");
    print_crash_hex64(redirect_context[nt_user_callback::USER_CONTEXT_RIP]);
    print_str(b" from-rsp=0x");
    print_crash_hex64(redirect_context[nt_user_callback::USER_CONTEXT_RSP]);
    print_str(b" saved-rip=0x");
    print_crash_hex64(completion_context[nt_user_callback::USER_CONTEXT_RIP]);
    print_str(b" saved-rsp=0x");
    print_crash_hex64(completion_context[nt_user_callback::USER_CONTEXT_RSP]);
    print_str(b" out-rip=0x");
    print_crash_hex64(output_context[nt_user_callback::USER_CONTEXT_RIP]);
    print_str(b" out-rsp=0x");
    print_crash_hex64(output_context[nt_user_callback::USER_CONTEXT_RSP]);
    print_str(b" resume-ip=0x");
    print_crash_hex64(resume_ip);
    print_str(b" callout-rsp=0x");
    print_crash_hex64(callout_rsp);
    print_str(b"\n");
    if n < 32 && client.process_role == Some(nt_exe_image::HostedProcessRole::InteractiveLogon) {
        trace_user_callback_stack_words(
            n,
            phase,
            client,
            api_index,
            b"out",
            output_context[nt_user_callback::USER_CONTEXT_RSP],
        );
        let saved_rsp = completion_context[nt_user_callback::USER_CONTEXT_RSP];
        if saved_rsp != output_context[nt_user_callback::USER_CONTEXT_RSP] {
            trace_user_callback_stack_words(n, phase, client, api_index, b"saved", saved_rsp);
        }
        if callout_rsp != 0
            && callout_rsp != output_context[nt_user_callback::USER_CONTEXT_RSP]
            && callout_rsp != saved_rsp
        {
            trace_user_callback_stack_words(n, phase, client, api_index, b"callout", callout_rsp);
        }
    }
}

unsafe fn trace_user_callback_stack_words(
    trace_id: u64,
    phase: &[u8],
    client: Win32kClientContext,
    api_index: u32,
    label: &[u8],
    base: u64,
) {
    if base < 0x10000 {
        print_str(b"[user-callback-stack] #");
        print_u64(trace_id);
        print_str(b" phase=");
        print_str(phase);
        print_str(b" api=");
        print_u64(api_index as u64);
        print_str(b" ");
        print_str(label);
        print_str(b" base=0x");
        print_crash_hex64(base);
        print_str(b" skipped-low\n");
        return;
    }
    print_str(b"[user-callback-stack] #");
    print_u64(trace_id);
    print_str(b" phase=");
    print_str(phase);
    print_str(b" api=");
    print_u64(api_index as u64);
    print_str(b" ");
    print_str(label);
    print_str(b" base=0x");
    print_crash_hex64(base);
    for i in 0..8u64 {
        let Some(va) = base.checked_add(i * 8) else {
            break;
        };
        print_str(b" +");
        print_u64(i * 8);
        print_str(b"=");
        match crate::img_spawn::client_read_u64_mapped(
            client.pi as u64,
            va,
            &[],
            0,
            client.scratch_base,
        ) {
            Some(value) => {
                print_str(b"0x");
                print_crash_hex64(value);
            }
            None => print_str(b"miss"),
        }
    }
    print_str(b"\n");
}

fn client_callback_teb_alias(client: crate::spawn_hosts::UserCallbackClient) -> Option<u64> {
    if callback_client_is_winlogon(client) {
        winlogon_callback_teb_alias(client)
    } else {
        main_gui_callback_teb_alias(client)
    }
}

fn client_callback_supported_for_api(
    client: crate::spawn_hosts::UserCallbackClient,
    api_index: u32,
) -> bool {
    if callback_client_owner_pi(client).is_none() {
        return false;
    }
    if api_index == nt_user_callback::USER32_CALLBACK_CLIENTTHREADSTARTUP {
        return true;
    }
    client
        .process_role
        .is_some_and(nt_exe_image::HostedProcessRole::uses_win32_client_gdi)
}

unsafe fn bind_client_callback_window(
    request: nt_user_callback::CallbackHeader,
    teb_alias: u64,
    hwnd: u64,
    message: u32,
) -> bool {
    const CALLBACK_WND_OFFSET: u64 = 0x840;
    const WND_ACTCTX_OFFSET: u64 = 0x120;
    let cache = teb_alias + CALLBACK_WND_OFFSET;
    let saved = [
        core::ptr::read_volatile(cache as *const u64),
        core::ptr::read_volatile((cache + 8) as *const u64),
        core::ptr::read_volatile((cache + 16) as *const u64),
    ];
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
    let state = nt_user_callback::ClientCallbackWindowState::new(teb_alias, saved);
    if (&mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE))
        .record_callback_window(correlation, state)
        .is_err()
    {
        return false;
    }

    let server_pwnd = crate::winlogon_pwnd_for_hwnd(hwnd);
    let client_pwnd = if server_pwnd >= win32k_subsystem::WIN32K_HEAP_VADDR
        && server_pwnd
            < win32k_subsystem::WIN32K_HEAP_VADDR + win32k_subsystem::WIN32K_HEAP_FRAMES * 0x1000
    {
        server_pwnd - (win32k_subsystem::WIN32K_HEAP_VADDR - win32k_subsystem::CSRSS_W32_SHARED_VA)
    } else {
        0
    };
    let activation_context = if server_pwnd != 0 {
        core::ptr::read_volatile((server_pwnd + WND_ACTCTX_OFFSET) as *const u64)
    } else {
        0
    };
    core::ptr::write_volatile(cache as *mut u64, hwnd);
    core::ptr::write_volatile((cache + 8) as *mut u64, client_pwnd);
    core::ptr::write_volatile((cache + 16) as *mut u64, activation_context);
    // Remember exactly what the bridge published for THIS frame, so the invariant can be re-asserted
    // every time control comes back to the client (see `reassert_top_client_callback_window`).
    let _ = (&mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE))
        .record_bridged_window(correlation, [hwnd, client_pwnd, activation_context]);
    if message == 0x0081 {
        let identity = nt_user_callback::ClientThreadIdentity::new(
            request.client_pi,
            request.client_tid,
            request.client_badge,
        );
        let client_is_explorer = (&*core::ptr::addr_of!(USER_CALLBACK_ACTIVE))
            .top_for(&identity)
            .is_some_and(|frame| {
                callback_process_role_from_code(frame.client_process_role())
                    == Some(nt_exe_image::HostedProcessRole::InteractiveShell)
            });
        print_str(b"[callback-wnd] WM_NCCREATE hwnd=0x");
        print_hex(hwnd as u32);
        print_str(b" server-pwnd=0x");
        print_hex((server_pwnd >> 32) as u32);
        print_hex(server_pwnd as u32);
        print_str(b" client-pwnd=0x");
        print_hex((client_pwnd >> 32) as u32);
        print_hex(client_pwnd as u32);
        if server_pwnd != 0 {
            print_str(b" state=0x");
            print_hex(core::ptr::read_volatile((server_pwnd + 0x28) as *const u32));
            print_str(b" fnid=0x");
            print_hex(core::ptr::read_volatile((server_pwnd + 0x40) as *const u32));
        }
        if client_is_explorer {
            let n = USER_CALLBACK_EXPLORER_NCCREATE_TRACES.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                let frame = (win32k_subsystem::WIN32K_SHARED_VADDR
                    + win32k_subsystem::SH_USER_CALLBACK)
                    as *mut nt_user_callback::CallbackFrame;
                let wndproc = if request.input_length >= 8 {
                    callback_payload_u64(frame, 0)
                } else {
                    0
                };
                let teb_tid = core::ptr::read_volatile((teb_alias + 0x48) as *const u64);
                print_str(b" explorer-tid=");
                print_u64(request.client_tid);
                print_str(b" teb-tid=");
                print_u64(teb_tid);
                print_str(b" teb=0x");
                print_hex((teb_alias >> 32) as u32);
                print_hex(teb_alias as u32);
                print_str(b" wndproc=0x");
                print_hex((wndproc >> 32) as u32);
                print_hex(wndproc as u32);
            }
        }
        print_str(b"\n");
    }
    true
}

unsafe fn restore_client_callback_window(frame: nt_user_callback::ActiveCallbackFrame) {
    let Some(state) = frame.callback_window() else {
        return;
    };
    const CALLBACK_WND_OFFSET: u64 = 0x840;
    let cache = state.teb_alias() + CALLBACK_WND_OFFSET;
    for (offset, value) in state.saved().iter().copied().enumerate() {
        core::ptr::write_volatile((cache + offset as u64 * 8) as *mut u64, value);
    }
}

/// ★ CALLBACK-WINDOW BRIDGE INVARIANT: while a redirected callback frame is on top, the client's
/// `CLIENTINFO.CallbackWnd` (TEB+0x840) MUST hold the executive-bridged triple for that frame —
/// because `user32!ValidateHwnd`'s fast path returns `CallbackWnd.pWnd` verbatim whenever the queried
/// `HWND` matches `CallbackWnd.hWnd`, and every window field access (`GetClientRect`, …) then
/// dereferences it.
///
/// The bridge exists because win32k's OWN `IntSetTebWndCallback` writes
/// `DesktopHeapAddressToUser(pwnd)` there, and in our split-VSpace topology that translation cannot
/// produce a valid client pointer: the executive publishes the correct
/// `server_pwnd - (WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA)` instead. But win32k keeps writing that
/// field on its own schedule — its `IntSetTebWndCallback`/`IntRestoreTebWndCallback` pair straddles
/// every callback (and `co_IntCallWindowProc` skips the restore entirely when the callback returns an
/// error, `callback.c:404`). So the executive's one-shot write at redirect time is NOT sufficient:
/// any nested dispatch or inner callback can leave win32k's untranslated pointer in place, and the
/// client then dereferences it and dies. Re-assert the invariant at every point where control returns
/// to the client while a callback is still in flight.
///
/// Idempotent, allocation-free, and a no-op when nothing clobbered the field. Scoped to ONE client
/// thread: the `CallbackWnd` cache lives in that thread's TEB, so the frame to restate is the top of
/// that thread's own chain, never whichever frame happens to be innermost across all threads.
pub(crate) unsafe fn reassert_top_client_callback_window(
    identity: &nt_user_callback::ClientThreadIdentity,
) {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let Some(frame) = active.top_for(identity) else {
        return;
    };
    if !frame.is_redirected() {
        return;
    }
    let Some(state) = frame.callback_window() else {
        return;
    };
    let bridged = *frame.bridged_window();
    if bridged[0] == 0 {
        return; // nothing was bridged for this frame (no window binding)
    }
    const CALLBACK_WND_OFFSET: u64 = 0x840;
    let cache = state.teb_alias() + CALLBACK_WND_OFFSET;
    USER_CALLBACK_WINDOW_REASSERTS.fetch_add(1, Ordering::Relaxed);
    let mut repaired = false;
    for (offset, value) in bridged.iter().copied().enumerate() {
        let slot = (cache + offset as u64 * 8) as *mut u64;
        if core::ptr::read_volatile(slot) != value {
            repaired = true;
            core::ptr::write_volatile(slot, value);
        }
    }
    if repaired {
        USER_CALLBACK_WINDOW_REPAIRS.fetch_add(1, Ordering::Relaxed);
    }
}

unsafe fn restore_all_client_callback_windows() {
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    while let Some(frame) = active.discard_top() {
        release_dispatch_output_stage(*frame.dispatch_context());
        restore_client_callback_window(frame);
    }
}

unsafe fn abort_controlled_user_callbacks() {
    restore_all_client_callback_windows();
    *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS) =
        nt_user_callback::ContinuationStack::new();
    clear_user_callback_client_registry();
    USER_CALLBACK_SAS_SEQUENCE_ACTIVE.store(0, Ordering::Relaxed);
    USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID.store(0, Ordering::Relaxed);
}

fn sas_sequence_matches(request: &nt_user_callback::CallbackHeader) -> bool {
    let dispatch_id = USER_CALLBACK_SAS_SEQUENCE_ACTIVE.load(Ordering::Relaxed);
    dispatch_id != 0
        && request.dispatch_id == dispatch_id
        && request.callback_id as u64
            == USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID.load(Ordering::Relaxed)
}

unsafe fn callback_payload_u64(frame: *mut nt_user_callback::CallbackFrame, offset: usize) -> u64 {
    let mut bytes = [0u8; 8];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = core::ptr::read_volatile(core::ptr::addr_of!((*frame).payload[offset + index]));
    }
    u64::from_le_bytes(bytes)
}

unsafe fn callback_payload_u32(frame: *mut nt_user_callback::CallbackFrame, offset: usize) -> u32 {
    callback_payload_u64(frame, offset) as u32
}

unsafe fn client_copyin_process_u64(pi: u64, scratch_base: u64, va: u64) -> Option<u64> {
    let mut bytes = [0u8; 8];
    crate::img_spawn::client_copyin_process_mapped(pi, va, &mut bytes, &[], 0, scratch_base, false)
        .then_some(u64::from_le_bytes(bytes))
}

unsafe fn client_copyin_process_u32(pi: u64, scratch_base: u64, va: u64) -> Option<u32> {
    let mut bytes = [0u8; 4];
    crate::img_spawn::client_copyin_process_mapped(pi, va, &mut bytes, &[], 0, scratch_base, false)
        .then_some(u32::from_le_bytes(bytes))
}

unsafe fn explorer_atl_create_data_for_tid(
    client: crate::spawn_hosts::UserCallbackClient,
) -> Option<(u64, u64)> {
    let pi = callback_client_owner_pi(client)?;
    let list_head_va =
        crate::PE_LOAD_BASE + EXPLORER_ATL_WIN_MODULE_RVA + ATL_CREATE_WND_LIST_OFFSET;
    let mut entry = client_copyin_process_u64(pi as u64, client.scratch_base, list_head_va)?;

    for _ in 0..8 {
        if entry == 0 {
            break;
        }
        let entry_tid = client_copyin_process_u32(
            pi as u64,
            client.scratch_base,
            entry + ATL_CREATE_WND_DATA_TID_OFFSET,
        )
        .unwrap_or(u32::MAX);
        let p_this = client_copyin_process_u64(
            pi as u64,
            client.scratch_base,
            entry + ATL_CREATE_WND_DATA_THIS_OFFSET,
        )
        .unwrap_or(0);
        if p_this != 0 && entry_tid as u64 == client.tid {
            return Some((entry, p_this));
        }
        entry = client_copyin_process_u64(
            pi as u64,
            client.scratch_base,
            entry + ATL_CREATE_WND_DATA_NEXT_OFFSET,
        )
        .unwrap_or(0);
    }
    None
}

unsafe fn remember_explorer_atl_pthis(
    client: crate::spawn_hosts::UserCallbackClient,
    request: &nt_user_callback::CallbackHeader,
    frame: *mut nt_user_callback::CallbackFrame,
    message: u32,
    hwnd: u64,
) {
    if !callback_client_is_explorer(client)
        || request.api_index != nt_user_callback::USER32_CALLBACK_WINDOWPROC
        || !matches!(message, WM_GETMINMAXINFO | WM_NCCREATE)
        || hwnd == 0
        || (request.input_length as usize) < 8
    {
        return;
    }

    if callback_payload_u64(frame, 0) != EXPLORER_ATL_START_WINDOW_PROC {
        return;
    }
    let Some((entry, p_this)) = explorer_atl_create_data_for_tid(client) else {
        return;
    };
    if p_this != 0 {
        let n = USER_CALLBACK_EXPLORER_ATL_CREATE_DATA_TRACES.fetch_add(1, Ordering::Relaxed);
        if n < 16 {
            print_str(b"[atl-create] explorer tid=");
            print_u64(client.tid);
            print_str(b" hwnd=0x");
            print_hex(hwnd as u32);
            print_str(b" msg=0x");
            print_hex(message);
            print_str(b" entry=0x");
            print_hex((entry >> 32) as u32);
            print_hex(entry as u32);
            print_str(b" pThis=0x");
            print_hex((p_this >> 32) as u32);
            print_hex(p_this as u32);
            print_str(b"\n");
        }
    }
}

unsafe fn callback_payload_result_u64(
    frame: *mut nt_user_callback::CallbackFrame,
    length: u32,
) -> u64 {
    let mut bytes = [0u8; 8];
    let limit = (length as usize).min(bytes.len());
    for index in 0..limit {
        bytes[index] = core::ptr::read_volatile(core::ptr::addr_of!((*frame).payload[index]));
    }
    u64::from_le_bytes(bytes)
}

unsafe fn copy_callback_result_to_shared(
    client_pi: u32,
    client_scratch_base: u64,
    result_pointer: u64,
    result_length: u64,
) -> bool {
    if result_length == 0 {
        return true;
    }
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let output = core::slice::from_raw_parts_mut(
        core::ptr::addr_of_mut!((*frame).payload) as *mut u8,
        result_length as usize,
    );
    crate::img_spawn::client_copyin_mapped(
        client_pi as u64,
        result_pointer,
        output,
        &[],
        0,
        client_scratch_base,
    )
}

unsafe fn callback_payload_write_u64(
    frame: *mut nt_user_callback::CallbackFrame,
    offset: usize,
    value: u64,
) {
    for (index, byte) in value.to_le_bytes().iter().enumerate() {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!((*frame).payload[offset + index]),
            *byte,
        );
    }
}

unsafe fn publish_callback_reply(
    request: nt_user_callback::CallbackHeader,
    client_pi: u32,
    client_scratch_base: u64,
    result_pointer: u64,
    result_length: u64,
    callback_status: u64,
) -> bool {
    if !copy_callback_result_to_shared(
        client_pi,
        client_scratch_base,
        result_pointer,
        result_length,
    ) {
        return false;
    }
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
        && request.payload_reference_offset != nt_user_callback::NO_PAYLOAD_REFERENCE
    {
        callback_payload_write_u64(frame, WINDOWPROC_LPARAM_OFFSET as usize, 0);
    }
    let mut reply = request;
    reply.state = nt_user_callback::CallbackState::Reply as u32;
    reply.output_length = result_length as u32;
    reply.status = callback_status as i32;
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).header), reply);
    let reply = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    nt_user_callback::validate_reply(&request, &reply).is_ok()
}

fn user_callback_validation_error_name(error: nt_user_callback::ValidationError) -> &'static [u8] {
    match error {
        nt_user_callback::ValidationError::Magic => b"magic",
        nt_user_callback::ValidationError::Version => b"version",
        nt_user_callback::ValidationError::Kind => b"kind",
        nt_user_callback::ValidationError::State => b"state",
        nt_user_callback::ValidationError::Length => b"length",
        nt_user_callback::ValidationError::OutputLength => b"output-length",
        nt_user_callback::ValidationError::Sequence => b"sequence",
        nt_user_callback::ValidationError::Correlation => b"correlation",
    }
}

unsafe fn trace_invalid_user_callback_request(
    request: &nt_user_callback::CallbackHeader,
    error: nt_user_callback::ValidationError,
) {
    let n = USER_CALLBACK_INVALID_REQUEST_TRACES.fetch_add(1, Ordering::Relaxed);
    if n >= 16 {
        return;
    }
    print_str(b"[user-callback] invalid component request reason=");
    print_str(user_callback_validation_error_name(error));
    print_str(b" magic=0x");
    print_hex(request.magic);
    print_str(b" state=");
    print_u64(request.state as u64);
    print_str(b" api=");
    print_u64(request.api_index as u64);
    print_str(b" in=0x");
    print_hex(request.input_length);
    print_str(b" out-cap=0x");
    print_hex(request.output_capacity);
    print_str(b" out-len=0x");
    print_hex(request.output_length);
    print_str(b" status=0x");
    print_hex(request.status as u32);
    print_str(b" pi=");
    print_u64(request.client_pi as u64);
    print_str(b" tid=");
    print_u64(request.client_tid);
    print_str(b" badge=");
    print_u64(request.client_badge);
    print_str(b" cb=");
    print_u64(request.callback_id as u64);
    print_str(b" dispatch=");
    print_u64(request.dispatch_id);
    print_str(b" ref=0x");
    print_hex(request.payload_reference_offset);
    print_str(b"\n");
}

pub(crate) unsafe fn service_user_callback() -> Option<UserCallbackDisposition> {
    const WPCA_MSG: usize = 0x18;
    const WPCA_RESULT: usize = 0x38;

    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let request = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    if let Err(error) = nt_user_callback::validate_request(&request) {
        trace_invalid_user_callback_request(&request, error);
        return None;
    }
    let Some(client) = user_callback_client_for_request(&request) else {
        let n = USER_CALLBACK_CLIENT_LOOKUP_FAILURES.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[user-callback] unregistered component request pi=");
            print_u64(request.client_pi as u64);
            print_str(b" badge=");
            print_u64(request.client_badge);
            print_str(b" tid=");
            print_u64(request.client_tid);
            print_str(b" dispatch=");
            print_u64(request.dispatch_id);
            print_str(b"\n");
        }
        return None;
    };
    USER_CALLBACK_RENDEZVOUS.fetch_add(1, Ordering::Relaxed);

    let contract = nt_user_callback::UserCallbackContract::for_api(request.api_index);
    let contract_valid = contract.is_some_and(|contract| {
        let base_shape_valid = contract.accepts_request(
            request.input_length,
            request.output_capacity,
            request.payload_reference_offset,
        );
        if !base_shape_valid {
            return false;
        }
        if matches!(contract, nt_user_callback::UserCallbackContract::Lpk) {
            contract.accepts_lpk_layout(
                request.input_length,
                callback_payload_u64(frame, 0),
                callback_payload_u32(frame, 0x2c),
            )
        } else {
            true
        }
    });

    let winlogon_api0_ordinal = if request.api_index == 0 && callback_client_is_winlogon(client) {
        USER_CALLBACK_WINLOGON_API0.fetch_add(1, Ordering::Relaxed) + 1
    } else {
        0
    };
    let window_message =
        if request.api_index == 0 && request.input_length as usize >= WPCA_RESULT + 8 {
            callback_payload_u32(frame, WPCA_MSG)
        } else {
            u32::MAX
        };
    let window_hwnd = if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
        && request.input_length as usize >= 0x40
    {
        callback_payload_u64(frame, 0x10)
    } else {
        0
    };
    let window_owner_pi = if window_hwnd != 0 {
        win32k_subsystem::win32k_window_owner_pi(window_hwnd)
    } else {
        None
    };
    let owner_mismatch = window_owner_pi.is_some_and(|owner| owner != client.pi);
    if owner_mismatch {
        let n = USER_CALLBACK_OWNER_MISMATCHES.fetch_add(1, Ordering::Relaxed);
        if n < 32 {
            print_str(b"[user-callback] api0 owner mismatch hwnd=0x");
            print_hex((window_hwnd >> 32) as u32);
            print_hex(window_hwnd as u32);
            print_str(b" current-pi=");
            print_u64(client.pi as u64);
            print_str(b" owner-pi=");
            print_u64(window_owner_pi.unwrap_or(u32::MAX) as u64);
            print_str(b" msg=0x");
            print_hex(window_message);
            print_str(b" -> fail closed\n");
        }
    }
    remember_explorer_atl_pthis(client, &request, frame, window_message, window_hwnd);
    let sas_session_before = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION) as *const u64,
    );
    let mut suspend_component = false;
    // A client whose callback thread has DIED can never reach `NtCallbackReturn`, so redirecting it
    // would park win32k forever. Fail such callbacks closed — this is what lets the dead-client
    // unwind (`unwind_dead_client_user_callbacks`) always converge: win32k may legitimately issue
    // further callbacks (cleanup/`WM_DESTROY`-ish paths) as it unwinds, and each one now returns an
    // error immediately instead of suspending the component again.
    let client_dead = user_callback_client_dead(client.pi);
    if client_callback_supported_for_api(client, request.api_index)
        && client.tcb > 1
        && contract_valid
        && !client_dead
        && !owner_mismatch
    {
        let callback_table = if client.peb_mirror == 0 {
            0
        } else {
            core::ptr::read_volatile((client.peb_mirror + 0x58) as *const u64)
        };
        let dispatcher_rva =
            crate::img_spawn::OUR_KI_USER_CALLBACK_DISPATCHER_RVA.load(Ordering::Relaxed);
        let dispatcher = if dispatcher_rva == 0 {
            0
        } else {
            crate::NTDLL_BASE + dispatcher_rva
        };
        let valid = callback_table != 0 && callback_table & 7 == 0;
        if winlogon_api0_ordinal == 1 {
            USER_CALLBACK_TABLE_VALID.fetch_add(valid as u64, Ordering::Relaxed);
            print_str(b"[user-callback] first winlogon api=0 pi=2 badge=");
            print_u64(client.badge);
            print_str(b" tid=");
            print_u64(client.tid);
            print_str(b" PEB+0x58 table=0x");
            print_hex((callback_table >> 32) as u32);
            print_hex(callback_table as u32);
            print_str(if valid {
                b" (nonzero, aligned)"
            } else {
                b" (INVALID)"
            });
            print_str(b" Rust-ntdll!KiUserCallbackDispatcher=0x");
            print_hex((dispatcher >> 32) as u32);
            print_hex(dispatcher as u32);
            print_str(b" RVA=0x");
            print_hex(dispatcher_rva as u32);
            print_str(b"\n");
        }
        let first_sas_create = request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            && window_message == 0x0001
            && sas_session_before == 0
            && request.payload_reference_offset == WINDOWPROC_PAYLOAD_OFFSET
            && request.input_length >= 0x40 + 0x50;
        let requires_window_binding = contract.unwrap().requires_window_binding();
        let callback_teb_alias = client_callback_teb_alias(client);
        if (!requires_window_binding || callback_teb_alias.is_some())
            && valid
            && dispatcher != 0
            && begin_controlled_continuation(request, client)
        {
            if !remember_active_dispatch(&request)
                || !remember_active_dispatch_arg_snapshot(&request)
            {
                abort_controlled_user_callbacks();
                return None;
            }
            // win32k's IntSetTebWndCallback executes in the isolated driver component. Bridge its
            // per-callback HWND/PWND cache into the client TEB that user32 actually reads, preserving
            // the same nested save/restore semantics as the native kernel path.
            if requires_window_binding
                && !bind_client_callback_window(
                    request,
                    callback_teb_alias.unwrap(),
                    window_hwnd,
                    window_message,
                )
            {
                // The dispatch context travels with the frame `abort_…` is about to discard.
                abort_controlled_user_callbacks();
                return None;
            }
            USER_CALLBACK_DISPATCHER.store(dispatcher, Ordering::Relaxed);
            if matches!(
                request.api_index,
                nt_user_callback::USER32_CALLBACK_LOADDEFAULTCURSORS
                    | nt_user_callback::USER32_CALLBACK_SETWNDICONS
                    | nt_user_callback::USER32_CALLBACK_SETOBM
                    | nt_user_callback::USER32_CALLBACK_LPK
            ) {
                USER_CALLBACK_REAL_RESOURCE_STARTED.store(1, Ordering::Relaxed);
            }
            if first_sas_create {
                let sas_hwnd = callback_payload_u64(frame, 0x10);
                let sas_session = callback_payload_u64(frame, WINDOWPROC_PAYLOAD_OFFSET as usize);
                if sas_hwnd != 0 && sas_session != 0 {
                    let sas_pwnd = crate::winlogon_pwnd_for_hwnd(sas_hwnd);
                    if sas_pwnd != 0 {
                        core::ptr::write_volatile(
                            (sas_pwnd + WND_DWUSERDATA_OFFSET) as *mut u64,
                            sas_session,
                        );
                    }
                    core::ptr::write_volatile(
                        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND)
                            as *mut u64,
                        sas_hwnd,
                    );
                    core::ptr::write_volatile(
                        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_SESSION)
                            as *mut u64,
                        sas_session,
                    );
                    print_str(b"[user-callback] latched real SAS WM_CREATE hwnd=0x");
                    print_hex(sas_hwnd as u32);
                    print_str(b" session=0x");
                    print_hex((sas_session >> 32) as u32);
                    print_hex(sas_session as u32);
                    print_str(b" pwnd=0x");
                    print_hex((sas_pwnd >> 32) as u32);
                    print_hex(sas_pwnd as u32);
                    print_str(b" dwUserData=");
                    print_u64((sas_pwnd != 0) as u64);
                    print_str(b"\n");
                }
                core::ptr::write(
                    core::ptr::addr_of_mut!(USER_CALLBACK_SAS_SEQUENCE),
                    nt_user_callback::SasWmCreateNestedSequence::new(),
                );
                USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID
                    .store(request.callback_id as u64, Ordering::Relaxed);
                USER_CALLBACK_SAS_SEQUENCE_ACTIVE.store(request.dispatch_id, Ordering::Relaxed);
            }
            suspend_component = true;
            print_str(b"[user-callback] selected real callback api=");
            print_u64(request.api_index as u64);
            if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC {
                print_str(b" msg=0x");
                print_hex(window_message);
            }
            print_str(b" depth=");
            print_u64((&*core::ptr::addr_of!(USER_CALLBACK_ACTIVE)).len() as u64);
            print_str(b"\n");
            if callback_client_is_explorer(client)
                && request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            {
                USER_CALLBACK_EXPLORER_API0_REDIRECTS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if suspend_component {
        capture_suspended_published_win32k_context(client);
        print_str(b"[user-callback] B component continuation parked in callback receive loop\n");
        Some(UserCallbackDisposition::SuspendComponent)
    } else {
        const STATUS_UNSUCCESSFUL: i32 = 0xc000_0001u32 as i32;
        const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc000_0004u32 as i32;
        const STATUS_NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;
        const STATUS_THREAD_IS_TERMINATING: i32 = 0xc000_004bu32 as i32;
        let status = if client_dead {
            STATUS_THREAD_IS_TERMINATING
        } else if owner_mismatch {
            STATUS_UNSUCCESSFUL
        } else if contract.is_none()
            || !client_callback_supported_for_api(client, request.api_index)
        {
            STATUS_NOT_SUPPORTED
        } else if !contract_valid {
            STATUS_INFO_LENGTH_MISMATCH
        } else {
            STATUS_UNSUCCESSFUL
        };
        print_str(b"[user-callback] callback not redirected api=");
        print_u64(request.api_index as u64);
        print_str(b" status=0x");
        print_hex(status as u32);
        print_str(b"\n");
        if callback_client_is_explorer(client) && !client_dead {
            USER_CALLBACK_EXPLORER_FAILURES.fetch_add(1, Ordering::Relaxed);
        } else if callback_client_is_explorer(client) {
            USER_CALLBACK_EXPLORER_DEAD_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        write_callback_failure_reply(request, status);
        Some(UserCallbackDisposition::ReplyImmediately)
    }
}

pub(crate) unsafe fn tcb_write_regs20(tcb: u64, registers: &[u64; 20], resume: bool) -> u64 {
    for (index, register) in registers.iter().enumerate().skip(2) {
        set_reply_mr(index + 2, *register);
    }
    let reply_info: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (LBL_TCB_WRITE_REGISTERS << 12) | 22 => reply_info,
        inout("r10") resume as u64 => _,
        inout("r8") 20u64 => _,
        inout("r9") registers[0] => _,
        inout("r15") registers[1] => _,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply_info >> 12
}

#[derive(Clone, Copy)]
pub(crate) struct TcbBreakpoint {
    pub(crate) vaddr: u64,
    pub(crate) breakpoint_type: u64,
    pub(crate) size: u64,
    pub(crate) access: u64,
    pub(crate) enabled: bool,
}

pub(crate) unsafe fn tcb_set_breakpoint(
    tcb: u64,
    bp_num: u64,
    vaddr: u64,
    breakpoint_type: u64,
    size: u64,
    access: u64,
) -> u64 {
    set_reply_mr(4, access);
    let reply_info: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (LBL_TCB_SET_BREAKPOINT << 12) | 5 => reply_info,
        inout("r10") bp_num => _,
        inout("r8") vaddr => _,
        inout("r9") breakpoint_type => _,
        inout("r15") size => _,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply_info >> 12
}

pub(crate) unsafe fn tcb_get_breakpoint(tcb: u64, bp_num: u64) -> Option<TcbBreakpoint> {
    let reply_info: u64;
    let (vaddr, breakpoint_type, size, access): (u64, u64, u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (LBL_TCB_GET_BREAKPOINT << 12) | 1 => reply_info,
        inout("r10") bp_num => vaddr,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r8") breakpoint_type,
        lateout("r9") size,
        lateout("r15") access,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    if reply_info >> 12 != 0 {
        return None;
    }
    Some(TcbBreakpoint {
        vaddr,
        breakpoint_type,
        size,
        access,
        enabled: crate::get_recv_mr(4) != 0,
    })
}

pub(crate) unsafe fn tcb_unset_breakpoint(tcb: u64, bp_num: u64) -> u64 {
    let reply_info: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (LBL_TCB_UNSET_BREAKPOINT << 12) | 1 => reply_info,
        inout("r10") bp_num => _,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r8") _,
        lateout("r9") _,
        lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    reply_info >> 12
}

/// Repoint a thread blocked on a fault without resuming it. The subsequent fault reply remains the
/// authority that clears `pending_fault` and makes the thread runnable.
pub(crate) unsafe fn rewind_fault_ip(tcb: u64, rip: u64) -> bool {
    let mut registers = [0u64; 20];
    tcb_read_regs20(tcb, &mut registers);
    registers[nt_user_callback::USER_CONTEXT_RIP] = rip;
    tcb_write_regs20(tcb, &registers, false) == 0
}

fn callback_context_tcb(client: Win32kClientContext) -> Option<u64> {
    (client.tcb > 1).then_some(client.tcb)
}

fn callback_resume_ip_executable(client: Win32kClientContext, ip: u64) -> bool {
    if ip == 0 {
        return false;
    }
    let Some(info) =
        (unsafe { crate::process_committed_mapping_basic_information(client.pi as u64, ip) })
    else {
        return false;
    };
    let access = nt_address_space::FaultAccess::Execute;
    match info.type_ {
        nt_address_space::MEM_IMAGE => {
            nt_address_space::image_view_fault_access_status(info.protect, access).is_ok()
        }
        nt_address_space::MEM_MAPPED | nt_address_space::MEM_PRIVATE => {
            nt_address_space::mapped_view_fault_access_status(info.protect, access).is_ok()
        }
        _ => false,
    }
}

unsafe fn resolve_callback_resume_ip(
    client: Win32kClientContext,
    message_resume_ip: u64,
    saved: &[u64; 20],
    phase: &[u8],
) -> Option<u64> {
    let resolved = nt_user_callback::repaired_syscall_resume_ip(message_resume_ip, saved, |ip| {
        callback_resume_ip_executable(client, ip)
    });
    match resolved {
        Some(ip) if ip != message_resume_ip => {
            let n = USER_CALLBACK_RESUME_IP_REPAIRS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[user-callback] repaired ");
                print_str(phase);
                print_str(b" resume-ip primary=0x");
                print_crash_hex64(message_resume_ip);
                print_str(b" tcb-rip=0x");
                print_crash_hex64(saved[nt_user_callback::USER_CONTEXT_RIP]);
                print_str(b" repaired=0x");
                print_crash_hex64(ip);
                print_str(b"\n");
            }
            Some(ip)
        }
        Some(ip) => Some(ip),
        None => {
            let n = USER_CALLBACK_RESUME_IP_REJECTS.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[user-callback] rejected ");
                print_str(phase);
                print_str(b" resume-ip primary=0x");
                print_crash_hex64(message_resume_ip);
                print_str(b" tcb-rip=0x");
                print_crash_hex64(saved[nt_user_callback::USER_CONTEXT_RIP]);
                print_str(b"\n");
            }
            None
        }
    }
}

pub(crate) unsafe fn resolve_active_callback_syscall_resume_ip(
    client: Win32kClientContext,
    message_resume_ip: u64,
) -> Option<u64> {
    let identity = nt_user_callback::ClientThreadIdentity::new(client.pi, client.tid, client.badge);
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    if active.top_for(&identity).is_none() {
        return Some(message_resume_ip);
    }
    let Some(tcb) = callback_context_tcb(client) else {
        return None;
    };
    let mut saved = [0u64; 20];
    tcb_read_regs20(tcb, &mut saved);
    resolve_callback_resume_ip(client, message_resume_ip, &saved, b"nested-syscall")
}

pub(crate) unsafe fn begin_controlled_user_callback_redirect(
    client: Win32kClientContext,
    outer_resume_ip: u64,
    outer_rsp: u64,
    outer_flags: u64,
) -> bool {
    let Some(tcb) = callback_context_tcb(client) else {
        return false;
    };
    let mut saved = [0u64; 20];
    tcb_read_regs20(tcb, &mut saved);
    let Some(outer_resume_ip) =
        resolve_callback_resume_ip(client, outer_resume_ip, &saved, b"outer")
    else {
        return false;
    };
    redirect_pending_user_callback(
        client,
        &saved,
        &saved,
        outer_resume_ip,
        outer_resume_ip,
        outer_rsp,
        outer_flags,
        b"root-redirect",
    )
}

unsafe fn redirect_pending_user_callback(
    client: Win32kClientContext,
    redirect_context: &[u64; 20],
    completion_context: &[u64; 20],
    completion_resume_ip: u64,
    callout_resume_ip: u64,
    callout_rsp: u64,
    callout_flags: u64,
    phase: &[u8],
) -> bool {
    let identity = nt_user_callback::ClientThreadIdentity::new(client.pi, client.tid, client.badge);
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    // The frame to redirect is the innermost one of THIS client thread — another thread's frame may
    // sit above it in the interleaved stack.
    let Some(active_frame) = active.top_for(&identity).copied() else {
        return false;
    };
    let request = *active_frame.request();
    if active_frame.is_redirected() {
        return false;
    }
    let Some(tcb) = callback_context_tcb(client) else {
        return false;
    };
    let dispatcher = USER_CALLBACK_DISPATCHER.load(Ordering::Relaxed);
    if dispatcher == 0 {
        return false;
    }

    let Ok(layout) = nt_user_callback::UserCallbackStackLayout::below(
        redirect_context[nt_user_callback::USER_CONTEXT_RSP],
        request.input_length as usize,
    ) else {
        return false;
    };
    if request.input_length != 0 {
        let shared = (win32k_subsystem::WIN32K_SHARED_VADDR
            + win32k_subsystem::SH_USER_CALLBACK
            + core::mem::size_of::<nt_user_callback::CallbackHeader>() as u64)
            as *const u8;
        let input = core::slice::from_raw_parts(shared, request.input_length as usize);
        if !crate::img_spawn::client_write_mapped(
            client.pi as u64,
            layout.input_pointer,
            input,
            &[],
            0,
            client.scratch_base,
        ) {
            return false;
        }
    }
    if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
        && request.payload_reference_offset != nt_user_callback::NO_PAYLOAD_REFERENCE
    {
        let Ok(reference) = nt_user_callback::client_payload_reference(
            layout.input_pointer,
            request.input_length as usize,
            request.payload_reference_offset,
        ) else {
            return false;
        };
        if !crate::img_spawn::client_write_mapped(
            client.pi as u64,
            layout.input_pointer + WINDOWPROC_LPARAM_OFFSET,
            &reference.to_le_bytes(),
            &[],
            0,
            client.scratch_base,
        ) {
            return false;
        }
    }
    let frame = nt_user_callback::UserCalloutFrame::callback(
        layout.input_pointer,
        request.input_length,
        request.api_index,
        callout_resume_ip,
        callout_rsp,
        callout_flags as u32,
    );
    let frame_bytes = core::slice::from_raw_parts(
        core::ptr::addr_of!(frame) as *const u8,
        core::mem::size_of::<nt_user_callback::UserCalloutFrame>(),
    );
    if !crate::img_spawn::client_write_mapped(
        client.pi as u64,
        layout.frame_pointer,
        frame_bytes,
        &[],
        0,
        client.scratch_base,
    ) {
        return false;
    }

    let redirected = nt_user_callback::callback_redirect_context(
        redirect_context,
        dispatcher,
        layout.frame_pointer,
    );
    trace_user_callback_context(
        phase,
        client,
        request.api_index,
        redirect_context,
        completion_context,
        &redirected,
        completion_resume_ip,
        callout_rsp,
    );
    let error = tcb_write_regs20(tcb, &redirected, false);
    if error != 0 {
        print_str(b"[user-callback] client redirect TCB_WriteRegisters failed error=");
        print_u64(error);
        print_str(b"\n");
        return false;
    }
    if active
        .record_redirect(
            nt_user_callback::CallbackCorrelation::from_request(&request),
            *completion_context,
            completion_resume_ip,
        )
        .is_err()
    {
        return false;
    }
    USER_CALLBACK_REAL_REDIRECTS.fetch_add(1, Ordering::Relaxed);
    print_str(b"[user-callback] A client redirected to real apfnDispatch[");
    print_u64(request.api_index as u64);
    print_str(b"] payload=0x");
    print_hex(request.input_length);
    print_str(b" bytes\n");
    true
}

/// ★ RISK R2 (`docs/transport-migration.md`) — a WALLED win32k is DEAD, and the transport now says
/// so. On a wall the component is left blocked in a fault `Call` with `R_win32k` STILL BOUND to it;
/// a later `reply_on(R, request)` would be delivered as a FAULT reply (`apply_fault_reply` returns
/// `restart = true` unconditionally for VMFault/CapFault), resuming win32k at the faulting
/// instruction carrying a request it never asked for. The pump has already `TCB_Suspend`ed it; this
/// is the win32k analogue of `dispatch_irp`'s `register_instance_ready(inst, false)` — retire the
/// component so nothing can ever reply on that stale binding. Zero walls occur on a green boot, so
/// this is defensive; if it ever fires, the boot says so loudly and every later win32k call fails
/// cleanly instead of corrupting.
pub(crate) static WIN32K_RETIRED: AtomicU64 = AtomicU64::new(0);

unsafe fn retire_win32k_on_wall(pr: &crate::spawn_hosts::PumpResult) {
    if pr.completed || pr.callback_suspended {
        return;
    }
    if WIN32K_RETIRED.swap(1, Ordering::Relaxed) == 0 {
        print_str(b"[w32disp] win32k WALLED (label=");
        print_u64(pr.wall_label);
        print_str(b") -> component RETIRED; its reply object stays bound to a suspended thread\n");
    }
}

fn callback_client_from_frame(
    request: nt_user_callback::CallbackHeader,
    frame: nt_user_callback::ActiveCallbackFrame,
) -> crate::spawn_hosts::UserCallbackClient {
    let mut token_user_sid = [0u8; win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX];
    token_user_sid.copy_from_slice(frame.client_token_user_sid());
    crate::spawn_hosts::UserCallbackClient {
        pi: request.client_pi,
        generation: unsafe {
            user_callback_client_for_request(&request)
                .map(|client| client.generation)
                .unwrap_or(0)
        },
        pid: frame.client_pid(),
        badge: request.client_badge,
        tid: request.client_tid,
        tcb: frame.client_tcb(),
        teb: frame.client_teb(),
        eprocess: frame.client_eprocess(),
        ethread: frame.client_ethread(),
        role: callback_runtime_role_from_code(frame.client_runtime_role()),
        process_role: callback_process_role_from_code(frame.client_process_role()),
        top_badge: frame.client_top_badge(),
        peb_mirror: frame.client_peb_mirror(),
        scratch_base: frame.client_scratch_base(),
        token_authentication_id: frame.client_token_authentication_id(),
        token_user_sid,
        token_user_sid_len: frame.client_token_user_sid_len(),
    }
}

unsafe fn flush_returned_user_callback_gdi_batch(
    request: nt_user_callback::CallbackHeader,
    frame: nt_user_callback::ActiveCallbackFrame,
) {
    let client = callback_client_from_frame(request, frame);
    let Some(teb_alias) = client_callback_teb_alias(client) else {
        return;
    };
    crate::ke_gdi_flush_user_batch(
        win32k_client_context_from_callback_client(client),
        teb_alias,
    );
    let identity = nt_user_callback::ClientThreadIdentity::new(
        request.client_pi,
        request.client_tid,
        request.client_badge,
    );
    reassert_top_client_callback_window(&identity);
}

unsafe fn resume_suspended_user_callback_component(
    request: nt_user_callback::CallbackHeader,
    client: crate::spawn_hosts::UserCallbackClient,
) -> crate::spawn_hosts::PumpResult {
    if client.pi != request.client_pi
        || client.tid != request.client_tid
        || client.badge != request.client_badge
    {
        return crate::spawn_hosts::PumpResult {
            status: 0xC000_000Du32 as i32,
            result: 0xC000_000Du32 as u64,
            reply_cap: REPLY_W32_SLOT.load(Ordering::Relaxed),
            completed: false,
            callback_suspended: false,
            scheduler_yielded: false,
            wall_ip: 0,
            wall_addr: 0,
            wall_label: 0,
            wall_flags: 0,
            wall_exception: 0,
            wall_code: 0,
            faults: 0,
            demand: 0,
        };
    }
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_PROCESS_ID) as *mut u64,
        client.pid,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_CLIENT_PI) as *mut u64,
        client.pi as u64,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_CLIENT_TEB) as *mut u64,
        client.teb,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_THREAD_ID) as *mut u64,
        client.tid,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_EPROCESS) as *mut u64,
        client.eprocess,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_ETHREAD) as *mut u64,
        client.ethread,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_PROCESS_ROLE) as *mut u64,
        callback_process_role_code(client.process_role) as u64,
    );
    if !win32k_subsystem::restore_current_context_for_user_callback_resume(
        client.pi,
        client.pid,
        client.tid,
        client.teb,
        client.eprocess,
        client.ethread,
        callback_process_role_code(client.process_role) as u64,
    ) {
        return crate::spawn_hosts::PumpResult {
            status: 0xC000_000Du32 as i32,
            result: 0xC000_000Du32 as u64,
            reply_cap: REPLY_W32_SLOT.load(Ordering::Relaxed),
            completed: false,
            callback_suspended: false,
            scheduler_yielded: false,
            wall_ip: 0,
            wall_addr: 0,
            wall_label: 0,
            wall_flags: 0,
            wall_exception: 0,
            wall_code: 0,
            faults: 0,
            demand: 0,
        };
    }
    let channel = crate::spawn_hosts::PumpChannel {
        fault_ep: WIN32K_FAULT_EP.load(Ordering::Relaxed),
        pml4: WIN32K_HOST_PML4.load(Ordering::Relaxed),
        code_va: win32k_subsystem::WIN32K_CODE_VA,
        image_frames: win32k_subsystem::WIN32K_IMAGE_FRAMES,
        exec_code_va: win32k_subsystem::WIN32K_CODE_VA,
        root_image_rights: 3,
        root_image_map_owner: crate::WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Relaxed) as u16,
        shared_va: win32k_subsystem::WIN32K_SHARED_VADDR,
        dispatch_label: win32k_subsystem::W32_DISPATCH_LABEL,
        demand_cap: 8192,
        trace_faults: false,
        // ★ THE RESUME IS A REPLY ON THE STILL-BOUND OBJECT. win32k has been sitting in its callback
        // `Call` since the pump that suspended it returned WITHOUT replying, so `R_win32k` is still
        // bound to exactly that Call — the resume is one `reply_on` carrying the RESUME tag. The
        // bespoke `ep_send(RESUME)` preamble and its `use_reply_cap` guard are gone.
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: WIN32K_TCB.load(Ordering::Relaxed),
        reply_cap: REPLY_W32_SLOT.load(Ordering::Relaxed),
        client_pi: client.pi as u64,
        client_generation: client.generation,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Syscall,
            client_attach: true,
            usermode_callback: true,
            wide_arg_marshal: true,
            assert_skip: true,
            sparse_vspace: true,
            io_port_faults: false,
        },
    };
    let pr = crate::spawn_hosts::component_pump_resume_user_callback(&channel);
    retire_win32k_on_wall(&pr);
    pr
}

/// Cancel the callback that is PENDING (parked, not yet redirected into its client). A pending frame
/// is necessarily the array's top whichever threads have chains open: it was pushed by the callback
/// request the executive is still servicing, so no other client event has been able to run since.
pub(crate) unsafe fn cancel_suspended_user_callback() -> (i32, bool) {
    const STATUS_UNSUCCESSFUL: i32 = 0xC000_0001u32 as i32;
    let mut cancelled_count = 0u64;
    let mut last_status = STATUS_UNSUCCESSFUL;
    while cancelled_count < nt_user_callback::MAX_CONTINUATION_DEPTH as u64 {
        let (request, dispatch_context, cancelled_frame) = {
            let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
            let Some(active_frame) = active.top().copied() else {
                if cancelled_count != 0 {
                    abort_controlled_user_callbacks();
                }
                return (last_status, false);
            };
            if active_frame.is_redirected() {
                if cancelled_count != 0 {
                    abort_controlled_user_callbacks();
                }
                return (STATUS_UNSUCCESSFUL, false);
            }
            let request = *active_frame.request();
            let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
            let dispatch_context = *active_frame.dispatch_context();
            write_callback_failure_reply(request, STATUS_UNSUCCESSFUL);
            let unwind_ok = unwind_controlled_callback(request);
            let cancelled = active.cancel_pending(correlation);
            let Ok(cancelled_frame) = cancelled else {
                abort_controlled_user_callbacks();
                return (STATUS_UNSUCCESSFUL, false);
            };
            restore_client_callback_window(cancelled_frame);
            if !unwind_ok {
                abort_controlled_user_callbacks();
                return (STATUS_UNSUCCESSFUL, false);
            }
            (request, dispatch_context, cancelled_frame)
        };

        cancelled_count += 1;
        let previous_dispatch =
            core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
        core::ptr::write(
            core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
            dispatch_context,
        );
        let result = resume_suspended_user_callback_component(
            request,
            callback_client_from_frame(request, cancelled_frame),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
            previous_dispatch,
        );
        last_status = result.status;

        if result.callback_suspended {
            let n = USER_CALLBACK_CANCEL_CHAINED.fetch_add(1, Ordering::Relaxed);
            if n < 16 {
                print_str(b"[user-callback] cancel propagated to chained callback api=");
                let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
                let api = active
                    .top()
                    .map(|frame| frame.request().api_index as u64)
                    .unwrap_or(u64::MAX);
                print_u64(api);
                print_str(b" cancelled=");
                print_u64(cancelled_count);
                print_str(b"\n");
            }
            continue;
        }

        let stack_ok = result.completed && unwind_controlled_dispatch(request);
        if !result.callback_suspended {
            release_dispatch_output_stage(dispatch_context);
        }
        if !stack_ok {
            abort_controlled_user_callbacks();
        }
        return (result.status, stack_ok);
    }

    print_str(b"[user-callback] cancel chain exceeded bounded continuation depth\n");
    abort_controlled_user_callbacks();
    (last_status, false)
}

unsafe fn print_crash_hex64(value: u64) {
    print_hex((value >> 32) as u32);
    print_hex(value as u32);
}

/// Crash-site diagnostic for a GUI client that faulted around the user-callback path. It prints the
/// faulting GPRs and callback metadata that lives in executive-owned memory. Do not chase arbitrary
/// client stack or TEB pointers from here: this runs in the executive/rootserver context and cannot
/// service hosted-client page faults.
pub(crate) unsafe fn dump_client_callback_crash_state(client_pi: usize, tcb: u64) {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let active_frame = active.top_for_pi(client_pi as u32);
    if tcb == 0 && active_frame.is_none() && client_pi != 2 {
        return;
    }
    if tcb != 0 {
        let mut regs = [0u64; 20];
        tcb_read_regs20(tcb, &mut regs);
        print_str(b"[cb-crash] regs rip=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RIP]);
        print_str(b" rsp=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RSP]);
        print_str(b" rax=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RAX]);
        print_str(b" rbx=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RBX]);
        print_str(b" rcx=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RCX]);
        print_str(b" rdx=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RDX]);
        print_str(b" rsi=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RSI]);
        print_str(b" rdi=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RDI]);
        print_str(b" rbp=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RBP]);
        print_str(b" r8=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R8]);
        print_str(b" r9=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R9]);
        print_str(b" r10=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R10]);
        print_str(b" r11=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R11]);
        print_str(b" r12=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R12]);
        print_str(b" r13=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R13]);
        print_str(b" r14=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R14]);
        print_str(b" r15=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_R15]);
        print_str(b"\n");
        print_str(b"[cb-crash] stack omitted: client rsp=0x");
        print_crash_hex64(regs[nt_user_callback::USER_CONTEXT_RSP]);
        print_str(b"\n");
    }
    let teb = if client_pi == 2 {
        WINLOGON_MAIN_TEB_MIRROR_VA
    } else {
        0
    };
    if teb == 0 {
        print_str(b"[cb-crash] CLIENTINFO skipped: no executive-owned TEB mirror\n");
    } else {
        let read = |offset: u64| core::ptr::read_volatile((teb + offset) as *const u64);
        print_str(b"[cb-crash] CLIENTINFO pDeskInfo=0x");
        print_crash_hex64(read(0x820));
        print_str(b" ulClientDelta=0x");
        print_crash_hex64(read(0x828));
        print_str(b" CallbackWnd{hWnd=0x");
        print_hex(read(0x840) as u32);
        print_str(b" pWnd=0x");
        print_crash_hex64(read(0x848));
        print_str(b" pActCtx=0x");
        print_crash_hex64(read(0x850));
        print_str(b"}\n");
    }
    if let Some(frame) = active_frame {
        let request = frame.request();
        print_str(b"[cb-crash] active callback api=");
        print_u64(request.api_index as u64);
        print_str(b" hwnd=0x");
        let hwnd = if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            && request.input_length as usize >= WINDOWPROC_PAYLOAD_OFFSET as usize
        {
            let callback_frame = (win32k_subsystem::WIN32K_SHARED_VADDR
                + win32k_subsystem::SH_USER_CALLBACK)
                as *mut nt_user_callback::CallbackFrame;
            callback_payload_u64(callback_frame, 0x10)
        } else {
            0
        };
        print_hex(hwnd as u32);
        print_str(b" depth=");
        print_u64(active.len() as u64);
        print_str(b" redirected=");
        print_u64(frame.is_redirected() as u64);
        print_str(b"\n");
    } else {
        print_str(b"[cb-crash] active callback none depth=0\n");
    }
}

/// ★ DEAD-CLIENT CALLBACK UNWIND — the executive-side answer to "the client died mid-callback".
///
/// A user-mode callback is an ADVERSARIAL re-entrancy point (`docs/user-callback-dispatch.md` §1.7):
/// while win32k's dispatch is suspended inside `KeUserModeCallback`, the *client* thread owns
/// execution — and it can die there (an unrecoverable user fault → crash-park, a critical
/// termination). Its `NtCallbackReturn` will never arrive, so the withheld
/// `W32_USER_CALLBACK_RESUME_LABEL` would never be sent: win32k's single TCB stays blocked in its
/// callback receive loop with a NON-EMPTY continuation stack, the executive's shared loop blocks in
/// `recv` forever, and the boot WEDGES — no quiesce, no gate, no measurement. Fault isolation
/// requires the opposite: one process dying must not strand a service.
///
/// Real NT has exactly this obligation and answers it the same way — the callback's kernel
/// continuation is unwound and `KeUserModeCallback` returns an ERROR `NTSTATUS`. That is a *faithful*
/// signal, not a shortcut: win32k already revalidates its objects (`PWND`, DCs, …) after every
/// callback return precisely because the user leg is untrusted, so an error return takes the same
/// paths a hostile `WndProc` would.
///
/// So, for every outstanding `UserCallbackFrame` of the dead client, INNERMOST FIRST:
/// 1. publish a FAILURE reply in the shared callback frame (`STATUS_THREAD_IS_TERMINATING`);
/// 2. unwind that callback continuation and pop the active frame (restoring the client TEB's
///    per-callback window cache exactly as a real return would);
/// 3. resume win32k's parked continuation and pump it until it re-parks at its normal dispatch
///    receive loop, then unwind the win32k dispatch continuation underneath it.
///
/// The dead `pi` is latched in `USER_CALLBACK_DEAD_CLIENTS` FIRST, so any FURTHER callback win32k
/// requests while unwinding fails closed through the existing non-redirect path in
/// [`service_user_callback`] rather than redirecting a thread that can never run again — that is what
/// makes the pump always converge on `completed`.
///
/// General (any client pi, any depth, nested frames unwound in order), bounded (each iteration pops
/// exactly one of at most `MAX_ACTIVE_CALLBACK_DEPTH` frames), allocation-free, and reset-safe: any
/// correlation failure falls back to [`abort_controlled_user_callbacks`], which resets the
/// continuation stack to its initial state so the executive stays consistent either way.
///
/// Returns the number of callback frames unwound (0 when the client held none — the common case, so
/// this is a cheap no-op at every crash-park site).
pub(crate) unsafe fn unwind_dead_client_user_callbacks(client_pi: u32) -> u64 {
    const STATUS_THREAD_IS_TERMINATING: i32 = 0xc000_004bu32 as i32;
    if client_pi < 64 {
        USER_CALLBACK_DEAD_CLIENTS.fetch_or(1u64 << client_pi, Ordering::Relaxed);
    }
    let mut unwound = 0u64;
    loop {
        let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
        // The INNERMOST frame of the dead process, across all of its threads. Frames of OTHER
        // processes are LIVE and are stepped over, not torn down: the stack interleaves several
        // client threads' chains, so "not mine" no longer means "stop". Because every thread of this
        // process shares `client_pi`, the innermost matching frame is always the top of its own
        // thread's chain, which is what keeps each teardown innermost-first.
        let Some(frame) = active.top_for_pi(client_pi).copied() else {
            break;
        };
        let request = *frame.request();
        let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
        let dispatch_context = *frame.dispatch_context();
        // (1) Fail the withheld KeUserModeCallback.
        write_callback_failure_reply(request, STATUS_THREAD_IS_TERMINATING);
        // (2) Unwind the callback continuation + pop the active frame (same order as a real return).
        if !unwind_controlled_callback(request) {
            print_str(b"[user-callback] dead-client callback continuation rejected -> reset\n");
            abort_controlled_user_callbacks();
            break;
        }
        let was_redirected = frame.is_redirected();
        let popped = if was_redirected {
            active.pop(correlation)
        } else {
            active.cancel_pending(correlation)
        };
        let Ok(popped) = popped else {
            print_str(b"[user-callback] dead-client active frame rejected -> reset\n");
            abort_controlled_user_callbacks();
            break;
        };
        restore_client_callback_window(popped);
        // (3) Resume win32k with the failure and let it unwind its own dispatch.
        let previous_dispatch =
            core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
        core::ptr::write(
            core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
            dispatch_context,
        );
        let component = resume_suspended_user_callback_component(
            request,
            callback_client_from_frame(request, popped),
        );
        core::ptr::write(
            core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
            previous_dispatch,
        );
        unwound += 1;
        if !component.callback_suspended {
            release_dispatch_output_stage(dispatch_context);
        }
        USER_CALLBACK_DEAD_CLIENT_UNWINDS.fetch_add(1, Ordering::Relaxed);
        // A REDIRECTED frame consumed a `real-redirect` that can never become a `real-return`; record
        // it so the redirect ledger stays exact (see the counter's doc comment).
        USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS
            .fetch_add(was_redirected as u64, Ordering::Relaxed);
        print_str(b"[user-callback] dead client pi=");
        print_u64(client_pi as u64);
        print_str(b" -> failed callback api=");
        print_u64(request.api_index as u64);
        print_str(b"; win32k resumed completed=");
        print_u64(component.completed as u64);
        print_str(b" status=0x");
        print_hex(component.status as u32);
        print_str(b" depth=");
        print_u64((&*core::ptr::addr_of!(USER_CALLBACK_ACTIVE)).len() as u64);
        print_str(b"\n");
        if !component.completed
            || component.callback_suspended
            || !unwind_controlled_dispatch(request)
        {
            print_str(b"[user-callback] dead-client win32k dispatch failed to unwind -> reset\n");
            abort_controlled_user_callbacks();
            break;
        }
    }
    if unwound != 0 {
        let stack = &*core::ptr::addr_of!(USER_CALLBACK_CONTINUATIONS);
        print_str(b"[user-callback] dead-client unwind complete: frames=");
        print_u64(unwound);
        print_str(b" continuation-depth=");
        print_u64(stack.len() as u64);
        print_str(b" (win32k back in its dispatch receive loop)\n");
        if !stack.is_empty() {
            abort_controlled_user_callbacks();
        }
    }
    unwound
}

/// Retire callback-transport state after the exact process generation has completed provider and
/// VM rundown. The service loop is serialized, so clearing the per-pi death latch here occurs
/// before that pi can be admitted for a replacement generation.
pub(crate) unsafe fn retire_dead_user_callback_client(client_pi: u32, pid: u64) -> bool {
    if client_pi == 0 || client_pi >= 64 || pid == 0 || client_has_active_callback_frames(client_pi)
    {
        return false;
    }
    let registry = user_callback_client_registry_mut();
    registry.retain(|record| record.client.pi != client_pi || record.client.pid != pid);
    let suspended = suspended_published_contexts_mut();
    suspended.retain(|record| record.pi != client_pi || record.pid != pid);
    USER_CALLBACK_DEAD_CLIENTS.fetch_and(!(1u64 << client_pi), Ordering::Relaxed);
    true
}

pub(crate) unsafe fn complete_controlled_user_callback(
    client_pi: u32,
    client_badge: u64,
    client_tid: u64,
    result_pointer: u64,
    result_length: u64,
    callback_status: u64,
    _return_resume_ip: u64,
    return_rsp: u64,
    _return_flags: u64,
) -> Option<CompletedUserCallback> {
    // `NtCallbackReturn` returns the callback that is innermost ON THE CALLING THREAD — the caller's
    // own identity selects the frame, never the interleaved stack's global top.
    let identity = nt_user_callback::ClientThreadIdentity::new(client_pi, client_tid, client_badge);
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    let Some(active_frame) = active.top_for(&identity).copied() else {
        return None;
    };
    let client_process_role = callback_process_role_from_code(active_frame.client_process_role());
    let client_is_winlogon =
        client_process_role == Some(nt_exe_image::HostedProcessRole::InteractiveLogon);
    let client_is_explorer =
        client_process_role == Some(nt_exe_image::HostedProcessRole::InteractiveShell);
    let request = *active_frame.request();
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    // (The frame's client identity is the caller's by construction — `top_for` selected it.)
    if !active_frame.is_redirected() {
        return None;
    }
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
    if active.is_global_top(correlation) != Ok(true) {
        return None;
    }
    let contract = nt_user_callback::UserCallbackContract::for_api(request.api_index);
    if result_length > request.output_capacity as u64
        || (result_length != 0 && result_pointer == 0)
        || !contract.is_some_and(|contract| {
            contract.accepts_result(
                request.input_length,
                result_length as u32,
                callback_status as u32 as i32,
            )
        })
    {
        abort_controlled_user_callbacks();
        return None;
    }
    if result_length != 0 {
        if !copy_callback_result_to_shared(
            client_pi,
            active_frame.client_scratch_base(),
            result_pointer,
            result_length,
        ) {
            abort_controlled_user_callbacks();
            return None;
        }
    }
    let request_window_message = if request.api_index
        == nt_user_callback::USER32_CALLBACK_WINDOWPROC
        && result_length as usize >= 0x40
    {
        callback_payload_u32(frame, 0x18)
    } else {
        u32::MAX
    };
    let request_window = if request_window_message != u32::MAX {
        callback_payload_u64(frame, 0x10)
    } else {
        0
    };
    if result_length != 0 {
        if (client_is_winlogon || client_is_explorer) && request_window_message == 0x0081 {
            let expected = nt_user_callback::UserCallbackStackLayout::below(
                active_frame.saved_user_context()[nt_user_callback::USER_CONTEXT_RSP],
                request.input_length as usize,
            )
            .ok()
            .map(|layout| layout.input_pointer)
            .unwrap_or(0);
            let mut returned_result = [0u8; 8];
            let returned_read = result_length >= 0x40
                && crate::img_spawn::client_copyin_mapped(
                    client_pi as u64,
                    result_pointer + 0x38,
                    &mut returned_result,
                    &[],
                    0,
                    active_frame.client_scratch_base(),
                );
            let mut expected_result = [0u8; 8];
            let expected_read = expected != 0
                && request.input_length >= 0x40
                && crate::img_spawn::client_copyin_mapped(
                    client_pi as u64,
                    expected + 0x38,
                    &mut expected_result,
                    &[],
                    0,
                    active_frame.client_scratch_base(),
                );
            print_str(b"[callback-result] WM_NCCREATE pointer=0x");
            print_hex((result_pointer >> 32) as u32);
            print_hex(result_pointer as u32);
            print_str(b" pi=");
            print_u64(client_pi as u64);
            print_str(b" tid=");
            print_u64(request.client_tid);
            print_str(b" expected=0x");
            print_hex((expected >> 32) as u32);
            print_hex(expected as u32);
            print_str(b" length=0x");
            print_hex(result_length as u32);
            print_str(b" returned-read=");
            print_u64(returned_read as u64);
            print_str(b" returned-result=0x");
            print_hex(u64::from_le_bytes(returned_result) as u32);
            print_str(b" expected-read=");
            print_u64(expected_read as u64);
            print_str(b" expected-result=0x");
            print_hex(u64::from_le_bytes(expected_result) as u32);
            print_str(b"\n");
        }
        if request.api_index != nt_user_callback::USER32_CALLBACK_WINDOWPROC {
            let result0 = callback_payload_result_u64(frame, result_length as u32);
            print_str(b"[user-callback] real callback returned api=");
            print_u64(request.api_index as u64);
            print_str(b" status=0x");
            print_hex(callback_status as u32);
            print_str(b" result-length=0x");
            print_hex(result_length as u32);
            print_str(b" result0=0x");
            print_hex((result0 >> 32) as u32);
            print_hex(result0 as u32);
            print_str(b"\n");
        }
        if client_is_explorer
            && request_window_message == 0x0081
            && result_length >= 0x40
            && callback_payload_u64(frame, 0x38) == 0
        {
            let n = USER_CALLBACK_EXPLORER_NCCREATE_FALSES.fetch_add(1, Ordering::Relaxed);
            if n < 4 {
                print_str(b"[user-callback] explorer WM_NCCREATE returned FALSE hwnd=0x");
                print_hex(request_window as u32);
                print_str(b" result-pointer=0x");
                print_hex((result_pointer >> 32) as u32);
                print_hex(result_pointer as u32);
                print_str(b" length=0x");
                print_hex(result_length as u32);
                print_str(b"\n");
            }
        }
    }
    if client_is_winlogon
        && WINLOGON_DIALOG_MODAL_READY.load(Ordering::Relaxed) != 0
        && request_window_message != u32::MAX
    {
        print_str(b"[user-callback] IDD real api0 proc=0x");
        let proc = callback_payload_u64(frame, 0);
        print_hex((proc >> 32) as u32);
        print_hex(proc as u32);
        print_str(b" hwnd=0x");
        print_hex(request_window as u32);
        print_str(b" msg=0x");
        print_hex(request_window_message);
        print_str(b" result=0x");
        let result = if result_length >= 0x40 {
            callback_payload_u64(frame, 0x38)
        } else {
            0
        };
        print_hex((result >> 32) as u32);
        print_hex(result as u32);
        print_str(b" status=0x");
        print_hex(callback_status as u32);
        print_str(b"\n");
    }
    // ReactOS flushes the caller's deferred GDI batch after `KiCallUserMode` returns from a
    // `KeUserModeCallback`, before the suspended win32k continuation runs again. Normal win32k
    // syscalls already do this at syscall entry; callbacks need the same kernel-owned boundary so
    // user32/GDI work performed inside WndProc cannot keep stale records across chained callbacks.
    flush_returned_user_callback_gdi_batch(request, active_frame);
    // The flush can itself enter win32k, and win32k reuses the same shared callback page for every
    // nested dispatch. Re-publish the reply after the flush so the parked `KeUserModeCallback`
    // continuation consumes the result for THIS callback, not the last nested dispatch's header.
    if !publish_callback_reply(
        request,
        client_pi,
        active_frame.client_scratch_base(),
        result_pointer,
        result_length,
        callback_status,
    ) {
        abort_controlled_user_callbacks();
        return None;
    }
    if !unwind_controlled_callback(request) {
        print_str(b"[user-callback] NtCallbackReturn continuation correlation rejected\n");
        abort_controlled_user_callbacks();
        return None;
    }
    if sas_sequence_matches(&request) {
        let sequence = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_SAS_SEQUENCE));
        if sequence.can_complete() {
            USER_CALLBACK_SEQUENCE_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
        }
        USER_CALLBACK_SAS_SEQUENCE_ACTIVE.store(0, Ordering::Relaxed);
        USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID.store(0, Ordering::Relaxed);
    }
    print_str(
        b"[user-callback] A real callback completed through NtCallbackReturn; resuming B component\n",
    );
    let Ok(completed_frame) = active.pop(correlation) else {
        abort_controlled_user_callbacks();
        return None;
    };
    restore_client_callback_window(completed_frame);
    let dispatch_context = *completed_frame.dispatch_context();
    if dispatch_context.dispatch_id != request.dispatch_id {
        release_dispatch_output_stage(dispatch_context);
        abort_controlled_user_callbacks();
        return None;
    }
    if callback_status as u32 == 0
        && request_window_message == nt_user_callback::WM_PAINT
        && request_window != 0
    {
        USER_CALLBACK_REAL_WM_PAINT_RETURNS.fetch_add(1, Ordering::Relaxed);
        USER_CALLBACK_LAST_REAL_WM_PAINT_HWND.store(request_window, Ordering::Relaxed);
    }
    let previous_dispatch = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        dispatch_context,
    );
    let completed_client = callback_client_from_frame(request, completed_frame);
    let completed_context = win32k_client_context_from_callback_client(completed_client);
    let component = resume_suspended_user_callback_component(request, completed_client);
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous_dispatch,
    );
    if component.callback_suspended {
        let chained_client = completed_context;
        if callback_context_tcb(chained_client).is_none() {
            abort_controlled_user_callbacks();
            print_str(b"[user-callback] chained callback missing client TCB\n");
            return None;
        }
        let Some(chained_outer_resume_ip) = resolve_callback_resume_ip(
            chained_client,
            completed_frame.outer_resume_ip(),
            completed_frame.saved_user_context(),
            b"chained-outer",
        ) else {
            abort_controlled_user_callbacks();
            print_str(b"[user-callback] chained callback missing executable outer resume=0x");
            print_crash_hex64(completed_frame.outer_resume_ip());
            print_str(b"\n");
            return None;
        };
        let saved_outer = completed_frame.saved_user_context();
        if !redirect_pending_user_callback(
            chained_client,
            saved_outer,
            saved_outer,
            chained_outer_resume_ip,
            chained_outer_resume_ip,
            saved_outer[nt_user_callback::USER_CONTEXT_RSP],
            saved_outer[nt_user_callback::USER_CONTEXT_RFLAGS],
            b"chained-redirect",
        ) {
            abort_controlled_user_callbacks();
            print_str(b"[user-callback] chained callback redirect failed\n");
            return None;
        }
        USER_CALLBACK_REAL_RETURNS.fetch_add(1, Ordering::Relaxed);
        print_str(b"[user-callback] B yielded another callback; reused outer trap context\n");
        return Some(CompletedUserCallback {
            outer_dispatch: None,
        });
    }
    if !component.completed {
        release_dispatch_output_stage(dispatch_context);
        abort_controlled_user_callbacks();
        print_str(b"[user-callback] B component continuation failed to complete\n");
        return None;
    }
    if !unwind_controlled_dispatch(request) {
        release_dispatch_output_stage(dispatch_context);
        abort_controlled_user_callbacks();
        print_str(b"[user-callback] dispatch continuation failed to unwind\n");
        return None;
    }
    unregister_user_callback_client_for_dispatch(
        request.dispatch_id,
        request.client_pi,
        request.client_tid,
        request.client_badge,
    );
    // The client is about to resume in the ENCLOSING callback (or in its original syscall). This inner
    // callback's teardown — our own `restore_client_callback_window` above plus win32k's
    // `IntRestoreTebWndCallback` — can have left win32k's untranslated PWND in CLIENTINFO.CallbackWnd,
    // so restate the enclosing frame's bridged triple before the client runs again.
    reassert_top_client_callback_window(&identity);
    let Some(tcb) = (completed_frame.client_tcb() > 1).then_some(completed_frame.client_tcb())
    else {
        release_dispatch_output_stage(dispatch_context);
        return None;
    };
    let Some(completed_outer_resume_ip) = resolve_callback_resume_ip(
        completed_context,
        completed_frame.outer_resume_ip(),
        completed_frame.saved_user_context(),
        b"completed-outer",
    ) else {
        abort_controlled_user_callbacks();
        print_str(b"[user-callback] completed callback missing executable outer resume=0x");
        print_crash_hex64(completed_frame.outer_resume_ip());
        print_str(b"\n");
        release_dispatch_output_stage(dispatch_context);
        return None;
    };
    let completed = nt_user_callback::completed_outer_context(
        completed_frame.saved_user_context(),
        component.result,
        completed_outer_resume_ip,
    );
    let mut return_context = [0u64; 20];
    tcb_read_regs20(tcb, &mut return_context);
    trace_user_callback_context(
        b"complete",
        completed_context,
        request.api_index,
        &return_context,
        completed_frame.saved_user_context(),
        &completed,
        completed_outer_resume_ip,
        return_rsp,
    );
    if tcb_write_regs20(tcb, &completed, false) != 0 {
        release_dispatch_output_stage(dispatch_context);
        return None;
    }
    USER_CALLBACK_REAL_RETURNS.fetch_add(1, Ordering::Relaxed);
    print_str(b"[user-callback] B completed; restored A with result in RAX depth=");
    print_u64(active.len() as u64);
    print_str(b"\n");
    let mut outer_dispatch = CompletedWin32kDispatch::new(
        dispatch_context.ssn,
        dispatch_context.args,
        dispatch_context.caller_sp,
        component.result,
    );
    if matches!(
        dispatch_context.ssn,
        nt_user_callback::NTUSER_GET_MESSAGE_SSN | nt_user_callback::NTUSER_PEEK_MESSAGE_SSN
    ) {
        // The provider publishes output validity only after the real outer handler returns. Bind
        // those bytes from this dispatch's retained lease before releasing it; nested callbacks use
        // different leases and therefore cannot overwrite the parked MSG.
        if let Some(stage) = dispatch_context.output_stage {
            match published_win32k_output_length(stage) {
                Some(len) => {
                    outer_dispatch.provider_output_len = len;
                    if len != 0 {
                        let _ = outer_dispatch
                            .capture_arg_snapshot_from(stage.provider_pointer, u64::from(len));
                    }
                }
                None => outer_dispatch.provider_output_len = u32::MAX,
            }
            let _ = release_win32k_message_stage(stage);
        } else {
            outer_dispatch.provider_output_len = u32::MAX;
        }
    } else if dispatch_context.ssn == nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN {
        let frame_snapshot_len = completed_frame.arg_snapshot_len() as usize;
        if frame_snapshot_len != 0 {
            let snapshot = &completed_frame.arg_snapshot()[..frame_snapshot_len];
            let _ = outer_dispatch.set_arg_snapshot(snapshot);
        }
    } else if dispatch_context.ssn == win32k_subsystem::SSN_NT_USER_INITIALIZE
        && component.result == 0
    {
        let frame_snapshot_len = completed_frame.arg_snapshot_len() as usize;
        if frame_snapshot_len != 0 {
            let snapshot = &completed_frame.arg_snapshot()[..frame_snapshot_len];
            let _ = outer_dispatch.set_arg_snapshot(snapshot);
        } else {
            let _ = outer_dispatch.capture_arg_snapshot(dispatch_context.args[2]);
        }
    } else {
        release_dispatch_output_stage(dispatch_context);
    }
    Some(CompletedUserCallback {
        outer_dispatch: Some(outer_dispatch),
    })
}

unsafe fn map_win32k_arena_prefix_into_client(
    handler: &mut ExecNtHandler,
    pml4: u64,
    pi: usize,
    frame_base: u64,
    client_base: u64,
    max_frames: u64,
    target_frames: u64,
    mapped_frames: &[AtomicU64],
    mapped_guard: &AtomicU64,
    rights: u64,
    label: &[u8],
) -> bool {
    if frame_base == 0 || pi >= MAX_PI || pi >= 64 || max_frames == 0 {
        return false;
    }
    let Some(mapped_row) = mapped_frames.get(pi) else {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return false;
    };

    let target_frames = target_frames.min(max_frames);
    if target_frames == 0 {
        return false;
    }
    let bit = 1u64 << pi;
    let already_mapped = mapped_row.load(Ordering::Relaxed).min(max_frames);
    if already_mapped >= target_frames {
        mapped_guard.fetch_or(bit, Ordering::Relaxed);
        return true;
    }

    for p in (already_mapped + 511) / 512..(target_frames + 511) / 512 {
        if !win32k_client_cap_bank_map_page_table(
            handler,
            pml4,
            pi,
            client_base + p * 0x20_0000,
            label,
            p,
        ) {
            return false;
        }
    }
    for i in already_mapped..target_frames {
        let (cp, copy_error) = copy_cap_r(frame_base + i);
        if copy_error != 0 {
            print_str(b"[win32k-svc] failed to copy ");
            print_str(label);
            print_str(b" frame for pi=");
            print_u64(pi as u64);
            print_str(b" index=0x");
            print_hex(i as u32);
            print_str(b" error=");
            print_u64(copy_error);
            print_str(b"\n");
            if cp != 0 {
                let _ = cnode_delete_recycle_r(cp);
            }
            return false;
        }
        let map_error = page_map_r(cp, client_base + i * 0x1000, rights, pml4);
        if map_error != 0 {
            print_str(b"[win32k-svc] failed to map ");
            print_str(label);
            print_str(b" into pi=");
            print_u64(pi as u64);
            print_str(b" va=0x");
            print_hex(((client_base + i * 0x1000) >> 32) as u32);
            print_hex((client_base + i * 0x1000) as u32);
            print_str(b" error=");
            print_u64(map_error);
            print_str(b"\n");
            let _ = cnode_delete_recycle_r(cp);
            return false;
        }
        if !win32k_client_cap_bank_store(pi, cp) {
            print_str(b"[win32k-svc] failed to retain ");
            print_str(label);
            print_str(b" mapping cap for pi=");
            print_u64(pi as u64);
            print_str(b" index=0x");
            print_hex(i as u32);
            print_str(b"\n");
            let _ = page_unmap_r(cp);
            let _ = cnode_delete_recycle_r(cp);
            return false;
        }
        mapped_row.store(i + 1, Ordering::Relaxed);
    }

    mapped_guard.fetch_or(bit, Ordering::Relaxed);
    true
}

unsafe fn win32k_client_cap_bank_map_page_table(
    handler: &mut ExecNtHandler,
    pml4: u64,
    pi: usize,
    vaddr: u64,
    label: &[u8],
    index: u64,
) -> bool {
    if let Err(status) = ensure_process_user_page_table(handler, pi, vaddr, pml4) {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        print_str(b"[win32k-svc] failed to map ");
        print_str(label);
        print_str(b" page table for pi=");
        print_u64(pi as u64);
        print_str(b" index=0x");
        print_hex(index as u32);
        print_str(b" status=0x");
        print_hex(status);
        print_str(b"\n");
        return false;
    }
    true
}

unsafe fn win32k_client_cap_bank_ensure_segment(segment: usize) -> Option<u64> {
    if segment >= WIN32K_CLIENT_CAP_BANK_SEGMENTS {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let existing = WIN32K_CLIENT_CAP_BANK_CNODE[segment].load(Ordering::Relaxed);
    if existing != 0 {
        return Some(existing);
    }
    let Some(raw) = try_alloc_slot() else {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    if untyped_retype_r(
        CAP_INIT_UNTYPED,
        OBJ_CNODE,
        WIN32K_CLIENT_CAP_BANK_RADIX,
        1,
        raw,
    ) != 0
    {
        recycle_deleted_root_slot(raw);
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    let Some(cnode) = try_alloc_slot() else {
        let _ = cnode_delete_recycle_r(raw);
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return None;
    };
    let mint = cnode_mint_r(
        CAP_INIT_THREAD_CNODE,
        cnode,
        raw,
        WIN32K_CLIENT_CAP_BANK_GUARD_BADGE,
    );
    if mint != 0 {
        recycle_deleted_root_slot(cnode);
        let _ = cnode_delete_recycle_r(raw);
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    WIN32K_CLIENT_CAP_BANK_RAW[segment].store(raw, Ordering::Relaxed);
    WIN32K_CLIENT_CAP_BANK_CNODE[segment].store(cnode, Ordering::Relaxed);
    Some(cnode)
}

fn win32k_client_cap_bank_slot_location(global_slot: u64) -> Option<(usize, u64)> {
    if global_slot >= WIN32K_CLIENT_CAP_BANK_SLOTS {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return None;
    }
    Some((
        (global_slot / WIN32K_CLIENT_CAP_BANK_SEGMENT_SLOTS) as usize,
        global_slot % WIN32K_CLIENT_CAP_BANK_SEGMENT_SLOTS,
    ))
}

fn win32k_client_cap_bank_next_slot() -> Option<(u64, usize, u64)> {
    let free_head = WIN32K_CLIENT_CAP_BANK_FREE_HEAD.load(Ordering::Relaxed);
    if free_head != 0 {
        let global_slot = free_head - 1;
        let owner_slot = global_slot as usize;
        if global_slot >= WIN32K_CLIENT_CAP_BANK_SLOTS
            || WIN32K_CLIENT_CAP_BANK_OWNER[owner_slot].load(Ordering::Relaxed) != 0
        {
            WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        WIN32K_CLIENT_CAP_BANK_FREE_HEAD.store(
            WIN32K_CLIENT_CAP_BANK_FREE_NEXT[owner_slot].load(Ordering::Relaxed),
            Ordering::Relaxed,
        );
        WIN32K_CLIENT_CAP_BANK_FREE_NEXT[owner_slot].store(0, Ordering::Relaxed);
        let (segment, segment_slot) = win32k_client_cap_bank_slot_location(global_slot)?;
        return Some((global_slot, segment, segment_slot));
    }

    let next = WIN32K_CLIENT_CAP_BANK_NEXT.load(Ordering::Relaxed);
    let (segment, segment_slot) = win32k_client_cap_bank_slot_location(next)?;
    Some((next, segment, segment_slot))
}

unsafe fn win32k_client_cap_bank_store(pi: usize, root_cap: u64) -> bool {
    if pi >= MAX_PI || pi >= u8::MAX as usize || root_cap == 0 {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    let Some(live_row) = win32k_client_cap_bank_live_row(pi) else {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return false;
    };
    let Some((next, segment, segment_slot)) = win32k_client_cap_bank_next_slot() else {
        return false;
    };
    let Some(cnode) = win32k_client_cap_bank_ensure_segment(segment) else {
        return false;
    };
    let label = cnode_move_root_to_cnode_r(cnode, segment_slot, root_cap);
    if label != 0 {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    if WIN32K_CLIENT_CAP_BANK_OWNER[next as usize].swap((pi + 1) as u8, Ordering::Relaxed) != 0 {
        let _ = cnode_delete_in_cnode_r(cnode, segment_slot);
        recycle_deleted_root_slot(root_cap);
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return false;
    }
    recycle_deleted_root_slot(root_cap);
    if next == WIN32K_CLIENT_CAP_BANK_NEXT.load(Ordering::Relaxed) {
        WIN32K_CLIENT_CAP_BANK_NEXT.store(next + 1, Ordering::Relaxed);
    }
    WIN32K_CLIENT_CAP_BANK_TO_BANK.fetch_add(1, Ordering::Relaxed);
    live_row.fetch_add(1, Ordering::Relaxed);
    let live = WIN32K_CLIENT_CAP_BANK_LIVE_TOTAL.fetch_add(1, Ordering::Relaxed) + 1;
    note_high_water(&WIN32K_CLIENT_CAP_BANK_LIVE_HW, live);
    true
}

pub(crate) fn win32k_client_cap_bank_stats() -> (u64, u64, u64, u64, u64) {
    let mut processes = 0u64;
    let mut banks = 0u64;
    let rows = unsafe { &*core::ptr::addr_of!(WIN32K_CLIENT_CAP_BANK_LIVE_BY_PI) };
    for row in rows.iter() {
        if row.load(Ordering::Relaxed) != 0 {
            processes += 1;
        }
    }
    for segment in 0..WIN32K_CLIENT_CAP_BANK_SEGMENTS {
        if WIN32K_CLIENT_CAP_BANK_CNODE[segment].load(Ordering::Relaxed) != 0 {
            banks += 1;
        }
    }
    let live = WIN32K_CLIENT_CAP_BANK_LIVE_TOTAL.load(Ordering::Relaxed);
    (
        live,
        WIN32K_CLIENT_CAP_BANK_NEXT.load(Ordering::Relaxed),
        processes,
        banks,
        WIN32K_CLIENT_CAP_BANK_FAILS.load(Ordering::Relaxed),
    )
}

pub(crate) fn win32k_client_cap_bank_is_empty(pi: usize) -> bool {
    unsafe { win32k_client_cap_bank_live_row(pi) }
        .is_some_and(|row| row.load(Ordering::Acquire) == 0)
}

#[derive(Clone, Copy, Default)]
pub(crate) struct Win32kClientCapBankReclaimStats {
    pub caps: u64,
    pub failures: u64,
}

pub(crate) unsafe fn release_win32k_client_cap_bank(pi: usize) -> Win32kClientCapBankReclaimStats {
    if pi >= MAX_PI || pi >= u8::MAX as usize {
        return Win32kClientCapBankReclaimStats::default();
    }
    let Some(live_row) = win32k_client_cap_bank_live_row(pi) else {
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        return Win32kClientCapBankReclaimStats {
            caps: 0,
            failures: 1,
        };
    };
    if pi < 64 {
        let bit = !(1u64 << pi);
        WIN32K_CLIENT_MAPPED.fetch_and(bit, Ordering::Relaxed);
        WIN32K_POOL_CLIENT_MAPPED.fetch_and(bit, Ordering::Relaxed);
        GDI_SHARED_TABLE_MAPPED.fetch_and(bit, Ordering::Relaxed);
        GDI_USERVM_MAPPED.fetch_and(bit, Ordering::Relaxed);
    }
    if let Some(row) = win32k_user_heap_mapped_row(pi) {
        row.store(0, Ordering::Relaxed);
    }
    if let Some(row) = win32k_pool_mapped_row(pi) {
        row.store(0, Ordering::Relaxed);
    }
    if let Some(row) = gdi_uservm_mapped_row(pi) {
        row.store(0, Ordering::Relaxed);
    }

    let live = live_row.load(Ordering::Relaxed);
    if live == 0 {
        return Win32kClientCapBankReclaimStats::default();
    }

    let owner = (pi + 1) as u8;
    let scan_limit = WIN32K_CLIENT_CAP_BANK_NEXT
        .load(Ordering::Relaxed)
        .min(WIN32K_CLIENT_CAP_BANK_SLOTS);
    let mut released = 0u64;
    let mut failures = 0u64;
    for global_slot in 0..scan_limit {
        let owner_slot = global_slot as usize;
        if WIN32K_CLIENT_CAP_BANK_OWNER[owner_slot].load(Ordering::Relaxed) != owner {
            continue;
        }
        let Some((segment, segment_slot)) = win32k_client_cap_bank_slot_location(global_slot)
        else {
            failures = failures.saturating_add(1);
            continue;
        };
        let cnode = WIN32K_CLIENT_CAP_BANK_CNODE[segment].load(Ordering::Relaxed);
        if cnode == 0 {
            failures = failures.saturating_add(1);
            if failures <= 4 {
                print_str(b"[w32-bank-release] missing cnode pi=");
                print_u64(pi as u64);
                print_str(b" global-slot=0x");
                print_hex(global_slot as u32);
                print_str(b" segment=");
                print_u64(segment as u64);
                print_str(b"\n");
            }
            continue;
        }
        let label = cnode_delete_in_cnode_r(cnode, segment_slot);
        if label == 0 {
            WIN32K_CLIENT_CAP_BANK_OWNER[owner_slot].store(0, Ordering::Relaxed);
            let head = WIN32K_CLIENT_CAP_BANK_FREE_HEAD.load(Ordering::Relaxed);
            WIN32K_CLIENT_CAP_BANK_FREE_NEXT[owner_slot].store(head, Ordering::Relaxed);
            WIN32K_CLIENT_CAP_BANK_FREE_HEAD.store(global_slot + 1, Ordering::Relaxed);
            released = released.saturating_add(1);
        } else {
            failures = failures.saturating_add(1);
            if failures <= 4 {
                print_str(b"[w32-bank-release] failed pi=");
                print_u64(pi as u64);
                print_str(b" cnode=0x");
                print_hex(cnode as u32);
                print_str(b" slot=0x");
                print_hex(segment_slot as u32);
                print_str(b" label=");
                print_u64(label);
                print_str(b"\n");
            }
        }
    }

    if released < live && failures == 0 {
        let missing = live - released;
        failures = failures.saturating_add(missing);
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(1, Ordering::Relaxed);
        print_str(b"[w32-bank-release] missing records pi=");
        print_u64(pi as u64);
        print_str(b" live=");
        print_u64(live);
        print_str(b" released=");
        print_u64(released);
        print_str(b"\n");
    }
    if WIN32K_CLIENT_CAP_BANK_LIVE_TOTAL.load(Ordering::Relaxed) == released {
        WIN32K_CLIENT_CAP_BANK_NEXT.store(0, Ordering::Relaxed);
        WIN32K_CLIENT_CAP_BANK_FREE_HEAD.store(0, Ordering::Relaxed);
    }

    let accounted = released.min(live);
    if accounted != 0 {
        WIN32K_CLIENT_CAP_BANK_RELEASES.fetch_add(accounted, Ordering::Relaxed);
        WIN32K_CLIENT_CAP_BANK_LIVE_TOTAL.fetch_sub(accounted, Ordering::Relaxed);
    }
    if failures == 0 {
        live_row.store(0, Ordering::Relaxed);
    } else {
        live_row.store(live.saturating_sub(accounted), Ordering::Relaxed);
        WIN32K_CLIENT_CAP_BANK_FAILS.fetch_add(failures, Ordering::Relaxed);
    }
    if released != 0 || failures != 0 {
        print_str(b"[w32-bank-release] pi=");
        print_u64(pi as u64);
        print_str(b" caps=");
        print_u64(released);
        print_str(b" failures=");
        print_u64(failures);
        print_str(b" next=");
        print_u64(WIN32K_CLIENT_CAP_BANK_NEXT.load(Ordering::Relaxed));
        print_str(b" total-released=");
        print_u64(WIN32K_CLIENT_CAP_BANK_RELEASES.load(Ordering::Relaxed));
        print_str(b"\n");
    }
    Win32kClientCapBankReclaimStats {
        caps: released,
        failures,
    }
}

/// RO-map win32k's global USER heap arena ([`win32k_subsystem::WIN32K_HEAP_VADDR`], where gpsi,
/// gHandleTable, handle entries, desktop-heap data, and live WND/CLS objects can live) into the GUI
/// client `pi`'s VSpace at [`win32k_subsystem::CSRSS_W32_SHARED_VA`]. Returns the server→client delta
/// (`WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`) only after the mapping is actually installed.
pub(crate) unsafe fn map_win32k_user_heap_into_client(
    handler: &mut ExecNtHandler,
    pml4: u64,
    pi: usize,
) -> Option<u64> {
    let delta = win32k_subsystem::WIN32K_HEAP_VADDR - win32k_subsystem::CSRSS_W32_SHARED_VA;
    let heap_base = WIN32K_HEAP_FRAME_BASE.load(Ordering::Relaxed);
    let already_mapped = win32k_user_heap_mapped_row(pi)
        .is_some_and(|row| row.load(Ordering::Relaxed) != 0)
        || (pi < 64 && WIN32K_CLIENT_MAPPED.load(Ordering::Relaxed) & (1u64 << pi) != 0);
    if !map_win32k_arena_prefix_into_client(
        handler,
        pml4,
        pi,
        heap_base,
        win32k_subsystem::CSRSS_W32_SHARED_VA,
        win32k_subsystem::WIN32K_HEAP_FRAMES,
        win32k_subsystem::win32k_user_heap_committed_frames(),
        win32k_user_heap_mapped_rows(),
        &WIN32K_CLIENT_MAPPED,
        2 | PAGE_EXECUTE_NEVER,
        b"win32k USER heap",
    ) {
        return None;
    }
    if !already_mapped {
        print_str(b"[win32k-svc] RO-mapped win32k USER heap into pi 0x");
        print_hex(pi as u32);
        print_str(b" @0x");
        print_hex(win32k_subsystem::CSRSS_W32_SHARED_VA as u32);
        print_str(b" (delta=0x");
        print_hex((delta >> 32) as u32);
        print_hex(delta as u32);
        print_str(b")\n");
    }
    Some(delta)
}

/// RO-map win32k's POOL arena ([`win32k_subsystem::WIN32K_POOL_VADDR`], where session-lifetime object
/// bodies can live) into the GUI client `pi`'s VSpace at [`win32k_subsystem::CSRSS_W32_POOL_VA`].
/// DESKTOPINFO is translated by the arena that actually owns the pointer; the current ReactOS desktop
/// heap path places it in the USER heap, but pool-resident objects still need this window. Returns the
/// pool server→client delta only after the mapping is actually installed.
pub(crate) unsafe fn map_win32k_pool_into_client(
    handler: &mut ExecNtHandler,
    pml4: u64,
    pi: usize,
) -> Option<u64> {
    let delta = win32k_subsystem::WIN32K_POOL_VADDR - win32k_subsystem::CSRSS_W32_POOL_VA;
    let pool_base = WIN32K_POOL_FRAME_BASE.load(Ordering::Relaxed);
    let already_mapped = win32k_pool_mapped_row(pi)
        .is_some_and(|row| row.load(Ordering::Relaxed) != 0)
        || (pi < 64 && WIN32K_POOL_CLIENT_MAPPED.load(Ordering::Relaxed) & (1u64 << pi) != 0);
    if !map_win32k_arena_prefix_into_client(
        handler,
        pml4,
        pi,
        pool_base,
        win32k_subsystem::CSRSS_W32_POOL_VA,
        win32k_subsystem::WIN32K_POOL_FRAMES,
        win32k_subsystem::WIN32K_POOL_FRAMES,
        win32k_pool_mapped_rows(),
        &WIN32K_POOL_CLIENT_MAPPED,
        2 | PAGE_EXECUTE_NEVER,
        b"win32k POOL",
    ) {
        return None;
    }
    if !already_mapped {
        print_str(b"[win32k-svc] RO-mapped win32k POOL into pi 0x");
        print_hex(pi as u32);
        print_str(b" @0x");
        print_hex(win32k_subsystem::CSRSS_W32_POOL_VA as u32);
        print_str(b" (pool-delta=0x");
        print_hex((delta >> 32) as u32);
        print_hex(delta as u32);
        print_str(b")\n");
    }
    Some(delta)
}

/// Publish the GDI shared handle table pointer for GUI client `pi`.
///
/// ReactOS win32k returns a user-mode pointer from `GDI_MapHandleTable`, then gdi32 caches
/// `PEB->GdiSharedHandleTable` during process setup. Our table is allocated inside win32k's USER heap,
/// so the correct client pointer is the USER-heap alias of that allocation. The committed USER heap
/// prefix mapping installed here covers the table pages; a second table window would retain duplicate
/// frame caps for every GUI process.
pub(crate) unsafe fn map_gdi_shared_handle_table_into_client(
    handler: &mut ExecNtHandler,
    pml4: u64,
    pi: usize,
) -> u64 {
    let server_base = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_GDI_TABLE_BASE) as *const u64,
    );
    let size = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_GDI_TABLE_SIZE) as *const u64,
    );
    let heap_frames = WIN32K_HEAP_FRAME_BASE.load(Ordering::Relaxed);
    if server_base < win32k_subsystem::WIN32K_HEAP_VADDR
        || size < win32k_subsystem::GDI_HANDLE_COUNT * win32k_subsystem::GDI_TABLE_ENTRY_SIZE
        || size > win32k_subsystem::GDI_SHARED_TABLE_MAX_BYTES
        || heap_frames == 0
    {
        return 0;
    }
    let server_page = server_base & !0xfff;
    let intra_page = server_base - server_page;
    let source_offset = (server_page - win32k_subsystem::WIN32K_HEAP_VADDR) / 0x1000;
    let Some(client_base) = win32k_subsystem::win32k_heap_server_to_client(server_base) else {
        return 0;
    };
    let frames = (intra_page + size + 0xfff) / 0x1000;
    if source_offset + frames > win32k_subsystem::WIN32K_HEAP_FRAMES {
        return 0;
    }
    if map_win32k_user_heap_into_client(handler, pml4, pi).is_none() {
        return 0;
    }
    GDI_SHARED_TABLE_FRAME_BASE.store(heap_frames + source_offset, Ordering::Relaxed);
    if pi < 64
        && GDI_SHARED_TABLE_MAPPED.fetch_or(1u64 << pi, Ordering::Relaxed) & (1u64 << pi) == 0
    {
        print_str(b"[win32k-svc] GDI handle table uses USER heap alias in pi 0x");
        print_hex(pi as u32);
        print_str(b" bytes=0x");
        print_hex(size as u32);
        print_str(b" client-table=0x");
        print_hex((client_base >> 32) as u32);
        print_hex(client_base as u32);
        print_str(b"\n");
    }
    client_base
}

pub(crate) unsafe fn map_gdi_user_attributes_into_client(
    handler: &mut ExecNtHandler,
    pml4: u64,
    pi: usize,
) -> bool {
    let base = WIN32K_USERVM_FRAME_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return false;
    }
    let already_mapped =
        gdi_uservm_mapped_row(pi).is_some_and(|row| row.load(Ordering::Relaxed) != 0);
    let mapped = map_win32k_arena_prefix_into_client(
        handler,
        pml4,
        pi,
        base,
        win32k_subsystem::WIN32K_USERVM_VADDR,
        win32k_subsystem::WIN32K_USERVM_FRAMES,
        win32k_subsystem::win32k_uservm_committed_frames(),
        gdi_uservm_mapped_rows(),
        &GDI_USERVM_MAPPED,
        RW_NX,
        b"live GDI user attributes",
    );
    if mapped && !already_mapped {
        print_str(b"[win32k-svc] RW-mapped live GDI user attributes into pi 0x");
        print_hex(pi as u32);
        print_str(b"\n");
    }
    mapped
}

// --- win32k cross-AS client-memory sharing (the authentic "win32k shares the caller's user AS") ---
// win32k-side paging structures provisioned for the shared client window, and pages already mapped,
// keyed by a level-tagged aligned index. Hosted client VAs can overlap win32k's high PML4 slot, so
// the sparse pager treats `DeleteFirst` while mapping a paging structure as "that level already
// exists" and only records levels whose map was observed to succeed or already be present.
static mut W32_CLIENT_SEEN: Option<Vec<u64>> = None;
const SEL4_FAILED_LOOKUP: u64 = 6;
const SEL4_DELETE_FIRST: u64 = 8;
static W32_PAGING_REPAIR_ATTEMPTS: AtomicU64 = AtomicU64::new(0);
static W32_PAGING_REPAIR_SUCCESSES: AtomicU64 = AtomicU64::new(0);

unsafe fn w32_client_seen_mut() -> &'static mut Vec<u64> {
    let slot = &mut *core::ptr::addr_of_mut!(W32_CLIENT_SEEN);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

pub(crate) unsafe fn w32_seen(key: u64) -> bool {
    (&*core::ptr::addr_of!(W32_CLIENT_SEEN))
        .as_ref()
        .is_some_and(|entries| entries.iter().any(|entry| *entry == key))
}

pub(crate) unsafe fn w32_mark(key: u64) {
    let entries = w32_client_seen_mut();
    if entries.iter().any(|entry| *entry == key) {
        return;
    }
    if entries.try_reserve(1).is_err() {
        print_str(b"[w32paging] seen-set allocation failed key=0x");
        print_hex((key >> 32) as u32);
        print_hex(key as u32);
        print_str(b"\n");
        return;
    }
    entries.push(key);
}

unsafe fn w32_forget(key: u64) -> bool {
    let entries = w32_client_seen_mut();
    let mut i = 0usize;
    let mut removed = false;
    while i < entries.len() {
        if entries[i] == key {
            entries.swap_remove(i);
            removed = true;
        } else {
            i += 1;
        }
    }
    removed
}

unsafe fn w32_client_paging_keys(page: u64) -> (u64, u64, u64) {
    (
        (1u64 << 60) | (page >> 39),
        (2u64 << 60) | (page >> 30),
        (3u64 << 60) | (page >> 21),
    )
}

unsafe fn w32_forget_client_paging(page: u64) {
    let (pdpt, pd, pt) = w32_client_paging_keys(page);
    let removed = (w32_forget(pt) as u64) + (w32_forget(pd) as u64) + (w32_forget(pdpt) as u64);
    if W32_PAGING_REPAIR_ATTEMPTS.fetch_add(1, Ordering::Relaxed) < 16 {
        print_str(b"[w32paging] stale hierarchy suspected page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" forgot=");
        print_u64(removed);
        print_str(b"\n");
    }
}

unsafe fn ensure_w32_paging_level(
    key: u64,
    object_type: u64,
    map_label: u64,
    page: u64,
    w_pml4: u64,
    level: &[u8],
) -> bool {
    if w32_seen(key) {
        return true;
    }
    let slot = alloc_slot();
    let retype = untyped_retype_r(CAP_INIT_UNTYPED, object_type, PAGING_BITS, 1, slot);
    if retype != 0 {
        print_str(b"[w32paging] retype ");
        print_str(level);
        print_str(b" failed page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" error=");
        print_u64(retype);
        print_str(b"\n");
        let _ = cnode_delete_recycle_r(slot);
        return false;
    }
    let map = paging_struct_map_r(slot, map_label, page, w_pml4);
    if map == 0 {
        w32_mark(key);
        return true;
    }
    let _ = cnode_delete_recycle_r(slot);
    if map == SEL4_DELETE_FIRST {
        w32_mark(key);
        return true;
    }
    print_str(b"[w32paging] map ");
    print_str(level);
    print_str(b" failed page=0x");
    print_hex((page >> 32) as u32);
    print_hex(page as u32);
    print_str(b" error=");
    print_u64(map);
    print_str(b"\n");
    false
}
/// Ensure win32k's VSpace has a PDPT/PD/PT chain covering `page` (each created once, tracked in
/// W32_CLIENT_SEEN). Used both for FOREIGN client pages (PML4[0/1], fresh hierarchy) AND for
/// win32k-OWN demand-mapped regions (the demand-mapped pool at 0x0A00, whose 2 MiB PTs don't exist
/// yet). Returns false when a required paging-structure map really failed.
pub(crate) unsafe fn ensure_w32_client_paging(page: u64, w_pml4: u64) -> bool {
    let (k_pdpt, k_pd, k_pt) = w32_client_paging_keys(page);
    if !ensure_w32_paging_level(
        k_pdpt,
        OBJ_X86_PDPT,
        LBL_X86_PDPT_MAP,
        page,
        w_pml4,
        b"pdpt",
    ) {
        return false;
    }
    if !ensure_w32_paging_level(
        k_pd,
        OBJ_X86_PAGE_DIRECTORY,
        LBL_X86_PAGE_DIRECTORY_MAP,
        page,
        w_pml4,
        b"pd",
    ) {
        return false;
    }
    ensure_w32_paging_level(
        k_pt,
        OBJ_X86_PAGE_TABLE,
        LBL_X86_PAGE_TABLE_MAP,
        page,
        w_pml4,
        b"pt",
    )
}

unsafe fn w32_map_frame_copy_checked(
    frame: u64,
    page: u64,
    rights: u64,
    w_pml4: u64,
    what: &[u8],
) -> u64 {
    if !ensure_w32_client_paging(page, w_pml4) {
        return 0;
    }

    let (cc, copy_error) = copy_cap_r(frame);
    if copy_error != 0 {
        print_str(b"[w32attach] ");
        print_str(what);
        print_str(b" copy failed page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" frame=0x");
        print_hex(frame as u32);
        print_str(b" error=");
        print_u64(copy_error);
        print_str(b"\n");
        if cc != 0 {
            let _ = cnode_delete_recycle_r(cc);
        }
        return 0;
    }

    let map = page_map_r(cc, page, rights, w_pml4);
    if map == 0 {
        return cc;
    }
    let _ = cnode_delete_recycle_r(cc);

    if map == SEL4_FAILED_LOOKUP {
        w32_forget_client_paging(page);
        if ensure_w32_client_paging(page, w_pml4) {
            let (retry, retry_copy) = copy_cap_r(frame);
            if retry_copy == 0 {
                let retry_map = page_map_r(retry, page, rights, w_pml4);
                if retry_map == 0 {
                    if W32_PAGING_REPAIR_SUCCESSES.fetch_add(1, Ordering::Relaxed) < 16 {
                        print_str(b"[w32paging] repaired hierarchy for ");
                        print_str(what);
                        print_str(b" page=0x");
                        print_hex((page >> 32) as u32);
                        print_hex(page as u32);
                        print_str(b"\n");
                    }
                    return retry;
                }
                print_str(b"[w32attach] ");
                print_str(what);
                print_str(b" retry map failed page=0x");
                print_hex((page >> 32) as u32);
                print_hex(page as u32);
                print_str(b" rights=0x");
                print_hex(rights as u32);
                print_str(b" error=");
                print_u64(retry_map);
                print_str(b"\n");
            } else {
                print_str(b"[w32attach] ");
                print_str(what);
                print_str(b" retry copy failed page=0x");
                print_hex((page >> 32) as u32);
                print_hex(page as u32);
                print_str(b" frame=0x");
                print_hex(frame as u32);
                print_str(b" error=");
                print_u64(retry_copy);
                print_str(b"\n");
            }
            if retry != 0 {
                let _ = cnode_delete_recycle_r(retry);
            }
            return 0;
        }
    }

    print_str(b"[w32attach] ");
    print_str(what);
    print_str(b" map failed page=0x");
    print_hex((page >> 32) as u32);
    print_hex(page as u32);
    print_str(b" rights=0x");
    print_hex(rights as u32);
    print_str(b" error=");
    print_u64(map);
    print_str(b"\n");
    0
}

unsafe fn w32_map_registered_client_frame_copy_checked(
    pi: u64,
    page: u64,
    rights: u64,
    w_pml4: u64,
    what: &[u8],
) -> u64 {
    if !ensure_w32_client_paging(page, w_pml4) {
        return 0;
    }

    let (cc, source, copy_error) = crate::csrss_frame_copy_exact_for_win32k(pi, page);
    if copy_error != 0 {
        print_str(b"[w32attach] ");
        print_str(what);
        print_str(b" copy failed page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" source=0x");
        print_hex(source as u32);
        print_str(b" error=");
        print_u64(copy_error);
        print_str(b"\n");
        return 0;
    }

    let map = page_map_r(cc, page, rights, w_pml4);
    if map == 0 {
        return cc;
    }
    let _ = cnode_delete_recycle_r(cc);

    if map == SEL4_FAILED_LOOKUP {
        w32_forget_client_paging(page);
        if ensure_w32_client_paging(page, w_pml4) {
            let (retry, retry_source, retry_copy) =
                crate::csrss_frame_copy_exact_for_win32k(pi, page);
            if retry_copy == 0 {
                let retry_map = page_map_r(retry, page, rights, w_pml4);
                if retry_map == 0 {
                    if W32_PAGING_REPAIR_SUCCESSES.fetch_add(1, Ordering::Relaxed) < 16 {
                        print_str(b"[w32paging] repaired hierarchy for ");
                        print_str(what);
                        print_str(b" page=0x");
                        print_hex((page >> 32) as u32);
                        print_hex(page as u32);
                        print_str(b"\n");
                    }
                    return retry;
                }
                print_str(b"[w32attach] ");
                print_str(what);
                print_str(b" retry map failed page=0x");
                print_hex((page >> 32) as u32);
                print_hex(page as u32);
                print_str(b" rights=0x");
                print_hex(rights as u32);
                print_str(b" error=");
                print_u64(retry_map);
                print_str(b"\n");
            } else {
                print_str(b"[w32attach] ");
                print_str(what);
                print_str(b" retry copy failed page=0x");
                print_hex((page >> 32) as u32);
                print_hex(page as u32);
                print_str(b" source=0x");
                print_hex(retry_source as u32);
                print_str(b" error=");
                print_u64(retry_copy);
                print_str(b"\n");
            }
            if retry != 0 {
                let _ = cnode_delete_recycle_r(retry);
            }
            return 0;
        }
    }

    print_str(b"[w32attach] ");
    print_str(what);
    print_str(b" map failed page=0x");
    print_hex((page >> 32) as u32);
    print_hex(page as u32);
    print_str(b" rights=0x");
    print_hex(rights as u32);
    print_str(b" error=");
    print_u64(map);
    print_str(b"\n");
    0
}
// --- win32k per-client attach/detach (the KeStackAttachProcess model) ---------------------------
// win32k's client window is shared with EXACTLY ONE GUI client at a time. csrss (pi 1) and winlogon
// (pi 2) map an overlapping DLL/stack set at IDENTICAL VAs but DISTINCT frames, so a static shared
// window can't hold both — win32k must re-point (attach to) the CURRENT dispatch's client. The
// attach table records the client leaf pages currently mapped into win32k (page -> the copy_cap
// slot used, so we can Unmap it on detach). On a client switch we Unmap the previous client's leaf
// pages (they re-fault fresh for the new client, resolving the colliding VA to THIS client's frame);
// the PDPT/PD/PT structures persist in W32_CLIENT_SEEN (empty tables after the leaf Unmap). The
// arch-level Unmap uses the invoked (win32k) cap's asid → only win32k's mapping is torn down; the
// client keeps its own mapping in its own VSpace.
/// Bit `pi` set once any hosted GUI client's `NtUserProcessConnect` (SSN 0x10FA) has been routed to
/// win32k, returned STATUS_SUCCESS, and copied USERCONNECT back to the caller. Early bits still feed
/// the historical csrss/winlogon/services gates, and later bits are the generic client-connected
/// signal for userinit, shell, and service descendants.
pub(crate) static W32_CONNECTED_MASK: AtomicU64 = AtomicU64::new(0);
pub(crate) static W32_ATTACHED_PI: AtomicU64 = AtomicU64::new(0xFFFF_FFFF);
/// The process index whose call `win32k_dispatch` is currently servicing. The service bootstrap
/// publishes the dynamically discovered Win32-subsystem process before starting the component;
/// every later forward arm replaces it with the exact routed client identity.
pub(crate) static W32_CLIENT_PI: AtomicU64 = AtomicU64::new(u64::MAX);

#[derive(Clone, Copy)]
struct W32AttachMapping {
    page: u64,
    slot: u64,
    rights: u64,
}

static mut W32_ATTACH_MAPPINGS: Option<Vec<W32AttachMapping>> = None;

unsafe fn w32_attach_mappings_mut() -> &'static mut Vec<W32AttachMapping> {
    let slot = &mut *core::ptr::addr_of_mut!(W32_ATTACH_MAPPINGS);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

/// Is `page` currently mapped into win32k for the attached client?
pub(crate) unsafe fn w32_attach_mapped(page: u64) -> bool {
    (&*core::ptr::addr_of!(W32_ATTACH_MAPPINGS))
        .as_ref()
        .is_some_and(|mappings| {
            mappings
                .iter()
                .any(|mapping| mapping.page == page && mapping.slot != 0)
        })
}

/// Re-point `page`'s attach record at a NEW copy-cap `slot` with `rights` (the copy-on-write and
/// narrow-remap swaps below), so detach Unmap tears down whichever frame is actually mapped.
/// Returns the OLD slot, OLD rights, and whether the requested replacement was recorded.
pub(crate) unsafe fn w32_attach_replace_mapping(
    page: u64,
    slot: u64,
    rights: u64,
) -> (u64, u64, bool) {
    let mappings = w32_attach_mappings_mut();
    let mut i = 0usize;
    while i < mappings.len() {
        if mappings[i].page == page {
            let old = mappings[i].slot;
            let old_rights = mappings[i].rights;
            if slot == 0 {
                mappings.swap_remove(i);
            } else {
                mappings[i].slot = slot;
                mappings[i].rights = rights;
            }
            return (old, old_rights, true);
        }
        i += 1;
    }
    let recorded = slot == 0 || w32_attach_record(page, slot, rights);
    (0, 0, recorded)
}

unsafe fn w32_attach_forget_or_release(page: u64, slot: u64, rights: u64) -> bool {
    if w32_attach_record(page, slot, rights) {
        return true;
    }
    let error = page_unmap_r(slot);
    if error != 0 {
        print_str(b"[w32attach] untracked mapping cleanup unmap failed page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" error=");
        print_u64(error);
        print_str(b"\n");
    }
    let _ = cnode_delete_recycle_r(slot);
    false
}

/// Forget a page's attach record after its leaf has been unmapped and no mapped cap remains.
pub(crate) unsafe fn w32_attach_remove(page: u64) -> bool {
    let mappings = w32_attach_mappings_mut();
    let mut i = 0usize;
    while i < mappings.len() {
        if mappings[i].page == page {
            mappings.swap_remove(i);
            return true;
        }
        i += 1;
    }
    false
}

/// ★ COPY-ON-WRITE the caller's TEB tail out from under a win32k store.
///
/// Called from the component fault pump when win32k takes a WRITE fault (`fsr` bit 1) on a page that
/// is already attached — which, for a tail page, can only mean the read-only mapping refused the
/// store. The client's real frame is swapped for a private shadow seeded from it, mapped RW at the
/// same VA, and recorded in the attach table so the ordinary detach unmaps it. win32k restarts the
/// faulting instruction and completes its write into the shadow.
///
/// The first few are reported with the faulting IP and its win32k RVA plus a stack backtrace: that
/// is the measurement which names the writer, and it is why this is a diagnosis rather than a guess.
pub(crate) unsafe fn w32_teb_tail_cow(page: u64, pi: u64, w_pml4: u64, ip: u64) -> bool {
    let seen = crate::W32_TEB_TAIL_WRITE_FAULTS.fetch_add(1, Ordering::Relaxed);
    let rva = ip.wrapping_sub(win32k_subsystem::WIN32K_CODE_VA);
    let _ = crate::W32_TEB_TAIL_FIRST_WRITER_RVA.compare_exchange(
        0,
        rva,
        Ordering::Relaxed,
        Ordering::Relaxed,
    );
    let shadow = crate::teb_tail_shadow(pi, page);
    if shadow == 0 {
        print_str(b"[teb-tail] no shadow available for client TEB tail page 0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" pi=");
        print_u64(pi);
        print_str(b"\n");
        return false;
    }
    let (old, old_rights, _) = w32_attach_replace_mapping(page, 0, 0);
    if old != 0 {
        let error = page_unmap_r(old);
        if error != 0 {
            print_str(b"[teb-tail] COW unmap failed error=");
            print_u64(error);
            print_str(b"\n");
            if !w32_attach_replace_mapping(page, old, old_rights).2 {
                print_str(b"[teb-tail] COW record restore failed after unmap failure\n");
            }
            return false;
        }
    }
    let cc = w32_map_frame_copy_checked(shadow, page, RW_NX, w_pml4, b"teb-tail COW");
    if cc == 0 {
        if old != 0 {
            let restore = page_map_r(old, page, old_rights, w_pml4);
            if restore == 0 {
                if !w32_attach_replace_mapping(page, old, old_rights).2 {
                    return false;
                }
            } else {
                print_str(b"[teb-tail] COW restore failed error=");
                print_u64(restore);
                print_str(b"\n");
                let _ = w32_attach_remove(page);
                let _ = cnode_delete_recycle_r(old);
            }
        }
        return false;
    }
    if old != 0 {
        let _ = cnode_delete_recycle_r(old);
    }
    let recorded = if old != 0 {
        w32_attach_replace_mapping(page, cc, RW_NX).2
    } else {
        w32_attach_record(page, cc, RW_NX)
    };
    if !recorded {
        let _ = page_unmap_r(cc);
        let _ = cnode_delete_recycle_r(cc);
        return false;
    }
    if seen < 6 {
        print_str(b"[teb-tail] win32k STORE into the client TEB tail REFUSED (page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" pi=");
        print_u64(pi);
        print_str(b") ip=0x");
        print_hex((ip >> 32) as u32);
        print_hex(ip as u32);
        print_str(b" win32k RVA=0x");
        print_hex(rva as u32);
        print_str(b" -> redirected to a private shadow\n");
        win32k_dispatch_backtrace();
    }
    true
}

/// Record that `page` is now mapped into win32k via copy-cap `slot` (for a later detach Unmap).
pub(crate) unsafe fn w32_attach_record(page: u64, slot: u64, rights: u64) -> bool {
    if slot == 0 {
        let _ = w32_attach_remove(page);
        return true;
    }
    let mappings = w32_attach_mappings_mut();
    for mapping in mappings.iter_mut() {
        if mapping.page == page {
            mapping.slot = slot;
            mapping.rights = rights;
            return true;
        }
    }
    if mappings.try_reserve(1).is_err() {
        print_str(b"[w32attach] attach record allocation failed page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b"\n");
        return false;
    }
    mappings.push(W32AttachMapping { page, slot, rights });
    true
}

/// Re-map a currently selected client frame into win32k with explicit rights. This is used for
/// narrow kernel-owned transitions where the normal demand mapping policy is too broad; for example
/// `NtGdiFlushUserBatch` must legitimately clear `TEB.GdiBatchCount` even though the rest of the
/// TEB tail remains read-only to ordinary win32k dispatches.
///
/// If the page is already attached, the attached win32k cap is the source of truth for this rights
/// flip: unmap it, then map the same cap again with the requested rights. The client-frame registry
/// is used only to create a missing attach mapping. Re-copying from the registry during a RO/RW flip
/// makes the transition depend on long-lived source cptrs that are unrelated to the attached leaf.
pub(crate) unsafe fn remap_attached_client_frame_in_win32k(
    page: u64,
    pi: u64,
    rights: u64,
) -> bool {
    let w_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if w_pml4 == 0 {
        return false;
    }
    if crate::csrss_frame_get_exact(pi, page).0 == 0 {
        return false;
    }
    let was_mapped = w32_attach_mapped(page);
    let (old, old_rights, _) = if was_mapped {
        w32_attach_replace_mapping(page, 0, 0)
    } else {
        (0, 0, true)
    };
    if old != 0 {
        let error = page_unmap_r(old);
        if error != 0 {
            print_str(b"[w32attach] remap unmap failed page=0x");
            print_hex((page >> 32) as u32);
            print_hex(page as u32);
            print_str(b" error=");
            print_u64(error);
            print_str(b"\n");
            let _ = w32_attach_replace_mapping(page, old, old_rights);
            return false;
        }

        let mut map = page_map_r(old, page, rights, w_pml4);
        if map == SEL4_FAILED_LOOKUP {
            w32_forget_client_paging(page);
            if ensure_w32_client_paging(page, w_pml4) {
                map = page_map_r(old, page, rights, w_pml4);
                if map == 0 && W32_PAGING_REPAIR_SUCCESSES.fetch_add(1, Ordering::Relaxed) < 16 {
                    print_str(b"[w32paging] repaired hierarchy for remap-existing page=0x");
                    print_hex((page >> 32) as u32);
                    print_hex(page as u32);
                    print_str(b"\n");
                }
            }
        }

        if map == 0 {
            if !w32_attach_replace_mapping(page, old, rights).2 {
                return false;
            }
        } else {
            print_str(b"[w32attach] remap existing map failed page=0x");
            print_hex((page >> 32) as u32);
            print_hex(page as u32);
            print_str(b" rights=0x");
            print_hex(rights as u32);
            print_str(b" error=");
            print_u64(map);
            print_str(b"\n");

            let restore = page_map_r(old, page, old_rights, w_pml4);
            if restore == 0 {
                if !w32_attach_replace_mapping(page, old, old_rights).2 {
                    return false;
                }
            } else {
                print_str(b"[w32attach] remap restore failed page=0x");
                print_hex((page >> 32) as u32);
                print_hex(page as u32);
                print_str(b" error=");
                print_u64(restore);
                print_str(b"\n");
                let _ = w32_attach_remove(page);
                let _ = cnode_delete_recycle_r(old);
            }
            return false;
        }
    } else {
        let cc = w32_map_registered_client_frame_copy_checked(pi, page, rights, w_pml4, b"remap");
        if cc == 0 {
            return false;
        }
        if !w32_attach_forget_or_release(page, cc, rights) {
            return false;
        }
    }
    if crate::W32_CLIENT_TEB_TAIL_PROTECTED
        && rights == crate::RO_NX
        && crate::is_teb_tail_page(page)
    {
        crate::W32_TEB_TAIL_RO_MAPS.fetch_add(1, Ordering::Relaxed);
    }
    true
}
/// Attach win32k's client window to GUI client `pi` (the KeStackAttachProcess model). If a DIFFERENT
/// client is currently attached, DETACH it: Unmap all its leaf client pages from win32k so the new
/// client's colliding VAs re-fault to THIS client's frames. Idempotent when `pi` is already attached.
pub(crate) unsafe fn w32_client_attach(pi: u64) -> bool {
    let prev = W32_ATTACHED_PI.load(Ordering::Relaxed);
    if prev == pi {
        return true;
    }
    let mappings = w32_attach_mappings_mut();
    let mut detached = 0usize;
    while !mappings.is_empty() {
        // Unmap win32k's mapping of the previous client's page (arch Unmap uses this cap's win32k
        // asid → csrss/winlogon's own VSpace mapping is untouched), then delete the transient copy
        // cap so the executive's root-slot allocator can recycle it.
        let mapping = mappings[mappings.len() - 1];
        let error = page_unmap_r(mapping.slot);
        if error != 0 {
            print_str(b"[w32attach] page_unmap failed page=0x");
            print_hex((mapping.page >> 32) as u32);
            print_hex(mapping.page as u32);
            print_str(b" error=");
            print_u64(error);
            print_str(b"\n");
            return false;
        }
        let _ = cnode_delete_recycle_r(mapping.slot);
        let _ = mappings.pop();
        detached += 1;
    }
    print_str(b"[w32attach] client ");
    print_u64(prev);
    print_str(b" -> ");
    print_u64(pi);
    print_str(b" (detached ");
    print_u64(detached as u64);
    print_str(b" client pages)\n");
    W32_ATTACHED_PI.store(pi, Ordering::Relaxed);
    true
}
/// Share GUI client `pi`'s frame for `page` into win32k's VSpace at the SAME VA (identity) so
/// win32k's handler dereferences the caller's real user memory. Returns false if the page isn't
/// backed by a known client frame (win32k would read garbage → the caller stops with a diagnostic).
/// Idempotent per page for the currently-attached client (see `w32_client_attach`).
pub(crate) unsafe fn map_csrss_page_into_win32k(page: u64, pi: u64, w_pml4: u64) -> bool {
    let already_mapped = w32_attach_mapped(page);
    if already_mapped {
        return true; // already shared for the currently-attached client
    }
    // RW: win32k (kernel-mode) may read AND write the caller's user memory; the frame is shared with
    // the client so writes propagate back (out-params). Non-executable — client data, not code.
    //
    // ★ EXCEPT the TEB TAIL. The caller's SECOND TEB page carries `StaticUnicodeString`, the ACS the
    // client used to keep there, TLS slots, `DeallocationStack` — user-mode state that win32k has no
    // contract to modify (see `main.rs`, `W32_CLIENT_TEB_TAIL_PROTECTED`). It is mapped READ-ONLY, so
    // win32k reads the caller's real values and the FIRST store faults into `w32_teb_tail_cow` below
    // instead of scribbling the live TEB.
    let protect_tail = crate::W32_CLIENT_TEB_TAIL_PROTECTED && crate::is_teb_tail_page(page);
    if protect_tail {
        crate::W32_TEB_TAIL_RO_MAPS.fetch_add(1, Ordering::Relaxed);
    }
    let rights = if protect_tail { crate::RO_NX } else { RW_NX };
    let cc = if crate::csrss_frame_get_exact(pi, page).0 != 0 {
        w32_map_registered_client_frame_copy_checked(pi, page, rights, w_pml4, b"attach")
    } else {
        let fr = csrss_frame_get(pi, page);
        if fr == 0 {
            return false;
        }
        w32_map_frame_copy_checked(fr, page, rights, w_pml4, b"attach")
    };
    if cc == 0 {
        return false;
    }
    w32_attach_forget_or_release(page, cc, rights)
}

/// Load ONE driver PE (raw at `src_va` in the executive) into `dst_va` in BOTH the executive (RW,
/// to load) and win32k (W^X, to run). Reuses [`win32k_subsystem::load_driver_into`]. `dxgthk_base` names
/// a prior-loaded dxgthk for import resolution (0 for a leaf). Returns (entry_rva, export_dir_rva,
/// size_of_image). The reusable driver-loader mechanism is also used by display DLL hosting.
#[inline(never)]
unsafe fn load_one_driver_fail(stage: &[u8], subject: u64, error: u64) -> Option<(u32, u32, u32)> {
    print_str(b"[win32k-svc] driver image load ");
    print_str(stage);
    print_str(b" failed subject=0x");
    print_hex((subject >> 32) as u32);
    print_hex(subject as u32);
    print_str(b" error=");
    print_u64(error);
    print_str(b"\n");
    None
}

unsafe fn release_driver_load_frame_run(base: u64, count: u64) {
    let mut i = 0u64;
    while i < count {
        let _ = cnode_delete_recycle_r(base + i);
        i += 1;
    }
}

unsafe fn release_driver_load_map_caps(caps: &mut [u64], count: u64) {
    let mut i = 0u64;
    while i < count.min(caps.len() as u64) {
        let cap = caps[i as usize];
        if cap != 0 {
            let _ = cnode_delete_recycle_r(cap);
            caps[i as usize] = 0;
        }
        i += 1;
    }
}

unsafe fn driver_load_scratch_records(frames: usize, fill: u64, stage: &[u8]) -> Option<Vec<u64>> {
    let mut records = Vec::new();
    if records.try_reserve_exact(frames).is_err() {
        print_str(b"[win32k-svc] driver image load ");
        print_str(stage);
        print_str(b" scratch allocation failed frames=");
        print_u64(frames as u64);
        print_str(b"\n");
        return None;
    }
    records.resize(frames, fill);
    Some(records)
}

unsafe fn alloc_driver_load_frame_run(frames: u64) -> Option<u64> {
    let Some(base) = try_alloc_slot_run(frames) else {
        print_str(b"[win32k-svc] driver image load frame-run slot allocation failed frames=");
        print_u64(frames);
        print_str(b"\n");
        return None;
    };
    let mut i = 0u64;
    while i < frames {
        let slot = base + i;
        let error = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_4K_PAGE, PAGING_BITS, 1, slot);
        if error != 0 {
            let mut j = 0u64;
            while j < i {
                let _ = cnode_delete_recycle_r(base + j);
                j += 1;
            }
            while j < frames {
                recycle_deleted_root_slot(base + j);
                j += 1;
            }
            let _ = load_one_driver_fail(b"frame-retype", slot, error);
            return None;
        }
        i += 1;
    }
    Some(base)
}

#[derive(Clone, Copy)]
struct DriverLoadPageTable {
    pml4: u64,
    base: u64,
    cap: u64,
}

const DRIVER_LOAD_PT_SPAN: u64 = 0x20_0000;
static mut DRIVER_LOAD_PAGE_TABLES: Option<Vec<DriverLoadPageTable>> = None;

#[inline]
fn driver_load_pt_base(va: u64) -> u64 {
    va & !(DRIVER_LOAD_PT_SPAN - 1)
}

unsafe fn driver_load_page_tables_mut() -> &'static mut Vec<DriverLoadPageTable> {
    let slot = &mut *core::ptr::addr_of_mut!(DRIVER_LOAD_PAGE_TABLES);
    if slot.is_none() {
        *slot = Some(Vec::new());
    }
    slot.as_mut().unwrap()
}

unsafe fn driver_load_page_table_find(pml4: u64, base: u64) -> Option<u64> {
    (&*core::ptr::addr_of!(DRIVER_LOAD_PAGE_TABLES))
        .as_ref()
        .and_then(|records| {
            records
                .iter()
                .find(|record| record.pml4 == pml4 && record.base == base)
                .map(|record| record.cap)
        })
}

unsafe fn driver_load_page_table_insert(pml4: u64, base: u64, cap: u64) -> bool {
    let records = driver_load_page_tables_mut();
    if records.try_reserve(1).is_err() {
        print_str(b"[driver-load] page-table record allocation failed pml4=0x");
        print_hex((pml4 >> 32) as u32);
        print_hex(pml4 as u32);
        print_str(b" base=0x");
        print_hex((base >> 32) as u32);
        print_hex(base as u32);
        print_str(b"\n");
        return false;
    }
    records.push(DriverLoadPageTable { pml4, base, cap });
    true
}

unsafe fn driver_load_page_table_remove(pml4: u64, base: u64, cap: u64) {
    let records = driver_load_page_tables_mut();
    let mut i = 0usize;
    while i < records.len() {
        let record = records[i];
        if record.cap == cap && record.pml4 == pml4 && record.base == base {
            records.swap_remove(i);
            return;
        }
        i += 1;
    }
}

unsafe fn ensure_driver_load_page_table(
    pml4: u64,
    va: u64,
    stage_prefix: &[u8],
) -> Option<(u64, bool)> {
    let base = driver_load_pt_base(va);
    if let Some(existing) = driver_load_page_table_find(pml4, base) {
        return Some((existing, false));
    }
    let Some(pt) = try_alloc_slot() else {
        return load_one_driver_fail(stage_prefix, base, 4).map(|_| (0, false));
    };
    let error = untyped_retype_r(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
    if error != 0 {
        recycle_deleted_root_slot(pt);
        return load_one_driver_fail(stage_prefix, pt, error).map(|_| (0, false));
    }
    let error = paging_struct_map_r(pt, LBL_X86_PAGE_TABLE_MAP, base, pml4);
    if error != 0 {
        let _ = cnode_delete_recycle_r(pt);
        return load_one_driver_fail(stage_prefix, base, error).map(|_| (0, false));
    }
    if !driver_load_page_table_insert(pml4, base, pt) {
        let _ = cnode_delete_recycle_r(pt);
        return load_one_driver_fail(stage_prefix, base, 4).map(|_| (0, false));
    }
    Some((pt, true))
}

unsafe fn release_driver_load_page_table_if_new(pml4: u64, va: u64, cap: u64, is_new: bool) {
    if is_new && cap != 0 {
        let base = driver_load_pt_base(va);
        driver_load_page_table_remove(pml4, base, cap);
        let _ = cnode_delete_recycle_r(cap);
    }
}

pub(crate) unsafe fn load_one_driver(
    src_va: u64,
    dst_va: u64,
    frames: u64,
    host_pml4: u64,
    dxgthk_base: u64,
) -> Option<(u32, u32, u32)> {
    let Ok(frame_count) = usize::try_from(frames) else {
        return load_one_driver_fail(b"frame-count", frames, 0);
    };
    if frame_count == 0 {
        return None;
    }
    // Executive-side PT + frames (RW), to load into.
    let (ept, ept_new) =
        ensure_driver_load_page_table(CAP_INIT_THREAD_VSPACE, dst_va, b"exec-pt-map")?;
    let Some(mut exec_map_caps) = driver_load_scratch_records(frame_count, 0, b"exec-map-caps")
    else {
        release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
        return None;
    };
    let Some(mut rights) = driver_load_scratch_records(frame_count, RW_NX, b"rights") else {
        release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
        return None;
    };
    let Some(mut host_map_caps) = driver_load_scratch_records(frame_count, 0, b"host-map-caps")
    else {
        release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
        return None;
    };
    let Some(base) = alloc_driver_load_frame_run(frames) else {
        release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
        return None;
    };
    for i in 0..frames {
        let (cap, copy_error) = copy_cap_r(base + i);
        if copy_error != 0 {
            release_driver_load_map_caps(exec_map_caps.as_mut_slice(), i);
            release_driver_load_frame_run(base, frames);
            release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
            return load_one_driver_fail(b"exec-frame-copy", base + i, copy_error);
        }
        let va = dst_va + i * 0x1000;
        let map_error = page_map_r(cap, va, RW_NX, CAP_INIT_THREAD_VSPACE);
        if map_error != 0 {
            let _ = cnode_delete_recycle_r(cap);
            release_driver_load_map_caps(exec_map_caps.as_mut_slice(), i);
            release_driver_load_frame_run(base, frames);
            release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
            return load_one_driver_fail(b"exec-frame-map", va, map_error);
        }
        exec_map_caps[i as usize] = cap;
    }
    // Parse + copy + reloc + resolve imports through the executive's RW mapping. The per-frame
    // rights live in a heap vector because display/keyboard/helper drivers are not inherently capped
    // at a particular image size.
    let Some(res) = win32k_subsystem::load_driver_into(
        src_va,
        dst_va,
        frames,
        rights.as_mut_slice(),
        dxgthk_base,
    ) else {
        release_driver_load_map_caps(exec_map_caps.as_mut_slice(), frames);
        release_driver_load_frame_run(base, frames);
        release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
        return load_one_driver_fail(b"pe-load", dst_va, 0);
    };
    // Map the SAME frames W^X into win32k's VSpace at the same VA (RX code / RW data).
    let Some((wpt, wpt_new)) = ensure_driver_load_page_table(host_pml4, dst_va, b"host-pt-map")
    else {
        release_driver_load_map_caps(exec_map_caps.as_mut_slice(), frames);
        release_driver_load_frame_run(base, frames);
        release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
        return None;
    };
    for i in 0..frames {
        let r = rights[i as usize];
        let (cap, copy_error) = copy_cap_r(base + i);
        if copy_error != 0 {
            release_driver_load_map_caps(host_map_caps.as_mut_slice(), i);
            release_driver_load_page_table_if_new(host_pml4, dst_va, wpt, wpt_new);
            release_driver_load_map_caps(exec_map_caps.as_mut_slice(), frames);
            release_driver_load_frame_run(base, frames);
            release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
            return load_one_driver_fail(b"host-frame-copy", base + i, copy_error);
        }
        let va = dst_va + i * 0x1000;
        let map_error = page_map_r(cap, va, r, host_pml4);
        if map_error != 0 {
            let _ = cnode_delete_recycle_r(cap);
            release_driver_load_map_caps(host_map_caps.as_mut_slice(), i);
            release_driver_load_page_table_if_new(host_pml4, dst_va, wpt, wpt_new);
            release_driver_load_map_caps(exec_map_caps.as_mut_slice(), frames);
            release_driver_load_frame_run(base, frames);
            release_driver_load_page_table_if_new(CAP_INIT_THREAD_VSPACE, dst_va, ept, ept_new);
            return load_one_driver_fail(b"host-frame-map", va, map_error);
        }
        host_map_caps[i as usize] = cap;
    }
    Some(res)
}

unsafe fn driver_image_frame_count(src_va: u64) -> Option<u64> {
    let e = core::ptr::read_unaligned((src_va + 0x3c) as *const u32) as u64;
    let nt = src_va.checked_add(e)?;
    if core::ptr::read_unaligned(nt as *const u32) != 0x0000_4550 {
        return None;
    }
    let file_hdr = nt + 4;
    let opt = file_hdr + 20;
    let size_of_image = core::ptr::read_unaligned((opt + 56) as *const u32) as u64;
    if size_of_image == 0 {
        return None;
    }
    let frames = size_of_image.checked_add(0x0fff)? / 0x1000;
    if frames == 0 {
        return None;
    }
    Some(frames)
}

fn reserve_win32k_static_import_va(next_va: &mut u64, frames: u64) -> Option<u64> {
    let bytes = frames.checked_mul(0x1000)?;
    let aligned = next_va
        .checked_add(WIN32K_STATIC_IMPORT_ALIGN - 1)
        .map(|v| v & !(WIN32K_STATIC_IMPORT_ALIGN - 1))?;
    let end = aligned.checked_add(bytes)?;
    if end > WIN32K_STATIC_IMPORT_LIMIT_VA {
        return None;
    }
    *next_va = end;
    Some(aligned)
}

pub(crate) fn register_win32k_gdi_loader(host_pml4: u64) {
    WIN32K_GDI_LOADER_PML4.store(host_pml4, Ordering::Relaxed);
}

fn gdi_leaf_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i].to_ascii_lowercase() != b[i].to_ascii_lowercase() {
            return false;
        }
    }
    true
}

pub(crate) unsafe fn ensure_win32k_gdi_driver_loaded(leaf: &[u8]) -> bool {
    if leaf.is_empty() || win32k_subsystem::gdi_driver_registered(leaf) {
        return true;
    }
    let host_pml4 = WIN32K_GDI_LOADER_PML4.load(Ordering::Relaxed);
    if host_pml4 == 0 {
        print_str(b"[win32k-svc] GDI demand-load requested before loader registration\n");
        return false;
    }

    if gdi_leaf_eq(leaf, b"dxg.sys") {
        load_directx_drivers(host_pml4);
        return win32k_subsystem::gdi_driver_registered(leaf);
    }

    if let Some(display_spec) = system_hive_display_driver_spec() {
        let display_spec = display_spec.win32k_spec();
        if gdi_leaf_eq(leaf, display_spec.display_driver_leaf) {
            load_display_driver(host_pml4, &display_spec);
            return win32k_subsystem::gdi_driver_registered(leaf);
        }
    }

    let mut layout_id = [0u8; 8];
    if let Some((layout_id_len, _source)) = registry_keyboard_layout_id(&mut layout_id) {
        let mut layout_file = [0u8; 32];
        if let Some(layout_file_len) =
            system_hive_keyboard_layout_file(&layout_id[..layout_id_len], &mut layout_file)
        {
            if gdi_leaf_eq(leaf, &layout_file[..layout_file_len]) {
                load_keyboard_layout_driver(
                    host_pml4,
                    &layout_id[..layout_id_len],
                    &layout_file[..layout_file_len],
                );
                return win32k_subsystem::gdi_driver_registered(leaf);
            }
        }
    }

    false
}

pub(crate) fn service_gdi_driver_load() -> i32 {
    unsafe {
        let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
        let leaf_len =
            core::ptr::read_volatile((sh + win32k_subsystem::SH_GDI_LOAD_LEAF_LEN) as *const u64)
                as usize;
        let status = if leaf_len == 0 || leaf_len > win32k_subsystem::SH_GDI_LOAD_LEAF_CAP {
            0xC000_000Du32 as i32 // STATUS_INVALID_PARAMETER
        } else {
            let mut leaf = [0u8; win32k_subsystem::SH_GDI_LOAD_LEAF_CAP];
            let mut valid = true;
            for i in 0..leaf_len {
                let b = core::ptr::read_volatile(
                    (sh + win32k_subsystem::SH_GDI_LOAD_LEAF + i as u64) as *const u8,
                )
                .to_ascii_lowercase();
                if !(b.is_ascii_lowercase()
                    || b.is_ascii_digit()
                    || b == b'_'
                    || b == b'-'
                    || b == b'.')
                {
                    valid = false;
                }
                leaf[i] = b;
            }
            if !valid || leaf[..leaf_len].windows(2).any(|w| w == b"..") {
                0xC000_000Du32 as i32
            } else if ensure_win32k_gdi_driver_loaded(&leaf[..leaf_len]) {
                0
            } else {
                0xC000_0135u32 as i32 // STATUS_DLL_NOT_FOUND
            }
        };
        core::ptr::write_volatile(
            (sh + win32k_subsystem::SH_GDI_LOAD_STATUS) as *mut i32,
            status,
        );
        status
    }
}

/// Demand-load dxg.sys + its dxgthk.sys dependency into win32k's VSpace when win32k asks for dxg
/// through `ZwSetSystemInformation(SystemLoadGdiDriverInformation)`. dxgthk (leaf) loads first,
/// then dxg imports dxgthk's Eng* exports plus ntoskrnl.
pub(crate) unsafe fn load_directx_drivers(host_pml4: u64) {
    if win32k_subsystem::gdi_driver_registered(b"dxg.sys") {
        return;
    }
    let Some(fs) = exec_fs() else {
        print_str(b"[win32k-svc] DirectX drivers unavailable - executive FS not mounted\n");
        return;
    };
    let mut dxgthk_size = 0u32;
    if DXGTHK_DRIVER_LOADED.load(Ordering::Relaxed) == 0 {
        let Some((dxgthk_src, loaded_dxgthk_size)) =
            load_file_to_pool(&fs, b"reactos\\system32\\drivers\\dxgthk.sys")
        else {
            print_str(b"[win32k-svc] dxgthk.sys not found in ReactOS driver directory\n");
            return;
        };
        let Some((_dxgthk_entry, _dxgthk_expdir, dxgthk_len)) = load_one_driver(
            dxgthk_src,
            win32k_subsystem::DXGTHK_VA,
            win32k_subsystem::DXGTHK_LOAD_FRAMES,
            host_pml4,
            0,
        ) else {
            print_str(b"[win32k-svc] dxgthk load failed\n");
            return;
        };
        let _ = register_system_module(
            b"reactos\\system32\\drivers\\dxgthk.sys",
            win32k_subsystem::DXGTHK_VA,
            dxgthk_len,
        );
        DXGTHK_DRIVER_LOADED.store(1, Ordering::Relaxed);
        dxgthk_size = loaded_dxgthk_size;
    }
    let Some((dxg_src, dxg_size)) = load_file_to_pool(&fs, b"reactos\\system32\\drivers\\dxg.sys")
    else {
        print_str(b"[win32k-svc] dxg.sys not found in ReactOS driver directory\n");
        return;
    };
    match load_one_driver(
        dxg_src,
        win32k_subsystem::DXG_VA,
        win32k_subsystem::DXG_LOAD_FRAMES,
        host_pml4,
        win32k_subsystem::DXGTHK_VA,
    ) {
        Some((entry, expdir, len)) => {
            let _ = register_system_module(
                b"reactos\\system32\\drivers\\dxg.sys",
                win32k_subsystem::DXG_VA,
                len,
            );
            win32k_subsystem::record_dxg(entry, expdir, len);
            print_str(b"[win32k-svc] hosted dxg.sys + dxgthk.sys: file_sizes=");
            print_u64(dxg_size as u64);
            print_str(b"/");
            print_u64(dxgthk_size as u64);
            print_str(b" entry_rva=0x");
            print_hex(entry);
            print_str(b" export_dir_rva=0x");
            print_hex(expdir);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] dxg load failed\n"),
    }
}

pub(crate) fn win32k_static_import_loader_proofs() -> (u64, u64, u64, u64) {
    (
        WIN32K_STATIC_IMPORT_DEPENDENCIES.load(Ordering::Relaxed),
        WIN32K_STATIC_IMPORTS_LOADED.load(Ordering::Relaxed),
        WIN32K_STATIC_IMPORT_IAT_PATCHES.load(Ordering::Relaxed),
        WIN32K_STATIC_IMPORT_FAILURES.load(Ordering::Relaxed),
    )
}

/// Host win32k's non-native static import DLLs into win32k's VSpace and patch win32k's IAT against
/// their real export tables. The dependency names come from win32k's own PE import descriptors;
/// native imports stay bound to the ntoskrnl/hal trampoline registry.
pub(crate) unsafe fn load_win32k_static_import_drivers(host_pml4: u64) {
    WIN32K_STATIC_IMPORT_DEPENDENCIES.store(0, Ordering::Relaxed);
    WIN32K_STATIC_IMPORTS_LOADED.store(0, Ordering::Relaxed);
    WIN32K_STATIC_IMPORT_IAT_PATCHES.store(0, Ordering::Relaxed);
    WIN32K_STATIC_IMPORT_FAILURES.store(0, Ordering::Relaxed);

    let Some(fs) = exec_fs() else {
        print_str(b"[win32k-svc] static win32k imports unavailable - executive FS not mounted\n");
        WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
        return;
    };

    let mut dep_index = 0usize;
    let mut next_static_import_va = WIN32K_STATIC_IMPORT_BASE_VA;
    loop {
        let mut dll_leaf = [0u8; 32];
        let Some(dll_len) =
            win32k_subsystem::win32k_static_import_dependency(dep_index, &mut dll_leaf)
        else {
            break;
        };
        let dll = &dll_leaf[..dll_len];
        WIN32K_STATIC_IMPORT_DEPENDENCIES.fetch_add(1, Ordering::Relaxed);

        let mut path = [0u8; 64];
        let Some(path_len) = system32_driver_path(dll, &mut path) else {
            print_str(b"[win32k-svc] static win32k import leaf rejected: ");
            print_str(dll);
            print_str(b"\n");
            WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
            dep_index += 1;
            continue;
        };
        print_str(b"[win32k-svc] loading static win32k import ");
        print_str(dll);
        print_str(b" from ");
        print_str(&path[..path_len]);
        print_str(b"\n");
        let Some((src, file_size)) = load_file_to_pool(&fs, &path[..path_len]) else {
            print_str(b"[win32k-svc] static win32k import not found: ");
            print_str(&path[..path_len]);
            print_str(b"\n");
            WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
            dep_index += 1;
            continue;
        };
        let Some(image_frames) = driver_image_frame_count(src) else {
            print_str(b"[win32k-svc] static win32k import PE rejected: ");
            print_str(&path[..path_len]);
            print_str(b"\n");
            WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
            dep_index += 1;
            continue;
        };
        let Some(image_va) =
            reserve_win32k_static_import_va(&mut next_static_import_va, image_frames)
        else {
            print_str(b"[win32k-svc] static win32k import allocation failed: ");
            print_str(dll);
            print_str(b" frames=");
            print_u64(image_frames);
            print_str(b"\n");
            WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
            dep_index += 1;
            continue;
        };
        match load_one_driver(src, image_va, image_frames, host_pml4, 0) {
            Some((entry, _expdir, len)) => {
                let _ = register_system_module(&path[..path_len], image_va, len);
                let patched = win32k_subsystem::patch_win32k_static_import(dll, image_va);
                print_str(b"[win32k-svc] hosted static win32k import ");
                print_str(dll);
                print_str(b": file_size=");
                print_u64(file_size as u64);
                print_str(b" entry_rva=0x");
                print_hex(entry);
                print_str(b" len=0x");
                print_hex(len);
                print_str(b" base=0x");
                print_hex((image_va >> 32) as u32);
                print_hex(image_va as u32);
                print_str(b" frames=");
                print_u64(image_frames);
                print_str(b" iat-patched=");
                print_u64(patched as u64);
                print_str(b"\n");
                if patched == 0 {
                    WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
                } else {
                    WIN32K_STATIC_IMPORTS_LOADED.fetch_add(1, Ordering::Relaxed);
                    WIN32K_STATIC_IMPORT_IAT_PATCHES.fetch_add(patched as u64, Ordering::Relaxed);
                }
            }
            None => {
                print_str(b"[win32k-svc] static win32k import load failed: ");
                print_str(dll);
                print_str(b"\n");
                WIN32K_STATIC_IMPORT_FAILURES.fetch_add(1, Ordering::Relaxed);
            }
        }
        dep_index += 1;
    }
}

fn system32_driver_leaf_is_safe(driver_leaf: &[u8]) -> bool {
    !driver_leaf.is_empty()
        && driver_leaf.iter().copied().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-' || b == b'.'
        })
        && !driver_leaf.windows(2).any(|w| w == b"..")
}

fn system32_driver_path_vec(driver_leaf: &[u8]) -> Option<Vec<u8>> {
    if !system32_driver_leaf_is_safe(driver_leaf) {
        return None;
    }
    let prefix = b"reactos\\system32\\";
    let len = prefix.len().checked_add(driver_leaf.len())?;
    let mut path = Vec::new();
    path.try_reserve_exact(len).ok()?;
    path.extend_from_slice(prefix);
    path.extend_from_slice(driver_leaf);
    Some(path)
}

fn system32_driver_path(driver_leaf: &[u8], out: &mut [u8]) -> Option<usize> {
    if !system32_driver_leaf_is_safe(driver_leaf) {
        return None;
    }
    let prefix = b"reactos\\system32\\";
    let len = prefix.len().checked_add(driver_leaf.len())?;
    if len > out.len() {
        return None;
    }
    out[..prefix.len()].copy_from_slice(prefix);
    out[prefix.len()..prefix.len() + driver_leaf.len()].copy_from_slice(driver_leaf);
    Some(len)
}

unsafe fn map_display_bar_into_win32k(host_pml4: u64) {
    // Map the full Phase-0 display BAR cap run into win32k. The bootloader framebuffer fields describe
    // only the current scanout view inside this aperture.
    let base = FB_BAR_FRAME_BASE.load(Ordering::Relaxed);
    let count = FB_BAR_FRAME_COUNT.load(Ordering::Relaxed);
    if base != 0 && count != 0 {
        for p in 0..(count + 511) / 512 {
            let pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
            let _ = paging_struct_map(
                pt,
                LBL_X86_PAGE_TABLE_MAP,
                win32k_subsystem::WIN32K_FB_VA + p * 0x20_0000,
                host_pml4,
            );
        }
        for i in 0..count {
            let _ = page_map(
                copy_cap(base + i),
                win32k_subsystem::WIN32K_FB_VA + i * 0x1000,
                RW_NX,
                host_pml4,
            );
        }
        print_str(b"[win32k-svc] mapped display BAR into win32k: ");
        print_u64(count);
        print_str(b" frames @ WIN32K_FB_VA=0x");
        print_hex((win32k_subsystem::WIN32K_FB_VA >> 32) as u32);
        print_hex(win32k_subsystem::WIN32K_FB_VA as u32);
        print_str(b"\n");
    }
}

/// Host the display driver selected by SYSTEM hive service metadata into win32k's VSpace and map
/// the owning display BAR. win32k loads the display DLL dynamically via
/// ZwSetSystemInformation when it enables the display device, so the executive preloads the selected
/// DLL and records its registry/device metadata for the narrow win32k import bridge.
pub(crate) unsafe fn load_display_driver(
    host_pml4: u64,
    spec: &win32k_subsystem::DisplayRegistrySpec<'_>,
) {
    let Some(fs) = exec_fs() else {
        print_str(b"[win32k-svc] display DLL unavailable - executive FS not mounted\n");
        return;
    };
    let Some(path) = system32_driver_path_vec(spec.display_driver_leaf) else {
        print_str(b"[win32k-svc] display DLL leaf rejected by loader policy\n");
        return;
    };
    let Some((src_va, sz)) = load_file_to_pool(&fs, &path) else {
        print_str(b"[win32k-svc] display DLL not found by registry path: ");
        print_str(&path);
        print_str(b"\n");
        return;
    };
    match load_one_driver(
        src_va,
        win32k_subsystem::FRAMEBUF_VA,
        win32k_subsystem::FRAMEBUF_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, expdir, len)) => {
            let _ = register_system_module(&path, win32k_subsystem::FRAMEBUF_VA, len);
            let recorded = win32k_subsystem::record_display_driver(spec, entry, expdir, len);
            print_str(b"[win32k-svc] hosted display driver ");
            print_str(spec.display_driver_leaf);
            print_str(b": file_size=");
            print_u64(sz as u64);
            print_str(b" entry_rva=0x");
            print_hex(entry);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b" recorded=");
            print_u64(recorded as u64);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] display DLL load failed\n"),
    }
    map_display_bar_into_win32k(host_pml4);
}

/// Host the keyboard layout DLL selected by the registry into win32k's VSpace. win32k loads keyboard
/// layouts dynamically from UserLoadKbdDll via EngLoadImage -> ZwSetSystemInformation, then looks up
/// the KbdLayerDescriptor export. The layout id and DLL leaf are supplied by the caller from the
/// DEFAULT/SYSTEM hive state.
pub(crate) unsafe fn load_keyboard_layout_driver(
    host_pml4: u64,
    layout_id: &[u8],
    layout_file: &[u8],
) {
    let Some(fs) = exec_fs() else {
        print_str(b"[win32k-svc] keyboard layout DLL unavailable - executive FS not mounted\n");
        return;
    };
    let mut path = [0u8; 64];
    let Some(path_len) = system32_driver_path(layout_file, &mut path) else {
        print_str(b"[win32k-svc] keyboard layout DLL leaf rejected by loader policy\n");
        return;
    };
    let Some((src_va, sz)) = load_file_to_pool(&fs, &path[..path_len]) else {
        print_str(b"[win32k-svc] keyboard layout DLL not found by registry path: ");
        print_str(&path[..path_len]);
        print_str(b"\n");
        return;
    };
    match load_one_driver(
        src_va,
        win32k_subsystem::KEYBOARD_LAYOUT_VA,
        win32k_subsystem::KEYBOARD_LAYOUT_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, expdir, len)) => {
            let _ = register_system_module(
                &path[..path_len],
                win32k_subsystem::KEYBOARD_LAYOUT_VA,
                len,
            );
            let recorded = win32k_subsystem::record_keyboard_layout_driver(
                layout_id,
                layout_file,
                entry,
                expdir,
                len,
            );
            print_str(b"[win32k-svc] hosted keyboard layout ");
            print_str(layout_file);
            print_str(b": file_size=");
            print_u64(sz as u64);
            print_str(b" entry_rva=0x");
            print_hex(entry);
            print_str(b" export_dir_rva=0x");
            print_hex(expdir);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b" recorded=");
            print_u64(recorded as u64);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] keyboard layout DLL load failed\n"),
    }
}

/// Dispatch one win32k SSN (>= 0x1000) into the parked win32k component and run its fault-service
/// loop until the handler completes (Milestone B). PRECONDITION: the component is blocked in its
/// dispatch `seL4_Call` on `w_fault` (the executive has received the Call but not yet replied). We
/// fill the request in the shared page, reply (the Call returns → the component runs the handler),
/// then demand-page the handler's faults until the component issues its NEXT dispatch Call = "done".
/// Returns `(status, ok)`; `ok=false` on a wall (null deref / W^X / demand cap / unexpected fault).
pub(crate) unsafe fn win32k_dispatch(ssn: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> (u64, bool) {
    let pi = W32_CLIENT_PI.load(Ordering::Relaxed) as u32;
    let (system_sid, system_sid_len) = local_system_sid_native();
    win32k_dispatch_wide(
        ssn,
        a0,
        a1,
        a2,
        a3,
        0,
        &[],
        Win32kClientContext {
            pi,
            generation: 0,
            pid: 0,
            badge: 0,
            tid: 0,
            tcb: 0,
            eprocess: 0,
            ethread: 0,
            role: None,
            process_role: None,
            top_badge: 0,
            // Executive-originated probes do not have a hosted caller TEB. Leaving this empty makes
            // win32k keep the component's already-selected GUI process/thread identity instead of
            // deriving a new client from SMSS' TEB.
            teb: 0,
            peb_mirror: 0,
            scratch_base: crate::EXECUTIVE_WIN32K_SCRATCH_BASE,
            token_authentication_id: SYSTEM_TOKEN_AUTHENTICATION_ID,
            token_user_sid: system_sid,
            token_user_sid_len: system_sid_len,
        },
    )
}

/// Like [`win32k_dispatch`] but carries the win64 stack-argument source for win32k SSNs. Real client
/// syscalls pass `caller_sp`, and the win32k component reads exactly the provider-required tail
/// from the attached client stack. Executive-originated calls pass explicit `stack_args`, which are
/// staged in `SH_REQ_A4..` and rejected by the component if they do not satisfy the provider arity.
pub(crate) unsafe fn win32k_dispatch_wide(
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    stack_args: &[u64],
    client: Win32kClientContext,
) -> (u64, bool) {
    win32k_dispatch_wide_with_completion_args(
        ssn,
        a0,
        a1,
        a2,
        a3,
        caller_sp,
        stack_args,
        [a0, a1, a2, a3],
        None,
        client,
    )
}

pub(crate) unsafe fn win32k_flush_user_gdi_batch(client: Win32kClientContext) -> (u64, bool) {
    const STATUS_INVALID_PARAMETER: u64 = 0xC000_000Du32 as u64;
    const STATUS_INSUFFICIENT_RESOURCES: u64 = 0xC000_009Au32 as u64;

    if client.pi == 0 || client.teb == 0 {
        return (STATUS_INVALID_PARAMETER, true);
    }

    let client_pi = client.pi as u64;
    if !w32_client_attach(client_pi) {
        return (STATUS_INSUFFICIENT_RESOURCES, false);
    }

    let tail_page = (client.teb + nt_user_callback::TEB_GDI_BATCH_COUNT) & !0xFFF;
    if !remap_attached_client_frame_in_win32k(tail_page, client_pi, RW_NX) {
        return (STATUS_INSUFFICIENT_RESOURCES, true);
    }
    crate::GDI_BATCH_TEB_TAIL_WRITE_WINDOWS.fetch_add(1, Ordering::Relaxed);

    let result = win32k_dispatch_wide(
        win32k_subsystem::SSN_GDI_BATCH_FLUSH_CALLOUT,
        0,
        0,
        0,
        0,
        0,
        &[],
        client,
    );

    if !remap_attached_client_frame_in_win32k(tail_page, client_pi, RO_NX) {
        print_str(b"[gdi-batch] failed to restore read-only TEB tail mapping page=0x");
        print_hex((tail_page >> 32) as u32);
        print_hex(tail_page as u32);
        print_str(b" pi=");
        print_u64(client_pi);
        print_str(b"\n");
    }

    result
}

pub(crate) unsafe fn win32k_dispatch_wide_with_completion_args(
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    stack_args: &[u64],
    completion_args: [u64; 4],
    output_stage: Option<nt_user_callback::DispatchOutputStage>,
    client: Win32kClientContext,
) -> (u64, bool) {
    win32k_dispatch_wide_with_completion_args_and_kind(
        ssn,
        a0,
        a1,
        a2,
        a3,
        caller_sp,
        stack_args,
        completion_args,
        output_stage,
        client,
        win32k_subsystem::WIN32K_REQUEST_SSDT,
        true,
    )
}

pub(crate) unsafe fn win32k_dispatch_ps_provider_command(
    command: u64,
    expected_provider_state: u64,
    flags: u64,
    client: Win32kClientContext,
) -> (u64, bool) {
    win32k_dispatch_wide_with_completion_args_and_kind(
        0,
        command,
        expected_provider_state,
        flags,
        0,
        0,
        &[],
        [command, expected_provider_state, flags, 0],
        None,
        client,
        win32k_subsystem::WIN32K_REQUEST_PS_PROVIDER,
        true,
    )
}

/// Complete provider-owned process backing after Ps has run the Object Manager delete procedure.
/// The client VSpace is already gone at this boundary, and this command is forbidden from attaching
/// or faulting client pages; it can touch only provider-owned context and pool state.
pub(crate) unsafe fn win32k_finalize_ps_provider_process_objects(
    client: Win32kClientContext,
) -> (u64, bool) {
    let command = win32k_subsystem::PS_WIN32_PROVIDER_FINALIZE_PROCESS_OBJECTS;
    win32k_dispatch_wide_with_completion_args_and_kind(
        0,
        command,
        0,
        0,
        0,
        0,
        &[],
        [command, 0, 0, 0],
        None,
        client,
        win32k_subsystem::WIN32K_REQUEST_PS_PROVIDER,
        false,
    )
}

unsafe fn win32k_dispatch_wide_with_completion_args_and_kind(
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    stack_args: &[u64],
    completion_args: [u64; 4],
    output_stage: Option<nt_user_callback::DispatchOutputStage>,
    client: Win32kClientContext,
    request_kind: u64,
    attach_client: bool,
) -> (u64, bool) {
    let w_fault = WIN32K_FAULT_EP.load(Ordering::Relaxed);
    let host_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    let debug_flags = WIN32K_NEXT_DISPATCH_DEBUG_FLAGS.swap(0, Ordering::Relaxed);
    if w_fault == 0 || WIN32K_RETIRED.load(Ordering::Relaxed) != 0 {
        return (0xC000_0001u64, false);
    }
    // ── REQUEST FILL (caller-owned, exactly as the FSD `dispatch_irp` fills the IRP before the pump).
    // Attach win32k's client window to the CURRENT dispatch client (KeStackAttachProcess). If this is
    // a different client than last time, the previous client's leaf pages are Unmapped so the new
    // client's identical VAs re-fault to THIS client's frames (per-client cross-AS client memory).
    let client_pi = client.pi as u64;
    // TAIL WATCH tag 4/5 — sample EVERY hosted process' TEB tail immediately before and after every
    // win32k dispatch (this is the single funnel all dispatch sites go through, nested ones too).
    if attach_client {
        for watch_pi in 1..5usize {
            crate::teb_tail_watch(watch_pi, 4, ssn, client_pi);
        }
    }
    if attach_client && !w32_client_attach(client_pi) {
        return (0xC000_0001u64, false);
    }
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    clear_published_win32k_context();
    let dispatch_id = USER_CALLBACK_DISPATCH_IDS.fetch_add(1, Ordering::Relaxed) + 1;
    let callback_client = client.callback_client();
    let callback_capable = request_kind == win32k_subsystem::WIN32K_REQUEST_SSDT
        && user_callback_client_can_register(callback_client);
    if callback_capable && !register_user_callback_client_for_dispatch(dispatch_id, callback_client)
    {
        print_str(b"[user-callback] callback client registry full for dispatch\n");
        return (0xC000_009Au64, false);
    }
    let nested_user_callback = match begin_nested_user_callback_dispatch(client, dispatch_id, ssn) {
        Ok(nested) => nested,
        Err(error) => {
            if error == nt_user_callback::ContinuationError::Overflow {
                USER_CALLBACK_CONTINUATION_OVERFLOWS.fetch_add(1, Ordering::Relaxed);
            }
            print_str(b"[user-callback] rejected nested win32k dispatch: ");
            print_str(match error {
                nt_user_callback::ContinuationError::Overflow => b"continuation stack overflow\n",
                nt_user_callback::ContinuationError::Underflow => b"continuation stack underflow\n",
                nt_user_callback::ContinuationError::Sequence => b"invalid sequence\n",
                nt_user_callback::ContinuationError::Kind => b"invalid continuation kind\n",
                nt_user_callback::ContinuationError::State => b"invalid continuation state\n",
                nt_user_callback::ContinuationError::Client => b"client identity mismatch\n",
                nt_user_callback::ContinuationError::Correlation => {
                    b"dispatch correlation mismatch\n"
                }
            });
            if callback_capable {
                unregister_user_callback_client_for_dispatch(
                    dispatch_id,
                    client.pi,
                    client.tid,
                    client.badge,
                );
            }
            return (0xC000_000Du64, false);
        }
    };
    let callback_frame =
        (sh + win32k_subsystem::SH_USER_CALLBACK) as *mut nt_user_callback::CallbackFrame;
    let previous_dispatch = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        UserCallbackDispatchContext {
            dispatch_id,
            ssn,
            args: completion_args,
            caller_sp,
            output_stage,
        },
    );
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*callback_frame).header),
        nt_user_callback::CallbackHeader::idle(dispatch_id, client.pi, client.tid, client.badge),
    );
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_SSN) as *mut u64, ssn);
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_KIND) as *mut u64,
        request_kind,
    );
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A0) as *mut u64, a0);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A1) as *mut u64, a1);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A2) as *mut u64, a2);
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A3) as *mut u64, a3);
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_PROCESS_ID) as *mut u64,
        client.pid,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_NESTED_CALLBACK) as *mut u64,
        nested_user_callback as u64,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_CLIENT_PI) as *mut u64,
        client.pi as u64,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_GENERATION) as *mut u64,
        client.generation,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_CLIENT_TEB) as *mut u64,
        client.teb,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_THREAD_ID) as *mut u64,
        client.tid,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_EPROCESS) as *mut u64,
        client.eprocess,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_ETHREAD) as *mut u64,
        client.ethread,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_PROCESS_ROLE) as *mut u64,
        callback_process_role_code(client.process_role) as u64,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_TOKEN_AUTH) as *mut u64,
        client.token_authentication_id,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_TOKEN_USER_SID_LEN) as *mut u64,
        client.token_user_sid_len as u64,
    );
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_TOKEN_USER_SID_PTR) as *mut u64,
        win32k_subsystem::WIN32K_TOKEN_USER_SID_VADDR,
    );
    let mut sid_i = 0usize;
    while sid_i < win32k_subsystem::WIN32K_TOKEN_USER_SID_MAX {
        let byte = if sid_i < client.token_user_sid_len as usize {
            client.token_user_sid[sid_i]
        } else {
            0
        };
        core::ptr::write_volatile(
            (win32k_subsystem::WIN32K_TOKEN_USER_SID_VADDR + sid_i as u64) as *mut u8,
            byte,
        );
        sid_i += 1;
    }
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_DEBUG_FLAGS) as *mut u64,
        debug_flags,
    );
    let caller_stack_source = caller_sp != 0 && stack_args.is_empty();
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_CALLER_SP) as *mut u64,
        if caller_stack_source { caller_sp } else { 0 },
    );
    // Stage explicit STACK-ARG TAIL values only for executive-originated calls. Clear all slots first
    // so a provider-derived wide arity can never observe stale tail args from a previous dispatch.
    let mut clear = 0u64;
    while clear < win32k_subsystem::WIN32K_STACK_TAIL_ARGS as u64 {
        core::ptr::write_volatile(
            (sh + win32k_subsystem::SH_REQ_A4 + clear * 8) as *mut u64,
            0,
        );
        clear += 1;
    }
    let staged_tail = stack_args
        .len()
        .min(win32k_subsystem::WIN32K_STACK_TAIL_ARGS);
    let staged_total = if staged_tail == 0 {
        0
    } else {
        4 + staged_tail as u64
    };
    core::ptr::write_volatile(
        (sh + win32k_subsystem::SH_REQ_NARGS) as *mut u64,
        staged_total,
    );
    let mut i = 0usize;
    while i < staged_tail {
        let v = stack_args[i];
        core::ptr::write_volatile(
            (sh + win32k_subsystem::SH_REQ_A4 + i as u64 * 8) as *mut u64,
            v,
        );
        i += 1;
    }
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_STATUS) as *mut i32, 0);
    // ── FAULT LOOP (shared): drive win32k's dispatch through the unified `component_pump`, all win32k
    // capability gates TRUE. Fix (A) [DONE via a plain Send, distinguished by label] + Fix (B) [nested
    // faults answered through the per-caller REPLY_W32 cap so REPLY_MAIN's binding to the outer csrss
    // caller survives] + (f) demand-fault client-frame sharing + (g) int-0x2c assert-skip + the
    // 8192-page demand cap all live in the pump behind these flags — no logic deleted, only relocated.
    let rw = REPLY_W32_SLOT.load(Ordering::Relaxed);
    let ch = crate::spawn_hosts::PumpChannel {
        fault_ep: w_fault,
        pml4: host_pml4,
        code_va: win32k_subsystem::WIN32K_CODE_VA,
        image_frames: win32k_subsystem::WIN32K_IMAGE_FRAMES,
        exec_code_va: win32k_subsystem::WIN32K_CODE_VA,
        root_image_rights: 3,
        root_image_map_owner: crate::WIN32K_ROOT_IMAGE_MAP_OWNER.load(Ordering::Relaxed) as u16,
        shared_va: sh,
        dispatch_label: win32k_subsystem::W32_DISPATCH_LABEL,
        // The desktop-graphics init (co_IntInitializeDesktopGraphics) is a deep chain that demand-maps
        // many pages and trips many checked-build asserts; allow generous headroom (still bounded).
        demand_cap: 8192,
        trace_faults: false,
        // ★ win32k is blocked in its dispatch `Call` bound to `R_win32k`; we hand it the request by
        // ANSWERING that Call. There is no wake `Send` any more — `reply_on` cannot block.
        initial: crate::spawn_hosts::InitialAction::ReplyRequest,
        tcb: WIN32K_TCB.load(Ordering::Relaxed),
        reply_cap: rw,
        client_pi,
        client_generation: client.generation,
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Syscall,
        client_attach: attach_client,
            usermode_callback: callback_capable,
            wide_arg_marshal: true,
            assert_skip: true,
            sparse_vspace: true,
            io_port_faults: false,
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    if attach_client {
        for watch_pi in 1..5usize {
            crate::teb_tail_watch(watch_pi, 5, ssn, client_pi);
        }
    }
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous_dispatch,
    );
    retire_win32k_on_wall(&pr);
    USER_CALLBACK_LAST_PUMP_SUSPENDED.store(pr.callback_suspended as u64, Ordering::Release);
    if pr.callback_suspended {
        capture_suspended_published_win32k_context(callback_client);
    }
    if nested_user_callback {
        if pr.callback_suspended {
            return (pr.result, false);
        }
        if !pr.completed || !complete_nested_user_callback_dispatch(client, dispatch_id) {
            print_str(b"[user-callback] nested win32k dispatch failed to unwind\n");
            if callback_capable {
                unregister_user_callback_client_for_dispatch(
                    dispatch_id,
                    client.pi,
                    client.tid,
                    client.badge,
                );
            }
            return (pr.result, false);
        }
    }
    if callback_capable && !pr.callback_suspended {
        unregister_user_callback_client_for_dispatch(
            dispatch_id,
            client.pi,
            client.tid,
            client.badge,
        );
    }
    (pr.result, pr.completed)
}

/// `seL4_TCB_ReadRegisters` (label 2, legacy length-0 form) → the target's `(rip, rsp, rax)`.
pub(crate) unsafe fn tcb_read_rsp(tcb: u64) -> u64 {
    let rsp: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") 2u64 << 12 => _, // TCBReadRegisters, length 0
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r10") _,             // MR0 = rip
        lateout("r8") rsp,            // MR1 = rsp
        lateout("r9") _,              // MR2 = rax
        lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rsp
}

/// `seL4_TCB_ReadRegisters` (label 2, legacy length-0 form) → the target's saved RIP (MR0).
/// Used to sample a PARKED thread's instruction pointer for spin-diagnosis (BATCH 10).
pub(crate) unsafe fn tcb_read_rip(tcb: u64) -> u64 {
    let rip: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") 2u64 << 12 => _, // TCBReadRegisters, length 0
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r10") rip,           // MR0 = rip
        lateout("r8") _,              // MR1 = rsp
        lateout("r9") _,              // MR2 = rax
        lateout("r15") _,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    rip
}

/// `seL4_TCB_ReadRegisters` (length=20) → the target's full GPR set in `seL4_UserContext` order:
/// `[rip, rsp, rflags, rax, rbx, rcx, rdx, rsi, rdi, rbp, r8..r15, fs_base, gs_base]`. The first 4
/// words come back in r10/r8/r9/r15; words 4..20 spill into the invoker's IPC buffer (readable via
/// `get_recv_mr`). Valid rcx/r11 only for #exception-captured threads (`use_iretq_resume`), which an
/// int3-stopped hosted thread is. Used to recover the EXCEPTION_RECORD ptr (RCX) at RtlRaiseException.
pub(crate) unsafe fn tcb_read_regs20(tcb: u64, out: &mut [u64; 20]) {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") (2u64 << 12) | 20 => _, // TCBReadRegisters, msginfo.length=20 (label<<12 | len)
        inout("r10") 0u64 => r0,   // MR0 in / word 0 (rip) out
        inout("r8") 20u64 => r1,   // MR1 = count(20) in / word 1 (rsp) out
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r9") r2,          // word 2 (rflags)
        lateout("r15") r3,         // word 3 (rax)
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    out[0] = r0;
    out[1] = r1;
    out[2] = r2;
    out[3] = r3;
    // Words 4..20 were spilled into the executive's IPC buffer at MR slot i.
    for (i, slot) in out.iter_mut().enumerate().take(20).skip(4) {
        *slot = crate::get_recv_mr(i);
    }
}

pub(crate) const TCB_DEBUG_STATE_WORDS: usize = 29;
pub(crate) const TCB_DEBUG_NONE: u64 = u64::MAX;
pub(crate) const TCB_DBG_STATE: usize = 0;
pub(crate) const TCB_DBG_SCHEDULABLE: usize = 1;
pub(crate) const TCB_DBG_ENQUEUED: usize = 2;
pub(crate) const TCB_DBG_PRIORITY: usize = 3;
pub(crate) const TCB_DBG_SC: usize = 4;
pub(crate) const TCB_DBG_ACTIVE_SC: usize = 5;
pub(crate) const TCB_DBG_PENDING_REPLY: usize = 6;
pub(crate) const TCB_DBG_REPLY_TO: usize = 7;
pub(crate) const TCB_DBG_BOUND_NOTIFICATION: usize = 8;
pub(crate) const TCB_DBG_BLOCKED_IS_CALL: usize = 9;
pub(crate) const TCB_DBG_BLOCKED_CAN_GRANT: usize = 10;
pub(crate) const TCB_DBG_DONATED_SC: usize = 11;
pub(crate) const TCB_DBG_PENDING_FAULT: usize = 12;
pub(crate) const TCB_DBG_HOSTED_SYSCALLS: usize = 13;
pub(crate) const TCB_DBG_REPLY_BOUND_TCB: usize = 14;
pub(crate) const TCB_DBG_CURRENT_TCB: usize = 15;
pub(crate) const TCB_DBG_TARGET_TCB: usize = 16;
pub(crate) const TCB_DBG_CSPACE_INDEX: usize = 17;
pub(crate) const TCB_DBG_FAULT_CAP_KIND: usize = 18;
pub(crate) const TCB_DBG_FAULT_CAP_DETAIL: usize = 19;
pub(crate) const TCB_DBG_FAULT_EP_STATE: usize = 20;
pub(crate) const TCB_DBG_FAULT_EP_HEAD: usize = 21;
pub(crate) const TCB_DBG_FAULT_EP_TAIL: usize = 22;
pub(crate) const TCB_DBG_COMPOSITE_REPLY_HANDOFF: usize = 23;
pub(crate) const TCB_DBG_AFFINITY: usize = 24;
pub(crate) const TCB_DBG_DOMAIN: usize = 25;
pub(crate) const TCB_DBG_CURRENT_DOMAIN: usize = 26;
pub(crate) const TCB_DBG_QUEUE_TOP_PRIORITY: usize = 27;
pub(crate) const TCB_DBG_DIRECT_HANDOFF: usize = 28;

fn print_tcb_debug_opt(value: u64) {
    if value == TCB_DEBUG_NONE {
        print_str(b"none");
    } else {
        print_u64(value);
    }
}

fn print_tcb_debug_state_body(state: &[u64; TCB_DEBUG_STATE_WORDS]) {
    print_str(b" state=");
    print_u64(state[TCB_DBG_STATE]);
    print_str(b" sched=");
    print_u64(state[TCB_DBG_SCHEDULABLE]);
    print_str(b" enq=");
    print_u64(state[TCB_DBG_ENQUEUED]);
    print_str(b" prio=");
    print_u64(state[TCB_DBG_PRIORITY]);
    print_str(b" sc=");
    print_tcb_debug_opt(state[TCB_DBG_SC]);
    print_str(b" active_sc=");
    print_tcb_debug_opt(state[TCB_DBG_ACTIVE_SC]);
    print_str(b" pend_reply=");
    print_tcb_debug_opt(state[TCB_DBG_PENDING_REPLY]);
    print_str(b" reply_to=");
    print_tcb_debug_opt(state[TCB_DBG_REPLY_TO]);
    print_str(b" ntfn=");
    print_tcb_debug_opt(state[TCB_DBG_BOUND_NOTIFICATION]);
    print_str(b" call=");
    print_u64(state[TCB_DBG_BLOCKED_IS_CALL]);
    print_str(b" grant=");
    print_u64(state[TCB_DBG_BLOCKED_CAN_GRANT]);
    print_str(b" donated=");
    print_tcb_debug_opt(state[TCB_DBG_DONATED_SC]);
    print_str(b" fault=");
    print_u64(state[TCB_DBG_PENDING_FAULT]);
    print_str(b" hosted=");
    print_u64(state[TCB_DBG_HOSTED_SYSCALLS]);
    print_str(b" reply_bound=");
    print_tcb_debug_opt(state[TCB_DBG_REPLY_BOUND_TCB]);
    print_str(b" current=");
    print_tcb_debug_opt(state[TCB_DBG_CURRENT_TCB]);
    print_str(b" target=");
    print_tcb_debug_opt(state[TCB_DBG_TARGET_TCB]);
    print_str(b" comp-handoff=");
    print_tcb_debug_opt(state[TCB_DBG_COMPOSITE_REPLY_HANDOFF]);
    print_str(b" aff=");
    print_u64(state[TCB_DBG_AFFINITY]);
    print_str(b" dom=");
    print_u64(state[TCB_DBG_DOMAIN]);
    print_str(b" cur-dom=");
    print_u64(state[TCB_DBG_CURRENT_DOMAIN]);
    print_str(b" qtop=");
    print_tcb_debug_opt(state[TCB_DBG_QUEUE_TOP_PRIORITY]);
    print_str(b" direct=");
    print_tcb_debug_opt(state[TCB_DBG_DIRECT_HANDOFF]);
    print_str(b" cspace=");
    print_tcb_debug_opt(state[TCB_DBG_CSPACE_INDEX]);
    print_str(b" fault-ep=");
    print_u64(state[TCB_DBG_FAULT_EP_STATE]);
    print_str(b"/");
    print_tcb_debug_opt(state[TCB_DBG_FAULT_EP_HEAD]);
    print_str(b"/");
    print_tcb_debug_opt(state[TCB_DBG_FAULT_EP_TAIL]);
}

pub(crate) unsafe fn trace_hosted_tcb_debug_state(label: &[u8], tcb: u64, reply_cap: u64) {
    if tcb == 0 {
        return;
    }
    let mut state = [0u64; TCB_DEBUG_STATE_WORDS];
    tcb_read_debug_state(tcb, reply_cap, &mut state);
    print_str(b"[");
    print_str(label);
    print_str(b"-tcb] tcb=0x");
    print_hex(tcb as u32);
    print_str(b" reply_cap=0x");
    print_hex(reply_cap as u32);
    print_tcb_debug_state_body(&state);
    print_str(b"\n");
}

pub(crate) unsafe fn trace_win32k_tcb_debug_state() {
    let tcb = WIN32K_TCB.load(Ordering::Relaxed);
    let reply = REPLY_W32_SLOT.load(Ordering::Relaxed);
    if tcb == 0 {
        return;
    }
    let mut state = [0u64; TCB_DEBUG_STATE_WORDS];
    tcb_read_debug_state(tcb, reply, &mut state);
    print_str(b"[w32disp] tcb");
    print_tcb_debug_state_body(&state);
    print_str(b"\n");
}

/// rust-micro extension: `TCB::ReadDebugState(reply_cap)` returns compact scheduler/IPC state for
/// a target TCB and, when `reply_cap != 0`, the TCB currently bound to that reply object.
pub(crate) unsafe fn tcb_read_debug_state(
    tcb: u64,
    reply_cap: u64,
    out: &mut [u64; TCB_DEBUG_STATE_WORDS],
) {
    let (r0, r1, r2, r3): (u64, u64, u64, u64);
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") LBL_TCB_READ_DEBUG_STATE << 12 => _,
        inout("r10") reply_cap => r0,
        in("r12") 0u64,
        in("r13") 0u64,
        lateout("r8") r1,
        lateout("r9") r2,
        lateout("r15") r3,
        lateout("rax") _, lateout("rcx") _, lateout("r11") _,
        options(nostack),
    );
    out[0] = r0;
    out[1] = r1;
    out[2] = r2;
    out[3] = r3;
    for (i, slot) in out
        .iter_mut()
        .enumerate()
        .take(TCB_DEBUG_STATE_WORDS)
        .skip(4)
    {
        *slot = crate::get_recv_mr(i);
    }
}

/// Print the win32k call chain (return-address RVAs, deepest first) at a `win32k_dispatch` wall.
/// Mirrors win32k's ACTIVE stack (fault-time RSP .. stack_top) into the executive's own VSpace and
/// scans it for return addresses in win32k's image — same technique as the DriverEntry-path backtrace.
pub(crate) unsafe fn win32k_dispatch_backtrace() {
    let ss = WIN32K_STACK_SLOT.load(Ordering::Relaxed);
    let sf = WIN32K_STACK_FRAMES.load(Ordering::Relaxed);
    let tcb = WIN32K_TCB.load(Ordering::Relaxed);
    if ss == 0 || sf == 0 || tcb == 0 {
        return;
    }
    let mirror = 0x0000_0100_0732_0000u64;
    if WIN32K_DISP_BT_PT.load(Ordering::Relaxed) == 0 {
        let spt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, spt);
        let _ = paging_struct_map(spt, LBL_X86_PAGE_TABLE_MAP, mirror, CAP_INIT_THREAD_VSPACE);
        for i in 0..sf {
            let _ = page_map(
                copy_cap(ss + i),
                mirror + i * 0x1000,
                RW_NX,
                CAP_INIT_THREAD_VSPACE,
            );
        }
        WIN32K_DISP_BT_PT.store(1, Ordering::Relaxed);
    }
    let mut registers = [0u64; 20];
    tcb_read_regs20(tcb, &mut registers);
    let rip = registers[nt_user_callback::USER_CONTEXT_RIP];
    let rsp = registers[nt_user_callback::USER_CONTEXT_RSP];
    let sbase = win32k_subsystem::WIN32K_STACK_VADDR;
    let stack_top = sbase + sf * 0x1000;
    let start = if rsp >= sbase && rsp < stack_top {
        rsp
    } else {
        sbase
    };
    let code_va = win32k_subsystem::WIN32K_CODE_VA;
    let lo = code_va;
    let hi = code_va + win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000;
    print_str(b"[w32disp] backtrace rip=0x");
    print_hex((rip >> 32) as u32);
    print_hex(rip as u32);
    if rip >= lo && rip < hi {
        print_str(b" rva=0x");
        print_hex(rip.wrapping_sub(code_va) as u32);
    }
    print_str(b" rsp=0x");
    print_hex((rsp >> 32) as u32);
    print_hex(rsp as u32);
    print_str(b" rax=0x");
    print_hex((registers[3] >> 32) as u32);
    print_hex(registers[3] as u32);
    print_str(b" rcx=0x");
    print_hex((registers[5] >> 32) as u32);
    print_hex(registers[5] as u32);
    print_str(b" rdx=0x");
    print_hex((registers[6] >> 32) as u32);
    print_hex(registers[6] as u32);
    print_str(b" rsi=0x");
    print_hex((registers[nt_user_callback::USER_CONTEXT_RSI] >> 32) as u32);
    print_hex(registers[nt_user_callback::USER_CONTEXT_RSI] as u32);
    print_str(b" rdi=0x");
    print_hex((registers[nt_user_callback::USER_CONTEXT_RDI] >> 32) as u32);
    print_hex(registers[nt_user_callback::USER_CONTEXT_RDI] as u32);
    print_str(b" r10=0x");
    print_hex((registers[nt_user_callback::USER_CONTEXT_R10] >> 32) as u32);
    print_hex(registers[nt_user_callback::USER_CONTEXT_R10] as u32);
    print_str(b" r8=0x");
    print_hex((registers[nt_user_callback::USER_CONTEXT_R8] >> 32) as u32);
    print_hex(registers[nt_user_callback::USER_CONTEXT_R8] as u32);
    print_str(b" r9=0x");
    print_hex((registers[nt_user_callback::USER_CONTEXT_R9] >> 32) as u32);
    print_hex(registers[nt_user_callback::USER_CONTEXT_R9] as u32);
    print_str(b" r15=0x");
    print_hex((registers[nt_user_callback::USER_CONTEXT_R15] >> 32) as u32);
    print_hex(registers[nt_user_callback::USER_CONTEXT_R15] as u32);
    print_str(b"\n");
    trace_win32k_tcb_debug_state();
    win32k_subsystem::trace_win32k_wall_context();
    // RAW stack window from fault rsp: each qword annotated with its win32k RVA if it lands in the
    // image (a return address). Keep the scan bounded; this path only runs after the component has
    // already walled, and the first few caller RVAs are the useful signal.
    if start >= sbase && start < stack_top {
        let scan_len = (stack_top - start).min(0x500);
        let mut off = 0u64;
        let mut printed = 0u32;
        while off < scan_len && printed < 24 {
            let va = start + off;
            let v = core::ptr::read_volatile((mirror + (va - sbase)) as *const u64);
            if v >= lo && v < hi {
                print_str(b"  [rsp+0x");
                print_hex(off as u32);
                print_str(b"] rva=0x");
                print_hex(v.wrapping_sub(code_va) as u32);
                print_str(b"\n");
                printed += 1;
            } else if v >= crate::IMAGE_BASE
                && v < crate::IMAGE_BASE
                    + crate::IMAGE_FRAMES_COUNT.load(Ordering::Relaxed) * 0x1000
            {
                print_str(b"  [rsp+0x");
                print_hex(off as u32);
                print_str(b"] exec-rva=0x");
                print_hex(v.wrapping_sub(crate::IMAGE_BASE) as u32);
                print_str(b"\n");
                printed += 1;
            }
            off += 8;
        }
    }
}
