//! `win32k_glue` — the executive-side win32k client plumbing: RO-map win32k's
//! USER heap into csrss, per-client cross-AS page attach (w32_*), the DirectX/
//! ftfd/framebuffer driver loaders, and the win32k syscall dispatch + backtrace.
//! Extracted verbatim from `main.rs` (pure reorg; no logic change).
#![allow(clippy::all)]
use crate::*;

const WINDOWPROC_LPARAM_OFFSET: u64 = 0x28;
const WINDOWPROC_PAYLOAD_OFFSET: u32 = 0x40;

static USER_CALLBACK_DISPATCH_IDS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_RENDEZVOUS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_WINLOGON_API0: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_API0_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_FAILURES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_DEAD_FAILURES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_EXPLORER_NCCREATE_FALSES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_TABLE_VALID: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_RETURNS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_RESOURCE_STARTED: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_PUSHES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_UNWINDS: AtomicU64 = AtomicU64::new(0);
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
static USER_CALLBACK_REAL_WM_PAINT_RETURNS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_LAST_REAL_WM_PAINT_HWND: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DISPATCHER: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_PEB: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_PID: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_TEB: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_SCRATCH: AtomicU64 = AtomicU64::new(0);
static mut USER_CALLBACK_CONTINUATIONS: nt_user_callback::ContinuationStack =
    nt_user_callback::ContinuationStack::new();
static mut USER_CALLBACK_ACTIVE: nt_user_callback::ActiveCallbackStack =
    nt_user_callback::ActiveCallbackStack::new();
static mut USER_CALLBACK_SAS_SEQUENCE: nt_user_callback::SasWmCreateNestedSequence =
    nt_user_callback::SasWmCreateNestedSequence::new();
static USER_CALLBACK_SAS_SEQUENCE_ACTIVE: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) struct CompletedWin32kDispatch {
    pub ssn: u64,
    pub args: [u64; 4],
    pub caller_sp: u64,
    pub status: i32,
}

#[derive(Clone, Copy)]
pub(crate) struct CompletedUserCallback {
    pub outer_dispatch: Option<CompletedWin32kDispatch>,
}

/// The win32k dispatch currently being serviced. The dispatch a SUSPENDED callback belongs to is
/// carried by that callback's own frame ([`nt_user_callback::ActiveCallbackFrame::dispatch_context`])
/// — it used to live in a glue-side array indexed in lockstep with the callback stack, which is only
/// sound while frames are removed strictly top-first (they are not: the stack interleaves the
/// chains of several client threads).
type UserCallbackDispatchContext = nt_user_callback::DispatchContext;

static mut USER_CALLBACK_CURRENT_DISPATCH: UserCallbackDispatchContext =
    UserCallbackDispatchContext::EMPTY;
/// Times the bridge invariant was re-asserted, and times it had actually been CLOBBERED (a foreign
/// writer had replaced the bridged `PWND`) — the durable proof this is a live correctness fix.
static USER_CALLBACK_WINDOW_REASSERTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_WINDOW_REPAIRS: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) enum UserCallbackDisposition {
    ReplyImmediately,
    SuspendComponent,
}

#[derive(Clone, Copy)]
pub(crate) struct Win32kClientContext {
    pub pi: u32,
    pub pid: u64,
    pub badge: u64,
    pub tid: u64,
    pub teb: u64,
    pub peb_mirror: u64,
    pub scratch_base: u64,
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
            core::ptr::write(core::ptr::addr_of_mut!(USER_CALLBACK_SAS_SEQUENCE), sequence);
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

unsafe fn write_callback_failure_reply(
    request: nt_user_callback::CallbackHeader,
    status: i32,
) {
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let mut reply = request;
    reply.state = nt_user_callback::CallbackState::Reply as u32;
    reply.output_length = 0;
    reply.status = status;
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).header), reply);
}

unsafe fn begin_controlled_continuation(request: nt_user_callback::CallbackHeader) -> bool {
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
    // "Root" is per client thread: this thread holds no continuation yet, so the win32k dispatch
    // this callback was raised inside has to be recorded first. Another thread's chain being live
    // is irrelevant.
    let root = stack.is_empty_for(&client);
    if (root && stack.push_dispatch(client, request.dispatch_id).is_err())
        || stack.push_callback(correlation).is_err()
        || active.push(request).is_err()
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
    if stack.complete_dispatch(client, request.dispatch_id).is_err() {
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

fn winlogon_callback_teb_alias(
    client: crate::spawn_hosts::UserCallbackClient,
) -> Option<u64> {
    if client.pi != 2 || client.tid == 0 {
        return None;
    }
    let alias = match client.badge {
        WINLOGON_BADGE if client.tid == PM_TIDS[2].load(Ordering::Relaxed) => {
            WINLOGON_MAIN_TEB_MIRROR_VA
        }
        WINLOGON_WORKER_BADGE if client.tid == PM_LISTENER_TID.load(Ordering::Relaxed) => {
            WINLOGON_WORKER_STACK_MIRROR_VA + WL_LISTENER_STACK_FRAMES * 0x1000
        }
        WINLOGON_WORKER2_BADGE if client.tid == WL_WORKER2_TID.load(Ordering::Relaxed) => {
            WINLOGON_WORKER2_STACK_MIRROR_VA + WL_WORKER2_STACK_FRAMES * 0x1000
        }
        WINLOGON_WORKER3_BADGE if client.tid == WL_WORKER3_TID.load(Ordering::Relaxed) => {
            WINLOGON_WORKER3_STACK_MIRROR_VA + WL_WORKER3_STACK_FRAMES * 0x1000
        }
        badge => {
            let Some((pi, slot)) = tp_worker_identity_from_badge(badge) else {
                return None;
            };
            if pi != 2 || client.tid != TP_WORKER_TID[2][slot].load(Ordering::Relaxed) {
                return None;
            }
            tp_worker_stack_mirror_va(2, slot) + TP_WORKER_STACK_FRAMES * 0x1000
        }
    };
    Some(alias)
}

fn main_gui_callback_teb_alias(client: crate::spawn_hosts::UserCallbackClient) -> Option<u64> {
    let pi = client.pi as usize;
    if client.tid == 0 || pi >= PM_TIDS.len() || client.tid != PM_TIDS[pi].load(Ordering::Relaxed) {
        return None;
    }
    match (client.pi, client.badge) {
        (6, EXPLORER_BADGE) => {
            let alias = crate::env_scratch_base_for_pi(pi);
            (alias != 0).then_some(alias)
        }
        _ => None,
    }
}

fn client_callback_teb_alias(client: crate::spawn_hosts::UserCallbackClient) -> Option<u64> {
    if client.pi == 2 {
        winlogon_callback_teb_alias(client)
    } else {
        main_gui_callback_teb_alias(client)
    }
}

fn client_callbacks_supported(pi: u32) -> bool {
    matches!(pi, 2 | 6)
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
            < win32k_subsystem::WIN32K_HEAP_VADDR
                + win32k_subsystem::WIN32K_HEAP_FRAMES * 0x1000
    {
        server_pwnd
            - (win32k_subsystem::WIN32K_HEAP_VADDR
                - win32k_subsystem::CSRSS_W32_SHARED_VA)
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
        restore_client_callback_window(frame);
    }
}

unsafe fn abort_controlled_user_callbacks() {
    restore_all_client_callback_windows();
    *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS) =
        nt_user_callback::ContinuationStack::new();
    USER_CALLBACK_SAS_SEQUENCE_ACTIVE.store(0, Ordering::Relaxed);
    USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID.store(0, Ordering::Relaxed);
}

fn sas_sequence_matches(request: &nt_user_callback::CallbackHeader) -> bool {
    let dispatch_id = USER_CALLBACK_SAS_SEQUENCE_ACTIVE.load(Ordering::Relaxed);
    dispatch_id != 0
        && request.dispatch_id == dispatch_id
        && request.callback_id as u64 == USER_CALLBACK_SAS_SEQUENCE_CALLBACK_ID.load(Ordering::Relaxed)
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

unsafe fn callback_payload_write_u64(frame: *mut nt_user_callback::CallbackFrame, offset: usize, value: u64) {
    for (index, byte) in value.to_le_bytes().iter().enumerate() {
        core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).payload[offset + index]), *byte);
    }
}

pub(crate) unsafe fn service_user_callback(
    client: crate::spawn_hosts::UserCallbackClient,
) -> Option<UserCallbackDisposition> {
    const WPCA_MSG: usize = 0x18;
    const WPCA_RESULT: usize = 0x38;

    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let request = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    if nt_user_callback::validate_request(&request).is_err()
        || request.client_pi != client.pi
        || request.client_tid != client.tid
        || request.client_badge != client.badge
    {
        print_str(b"[user-callback] invalid or stale component request\n");
        return None;
    }
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

    let winlogon_api0_ordinal = if request.api_index == 0 && client.pi == 2 {
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
    if client_callbacks_supported(client.pi) && contract_valid && !client_dead {
        let callback_table = if client.peb_mirror == 0 {
            0
        } else {
            core::ptr::read_volatile((client.peb_mirror + 0x58) as *const u64)
        };
        let dispatcher_rva = crate::img_spawn::OUR_KI_USER_CALLBACK_DISPATCHER_RVA.load(Ordering::Relaxed);
        let dispatcher = if dispatcher_rva == 0 { 0 } else { crate::NTDLL_BASE + dispatcher_rva };
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
            print_str(if valid { b" (nonzero, aligned)" } else { b" (INVALID)" });
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
            && begin_controlled_continuation(request)
        {
            if !remember_active_dispatch(&request) {
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
                    callback_payload_u64(frame, 0x10),
                    window_message,
                )
            {
                // The dispatch context travels with the frame `abort_…` is about to discard.
                abort_controlled_user_callbacks();
                return None;
            }
            USER_CALLBACK_DISPATCHER.store(dispatcher, Ordering::Relaxed);
            USER_CALLBACK_CLIENT_PEB.store(client.peb_mirror, Ordering::Relaxed);
            USER_CALLBACK_CLIENT_SCRATCH.store(client.scratch_base, Ordering::Relaxed);
            USER_CALLBACK_CLIENT_PID.store(
                core::ptr::read_volatile(
                    (win32k_subsystem::WIN32K_SHARED_VADDR
                        + win32k_subsystem::SH_REQ_PROCESS_ID) as *const u64,
                ),
                Ordering::Relaxed,
            );
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
                    core::ptr::write_volatile(
                        (win32k_subsystem::WIN32K_SHARED_VADDR
                            + win32k_subsystem::SH_SAS_HWND) as *mut u64,
                        sas_hwnd,
                    );
                    core::ptr::write_volatile(
                        (win32k_subsystem::WIN32K_SHARED_VADDR
                            + win32k_subsystem::SH_SAS_SESSION) as *mut u64,
                        sas_session,
                    );
                    print_str(b"[user-callback] latched real SAS WM_CREATE hwnd=0x");
                    print_hex(sas_hwnd as u32);
                    print_str(b" session=0x");
                    print_hex((sas_session >> 32) as u32);
                    print_hex(sas_session as u32);
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
            if client.pi == 6
                && request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            {
                USER_CALLBACK_EXPLORER_API0_REDIRECTS.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    if suspend_component {
        print_str(b"[user-callback] B component continuation parked in callback receive loop\n");
        Some(UserCallbackDisposition::SuspendComponent)
    } else {
        const STATUS_UNSUCCESSFUL: i32 = 0xc000_0001u32 as i32;
        const STATUS_INFO_LENGTH_MISMATCH: i32 = 0xc000_0004u32 as i32;
        const STATUS_NOT_SUPPORTED: i32 = 0xc000_00bbu32 as i32;
        const STATUS_THREAD_IS_TERMINATING: i32 = 0xc000_004bu32 as i32;
        let status = if client_dead {
            STATUS_THREAD_IS_TERMINATING
        } else if contract.is_none() || client.pi != 2 {
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
        if client.pi == 6 && !client_dead {
            USER_CALLBACK_EXPLORER_FAILURES.fetch_add(1, Ordering::Relaxed);
        } else if client.pi == 6 {
            USER_CALLBACK_EXPLORER_DEAD_FAILURES.fetch_add(1, Ordering::Relaxed);
        }
        write_callback_failure_reply(request, status);
        Some(UserCallbackDisposition::ReplyImmediately)
    }
}

unsafe fn tcb_write_regs20(tcb: u64, registers: &[u64; 20], resume: bool) -> u64 {
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

fn callback_client_tcb(tid: u64) -> Option<u64> {
    hosted_thread_tcb_cell(tid)
        .map(|cell| cell.load(Ordering::Relaxed))
        .filter(|tcb| *tcb != 0)
}

pub(crate) unsafe fn begin_controlled_user_callback_redirect(
    client: Win32kClientContext,
    outer_resume_ip: u64,
    outer_rsp: u64,
    outer_flags: u64,
) -> bool {
    let Some(tcb) = callback_client_tcb(client.tid) else {
        return false;
    };
    let mut saved = [0u64; 20];
    tcb_read_regs20(tcb, &mut saved);
    redirect_pending_user_callback(
        client,
        &saved,
        outer_resume_ip,
        outer_rsp,
        outer_flags,
    )
}

unsafe fn redirect_pending_user_callback(
    client: Win32kClientContext,
    saved: &[u64; 20],
    outer_resume_ip: u64,
    outer_rsp: u64,
    outer_flags: u64,
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
    let Some(tcb) = callback_client_tcb(client.tid) else {
        return false;
    };
    let dispatcher = USER_CALLBACK_DISPATCHER.load(Ordering::Relaxed);
    if dispatcher == 0 {
        return false;
    }

    let Ok(layout) = nt_user_callback::UserCallbackStackLayout::below(
        saved[nt_user_callback::USER_CONTEXT_RSP],
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
        outer_resume_ip,
        outer_rsp,
        outer_flags as u32,
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

    let redirected =
        nt_user_callback::callback_redirect_context(saved, dispatcher, layout.frame_pointer);
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
            *saved,
            outer_resume_ip,
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

unsafe fn resume_suspended_user_callback_component(
    request: nt_user_callback::CallbackHeader,
) -> crate::spawn_hosts::PumpResult {
    let client = crate::spawn_hosts::UserCallbackClient {
        pi: request.client_pi,
        badge: request.client_badge,
        tid: request.client_tid,
        peb_mirror: USER_CALLBACK_CLIENT_PEB.load(Ordering::Relaxed),
        scratch_base: USER_CALLBACK_CLIENT_SCRATCH.load(Ordering::Relaxed),
    };
    let channel = crate::spawn_hosts::PumpChannel {
        fault_ep: WIN32K_FAULT_EP.load(Ordering::Relaxed),
        pml4: WIN32K_HOST_PML4.load(Ordering::Relaxed),
        code_va: win32k_subsystem::WIN32K_CODE_VA,
        image_frames: win32k_subsystem::WIN32K_IMAGE_FRAMES,
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
        callback_client: Some(client),
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Syscall,
            client_attach: true,
            usermode_callback: true,
            wide_arg_marshal: true,
            assert_skip: true,
            sparse_vspace: true,
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
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    let Some(active_frame) = active.top().copied() else {
        return (0xC000_0001u32 as i32, false);
    };
    if active_frame.is_redirected() {
        return (0xC000_0001u32 as i32, false);
    }
    let request = *active_frame.request();
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
    let dispatch_context = *active_frame.dispatch_context();
    write_callback_failure_reply(request, 0xc000_0001u32 as i32);
    let unwind_ok = unwind_controlled_callback(request);
    let cancelled = active.cancel_pending(correlation);
    if let Ok(frame) = cancelled {
        restore_client_callback_window(frame);
    }
    if !unwind_ok || cancelled.is_err() {
        abort_controlled_user_callbacks();
        return (0xC000_0001u32 as i32, false);
    }
    let previous_dispatch = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        dispatch_context,
    );
    let result = resume_suspended_user_callback_component(request);
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous_dispatch,
    );
    let stack_ok = result.completed
        && !result.callback_suspended
        && unwind_controlled_dispatch(request);
    if !stack_ok {
        abort_controlled_user_callbacks();
    }
    (result.status, stack_ok)
}

/// Crash-site diagnostic for a client that faulted while a user-mode callback was in flight. Prints
/// the faulting GPRs plus the exact client-side state `user32`'s `ValidateHwnd`/`DesktopPtrToUser`
/// read to produce a `PWND`: the `CLIENTINFO.CallbackWnd` triple the callback bridge maintains
/// (TEB+0x840 hWnd / +0x848 pWnd / +0x850 pActCtx) and `CLIENTINFO.pDeskInfo` / `.ulClientDelta`
/// (TEB+0x820 / +0x828). A corrupt `PWND` is either the cached one or a delta-translated one — this
/// line says WHICH, without which the two are indistinguishable from the fault address alone.
pub(crate) unsafe fn dump_client_callback_crash_state(client_pi: usize, tcb: u64) {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    if client_pi != 2 || active.is_empty() {
        return;
    }
    if tcb != 0 {
        let mut regs = [0u64; 20];
        tcb_read_regs20(tcb, &mut regs);
        print_str(b"[cb-crash] regs rip=0x");
        print_hex(regs[0] as u32);
        print_str(b" rsp=0x");
        print_hex((regs[1] >> 32) as u32);
        print_hex(regs[1] as u32);
        print_str(b" rax=0x");
        print_hex((regs[3] >> 32) as u32);
        print_hex(regs[3] as u32);
        print_str(b" rcx=0x");
        print_hex((regs[5] >> 32) as u32);
        print_hex(regs[5] as u32);
        print_str(b" rdx=0x");
        print_hex((regs[6] >> 32) as u32);
        print_hex(regs[6] as u32);
        print_str(b"\n");
        print_str(b"[cb-crash] stack:");
        let mut slot = 0u64;
        while slot < 12 {
            let value = crate::img_spawn::smss_stack_read(regs[1] + slot * 8);
            print_str(b" +0x");
            print_hex((slot * 8) as u32);
            print_str(b":0x");
            print_hex((value >> 32) as u32);
            print_hex(value as u32);
            slot += 1;
        }
        print_str(b"\n");
    }
    let teb = WINLOGON_MAIN_TEB_MIRROR_VA;
    let read = |offset: u64| core::ptr::read_volatile((teb + offset) as *const u64);
    print_str(b"[cb-crash] CLIENTINFO pDeskInfo=0x");
    print_hex((read(0x820) >> 32) as u32);
    print_hex(read(0x820) as u32);
    print_str(b" ulClientDelta=0x");
    print_hex((read(0x828) >> 32) as u32);
    print_hex(read(0x828) as u32);
    print_str(b" CallbackWnd{hWnd=0x");
    print_hex(read(0x840) as u32);
    print_str(b" pWnd=0x");
    print_hex((read(0x848) >> 32) as u32);
    print_hex(read(0x848) as u32);
    print_str(b" pActCtx=0x");
    print_hex((read(0x850) >> 32) as u32);
    print_hex(read(0x850) as u32);
    print_str(b"}\n");
    if let Some(frame) = active.top() {
        let request = frame.request();
        print_str(b"[cb-crash] active callback api=");
        print_u64(request.api_index as u64);
        print_str(b" depth=");
        print_u64(active.len() as u64);
        print_str(b" redirected=");
        print_u64(frame.is_redirected() as u64);
        print_str(b"\n");
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
        let component = resume_suspended_user_callback_component(request);
        core::ptr::write(
            core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
            previous_dispatch,
        );
        unwound += 1;
        USER_CALLBACK_DEAD_CLIENT_UNWINDS.fetch_add(1, Ordering::Relaxed);
        // A REDIRECTED frame consumed a `real-redirect` that can never become a `real-return`; record
        // it so the redirect ledger stays exact (see the counter's doc comment).
        USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS.fetch_add(was_redirected as u64, Ordering::Relaxed);
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

// ── FAULT INJECTION: `exec_user_callback_dead_client_unwind` ────────────────────────────────────
// Proof bits returned by [`inject_dead_client_callback_unwind`]; ALL set = the spec passes.
/// win32k really SUSPENDED itself inside `KeUserModeCallback` awaiting the injected client's reply.
pub(crate) const DEAD_CLIENT_INJECT_PARKED: u64 = 0x01;
/// The client really entered the reverse transition: the top active frame is REDIRECTED, depth >= 1.
pub(crate) const DEAD_CLIENT_INJECT_REDIRECTED: u64 = 0x02;
/// The injected client thread was really TERMINATED (TCB suspended + revoked) while at that depth.
pub(crate) const DEAD_CLIENT_INJECT_VICTIM_DEAD: u64 = 0x04;
/// `unwind_dead_client_user_callbacks` unwound the frame (and counted it as a redirect teardown).
pub(crate) const DEAD_CLIENT_INJECT_UNWOUND: u64 = 0x08;
/// The continuation + active stacks DRAINED (pushes == unwinds, nothing left for that client).
pub(crate) const DEAD_CLIENT_INJECT_DRAINED: u64 = 0x10;
/// win32k is back in its NORMAL dispatch receive loop — proven by a fresh dispatch that COMPLETES.
pub(crate) const DEAD_CLIENT_INJECT_WIN32K_IDLE: u64 = 0x20;
pub(crate) const DEAD_CLIENT_INJECT_ALL: u64 = 0x3f;

/// ★ DELIBERATE FAULT INJECTION that makes [`unwind_dead_client_user_callbacks`] a GATE-PROTECTED
/// path instead of a path evidenced only by historical crash boots.
///
/// The wedge this guards against is real and was measured (BATCH 48): a client that dies while
/// win32k's dispatch is suspended inside `KeUserModeCallback` never sends its `NtCallbackReturn`, the
/// withheld `W32_USER_CALLBACK_RESUME_LABEL` is never sent, win32k's single TCB stays blocked in its
/// callback receive loop and the executive's shared loop blocks in `recv` FOREVER — `RUNEXIT=124`,
/// no gate, no measurement. But on a green boot no client dies, so nothing exercises the recovery.
/// This self-test manufactures the exact condition, for real, and asserts the recovery.
///
/// It is REAL, not a mock, at every step:
///  1. a genuine win32k dispatch (`NtUserMessageCall(hwnd, WM_NULL, …, FNID_SENDMESSAGE)`) is issued
///     on the VICTIM thread's identity → win32k's `co_IntDoSendMessage → co_IntSendMessage →
///     co_IntCallWindowProc` reaches the client's window procedure and calls `KeUserModeCallback`;
///  2. `service_user_callback` SUSPENDS the component for real (its dispatch parks in the callback
///     receive loop with a non-empty continuation stack) and the victim is REDIRECTED for real into
///     `KiUserCallbackDispatcher` (registers rewritten, callout frame written to its stack);
///  3. the victim thread is then genuinely TERMINATED through the normal hosted-thread terminate
///     mechanism (TCB suspended, cap revoked) — from here it can never reach `NtCallbackReturn`,
///     which is precisely the wedge condition;
///  4. `unwind_dead_client_user_callbacks` runs, and the recovery is asserted: the frame unwinds,
///     both stacks drain, and a FRESH win32k dispatch COMPLETES (win32k really is back in its idle
///     dispatch receive loop rather than stranded).
///
/// SAFETY FOR THE REAL FLOW. This runs POST-QUIESCE — after the hosted receive loop has broken, so
/// after the entire load-bearing boot (winlogon SAS → msgina dialog → the authentic desktop/dialog
/// paints) has already completed and its counters are latched. The victim is a NON-CRITICAL winlogon
/// RPC worker thread (never the main thread, which the gate still samples), and the message sent is
/// `WM_NULL` — the one message defined to do nothing, so no window state and no pixel can change.
/// Note the `pi`-scoped dead latch this sets is likewise harmless here: no further win32k callback is
/// requested for winlogon after quiesce.
///
/// Returns the `DEAD_CLIENT_INJECT_*` proof mask.
/// An EXPENDABLE winlogon (pi 2) worker thread usable as a callback-injection client: a real hosted
/// thread with a live TCB, a registered client stack and a TEB alias the callback-window bridge can
/// write (what a redirect needs). NEVER winlogon's main thread (the gate still samples that one).
/// Returns `(badge, tid, teb_va, stack_top)`.
unsafe fn expendable_winlogon_callback_thread() -> Option<(u64, u64, u64, u64)> {
    let candidates = [
        (
            WINLOGON_WORKER2_BADGE,
            WL_WORKER2_TID.load(Ordering::Relaxed),
            WL_WORKER2_TEB_VA,
            WL_WORKER2_STACK_BASE + WL_WORKER2_STACK_FRAMES * 0x1000,
        ),
        (
            WINLOGON_WORKER_BADGE,
            PM_LISTENER_TID.load(Ordering::Relaxed),
            WL_LISTENER_TEB_VA,
            WL_LISTENER_STACK_BASE + WL_LISTENER_STACK_FRAMES * 0x1000,
        ),
    ];
    candidates
        .iter()
        .find(|(_, tid, _, _)| *tid != 0 && callback_client_tcb(*tid).is_some())
        .copied()
}

// ── SCENARIO INJECTION: `exec_win32k_transport_call_nested` ─────────────────────────────────────
// Proof bits returned by [`inject_win32k_nested_dispatch_slip`]; ALL set = the spec passes.
/// win32k really SUSPENDED an outer dispatch inside `KeUserModeCallback` (the nesting precondition).
pub(crate) const NESTED_SLIP_PARKED: u64 = 0x01;
/// The client really entered the reverse transition, so a NESTED `NtUser*` from its `WndProc` is a
/// legitimate re-entry (this is the shape the binding has to survive).
pub(crate) const NESTED_SLIP_REDIRECTED: u64 = 0x02;
/// ★ THE REPLY OBJECT STAYED BOUND ACROSS THE WHOLE SUSPENSION. `R_win32k` was OUTSTANDING (exactly
/// one dispatch level suspended, i.e. the pump returned without replying) both BEFORE and AFTER the
/// client redirect — the outer dispatch's reply really did survive the callback excursion as KERNEL
/// state, not as bookkeeping of ours. This bit replaces the token-transport's `NESTED_SLIP_REJECTED`
/// (a stale completion is now UNREPRESENTABLE, so there is nothing left to reject).
pub(crate) const NESTED_SLIP_R_HELD: u64 = 0x04;
/// …and the NESTED dispatch — replied onto that SAME still-bound object, one level deeper —
/// returned ITS OWN real result, at a measured nesting depth of >= 2.
pub(crate) const NESTED_SLIP_MATCHED: u64 = 0x08;
/// The callback then RETURNED for real and the RESUME reply (on the same object again) drove the
/// SUSPENDED OUTER dispatch to its own completion — the level whose completion never travelled with
/// a request of its own.
pub(crate) const NESTED_SLIP_OUTER_RESUMED: u64 = 0x10;
/// Everything drained (callback/continuation stacks empty, dispatch depth + suspended-outstanding
/// back to 0) and a FRESH win32k dispatch completes — win32k is genuinely back in its idle loop.
pub(crate) const NESTED_SLIP_DRAINED_IDLE: u64 = 0x20;
pub(crate) const NESTED_SLIP_ALL: u64 = 0x3f;

/// ★ DELIBERATE SCENARIO INJECTION for the **nesting-safe request↔reply binding** on win32k's
/// Syscall substrate — now the KERNEL'S binding (`docs/transport-migration.md` Phase 2), not ours.
///
/// The scenario is unchanged and it is REAL: win32k's dispatch loop legitimately RE-ENTERS — an
/// outer dispatch parks inside `KeUserModeCallback` while the client's redirected `WndProc` issues
/// nested `NtUser*`/`NtGdi*` syscalls, unwound innermost-first. What changed is the *claim* being
/// tested. The old transport was a plain Send/Recv pair in which one level could consume another
/// level's completion, so it needed a per-dispatch token and this injection published a MISORDERED
/// completion to prove the token rejected it. Under `Call` ⇄ reply-object that misordering is
/// UNREPRESENTABLE — the component cannot speak until we reply, and our reply reaches only the
/// thread the kernel bound — so there is nothing to inject and nothing to reject. The injection now
/// proves the STRUCTURE instead: ONE reply object, held bound across an entire callback excursion,
/// carries an outer dispatch, an arbitrarily deep nested dispatch and the resume.
///
/// It runs for real, POST-QUIESCE (the entire load-bearing boot — winlogon SAS, the msgina dialog,
/// the authentic desktop/dialog paints — has finished and its counters are latched), on an
/// EXPENDABLE winlogon RPC worker thread, with `WM_NULL` (the message defined to do nothing, so no
/// window state and no pixel can change):
///  1. a genuine `NtUserMessageCall(hwnd, WM_NULL, …)` dispatch reaches the client's window
///     procedure and win32k calls `KeUserModeCallback` → the OUTER dispatch SUSPENDS, i.e. the pump
///     returns WITHOUT replying and `R_win32k` stays bound to win32k's callback `Call`;
///  2. the client is genuinely REDIRECTED into `KiUserCallbackDispatcher` (the reverse transition
///     that makes a nested dispatch legitimate) — and the binding is sampled BEFORE and AFTER it;
///  3. a genuine NESTED dispatch is issued: a reply on that SAME object one level deeper. It must
///     return ITS OWN result, with the measured nesting depth >= 2;
///  4. the callback RETURNS for real, so the RESUME reply — on the same object again — drives the
///     suspended OUTER dispatch to its own completion (a level that never sent a request);
///  5. everything drains and a fresh dispatch completes.
///
/// Unlike the dead-client injection this leaves the victim thread ALIVE and latches nothing, so it
/// is safe to run BEFORE `inject_dead_client_callback_unwind` on the same worker.
///
/// Returns the `NESTED_SLIP_*` proof mask.
pub(crate) unsafe fn inject_win32k_nested_dispatch_slip(client_pid: u64, scratch_base: u64) -> u64 {
    const NTUSER_MESSAGE_CALL_SSN: u64 = 0x1007; // NtUserMessageCall (7 args)
    const NTUSER_MESSAGE_CALL_ARGC: u64 = 7;
    const FNID_SENDMESSAGE: u64 = 0x02B1; // ntuser.h — the plain SendMessage arm
    const WM_NULL: u64 = 0x0000;
    const WINLOGON_PEB_MIRROR: u64 = 0x0000_0100_107C_1000;
    const STATUS_UNSUCCESSFUL: u64 = 0xc000_0001;

    let mut proof = 0u64;
    let Some((badge, tid, teb, stack_top)) = expendable_winlogon_callback_thread() else {
        print_str(b"[w32-slip] no expendable winlogon worker thread available -> skipped\n");
        return proof;
    };
    let Some(tcb) = callback_client_tcb(tid) else {
        return proof;
    };
    // Park the victim's RSP at the top of its ORIGINAL (always-mapped, executive-registered) stack so
    // the redirect's callout-frame write has guaranteed room, exactly as the dead-client injection
    // does. `complete_controlled_user_callback` restores the thread's context at the end.
    let mut saved = [0u64; 20];
    tcb_read_regs20(tcb, &mut saved);
    let victim_rip = saved[nt_user_callback::USER_CONTEXT_RIP];
    let victim_flags = saved[nt_user_callback::USER_CONTEXT_RFLAGS];
    let victim_rsp = (stack_top - 0x400) & !0xfu64;
    saved[nt_user_callback::USER_CONTEXT_RSP] = victim_rsp;
    let write_error = tcb_write_regs20(tcb, &saved, false);
    print_str(b"[w32-slip] victim winlogon worker badge=");
    print_u64(badge);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" write-error=");
    print_u64(write_error);
    print_str(b" sas-sequence-active=");
    print_u64(USER_CALLBACK_SAS_SEQUENCE_ACTIVE.load(Ordering::Relaxed));
    print_str(b" dispatch-depth=");
    print_u64(crate::spawn_hosts::dispatch_depth());
    print_str(b"\n");

    let client = Win32kClientContext {
        pi: 2,
        pid: client_pid,
        badge,
        tid,
        teb,
        peb_mirror: WINLOGON_PEB_MIRROR,
        scratch_base,
    };

    // (1) SUSPEND an outer dispatch inside a REAL user-mode callback.
    let sas_hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    let targets = [sas_hwnd, last_real_wm_paint_hwnd()];
    let mut parked = false;
    for hwnd in targets {
        if hwnd == 0 || parked {
            continue;
        }
        let (status, completed) = win32k_dispatch_wide(
            NTUSER_MESSAGE_CALL_SSN,
            hwnd,
            WM_NULL,
            0,
            0,
            victim_rsp,
            NTUSER_MESSAGE_CALL_ARGC,
            &[0 /* ResultInfo */, FNID_SENDMESSAGE, 0 /* Ansi */],
            client,
        );
        parked = take_user_callback_pump_suspended();
        print_str(b"[w32-slip] NtUserMessageCall(WM_NULL) hwnd=0x");
        print_hex(hwnd as u32);
        print_str(b" -> status=0x");
        print_hex(status as u32);
        print_str(b" completed=");
        print_u64(completed as u64);
        print_str(b" callback-parked=");
        print_u64(parked as u64);
        print_str(b"\n");
    }
    if !parked {
        print_str(b"[w32-slip] win32k issued no user callback -> injection did not arm\n");
        return proof;
    }
    proof |= NESTED_SLIP_PARKED;
    // ★ `R_win32k` is now BOUND to win32k's callback `Call` — the pump returned WITHOUT replying.
    // Exactly one dispatch level is suspended holding it. Sample it BEFORE the client redirect.
    let held_before = crate::spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed);

    // (2) REDIRECT the client — the real reverse transition that legitimises a nested dispatch.
    if !begin_controlled_user_callback_redirect(client, victim_rip, victim_rsp, victim_flags) {
        print_str(b"[w32-slip] redirect failed -> cancelling the parked callback\n");
        let _ = cancel_suspended_user_callback();
        return proof;
    }
    let (active_depth, continuation_depth) = user_callback_stack_depths();
    if active_depth >= 1
        && (*core::ptr::addr_of!(USER_CALLBACK_ACTIVE))
            .top()
            .is_some_and(|frame| frame.is_redirected())
    {
        proof |= NESTED_SLIP_REDIRECTED;
    }
    print_str(b"[w32-slip] armed: R-held=");
    print_u64(held_before);
    print_str(b" callback-depth=");
    print_u64(active_depth as u64);
    print_str(b" continuation-depth=");
    print_u64(continuation_depth as u64);
    print_str(b"\n");

    // ★ The binding SURVIVED the client redirect: still exactly one suspended level holding `R`.
    let held_after = crate::spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed);
    if held_before >= 1 && held_after == held_before {
        proof |= NESTED_SLIP_R_HELD;
    }

    // (3) THE NESTED DISPATCH — a reply on that SAME still-bound object, one level deeper.
    // `depth_before_nested >= 1` is the DIRECT measurement that the level about to be entered is a
    // NESTED one: an outer dispatch is outstanding on `R_win32k` at this instant, so the dispatch
    // below necessarily runs at depth >= 2 (the boot-wide high-water is a weaker statement, since
    // live GUI nesting already reaches 5 long before this injection runs).
    let depth_before_nested = crate::spawn_hosts::dispatch_depth();
    let reply_errors_before = crate::spawn_hosts::PUMP_REPLY_ERRORS.load(Ordering::Relaxed);
    let max_depth_before = crate::spawn_hosts::PUMP_MAX_DISPATCH_DEPTH.load(Ordering::Relaxed);
    let (nested_status, nested_ok) = win32k_dispatch_wide(
        win32k_subsystem::SSN_TEST_FAULT,
        0,
        0,
        0,
        0,
        victim_rsp,
        0,
        &[],
        client,
    );
    let reply_errors_after = crate::spawn_hosts::PUMP_REPLY_ERRORS.load(Ordering::Relaxed);
    let max_depth_after = crate::spawn_hosts::PUMP_MAX_DISPATCH_DEPTH.load(Ordering::Relaxed);
    // The nested level returned ITS OWN result, the nesting really was >= 2 levels deep on ONE
    // reply object, and no reply along the way found that object unbound.
    if nested_ok
        && nested_status == win32k_subsystem::TEST_FAULT_STATUS
        && depth_before_nested >= 1
        && max_depth_after >= 2
        && reply_errors_after == reply_errors_before
    {
        proof |= NESTED_SLIP_MATCHED;
    }
    print_str(b"[w32-slip] nested dispatch -> status=0x");
    print_hex(nested_status as u32);
    print_str(b" completed=");
    print_u64(nested_ok as u64);
    print_str(b" R-held-before/after=");
    print_u64(held_before);
    print_str(b"/");
    print_u64(held_after);
    print_str(b" reply-errors=");
    print_u64(reply_errors_after.saturating_sub(reply_errors_before));
    print_str(b" outer-levels-outstanding-at-nest=");
    print_u64(depth_before_nested);
    print_str(b" nesting-depth-high-water=");
    print_u64(max_depth_after.max(max_depth_before));
    print_str(b"\n");

    // (4) RETURN the callback for real: the RESUME reply goes onto that same still-bound object and
    // must drive the suspended OUTER dispatch to its own completion.
    let returned = complete_controlled_user_callback(2, badge, tid, 0, 0, STATUS_UNSUCCESSFUL);
    if returned.is_some() {
        proof |= NESTED_SLIP_OUTER_RESUMED;
    }

    // (5) DRAINED + win32k idle. `SUSPENDED_COMPONENT_OUTSTANDING == 0` is risk R6's assertion:
    // every suspension that took `R` gave it back.
    let (active_after, continuation_after) = user_callback_stack_depths();
    let depth_after = crate::spawn_hosts::dispatch_depth();
    let suspended_after =
        crate::spawn_hosts::SUSPENDED_COMPONENT_OUTSTANDING.load(Ordering::Relaxed);
    let (probe_status, probe_ok) = win32k_dispatch(win32k_subsystem::SSN_TEST_FAULT, 0, 0, 0, 0);
    if active_after == 0
        && continuation_after == 0
        && depth_after == 0
        && suspended_after == 0
        && probe_ok
        && probe_status == win32k_subsystem::TEST_FAULT_STATUS
    {
        proof |= NESTED_SLIP_DRAINED_IDLE;
    }
    print_str(b"[w32-slip] outer-resumed=");
    print_u64(returned.is_some() as u64);
    print_str(b" active-depth=");
    print_u64(active_after as u64);
    print_str(b" continuation-depth=");
    print_u64(continuation_after as u64);
    print_str(b" dispatch-depth=");
    print_u64(depth_after);
    print_str(b" suspended-outstanding=");
    print_u64(suspended_after);
    print_str(b" probe=0x");
    print_hex(probe_status as u32);
    print_str(b" proof=0x");
    print_hex(proof as u32);
    print_str(b"\n");
    proof
}

pub(crate) unsafe fn inject_dead_client_callback_unwind(
    client_pid: u64,
    scratch_base: u64,
    kill_victim: &mut dyn FnMut(u64) -> bool,
) -> u64 {
    const NTUSER_MESSAGE_CALL_SSN: u64 = 0x1007; // NtUserMessageCall (7 args)
    const NTUSER_MESSAGE_CALL_ARGC: u64 = 7;
    const FNID_SENDMESSAGE: u64 = 0x02B1; // ntuser.h — the plain SendMessage arm
    const WM_NULL: u64 = 0x0000;
    const WINLOGON_PEB_MIRROR: u64 = 0x0000_0100_107C_1000;

    let mut proof = 0u64;
    // (0) VICTIM SELECTION — an expendable winlogon (pi 2) worker thread (see
    // [`expendable_winlogon_callback_thread`]).
    let Some((badge, tid, teb, stack_top)) = expendable_winlogon_callback_thread() else {
        print_str(b"[cb-inject] no expendable winlogon worker thread available -> skipped\n");
        return proof;
    };
    let Some(tcb) = callback_client_tcb(tid) else {
        return proof;
    };
    // Park the victim's RSP at the top of its ORIGINAL (always-mapped, executive-registered) stack so
    // the redirect's callout-frame write has guaranteed room. The thread is about to be destroyed, so
    // its live context is irrelevant; this only removes a spurious failure mode from the self-test.
    let mut saved = [0u64; 20];
    tcb_read_regs20(tcb, &mut saved);
    let victim_rip = saved[nt_user_callback::USER_CONTEXT_RIP];
    let victim_flags = saved[nt_user_callback::USER_CONTEXT_RFLAGS];
    let victim_rsp = (stack_top - 0x400) & !0xfu64;
    saved[nt_user_callback::USER_CONTEXT_RSP] = victim_rsp;
    let write_error = tcb_write_regs20(tcb, &saved, false);
    print_str(b"[cb-inject] victim winlogon worker badge=");
    print_u64(badge);
    print_str(b" tid=");
    print_u64(tid);
    print_str(b" tcb=0x");
    print_hex(tcb as u32);
    print_str(b" staged-rsp=0x");
    print_hex((victim_rsp >> 32) as u32);
    print_hex(victim_rsp as u32);
    print_str(b" write-error=");
    print_u64(write_error);
    print_str(b"\n");

    let client = Win32kClientContext {
        pi: 2,
        pid: client_pid,
        badge,
        tid,
        teb,
        peb_mirror: WINLOGON_PEB_MIRROR,
        scratch_base,
    };
    // (1) Drive a REAL win32k dispatch that reaches a client window procedure. WM_NULL is the
    // do-nothing message, so the only observable effect is the reverse transition itself.
    let sas_hwnd = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_SAS_HWND) as *const u64,
    );
    let targets = [sas_hwnd, last_real_wm_paint_hwnd()];
    let mut parked = false;
    for hwnd in targets {
        if hwnd == 0 || parked {
            continue;
        }
        let (status, completed) = win32k_dispatch_wide(
            NTUSER_MESSAGE_CALL_SSN,
            hwnd,
            WM_NULL,
            0,
            0,
            victim_rsp,
            NTUSER_MESSAGE_CALL_ARGC,
            &[0 /* ResultInfo */, FNID_SENDMESSAGE, 0 /* Ansi */],
            client,
        );
        parked = take_user_callback_pump_suspended();
        print_str(b"[cb-inject] NtUserMessageCall(WM_NULL) hwnd=0x");
        print_hex(hwnd as u32);
        print_str(b" -> status=0x");
        print_hex(status as u32);
        print_str(b" completed=");
        print_u64(completed as u64);
        print_str(b" callback-parked=");
        print_u64(parked as u64);
        print_str(b"\n");
    }
    if !parked {
        print_str(b"[cb-inject] win32k issued no user callback -> injection did not arm\n");
        return proof;
    }
    proof |= DEAD_CLIENT_INJECT_PARKED;

    // (2) REDIRECT the victim into `KiUserCallbackDispatcher` — the real reverse transition.
    if !begin_controlled_user_callback_redirect(client, victim_rip, victim_rsp, victim_flags) {
        print_str(b"[cb-inject] redirect failed -> cancelling the parked callback\n");
        let _ = cancel_suspended_user_callback();
        return proof;
    }
    let (active_depth, continuation_depth) = user_callback_stack_depths();
    let top_redirected = (*core::ptr::addr_of!(USER_CALLBACK_ACTIVE))
        .top()
        .is_some_and(|frame| frame.is_redirected());
    if active_depth >= 1 && top_redirected {
        proof |= DEAD_CLIENT_INJECT_REDIRECTED;
    }
    print_str(b"[cb-inject] armed: callback depth=");
    print_u64(active_depth as u64);
    print_str(b" continuation-depth=");
    print_u64(continuation_depth as u64);
    print_str(b" redirected=");
    print_u64(top_redirected as u64);
    print_str(b" (win32k parked awaiting the callback result)\n");

    // (3) KILL the client thread while it is AT that depth — it can never send NtCallbackReturn now.
    let killed = kill_victim(tid);
    let tcb_gone = callback_client_tcb(tid).is_none();
    if killed && tcb_gone {
        proof |= DEAD_CLIENT_INJECT_VICTIM_DEAD;
    }
    print_str(b"[cb-inject] victim terminated mid-callback: terminated=");
    print_u64(killed as u64);
    print_str(b" tcb-reclaimed=");
    print_u64(tcb_gone as u64);
    print_str(b"\n");

    // (4) RECOVERY — the path under test.
    let unwinds_before = USER_CALLBACK_DEAD_CLIENT_UNWINDS.load(Ordering::Relaxed);
    let redirect_unwinds_before =
        USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS.load(Ordering::Relaxed);
    let unwound = unwind_dead_client_user_callbacks(client.pi);
    if unwound >= 1
        && USER_CALLBACK_DEAD_CLIENT_UNWINDS.load(Ordering::Relaxed) >= unwinds_before + 1
        && USER_CALLBACK_DEAD_CLIENT_UNWIND_REDIRECTS.load(Ordering::Relaxed)
            >= redirect_unwinds_before + 1
    {
        proof |= DEAD_CLIENT_INJECT_UNWOUND;
    }
    let (active_after, continuation_after) = user_callback_stack_depths();
    if active_after == 0
        && continuation_after == 0
        && USER_CALLBACK_CONTINUATION_UNWINDS.load(Ordering::Relaxed)
            == USER_CALLBACK_CONTINUATION_PUSHES.load(Ordering::Relaxed)
    {
        proof |= DEAD_CLIENT_INJECT_DRAINED;
    }
    // win32k is genuinely BACK in its normal dispatch receive loop, not stranded: a fresh dispatch
    // round-trips and COMPLETES. Had the unwind not resumed + re-parked it, this would WALL — which
    // is exactly what the wedge looked like.
    let (probe_status, probe_ok) = win32k_dispatch(win32k_subsystem::SSN_TEST_FAULT, 0, 0, 0, 0);
    if probe_ok && probe_status == win32k_subsystem::TEST_FAULT_STATUS {
        proof |= DEAD_CLIENT_INJECT_WIN32K_IDLE;
    }
    print_str(b"[cb-inject] recovery: frames-unwound=");
    print_u64(unwound);
    print_str(b" active-depth=");
    print_u64(active_after as u64);
    print_str(b" continuation-depth=");
    print_u64(continuation_after as u64);
    print_str(b" win32k-probe status=0x");
    print_hex(probe_status as u32);
    print_str(b" ok=");
    print_u64(probe_ok as u64);
    print_str(b" proof=0x");
    print_hex(proof as u32);
    print_str(b"\n");
    proof
}

pub(crate) unsafe fn complete_controlled_user_callback(
    client_pi: u32,
    client_badge: u64,
    client_tid: u64,
    result_pointer: u64,
    result_length: u64,
    callback_status: u64,
) -> Option<CompletedUserCallback> {
    // `NtCallbackReturn` returns the callback that is innermost ON THE CALLING THREAD — the caller's
    // own identity selects the frame, never the interleaved stack's global top.
    let identity =
        nt_user_callback::ClientThreadIdentity::new(client_pi, client_tid, client_badge);
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    let Some(active_frame) = active.top_for(&identity).copied() else {
        return None;
    };
    let request = *active_frame.request();
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR
        + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let request_window_message = if request.api_index
        == nt_user_callback::USER32_CALLBACK_WINDOWPROC
        && request.input_length as usize >= 0x40
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
    // (The frame's client identity is the caller's by construction — `top_for` selected it.)
    if !active_frame.is_redirected() {
        return None;
    }
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
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
        let output = core::slice::from_raw_parts_mut(
            core::ptr::addr_of_mut!((*frame).payload) as *mut u8,
            result_length as usize,
        );
        if client_pi == 2 && request_window_message == 0x0081 {
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
                    USER_CALLBACK_CLIENT_SCRATCH.load(Ordering::Relaxed),
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
                    USER_CALLBACK_CLIENT_SCRATCH.load(Ordering::Relaxed),
                );
            print_str(b"[callback-result] WM_NCCREATE pointer=0x");
            print_hex((result_pointer >> 32) as u32);
            print_hex(result_pointer as u32);
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
        if !crate::img_spawn::client_copyin_mapped(
            client_pi as u64,
            result_pointer,
            output,
            &[],
            0,
            USER_CALLBACK_CLIENT_SCRATCH.load(Ordering::Relaxed),
        ) {
            abort_controlled_user_callbacks();
            return None;
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
        if client_pi == 6
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
    if client_pi == 2
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
    if nt_user_callback::validate_reply(&request, &reply).is_err() {
        abort_controlled_user_callbacks();
        return None;
    }
    if !unwind_controlled_callback(request) {
        print_str(b"[user-callback] continuation correlation rejected SSN 22\n");
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
        b"[user-callback] A real callback returned through SSN 22; resuming B component\n",
    );
    let Ok(completed_frame) = active.pop(correlation) else {
        abort_controlled_user_callbacks();
        return None;
    };
    restore_client_callback_window(completed_frame);
    let dispatch_context = *completed_frame.dispatch_context();
    if dispatch_context.dispatch_id != request.dispatch_id {
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
    let component = resume_suspended_user_callback_component(request);
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous_dispatch,
    );
    if component.callback_suspended {
        let chained_client = Win32kClientContext {
            pi: request.client_pi,
            pid: USER_CALLBACK_CLIENT_PID.load(Ordering::Relaxed),
            badge: request.client_badge,
            tid: request.client_tid,
            teb: USER_CALLBACK_CLIENT_TEB.load(Ordering::Relaxed),
            peb_mirror: USER_CALLBACK_CLIENT_PEB.load(Ordering::Relaxed),
            scratch_base: USER_CALLBACK_CLIENT_SCRATCH.load(Ordering::Relaxed),
        };
        if !redirect_pending_user_callback(
            chained_client,
            completed_frame.saved_user_context(),
            completed_frame.outer_resume_ip(),
            completed_frame.saved_user_context()[nt_user_callback::USER_CONTEXT_RSP],
            completed_frame.saved_user_context()[nt_user_callback::USER_CONTEXT_RFLAGS],
        ) {
            abort_controlled_user_callbacks();
            print_str(b"[user-callback] chained callback redirect failed\n");
            return None;
        }
        USER_CALLBACK_REAL_RETURNS.fetch_add(1, Ordering::Relaxed);
        print_str(b"[user-callback] B yielded another callback; transferred saved A context\n");
        return Some(CompletedUserCallback {
            outer_dispatch: None,
        });
    }
    if !component.completed {
        abort_controlled_user_callbacks();
        print_str(b"[user-callback] B component continuation failed to complete\n");
        return None;
    }
    if !unwind_controlled_dispatch(request) {
        abort_controlled_user_callbacks();
        print_str(b"[user-callback] dispatch continuation failed to unwind\n");
        return None;
    }
    // The client is about to resume in the ENCLOSING callback (or in its original syscall). This inner
    // callback's teardown — our own `restore_client_callback_window` above plus win32k's
    // `IntRestoreTebWndCallback` — can have left win32k's untranslated PWND in CLIENTINFO.CallbackWnd,
    // so restate the enclosing frame's bridged triple before the client runs again.
    reassert_top_client_callback_window(&identity);
    let Some(tcb) = callback_client_tcb(client_tid) else {
        return None;
    };
    let completed = nt_user_callback::completed_outer_context(
        completed_frame.saved_user_context(),
        component.status as u32 as u64,
        completed_frame.outer_resume_ip(),
    );
    if tcb_write_regs20(tcb, &completed, false) != 0 {
        return None;
    }
    USER_CALLBACK_REAL_RETURNS.fetch_add(1, Ordering::Relaxed);
    print_str(b"[user-callback] B completed; restored A with result in RAX depth=");
    print_u64(active.len() as u64);
    print_str(b"\n");
    Some(CompletedUserCallback {
        outer_dispatch: Some(CompletedWin32kDispatch {
            ssn: dispatch_context.ssn,
            args: dispatch_context.args,
            caller_sp: dispatch_context.caller_sp,
            status: component.status,
        }),
    })
}

/// RO-map win32k's global USER heap arena ([`win32k_subsystem::WIN32K_HEAP_VADDR`], where gpsi /
/// gHandleTable / the USER handle-entry array live) into the caller's (csrss's) VSpace at
/// [`win32k_subsystem::CSRSS_W32_SHARED_VA`], so the Win32 client can dereference the SHAREDINFO the
/// USERCONNECT points at. Maps a fresh copy of each arena frame RO+NX (win32k keeps its own RW
/// copy — coherent shared memory). One-time (guarded). Returns the server→client delta
/// (`WIN32K_HEAP_VADDR - CSRSS_W32_SHARED_VA`) the marshaling applies to the siClient pointers.
pub(crate) unsafe fn map_win32k_heap_into_csrss(pml4: u64, pi: usize) -> u64 {
    let delta = win32k_subsystem::WIN32K_HEAP_VADDR - win32k_subsystem::CSRSS_W32_SHARED_VA;
    // Per-process guard (bit `pi`): the arena is mapped into EACH GUI client's VSpace independently
    // (csrss = pi 1, winlogon = pi 2) at the same CSRSS_W32_SHARED_VA window, so the delta — hence
    // the siClient rewrite — is identical for both. A single bool would skip the 2nd client's map.
    let bit = 1u64 << pi;
    if WIN32K_CLIENT_MAPPED.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return delta; // already mapped into this process's VSpace
    }
    let heap_base = WIN32K_HEAP_FRAME_BASE.load(Ordering::Relaxed);
    if heap_base == 0 {
        return delta;
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER; // read-only, non-executable
    let frames = win32k_subsystem::WIN32K_HEAP_FRAMES;
    // The 1 GiB PD covering 0x8000_0000..0xC000_0000 already exists in csrss (its DLL region shares
    // it). The CSRSS_W32_SHARED_VA window is fresh, so allocate + map one page table per 2 MiB
    // sub-range UP FRONT — deterministic, because the SYS_SEND `page_map` is fire-and-forget and
    // can't report a missing-PT error to drive a retry.
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_subsystem::CSRSS_W32_SHARED_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(heap_base + i);
        let _ = page_map(cp, win32k_subsystem::CSRSS_W32_SHARED_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped win32k USER heap into csrss @0x");
    print_hex(win32k_subsystem::CSRSS_W32_SHARED_VA as u32);
    print_str(b" (delta=0x");
    print_hex((delta >> 32) as u32);
    print_hex(delta as u32);
    print_str(b")\n");
    delta
}

/// RO-map win32k's POOL arena ([`win32k_subsystem::WIN32K_POOL_VADDR`] — where the DESKTOP body + its
/// DESKTOPINFO are `pool_alloc`ed) into the GUI client `pi`'s VSpace at
/// [`win32k_subsystem::CSRSS_W32_POOL_VA`], so user32's client-side `DesktopPtrToUser` can read the
/// bound DESKTOPINFO (`pci->pDeskInfo->pvDesktopBase/pvDesktopLimit`) — the desktop-heap client-window
/// mapping (the DESKTOPINFO lives in the POOL, NOT the RO-mapped USER heap). Per-pi guarded, mirroring
/// [`map_win32k_heap_into_csrss`]. Returns the pool server→client delta.
pub(crate) unsafe fn map_win32k_pool_into_csrss(pml4: u64, pi: usize) -> u64 {
    let delta = win32k_subsystem::WIN32K_POOL_VADDR - win32k_subsystem::CSRSS_W32_POOL_VA;
    // Validate the frame base BEFORE consuming the per-pi guard bit: a base-not-yet-stored call must
    // NOT latch the bit (it would leave the POOL unmapped on a later real call → an unmapped
    // pci->pDeskInfo deref). On the live path pool_base is stored at bring-up before any dispatch.
    let pool_base = WIN32K_POOL_FRAME_BASE.load(Ordering::Relaxed);
    if pool_base == 0 {
        return delta;
    }
    let bit = 1u64 << pi;
    if WIN32K_POOL_CLIENT_MAPPED.fetch_or(bit, Ordering::Relaxed) & bit != 0 {
        return delta; // already mapped into this process's VSpace
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER;
    let frames = win32k_subsystem::WIN32K_POOL_FRAMES;
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_subsystem::CSRSS_W32_POOL_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(pool_base + i);
        let _ = page_map(cp, win32k_subsystem::CSRSS_W32_POOL_VA + i * 0x1000, RO_NX, pml4);
    }
    print_str(b"[win32k-svc] RO-mapped win32k POOL into csrss @0x");
    print_hex(win32k_subsystem::CSRSS_W32_POOL_VA as u32);
    print_str(b" (pool-delta=0x");
    print_hex((delta >> 32) as u32);
    print_hex(delta as u32);
    print_str(b")\n");
    delta
}

/// ★ DIALOG BATCH 3 — RO-map the GDI shared handle table into GUI client `pi`'s VSpace at
/// [`win32k_subsystem::GDI_SHARED_TABLE_VA`]. Client-side gdi32 validates every GDI handle through
/// `GdiSharedHandleTable[handle & 0xffff]` (base = `PEB->GdiSharedHandleTable`, PEB+0xf8). In real
/// Windows win32k allocates this table from a GdiPool section + RO-maps it into every GUI process; our
/// host allocates the frames ONCE (globally, zero-initialized — a zero `entry.Type@0xc` mismatches
/// gdi32's type-bits check → gdi32 takes its `invalid handle` path instead of NULL-derefing at RVA
/// 0x535a), then RO-maps that same table into each client. Per-pi guarded (mirrors
/// [`map_win32k_pool_into_csrss`]). The section allocation is deliberately left at its original
/// heap address to preserve win32k's allocation order. Its containing pages are mapped at
/// `GDI_SHARED_TABLE_VA`, and the returned client pointer retains the section's intra-page offset.
pub(crate) unsafe fn map_gdi_shared_handle_table_into_client(pml4: u64, pi: usize) -> u64 {
    let server_base = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_GDI_TABLE_BASE)
            as *const u64,
    );
    let size = core::ptr::read_volatile(
        (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_GDI_TABLE_SIZE)
            as *const u64,
    );
    let heap_frames = WIN32K_HEAP_FRAME_BASE.load(Ordering::Relaxed);
    if server_base < win32k_subsystem::WIN32K_HEAP_VADDR
        || size < win32k_subsystem::GDI_HANDLE_COUNT * win32k_subsystem::GDI_TABLE_ENTRY_SIZE
        || size > 0x0020_0000
        || heap_frames == 0
    {
        return 0;
    }
    let server_page = server_base & !0xfff;
    let intra_page = server_base - server_page;
    let client_base = win32k_subsystem::GDI_SHARED_TABLE_VA + intra_page;
    let source_offset = (server_page - win32k_subsystem::WIN32K_HEAP_VADDR) / 0x1000;
    let frames = (intra_page + size + 0xfff) / 0x1000;
    if source_offset + frames > win32k_subsystem::WIN32K_HEAP_FRAMES {
        return 0;
    }
    let bit = 1u64 << pi;
    if GDI_SHARED_TABLE_MAPPED.load(Ordering::Relaxed) & bit != 0 {
        return client_base; // already mapped into this process's VSpace
    }
    const RO_NX: u64 = 2 | PAGE_EXECUTE_NEVER; // read-only, non-executable
    // The 1 GiB PD covering 0x8000_0000..0xC000_0000 already exists in the client; the table window is
    // fresh, so allocate + map one PT per 2 MiB sub-range up front (page_map is fire-and-forget).
    for p in 0..(frames + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_subsystem::GDI_SHARED_TABLE_VA + p * 0x20_0000,
            pml4,
        );
    }
    for i in 0..frames {
        let cp = copy_cap(heap_frames + source_offset + i);
        let _ = page_map(cp, win32k_subsystem::GDI_SHARED_TABLE_VA + i * 0x1000, RO_NX, pml4);
    }
    GDI_SHARED_TABLE_FRAME_BASE.store(heap_frames + source_offset, Ordering::Relaxed);
    GDI_SHARED_TABLE_MAPPED.fetch_or(bit, Ordering::Relaxed);
    print_str(b"[win32k-svc] RO-mapped live GDI handle table into pi 0x");
    print_hex(pi as u32);
    print_str(b" @0x");
    print_hex(win32k_subsystem::GDI_SHARED_TABLE_VA as u32);
    print_str(b" bytes=0x");
    print_hex(size as u32);
    print_str(b" client-table=0x");
    print_hex(client_base as u32);
    print_str(b"\n");
    client_base
}

pub(crate) unsafe fn map_gdi_user_attributes_into_client(pml4: u64, pi: usize) -> bool {
    let base = WIN32K_USERVM_FRAME_BASE.load(Ordering::Relaxed);
    if base == 0 {
        return false;
    }
    let bit = 1u64 << pi;
    if GDI_USERVM_MAPPED.load(Ordering::Relaxed) & bit != 0 {
        return true;
    }
    for page_table in 0..(win32k_subsystem::WIN32K_USERVM_FRAMES + 511) / 512 {
        let pt = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
        let _ = paging_struct_map(
            pt,
            LBL_X86_PAGE_TABLE_MAP,
            win32k_subsystem::WIN32K_USERVM_VADDR + page_table * 0x20_0000,
            pml4,
        );
    }
    for frame in 0..win32k_subsystem::WIN32K_USERVM_FRAMES {
        let cp = copy_cap(base + frame);
        let _ = page_map(
            cp,
            win32k_subsystem::WIN32K_USERVM_VADDR + frame * 0x1000,
            RW_NX,
            pml4,
        );
    }
    GDI_USERVM_MAPPED.fetch_or(bit, Ordering::Relaxed);
    print_str(b"[win32k-svc] RW-mapped live GDI user attributes into pi 0x");
    print_hex(pi as u32);
    print_str(b"\n");
    true
}

// --- win32k cross-AS client-memory sharing (the authentic "win32k shares the caller's user AS") ---
// win32k-side paging structures provisioned for the shared client window, and pages already mapped,
// keyed by a level-tagged aligned index (SYS_SEND paging_struct_map is fire-and-forget so we can't
// detect "already mapped" — track it). Client VAs are all < 0x100_0000_0000 (PML4 slots 0/1), never
// win32k's own PML4[2] (>= 0x100_..), so building a fresh PDPT/PD/PT hierarchy here can't collide
// with win32k's own mappings.
pub(crate) static mut W32_CLIENT_SEEN: [u64; 8192] = [0; 8192];
pub(crate) static mut W32_CLIENT_SEEN_N: usize = 0;
pub(crate) unsafe fn w32_seen(key: u64) -> bool {
    let n = core::ptr::read(core::ptr::addr_of!(W32_CLIENT_SEEN_N));
    let a = core::ptr::addr_of!(W32_CLIENT_SEEN) as *const u64;
    for i in 0..n {
        if core::ptr::read(a.add(i)) == key {
            return true;
        }
    }
    false
}
pub(crate) unsafe fn w32_mark(key: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(W32_CLIENT_SEEN_N));
    if n < 8192 {
        core::ptr::write((core::ptr::addr_of_mut!(W32_CLIENT_SEEN) as *mut u64).add(n), key);
        core::ptr::write(core::ptr::addr_of_mut!(W32_CLIENT_SEEN_N), n + 1);
    }
}
/// Ensure win32k's VSpace has a PDPT/PD/PT chain covering `page` (each created once, tracked in
/// W32_CLIENT_SEEN). Used both for FOREIGN client pages (PML4[0/1], fresh hierarchy) AND for
/// win32k-OWN demand-mapped regions (the demand-mapped pool at 0x0A00, whose 2 MiB PTs don't exist
/// yet). Deterministic because `page_map`/`paging_struct_map` are SYS_SEND (fire-and-forget) and
/// can't report a missing-PT error to drive a retry — so the PT must be created up front. For
/// win32k-own PML4[2] pages the PDPT/PD already exist; the duplicate retype+map fails silently
/// (seL4 won't replace an occupied slot) and only the fresh PT actually takes.
pub(crate) unsafe fn ensure_w32_client_paging(page: u64, w_pml4: u64) {
    let k_pdpt = (1u64 << 60) | (page >> 39);
    if !w32_seen(k_pdpt) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PDPT, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PDPT_MAP, page, w_pml4);
        w32_mark(k_pdpt);
    }
    let k_pd = (2u64 << 60) | (page >> 30);
    if !w32_seen(k_pd) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_DIRECTORY, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PAGE_DIRECTORY_MAP, page, w_pml4);
        w32_mark(k_pd);
    }
    let k_pt = (3u64 << 60) | (page >> 21);
    if !w32_seen(k_pt) {
        let s = alloc_slot();
        let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, s);
        let _ = paging_struct_map(s, LBL_X86_PAGE_TABLE_MAP, page, w_pml4);
        w32_mark(k_pt);
    }
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
/// Bit `pi` set once a GUI client's `NtUserProcessConnect` (SSN 0x10FA) has been routed to win32k and
/// returned STATUS_SUCCESS — the "win32k client connected" mask. csrss=pi 1, winlogon=pi 2,
/// services=pi 3. Drives the `exec_services_win32k_connect` gate spec (bit 3 = the 3rd client).
pub(crate) static W32_CONNECTED_MASK: AtomicU64 = AtomicU64::new(0);
pub(crate) static W32_ATTACHED_PI: AtomicU64 = AtomicU64::new(0xFFFF_FFFF);
/// The pi of the client whose call `win32k_dispatch` is currently servicing (set by the forward arm
/// before each dispatch; defaults to csrss so bring-up/self-test dispatches attach to pi 1). Read by
/// `win32k_dispatch` at entry to drive `w32_client_attach`.
pub(crate) static W32_CLIENT_PI: AtomicU64 = AtomicU64::new(1);
pub(crate) const W32_ATTACH_CAP: usize = 8192;
pub(crate) static mut W32_ATTACH_PAGE: [u64; W32_ATTACH_CAP] = [0; W32_ATTACH_CAP];
pub(crate) static mut W32_ATTACH_SLOT: [u64; W32_ATTACH_CAP] = [0; W32_ATTACH_CAP];
pub(crate) static mut W32_ATTACH_N: usize = 0;
/// Is `page` currently mapped into win32k for the attached client?
pub(crate) unsafe fn w32_attach_mapped(page: u64) -> bool {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let a = core::ptr::addr_of!(W32_ATTACH_PAGE) as *const u64;
    for i in 0..n {
        if core::ptr::read(a.add(i)) == page {
            return true;
        }
    }
    false
}
/// Re-point `page`'s attach record at a NEW copy-cap `slot` (the copy-on-write swap below), so the
/// detach Unmap tears down whichever frame is actually mapped. Returns the OLD slot, or 0.
pub(crate) unsafe fn w32_attach_replace_slot(page: u64, slot: u64) -> u64 {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let pages = core::ptr::addr_of!(W32_ATTACH_PAGE) as *const u64;
    let slots = core::ptr::addr_of_mut!(W32_ATTACH_SLOT) as *mut u64;
    for i in 0..n {
        if core::ptr::read(pages.add(i)) == page {
            let old = core::ptr::read(slots.add(i));
            core::ptr::write(slots.add(i), slot);
            return old;
        }
    }
    0
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
    let old = w32_attach_replace_slot(page, 0);
    if old != 0 {
        let error = page_unmap(old);
        let _ = cnode_delete_recycle_r(old);
        if error != 0 {
            print_str(b"[teb-tail] COW unmap failed error=");
            print_u64(error);
            print_str(b"\n");
        }
    }
    let cc = copy_cap(shadow);
    let error = page_map(cc, page, RW_NX, w_pml4);
    if error != 0 {
        print_str(b"[teb-tail] COW map failed error=");
        print_u64(error);
        print_str(b"\n");
        let _ = cnode_delete_recycle_r(cc);
        return false;
    }
    if w32_attach_replace_slot(page, cc) == 0 {
        w32_attach_record(page, cc);
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
pub(crate) unsafe fn w32_attach_record(page: u64, slot: u64) {
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    if n < W32_ATTACH_CAP {
        core::ptr::write((core::ptr::addr_of_mut!(W32_ATTACH_PAGE) as *mut u64).add(n), page);
        core::ptr::write((core::ptr::addr_of_mut!(W32_ATTACH_SLOT) as *mut u64).add(n), slot);
        core::ptr::write(core::ptr::addr_of_mut!(W32_ATTACH_N), n + 1);
    }
}
/// Attach win32k's client window to GUI client `pi` (the KeStackAttachProcess model). If a DIFFERENT
/// client is currently attached, DETACH it: Unmap all its leaf client pages from win32k so the new
/// client's colliding VAs re-fault to THIS client's frames. Idempotent when `pi` is already attached.
pub(crate) unsafe fn w32_client_attach(pi: u64) -> bool {
    let prev = W32_ATTACHED_PI.load(Ordering::Relaxed);
    if prev == pi {
        return true;
    }
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let slots = core::ptr::addr_of!(W32_ATTACH_SLOT) as *const u64;
    for i in 0..n {
        // Unmap win32k's mapping of the previous client's page (arch Unmap uses this cap's win32k
        // asid → csrss/winlogon's own VSpace mapping is untouched), then delete the transient copy
        // cap so the executive's root-slot allocator can recycle it.
        let cap = core::ptr::read(slots.add(i));
        let error = page_unmap(cap);
        let _ = cnode_delete_recycle_r(cap);
        if error != 0 {
            print_str(b"[w32attach] page_unmap failed page=0x");
            print_hex(core::ptr::read((core::ptr::addr_of!(W32_ATTACH_PAGE) as *const u64).add(i)) as u32);
            print_str(b" error=");
            print_u64(error);
            print_str(b"\n");
            return false;
        }
    }
    print_str(b"[w32attach] client ");
    print_u64(prev);
    print_str(b" -> ");
    print_u64(pi);
    print_str(b" (detached ");
    print_u64(n as u64);
    print_str(b" client pages)\n");
    core::ptr::write(core::ptr::addr_of_mut!(W32_ATTACH_N), 0);
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
    let fr = csrss_frame_get(pi, page);
    if fr == 0 {
        return false;
    }
    ensure_w32_client_paging(page, w_pml4);
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
    let cc = copy_cap(fr);
    let error = page_map(cc, page, rights, w_pml4);
    if error != 0 {
        print_str(b"[w32attach] page_map failed page=0x");
        print_hex((page >> 32) as u32);
        print_hex(page as u32);
        print_str(b" pi=");
        print_u64(pi);
        print_str(b" error=");
        print_u64(error);
        print_str(b"\n");
        let _ = cnode_delete_recycle_r(cc);
        return false;
    }
    w32_attach_record(page, cc);
    true
}

/// Load ONE driver PE (raw at `src_va` in the executive) into `dst_va` in BOTH the executive (RW,
/// to load) and win32k (W^X, to run). Reuses [`win32k_subsystem::load_driver_into`]. `dxgthk_base` names
/// a prior-loaded dxgthk for import resolution (0 for a leaf). Returns (entry_rva, export_dir_rva,
/// size_of_image). The reusable driver-loader mechanism (framebuf.dll will use it too).
pub(crate) unsafe fn load_one_driver(
    src_va: u64,
    dst_va: u64,
    frames: u64,
    host_pml4: u64,
    dxgthk_base: u64,
) -> Option<(u32, u32, u32)> {
    // Executive-side PT + frames (RW), to load into.
    let ept = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, ept);
    let _ = paging_struct_map(ept, LBL_X86_PAGE_TABLE_MAP, dst_va, CAP_INIT_THREAD_VSPACE);
    let base = alloc_frame();
    for _ in 1..frames {
        let _ = alloc_frame();
    }
    for i in 0..frames {
        let _ = page_map(copy_cap(base + i), dst_va + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
    }
    // Parse + copy + reloc + resolve imports (writes via the executive's RW mapping). The per-frame
    // rights live in a `static` (ftfd.dll = 248 frames is too large for the bounded rootserver
    // stack). Single-threaded + sequential loads -> the shared static is safe.
    static mut DRIVER_RIGHTS: [u64; 256] = [RW_NX; 256];
    let rights = &mut *core::ptr::addr_of_mut!(DRIVER_RIGHTS);
    for r in rights.iter_mut() {
        *r = RW_NX;
    }
    let res = win32k_subsystem::load_driver_into(
        src_va,
        dst_va,
        frames,
        &mut rights[..frames as usize],
        dxgthk_base,
    )?;
    // Map the SAME frames W^X into win32k's VSpace at the same VA (RX code / RW data).
    let wpt = alloc_slot();
    let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, wpt);
    let _ = paging_struct_map(wpt, LBL_X86_PAGE_TABLE_MAP, dst_va, host_pml4);
    for i in 0..frames {
        let r = rights[i as usize];
        let _ = page_map(copy_cap(base + i), dst_va + i * 0x1000, r, host_pml4);
    }
    Some(res)
}

/// Pre-load dxg.sys + its dxgthk.sys dependency into win32k's VSpace so win32k's
/// `ZwSetSystemInformation(SystemLoadGdiDriverInformation)` (from InitializeGreCSRSS →
/// DxDdStartupDxGraphics) can report the hosted dxg image. dxgthk (leaf) first, then dxg (imports
/// dxgthk's Eng* + ntoskrnl). Called once at win32k bring-up.
pub(crate) unsafe fn load_directx_drivers(host_pml4: u64) {
    let dxg_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x80) as *const u32);
    let dxgthk_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x84) as *const u32);
    if dxg_size == 0 || dxgthk_size == 0 {
        print_str(b"[win32k-svc] dxg/dxgthk not staged - DirectX gate will fail\n");
        return;
    }
    if load_one_driver(DXGTHKBUF_VADDR, win32k_subsystem::DXGTHK_VA, win32k_subsystem::DXGTHK_LOAD_FRAMES, host_pml4, 0)
        .is_none()
    {
        print_str(b"[win32k-svc] dxgthk load failed\n");
        return;
    }
    match load_one_driver(
        DXGBUF_VADDR,
        win32k_subsystem::DXG_VA,
        win32k_subsystem::DXG_LOAD_FRAMES,
        host_pml4,
        win32k_subsystem::DXGTHK_VA,
    ) {
        Some((entry, expdir, len)) => {
            win32k_subsystem::record_dxg(entry, expdir, len);
            print_str(b"[win32k-svc] hosted dxg.sys + dxgthk.sys: entry_rva=0x");
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

/// Host ftfd.dll (the FreeType font driver) into win32k's VSpace + patch win32k's OWN IAT for its 34
/// FT_* imports against ftfd's export table. Unlike dxg (dynamic, via ZwSetSystemInformation), ftfd
/// is a STATIC win32k import: win32k's InitFontSupport → FT_Init_FreeType calls it directly. ftfd
/// imports only 8 Eng*/Rtl thunks back from win32k.sys (resolved by load_driver_into's is_win32k arm).
/// Called once at win32k bring-up, AFTER win32k is loaded (its exports must be present for ftfd's IAT)
/// and BEFORE any FT_* call (which happens far later, during a routed NtUserInitialize dispatch).
pub(crate) unsafe fn load_ftfd_driver(host_pml4: u64) {
    let ftfd_size = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x88) as *const u32);
    if ftfd_size == 0 {
        print_str(b"[win32k-svc] ftfd.dll not staged - font gate will fail\n");
        return;
    }
    match load_one_driver(
        FTFDBUF_VADDR,
        win32k_subsystem::FTFD_VA,
        win32k_subsystem::FTFD_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, _expdir, len)) => {
            let patched = win32k_subsystem::patch_win32k_ftfd_imports(win32k_subsystem::FTFD_VA);
            print_str(b"[win32k-svc] hosted ftfd.dll: entry_rva=0x");
            print_hex(entry);
            print_str(b" len=0x");
            print_hex(len);
            print_str(b" win32k FT_* IAT patched=");
            print_u64(patched as u64);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] ftfd load failed\n"),
    }
}

/// Host framebuf.dll (the display driver) into win32k's VSpace + map the BOOTBOOT framebuffer into
/// win32k. win32k loads framebuf DYNAMICALLY (like dxg) via ZwSetSystemInformation when it enables the
/// display device (co_IntInitializeDesktopGraphics → PDEVOBJ_Create → LDEVOBJ_pLoadDriver("framebuf")),
/// so pre-load it + record it for the s_zw_set_system_information trampoline. framebuf's video-miniport
/// IOCTLs (DrvEnablePDEV/DrvEnableSurface) are serviced by the patched EngDeviceIoControl intercept,
/// which returns WIN32K_FB_VA — the fb frames mapped here.
pub(crate) unsafe fn load_framebuf_driver(host_pml4: u64) {
    let sz = core::ptr::read_volatile((STORAGE_SHARED_VADDR + 0x8C) as *const u32);
    if sz == 0 {
        print_str(b"[win32k-svc] framebuf.dll not staged - display gate will fail\n");
        return;
    }
    match load_one_driver(
        FRAMEBUFBUF_VADDR,
        win32k_subsystem::FRAMEBUF_VA,
        win32k_subsystem::FRAMEBUF_LOAD_FRAMES,
        host_pml4,
        0,
    ) {
        Some((entry, expdir, len)) => {
            win32k_subsystem::record_framebuf(entry, expdir, len);
            print_str(b"[win32k-svc] hosted framebuf.dll: entry_rva=0x");
            print_hex(entry);
            print_str(b" (DrvEnableDriver) len=0x");
            print_hex(len);
            print_str(b"\n");
        }
        None => print_str(b"[win32k-svc] framebuf load failed\n"),
    }
    // Map the BOOTBOOT framebuffer (Phase-0a fb device frames) into win32k at WIN32K_FB_VA, RW.
    let base = FB_FRAME_BASE.load(Ordering::Relaxed);
    let count = FB_FRAME_COUNT.load(Ordering::Relaxed);
    if base != 0 && count != 0 {
        for p in 0..(count + 511) / 512 {
            let pt = alloc_slot();
            let _ = untyped_retype(CAP_INIT_UNTYPED, OBJ_X86_PAGE_TABLE, PAGING_BITS, 1, pt);
            let _ = paging_struct_map(pt, LBL_X86_PAGE_TABLE_MAP, win32k_subsystem::WIN32K_FB_VA + p * 0x20_0000, host_pml4);
        }
        for i in 0..count {
            let _ = page_map(copy_cap(base + i), win32k_subsystem::WIN32K_FB_VA + i * 0x1000, RW_NX, host_pml4);
        }
        print_str(b"[win32k-svc] mapped BOOTBOOT framebuffer into win32k: ");
        print_u64(count);
        print_str(b" frames @ WIN32K_FB_VA=0x");
        print_hex((win32k_subsystem::WIN32K_FB_VA >> 32) as u32);
        print_hex(win32k_subsystem::WIN32K_FB_VA as u32);
        print_str(b"\n");
    }
}

/// Dispatch one win32k SSN (>= 0x1000) into the parked win32k component and run its fault-service
/// loop until the handler completes (Milestone B). PRECONDITION: the component is blocked in its
/// dispatch `seL4_Call` on `w_fault` (the executive has received the Call but not yet replied). We
/// fill the request in the shared page, reply (the Call returns → the component runs the handler),
/// then demand-page the handler's faults until the component issues its NEXT dispatch Call = "done".
/// Returns `(status, ok)`; `ok=false` on a wall (null deref / W^X / demand cap / unexpected fault).
pub(crate) unsafe fn win32k_dispatch(ssn: u64, a0: u64, a1: u64, a2: u64, a3: u64) -> (i32, bool) {
    let pi = W32_CLIENT_PI.load(Ordering::Relaxed) as u32;
    win32k_dispatch_wide(
        ssn, a0, a1, a2, a3, 0, 0, &[],
        Win32kClientContext {
            pi,
            pid: 0,
            badge: 0,
            tid: 0,
            teb: crate::SMSS_TEB_VA,
            peb_mirror: 0,
            scratch_base: crate::SM_FILL_SCRATCH_BASE,
        },
    )
}

/// Like [`win32k_dispatch`] but marshals the win64 STACK-ARG TAIL for WIDE SSNs (args 5+). The x64
/// win64 ABI passes args 1-4 in rcx/rdx/r8/r9 and args 5..N on the CALLER's stack at
/// `[rsp+0x28], [rsp+0x30], …` (rsp = the syscall-entry stack pointer). `caller_sp` is the client's
/// stack pointer at the syscall (get_recv_mr(16)); `nargs` is the handler's TOTAL arg count. For
/// `nargs<=4` this is byte-identical to the old register-only dispatch. For a wide SSN (e.g.
/// NtUserCreateWindowEx = 15 args) we read stack args 5..N from the client's stack via
/// `smss_stack_read` and stage them into SH_REQ_A4.. so win32k's `dispatch_ssn` can rebuild a real
/// N-arg win64 call — the FIX for the garbage-hMenu wall (BATCH 44).
pub(crate) unsafe fn win32k_dispatch_wide(
    ssn: u64,
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    caller_sp: u64,
    nargs: u64,
    stack_args: &[u64],
    client: Win32kClientContext,
) -> (i32, bool) {
    let w_fault = WIN32K_FAULT_EP.load(Ordering::Relaxed);
    let host_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if w_fault == 0 || WIN32K_RETIRED.load(Ordering::Relaxed) != 0 {
        return (0xC000_0001u32 as i32, false);
    }
    // A suspended callback only carries the compact pump identity. Latch the full dispatch's TEB
    // here so a callback-driven nested win32k call retains the same current-thread context.
    USER_CALLBACK_CLIENT_TEB.store(client.teb, Ordering::Relaxed);
    // ── REQUEST FILL (caller-owned, exactly as the FSD `dispatch_irp` fills the IRP before the pump).
    // Attach win32k's client window to the CURRENT dispatch client (KeStackAttachProcess). If this is
    // a different client than last time, the previous client's leaf pages are Unmapped so the new
    // client's identical VAs re-fault to THIS client's frames (per-client cross-AS client memory).
    let client_pi = client.pi as u64;
    // TAIL WATCH tag 4/5 — sample EVERY hosted process' TEB tail immediately before and after every
    // win32k dispatch (this is the single funnel all dispatch sites go through, nested ones too).
    for watch_pi in 1..5usize {
        crate::teb_tail_watch(watch_pi, 4, ssn, client_pi);
    }
    if !w32_client_attach(client_pi) {
        return (0xC000_0001u32 as i32, false);
    }
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    let dispatch_id = USER_CALLBACK_DISPATCH_IDS.fetch_add(1, Ordering::Relaxed) + 1;
    let nested_user_callback = match begin_nested_user_callback_dispatch(client, dispatch_id, ssn) {
        Ok(nested) => nested,
        Err(error) => {
            print_str(b"[user-callback] rejected nested win32k dispatch: ");
            print_str(match error {
                nt_user_callback::ContinuationError::Overflow => b"continuation stack overflow\n",
                nt_user_callback::ContinuationError::Underflow => b"continuation stack underflow\n",
                nt_user_callback::ContinuationError::Sequence => b"invalid sequence\n",
                nt_user_callback::ContinuationError::Kind => b"invalid continuation kind\n",
                nt_user_callback::ContinuationError::State => b"invalid continuation state\n",
                nt_user_callback::ContinuationError::Client => b"client identity mismatch\n",
                nt_user_callback::ContinuationError::Correlation => b"dispatch correlation mismatch\n",
            });
            return (0xC000_000Du32 as i32, false);
        }
    };
    let callback_frame = (sh + win32k_subsystem::SH_USER_CALLBACK) as *mut nt_user_callback::CallbackFrame;
    let previous_dispatch = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        UserCallbackDispatchContext {
            dispatch_id,
            ssn,
            args: [a0, a1, a2, a3],
            caller_sp,
        },
    );
    core::ptr::write_volatile(
        core::ptr::addr_of_mut!((*callback_frame).header),
        nt_user_callback::CallbackHeader::idle(dispatch_id, client.pi, client.tid, client.badge),
    );
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_SSN) as *mut u64, ssn);
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
        (sh + win32k_subsystem::SH_REQ_CLIENT_TEB) as *mut u64,
        client.teb,
    );
    // Stage the win64 STACK-ARG TAIL (args 5..N) from the client's stack. `nargs<=4` (or a 0-sp
    // self-test dispatch) leaves SH_REQ_NARGS=0 → win32k's dispatch_ssn takes the register-only path.
    let staged = if nargs > 4
        && caller_sp != 0
        && stack_args.len() >= nargs.min(16).saturating_sub(4) as usize
    {
        nargs.min(16)
    } else {
        0
    };
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_NARGS) as *mut u64, staged);
    let mut i = 4u64;
    while i < staged {
        let v = stack_args[(i - 4) as usize];
        core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_A4 + (i - 4) * 8) as *mut u64, v);
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
        callback_client: Some(crate::spawn_hosts::UserCallbackClient {
            pi: client.pi,
            badge: client.badge,
            tid: client.tid,
            peb_mirror: client.peb_mirror,
            scratch_base: client.scratch_base,
        }),
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Syscall,
            client_attach: true,
            usermode_callback: true,
            wide_arg_marshal: true,
            assert_skip: true,
            sparse_vspace: true,
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    for watch_pi in 1..5usize {
        crate::teb_tail_watch(watch_pi, 5, ssn, client_pi);
    }
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous_dispatch,
    );
    retire_win32k_on_wall(&pr);
    USER_CALLBACK_LAST_PUMP_SUSPENDED.store(pr.callback_suspended as u64, Ordering::Release);
    if nested_user_callback {
        if pr.callback_suspended {
            return (pr.status, false);
        }
        if !pr.completed || !complete_nested_user_callback_dispatch(client, dispatch_id) {
            print_str(b"[user-callback] nested win32k dispatch failed to unwind\n");
            return (pr.status, false);
        }
    }
    (pr.status, pr.completed)
}

/// `seL4_TCB_ReadRegisters` (label 2, legacy length-0 form) → the target's `(rip, rsp, rax)`.
pub(crate) unsafe fn tcb_read_rsp(tcb: u64) -> u64 {
    let rsp: u64;
    core::arch::asm!(
        "syscall",
        inout("rdx") SYS_CALL as u64 => _,
        inout("rdi") tcb => _,
        inout("rsi") 2u64 << 12 => _, // TCBReadRegisters, length 0
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
            let _ = page_map(copy_cap(ss + i), mirror + i * 0x1000, RW_NX, CAP_INIT_THREAD_VSPACE);
        }
        WIN32K_DISP_BT_PT.store(1, Ordering::Relaxed);
    }
    let mut registers = [0u64; 20];
    tcb_read_regs20(tcb, &mut registers);
    let rsp = registers[nt_user_callback::USER_CONTEXT_RSP];
    let sbase = win32k_subsystem::WIN32K_STACK_VADDR;
    let stack_top = sbase + sf * 0x1000;
    let start = if rsp >= sbase && rsp < stack_top { rsp } else { sbase };
    let code_va = win32k_subsystem::WIN32K_CODE_VA;
    let lo = code_va;
    let hi = code_va + win32k_subsystem::WIN32K_IMAGE_FRAMES * 0x1000;
    print_str(b"[w32disp] backtrace rsp=0x");
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
    print_str(b"\n");
    // RAW stack window from fault rsp: each qword annotated with its win32k RVA if it lands in the
    // image (a return address). RtlpCheckListEntry (0x24c50) did `sub rsp,0x28`, so its own return
    // address is at [rsp+0x28] = the exact InsertXxxList wrapper caller — read that precisely.
    if start >= sbase && start + 0x120 <= stack_top {
        let mut off = 0u64;
        while off < 0x120 {
            let va = start + off;
            let v = core::ptr::read_volatile((mirror + (va - sbase)) as *const u64);
            if v >= lo && v < hi {
                print_str(b"  [rsp+0x");
                print_hex(off as u32);
                print_str(b"] rva=0x");
                print_hex(v.wrapping_sub(code_va) as u32);
                print_str(b"\n");
            }
            off += 8;
        }
    }
}
