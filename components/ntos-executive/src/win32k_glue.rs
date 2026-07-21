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
static USER_CALLBACK_TABLE_VALID: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_REDIRECTS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_RETURNS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_PUSHES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CONTINUATION_UNWINDS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_NESTED_DISPATCHES: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_NESTED_SSN_1298: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_NESTED_SSN_126B: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_SEQUENCE_COMPLETIONS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_REAL_WM_PAINT_RETURNS: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_LAST_REAL_WM_PAINT_HWND: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_DISPATCHER: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_PEB: AtomicU64 = AtomicU64::new(0);
static USER_CALLBACK_CLIENT_PID: AtomicU64 = AtomicU64::new(0);
static mut USER_CALLBACK_CONTINUATIONS: nt_user_callback::ContinuationStack =
    nt_user_callback::ContinuationStack::new();
static mut USER_CALLBACK_ACTIVE: nt_user_callback::ActiveCallbackStack =
    nt_user_callback::ActiveCallbackStack::new();
static mut USER_CALLBACK_SAS_SEQUENCE: nt_user_callback::SasWmCreateNestedSequence =
    nt_user_callback::SasWmCreateNestedSequence::new();
static USER_CALLBACK_SAS_SEQUENCE_ACTIVE: AtomicU64 = AtomicU64::new(0);

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

#[derive(Clone, Copy)]
struct UserCallbackDispatchContext {
    dispatch_id: u64,
    ssn: u64,
    args: [u64; 4],
    caller_sp: u64,
}

impl UserCallbackDispatchContext {
    const EMPTY: Self = Self {
        dispatch_id: 0,
        ssn: 0,
        args: [0; 4],
        caller_sp: 0,
    };
}

static mut USER_CALLBACK_CURRENT_DISPATCH: UserCallbackDispatchContext =
    UserCallbackDispatchContext::EMPTY;
static mut USER_CALLBACK_ACTIVE_DISPATCHES: [UserCallbackDispatchContext;
    nt_user_callback::MAX_ACTIVE_CALLBACK_DEPTH] =
    [UserCallbackDispatchContext::EMPTY; nt_user_callback::MAX_ACTIVE_CALLBACK_DEPTH];

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
    pub peb_mirror: u64,
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

pub(crate) unsafe fn begin_nested_user_callback_dispatch(
    client: Win32kClientContext,
    dispatch_id: u64,
    ssn: u64,
) -> Option<bool> {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let Some(parent) = active.top() else {
        return Some(false);
    };
    if !parent.is_redirected()
        || parent.request().client_pi != client.pi
        || parent.request().client_badge != client.badge
        || parent.request().client_tid != client.tid
    {
        return None;
    }
    let identity = nt_user_callback::ClientThreadIdentity::new(client.pi, client.tid, client.badge);
    let stack = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS);
    if stack.push_dispatch(identity, dispatch_id).is_err() {
        return None;
    }
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
    Some(true)
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
    true
}

unsafe fn write_synthetic_callback_reply(request: nt_user_callback::CallbackHeader) {
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    let mut reply = request;
    reply.state = nt_user_callback::CallbackState::Reply as u32;
    reply.output_length = request.output_capacity;
    reply.status = 0;
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
    let root = stack.is_empty();
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

pub(crate) fn last_real_wm_paint_hwnd() -> u64 {
    USER_CALLBACK_LAST_REAL_WM_PAINT_HWND.load(Ordering::Relaxed)
}

unsafe fn remember_active_dispatch(request: &nt_user_callback::CallbackHeader) -> bool {
    let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
    let index = match active.len().checked_sub(1) {
        Some(index) => index,
        None => return false,
    };
    let context = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    if context.dispatch_id == 0 || context.dispatch_id != request.dispatch_id {
        return false;
    }
    core::ptr::write(
        (core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE_DISPATCHES)
            as *mut UserCallbackDispatchContext)
            .add(index),
        context,
    );
    true
}

unsafe fn take_active_dispatch(index: usize) -> UserCallbackDispatchContext {
    let slot = (core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE_DISPATCHES)
        as *mut UserCallbackDispatchContext)
        .add(index);
    let context = core::ptr::read(slot);
    core::ptr::write(slot, UserCallbackDispatchContext::EMPTY);
    context
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
        _ => return None,
    };
    Some(alias)
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

unsafe fn restore_all_client_callback_windows() {
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    while !active.is_empty() {
        let index = active.len() - 1;
        let frame = active.discard_top().unwrap();
        let _ = take_active_dispatch(index);
        restore_client_callback_window(frame);
    }
}

unsafe fn abort_controlled_user_callbacks() {
    restore_all_client_callback_windows();
    *core::ptr::addr_of_mut!(USER_CALLBACK_CONTINUATIONS) =
        nt_user_callback::ContinuationStack::new();
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

    let output_capacity = request.output_capacity as usize;
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
    if client.pi == 2 {
        let callback_table = if client.peb_mirror == 0 {
            0
        } else {
            core::ptr::read_volatile((client.peb_mirror + 0x58) as *const u64)
        };
        let dispatcher_rva = crate::img_spawn::OUR_KI_USER_CALLBACK_DISPATCHER_RVA.load(Ordering::Relaxed);
        let dispatcher = if dispatcher_rva == 0 { 0 } else { crate::NTDLL_BASE + dispatcher_rva };
        let valid = callback_table != 0 && callback_table & 7 == 0;
        let callback_teb_alias = winlogon_callback_teb_alias(client);
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
        if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            && valid
            && dispatcher != 0
            && callback_teb_alias.is_some()
            && begin_controlled_continuation(request)
        {
            if !remember_active_dispatch(&request) {
                abort_controlled_user_callbacks();
                return None;
            }
            // win32k's IntSetTebWndCallback executes in the isolated driver component. Bridge its
            // per-callback HWND/PWND cache into the client TEB that user32 actually reads, preserving
            // the same nested save/restore semantics as the native kernel path.
            if !bind_client_callback_window(
                request,
                callback_teb_alias.unwrap(),
                callback_payload_u64(frame, 0x10),
                window_message,
            ) {
                let active = &*core::ptr::addr_of!(USER_CALLBACK_ACTIVE);
                if let Some(index) = active.len().checked_sub(1) {
                    let _ = take_active_dispatch(index);
                }
                abort_controlled_user_callbacks();
                return None;
            }
            USER_CALLBACK_DISPATCHER.store(dispatcher, Ordering::Relaxed);
            USER_CALLBACK_CLIENT_PEB.store(client.peb_mirror, Ordering::Relaxed);
            USER_CALLBACK_CLIENT_PID.store(
                core::ptr::read_volatile(
                    (win32k_subsystem::WIN32K_SHARED_VADDR
                        + win32k_subsystem::SH_REQ_PROCESS_ID) as *const u64,
                ),
                Ordering::Relaxed,
            );
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
                USER_CALLBACK_SAS_SEQUENCE_ACTIVE.store(1, Ordering::Relaxed);
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
        }
    }

    if suspend_component {
        print_str(b"[user-callback] B component continuation parked in callback receive loop\n");
        Some(UserCallbackDisposition::SuspendComponent)
    } else {
        if request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC {
            for offset in request.input_length as usize..output_capacity {
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).payload[offset]), 0);
            }
            if request.input_length as usize >= WPCA_RESULT + 8 {
                let result = if window_message == 0x0083 { 0 } else { 1 };
                callback_payload_write_u64(frame, WPCA_RESULT, result);
                print_str(b"[user-callback] WINDOWPROC api=0 msg=0x");
                print_hex(window_message);
                print_str(b" -> fallback Result=");
                print_u64(result);
                print_str(b" via rendezvous\n");
            }
        } else {
            for offset in 0..output_capacity {
                core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).payload[offset]), 0);
            }
        }
        write_synthetic_callback_reply(request);
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
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    let Some(active_frame) = active.top().copied() else {
        return false;
    };
    let request = *active_frame.request();
    if active_frame.is_redirected()
        || request.client_pi != client.pi
        || request.client_badge != client.badge
        || request.client_tid != client.tid
    {
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
        if !crate::img_spawn::smss_copyout(layout.input_pointer, input) {
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
        if !crate::img_spawn::smss_copyout(
            layout.input_pointer + WINDOWPROC_LPARAM_OFFSET,
            &reference.to_le_bytes(),
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
    if !crate::img_spawn::smss_copyout(layout.frame_pointer, frame_bytes) {
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

unsafe fn resume_suspended_user_callback_component(
    request: nt_user_callback::CallbackHeader,
) -> crate::spawn_hosts::PumpResult {
    let client = crate::spawn_hosts::UserCallbackClient {
        pi: request.client_pi,
        badge: request.client_badge,
        tid: request.client_tid,
        peb_mirror: USER_CALLBACK_CLIENT_PEB.load(Ordering::Relaxed),
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
        wake_first: false,
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
            nested_reply_cap: true,
        },
    };
    crate::spawn_hosts::component_pump_resume_user_callback(&channel)
}

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
    let active_index = active.len() - 1;
    let dispatch_context = take_active_dispatch(active_index);
    write_synthetic_callback_reply(request);
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

pub(crate) unsafe fn complete_controlled_user_callback(
    client_pi: u32,
    client_badge: u64,
    client_tid: u64,
    result_pointer: u64,
    result_length: u64,
    callback_status: u64,
) -> Option<CompletedUserCallback> {
    let active = &mut *core::ptr::addr_of_mut!(USER_CALLBACK_ACTIVE);
    let Some(active_frame) = active.top().copied() else {
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
    if !active_frame.is_redirected()
        || request.client_pi != client_pi
        || request.client_badge != client_badge
        || request.client_tid != client_tid
    {
        return None;
    }
    let correlation = nt_user_callback::CallbackCorrelation::from_request(&request);
    if result_length > request.output_capacity as u64
        || (result_length != 0 && result_pointer == 0)
        || (request.api_index == nt_user_callback::USER32_CALLBACK_WINDOWPROC
            && result_length != request.input_length as u64)
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
                && crate::img_spawn::smss_copyin(result_pointer + 0x38, &mut returned_result);
            let mut expected_result = [0u8; 8];
            let expected_read = expected != 0
                && request.input_length >= 0x40
                && crate::img_spawn::smss_copyin(expected + 0x38, &mut expected_result);
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
        if !crate::img_spawn::smss_copyin(result_pointer, output) {
            abort_controlled_user_callbacks();
            return None;
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
    if USER_CALLBACK_SAS_SEQUENCE_ACTIVE.load(Ordering::Relaxed) != 0 {
        let sequence = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_SAS_SEQUENCE));
        if sequence.can_complete() {
            USER_CALLBACK_SEQUENCE_COMPLETIONS.fetch_add(1, Ordering::Relaxed);
        }
        USER_CALLBACK_SAS_SEQUENCE_ACTIVE.store(0, Ordering::Relaxed);
    }
    print_str(
        b"[user-callback] A real callback returned through SSN 22; resuming B component\n",
    );
    let Ok(completed_frame) = active.pop(correlation) else {
        abort_controlled_user_callbacks();
        return None;
    };
    restore_client_callback_window(completed_frame);
    let dispatch_context = take_active_dispatch(active.len());
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
            peb_mirror: USER_CALLBACK_CLIENT_PEB.load(Ordering::Relaxed),
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
pub(crate) unsafe fn w32_client_attach(pi: u64) {
    let prev = W32_ATTACHED_PI.load(Ordering::Relaxed);
    if prev == pi {
        return;
    }
    let n = core::ptr::read(core::ptr::addr_of!(W32_ATTACH_N));
    let slots = core::ptr::addr_of!(W32_ATTACH_SLOT) as *const u64;
    for i in 0..n {
        // Unmap win32k's mapping of the previous client's page (arch Unmap uses this cap's win32k
        // asid → csrss/winlogon's own VSpace mapping is untouched). Cap slot is leaked (bump CNode,
        // XL 131072-slot pool → bounded for bring-up); a fresh copy_cap is used on the re-map.
        let _ = page_unmap(core::ptr::read(slots.add(i)));
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
}
/// Share GUI client `pi`'s frame for `page` into win32k's VSpace at the SAME VA (identity) so
/// win32k's handler dereferences the caller's real user memory. Returns false if the page isn't
/// backed by a known client frame (win32k would read garbage → the caller stops with a diagnostic).
/// Idempotent per page for the currently-attached client (see `w32_client_attach`).
pub(crate) unsafe fn map_csrss_page_into_win32k(page: u64, pi: u64, w_pml4: u64) -> bool {
    if w32_attach_mapped(page) {
        return true; // already shared for the currently-attached client
    }
    let fr = csrss_frame_get(pi, page);
    if fr == 0 {
        return false;
    }
    ensure_w32_client_paging(page, w_pml4);
    // RW: win32k (kernel-mode) may read AND write the caller's user memory; the frame is shared with
    // the client so writes propagate back (out-params). Non-executable — client data, not code.
    let cc = copy_cap(fr);
    let _ = page_map(cc, page, RW_NX, w_pml4);
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
        ssn, a0, a1, a2, a3, 0, 0,
        Win32kClientContext { pi, pid: 0, badge: 0, tid: 0, peb_mirror: 0 },
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
    client: Win32kClientContext,
) -> (i32, bool) {
    let w_fault = WIN32K_FAULT_EP.load(Ordering::Relaxed);
    let host_pml4 = WIN32K_HOST_PML4.load(Ordering::Relaxed);
    if w_fault == 0 {
        return (0xC000_0001u32 as i32, false);
    }
    // ── REQUEST FILL (caller-owned, exactly as the FSD `dispatch_irp` fills the IRP before the pump).
    // Attach win32k's client window to the CURRENT dispatch client (KeStackAttachProcess). If this is
    // a different client than last time, the previous client's leaf pages are Unmapped so the new
    // client's identical VAs re-fault to THIS client's frames (per-client cross-AS client memory).
    let client_pi = client.pi as u64;
    w32_client_attach(client_pi);
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    let dispatch_id = USER_CALLBACK_DISPATCH_IDS.fetch_add(1, Ordering::Relaxed) + 1;
    let nested_user_callback = match begin_nested_user_callback_dispatch(client, dispatch_id, ssn) {
        Some(nested) => nested,
        None => {
            print_str(b"[user-callback] rejected uncorrelated nested win32k dispatch\n");
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
    // Stage the win64 STACK-ARG TAIL (args 5..N) from the client's stack. `nargs<=4` (or a 0-sp
    // self-test dispatch) leaves SH_REQ_NARGS=0 → win32k's dispatch_ssn takes the register-only path.
    let staged = if nargs > 4 && caller_sp != 0 { nargs.min(16) } else { 0 };
    core::ptr::write_volatile((sh + win32k_subsystem::SH_REQ_NARGS) as *mut u64, staged);
    let mut i = 4u64;
    while i < staged {
        // arg (i+1) is the (i-3)-th stack slot at [rsp + 0x28 + (i-4)*8].
        let v = crate::img_spawn::smss_stack_read(caller_sp + 0x28 + (i - 4) * 8);
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
        wake_first: true, // win32k is parked in `recv_req` → wake it with a leading plain Send
        reply_cap: rw,
        client_pi,
        callback_client: Some(crate::spawn_hosts::UserCallbackClient {
            pi: client.pi,
            badge: client.badge,
            tid: client.tid,
            peb_mirror: client.peb_mirror,
        }),
        caps: crate::spawn_hosts::HostCaps {
            dispatch_server: true,
            kind: crate::spawn_hosts::ReqKind::Syscall,
            client_attach: true,
            usermode_callback: true,
            wide_arg_marshal: true,
            assert_skip: true,
            nested_reply_cap: true,
        },
    };
    let pr = crate::spawn_hosts::component_pump(&ch);
    core::ptr::write(
        core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH),
        previous_dispatch,
    );
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
