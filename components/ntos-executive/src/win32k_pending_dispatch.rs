//! Captured win32k wait payloads and pump outcomes.

use super::*;

#[path = "win32k_shared_request_owner.rs"]
mod shared_request_owner;

#[derive(Clone, Copy)]
pub(crate) struct ReceiveYield {
    pub parent: nt_component_suspension::NestedExecutionIdentity,
    pub child: nt_component_suspension::ExternalAdmissionKey,
    pub owner: nt_component_suspension::SuspensionOwner,
    pub replaces: Option<nt_component_suspension::SuspensionKey>,
}

/// A dispatch worker's exact retained service wait while the win32k syscall pump yields its
/// receive half to the root. This does not represent a nested parent or a provider completion.
#[derive(Clone, Copy)]
pub(crate) struct ServiceWaitYield {
    pub route: nt_component_suspension::peer_registry::PeerRoute,
    pub dispatch: nt_component_suspension::LaneDispatchIdentity,
    pub reply: u64,
    pub token: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct PendingServiceWaitDispatch {
    pub yielded: ServiceWaitYield,
    pub pump: crate::spawn_hosts::PumpResult,
    pub channel: crate::spawn_hosts::PumpChannel,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub shared_resume: SharedResumeSnapshot,
    /// The parent callback token, when NtCallbackReturn resumed this pump.
    pub callback_token: Option<u64>,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut SERVICE_WAIT_PENDING_DISPATCH: Option<PendingServiceWaitDispatch> = None;

pub(crate) unsafe fn take_pending_service_wait_dispatch() -> Option<PendingServiceWaitDispatch> {
    core::ptr::replace(core::ptr::addr_of_mut!(SERVICE_WAIT_PENDING_DISPATCH), None)
}

#[derive(Clone, Copy)]
pub(crate) struct PendingReceiveDispatch {
    pub yielded: ReceiveYield,
    pub pump: crate::spawn_hosts::PumpResult,
    pub channel: crate::spawn_hosts::PumpChannel,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub shared_resume: SharedResumeSnapshot,
    pub callback_token: Option<u64>,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut RECEIVE_PENDING_DISPATCH: Option<PendingReceiveDispatch> = None;

/// Dispatch-owned cells in the one physical win32k shared page. Global SSDT, SAS, font and
/// handle-table publications deliberately stay outside this snapshot.
#[derive(Clone, Copy)]
pub(crate) struct SharedResumeSnapshot {
    header: nt_user_callback::CallbackHeader,
    published: Win32kPublishedContext,
    request: [u64; SHARED_RESUME_REQUEST_OFFSETS.len()],
}

impl SharedResumeSnapshot {
    pub(crate) fn callback_publication(&self) -> nt_user_callback::SharedCallbackPublication {
        nt_user_callback::SharedCallbackPublication::new(self.request, [
            self.published.pid,
            self.published.tid,
            self.published.eprocess,
            self.published.ethread,
            self.published.w32process,
            self.published.w32thread,
        ])
    }

    pub(crate) fn from_callback_publication(
        header: nt_user_callback::CallbackHeader,
        publication: nt_user_callback::SharedCallbackPublication,
    ) -> Self {
        let context = publication.context();
        Self {
            header,
            request: *publication.request(),
            published: Win32kPublishedContext {
                pid: context[0], tid: context[1],
                eprocess: context[2], ethread: context[3],
                w32process: context[4], w32thread: context[5],
            },
        }
    }
}

const SHARED_RESUME_REQUEST_OFFSETS: [u64; shared_request_owner::WORDS] = [
    win32k_subsystem::SH_REQ_SSN,
    win32k_subsystem::SH_REQ_A0,
    win32k_subsystem::SH_REQ_A1,
    win32k_subsystem::SH_REQ_A2,
    win32k_subsystem::SH_REQ_A3,
    win32k_subsystem::SH_REQ_STATUS,
    win32k_subsystem::SH_REQ_KIND,
    win32k_subsystem::SH_REQ_A4,
    win32k_subsystem::SH_REQ_A4 + 8,
    win32k_subsystem::SH_REQ_A4 + 16,
    win32k_subsystem::SH_REQ_A4 + 24,
    win32k_subsystem::SH_REQ_A4 + 32,
    win32k_subsystem::SH_REQ_A4 + 40,
    win32k_subsystem::SH_REQ_A4 + 48,
    win32k_subsystem::SH_REQ_A4 + 56,
    win32k_subsystem::SH_REQ_A4 + 64,
    win32k_subsystem::SH_REQ_A4 + 72,
    win32k_subsystem::SH_REQ_A4 + 80,
    win32k_subsystem::SH_REQ_A4 + 88,
    win32k_subsystem::SH_REQ_NARGS,
    win32k_subsystem::SH_REQ_PROCESS_ID,
    win32k_subsystem::SH_REQ_NESTED_CALLBACK,
    win32k_subsystem::SH_REQ_CLIENT_PI,
    win32k_subsystem::SH_REQ_CLIENT_TEB,
    win32k_subsystem::SH_REQ_CALLER_SP,
    win32k_subsystem::SH_REQ_THREAD_ID,
    win32k_subsystem::SH_REQ_EPROCESS,
    win32k_subsystem::SH_REQ_ETHREAD,
    win32k_subsystem::SH_REQ_PROCESS_ROLE,
    win32k_subsystem::SH_REQ_TOKEN_AUTH,
    win32k_subsystem::SH_REQ_TOKEN_USER_SID_LEN,
    win32k_subsystem::SH_REQ_TOKEN_USER_SID_PTR,
    win32k_subsystem::SH_DISPATCH_RETURN,
    win32k_subsystem::SH_DISPATCH_RETURN + 8,
    win32k_subsystem::SH_DISPATCH_RETURN + 16,
    win32k_subsystem::SH_DISPATCH_RETURN + 24,
    win32k_subsystem::SH_REQ_BATCH_RECORDS,
    win32k_subsystem::SH_REQ_GENERATION,
];
const _: () = assert!(SHARED_RESUME_REQUEST_OFFSETS.len()
    == nt_user_callback::SHARED_CALLBACK_REQUEST_WORDS);
const _: () = {
    assert!(SHARED_RESUME_REQUEST_OFFSETS[0] == win32k_subsystem::SH_REQ_SSN);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[20] == win32k_subsystem::SH_REQ_PROCESS_ID);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[22] == win32k_subsystem::SH_REQ_CLIENT_PI);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[25] == win32k_subsystem::SH_REQ_THREAD_ID);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[29] == win32k_subsystem::SH_REQ_TOKEN_AUTH);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[30] == win32k_subsystem::SH_REQ_TOKEN_USER_SID_LEN);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[31] == win32k_subsystem::SH_REQ_TOKEN_USER_SID_PTR);
    assert!(SHARED_RESUME_REQUEST_OFFSETS[37] == win32k_subsystem::SH_REQ_GENERATION);
};

fn shared_resume_request_word(snapshot: &SharedResumeSnapshot, offset: u64) -> u64 {
    let index = SHARED_RESUME_REQUEST_OFFSETS.iter().position(|word| *word == offset)
        .expect("shared request field is retained");
    snapshot.request[index]
}

pub(crate) unsafe fn capture_shared_resume_snapshot(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> SharedResumeSnapshot {
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    let frame = (sh + win32k_subsystem::SH_USER_CALLBACK)
        as *const nt_user_callback::CallbackFrame;
    let header = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    assert!(header.matches_dispatch_identity(
        dispatch.dispatch_id, client.pi, client.tid, client.badge,
    ), "yielded win32k shared callback belongs to another dispatch");
    let mut request = [0u64; SHARED_RESUME_REQUEST_OFFSETS.len()];
    for (value, offset) in request.iter_mut().zip(SHARED_RESUME_REQUEST_OFFSETS) {
        *value = core::ptr::read_volatile((sh + offset) as *const u64);
    }
    shared_request_owner::canonicalize(&mut request, shared_request_owner::RequestOwner {
        ssn: dispatch.ssn,
        pid: client.pid,
        pi: client.pi as u64,
        tid: client.tid,
        generation: client.generation,
        token_auth: client.token_authentication_id,
        token_sid_len: client.token_user_sid_len as u64,
        token_sid_ptr: win32k_subsystem::WIN32K_TOKEN_USER_SID_VADDR,
    });
    SharedResumeSnapshot { header, published: published_win32k_context(), request }
}

pub(crate) unsafe fn restore_shared_resume_snapshot(
    snapshot: SharedResumeSnapshot,
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> bool {
    let checks = [
        win32k_client_context_is_admitted(client),
        snapshot.header.matches_dispatch_identity(
            dispatch.dispatch_id, client.pi, client.tid, client.badge,
        ),
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_SSN) == dispatch.ssn,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_PROCESS_ID) == client.pid,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_CLIENT_PI) == client.pi as u64,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_THREAD_ID) == client.tid,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_GENERATION) == client.generation,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_TOKEN_AUTH)
            == client.token_authentication_id,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_TOKEN_USER_SID_LEN)
            == client.token_user_sid_len as u64,
        shared_resume_request_word(&snapshot, win32k_subsystem::SH_REQ_TOKEN_USER_SID_PTR)
            == win32k_subsystem::WIN32K_TOKEN_USER_SID_VADDR,
        client.token_user_sid_len as usize <= client.token_user_sid.len(),
    ];
    if checks.iter().any(|valid| !valid) {
        let missing = checks.iter().enumerate().fold(0u64, |bits, (index, valid)| {
            bits | (u64::from(!*valid) << index)
        });
        print_str(b"[win32k-resume-snapshot-rejected] dispatch/pi/tid/missing=");
        print_u64(dispatch.dispatch_id);
        print_str(b"/"); print_u64(client.pi as u64);
        print_str(b"/"); print_u64(client.tid);
        print_str(b"/0x"); print_hex_u64(missing);
        print_str(b"\n");
        return false;
    }
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    for (value, offset) in snapshot.request.into_iter().zip(SHARED_RESUME_REQUEST_OFFSETS) {
        core::ptr::write_volatile((sh + offset) as *mut u64, value);
    }
    for (index, byte) in client.token_user_sid.iter().enumerate() {
        core::ptr::write_volatile(
            (win32k_subsystem::WIN32K_TOKEN_USER_SID_VADDR + index as u64) as *mut u8,
            if index < client.token_user_sid_len as usize { *byte } else { 0 },
        );
    }
    for (offset, value) in [
        (win32k_subsystem::SH_CTX_PROCESS_ID, snapshot.published.pid),
        (win32k_subsystem::SH_CTX_THREAD_ID, snapshot.published.tid),
        (win32k_subsystem::SH_CTX_EPROCESS, snapshot.published.eprocess),
        (win32k_subsystem::SH_CTX_ETHREAD, snapshot.published.ethread),
        (win32k_subsystem::SH_CTX_W32PROCESS, snapshot.published.w32process),
        (win32k_subsystem::SH_CTX_W32THREAD, snapshot.published.w32thread),
    ] {
        core::ptr::write_volatile((sh + offset) as *mut u64, value);
    }
    let frame = (sh + win32k_subsystem::SH_USER_CALLBACK)
        as *mut nt_user_callback::CallbackFrame;
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).header), snapshot.header);
    true
}

pub(crate) unsafe fn take_pending_receive_dispatch() -> Option<PendingReceiveDispatch> {
    core::ptr::replace(core::ptr::addr_of_mut!(RECEIVE_PENDING_DISPATCH), None)
}

pub(super) static PROVIDER_WAIT_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);
pub(super) static LPC_WAIT_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) struct PendingProviderWaitDispatch {
    pub request: nt_provider_wait::ProviderWaitRequest,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub nested_user_callback: bool,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut PROVIDER_WAIT_PENDING_DISPATCH: Option<PendingProviderWaitDispatch> = None;

#[derive(Clone, Copy)]
pub(crate) struct PendingLpcWaitDispatch {
    pub request: win32k_subsystem::Win32kLpcWaitRequest,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub nested_user_callback: bool,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut LPC_WAIT_PENDING_DISPATCH: Option<PendingLpcWaitDispatch> = None;

pub(crate) enum ProviderWaitPumpCompletion {
    Completed(CompletedWin32kDispatch),
    Reparked(PendingProviderWaitDispatch),
    LpcReparked(PendingLpcWaitDispatch),
    ReceiveReparked(PendingReceiveDispatch),
    ServiceReparked(PendingServiceWaitDispatch),
    UserCallbackSuspended,
    Failed(i32),
}

pub(crate) enum LpcWaitPumpCompletion {
    Completed(CompletedWin32kDispatch),
    ProviderReparked(PendingProviderWaitDispatch),
    Reparked(PendingLpcWaitDispatch),
    ReceiveReparked(PendingReceiveDispatch),
    ServiceReparked(PendingServiceWaitDispatch),
    UserCallbackSuspended,
    Failed(i32),
}

pub(crate) unsafe fn take_pending_provider_wait_dispatch() -> Option<PendingProviderWaitDispatch> {
    if PROVIDER_WAIT_LAST_PUMP_SUSPENDED.swap(0, Ordering::AcqRel) == 0 {
        return None;
    }
    core::ptr::replace(
        core::ptr::addr_of_mut!(PROVIDER_WAIT_PENDING_DISPATCH),
        None,
    )
}

pub(crate) unsafe fn take_pending_lpc_wait_dispatch() -> Option<PendingLpcWaitDispatch> {
    if LPC_WAIT_LAST_PUMP_SUSPENDED.swap(0, Ordering::AcqRel) == 0 {
        return None;
    }
    core::ptr::replace(core::ptr::addr_of_mut!(LPC_WAIT_PENDING_DISPATCH), None)
}

pub(super) unsafe fn capture_provider_wait_repark(
    prior: PendingProviderWaitDispatch,
) -> PendingProviderWaitDispatch {
    let page = win32k_subsystem::WIN32K_PROVIDER_WAIT_VADDR
        as *const nt_provider_wait::ProviderWaitSharedPage;
    PendingProviderWaitDispatch {
        request: core::ptr::read_volatile(core::ptr::addr_of!((*page).request)),
        dispatch: prior.dispatch,
        client: prior.client,
        nested_user_callback: prior.nested_user_callback,
        arg_snapshot_len: prior.arg_snapshot_len,
        arg_snapshot: prior.arg_snapshot,
    }
}

pub(super) unsafe fn capture_lpc_wait_repark(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
    nested_user_callback: bool,
    arg_snapshot_len: u32,
    arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
) -> Option<PendingLpcWaitDispatch> {
    Some(PendingLpcWaitDispatch {
        request: win32k_subsystem::capture_lpc_wait_request()?,
        dispatch,
        client,
        nested_user_callback,
        arg_snapshot_len,
        arg_snapshot,
    })
}

pub(super) unsafe fn capture_initial_arg_snapshot(
    ssn: u64,
    completion_args: [u64; 4],
) -> (u32, [u8; COMPLETED_ARG_SNAPSHOT_BYTES]) {
    let mut arg_snapshot = [0u8; COMPLETED_ARG_SNAPSHOT_BYTES];
    let arg_snapshot_len = match ssn {
        nt_user_callback::NTUSER_DISPATCH_MESSAGE_SSN => {
            nt_user_callback::DISPATCH_MESSAGE_OUTPUT_BYTES as usize
        }
        win32k_subsystem::SSN_NT_USER_INITIALIZE => {
            (completion_args[2] as usize).min(COMPLETED_ARG_SNAPSHOT_BYTES)
        }
        _ => 0,
    };
    if arg_snapshot_len != 0 {
        core::ptr::copy_nonoverlapping(
            win32k_subsystem::WIN32K_ARG_VADDR as *const u8,
            arg_snapshot.as_mut_ptr(),
            arg_snapshot_len,
        );
    }
    (arg_snapshot_len as u32, arg_snapshot)
}
