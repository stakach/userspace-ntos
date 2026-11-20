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
    pub shared_resume: SharedResumeSnapshot,
}

/// A selected ordinary root Call has not entered its handler. The physical parent remains in
/// PARENTS; this copyable ticket is only a selector, never a replacement for its held Reply.
#[derive(Clone, Copy)]
pub(crate) enum RootIngressYield {
    ParkedUnbound {
        ticket: crate::spawn_hosts::shared_ingress::owner::runtime::nested::NestedRestoreTicket,
        child: nt_component_suspension::ExternalAdmissionKey,
        owner: nt_component_suspension::SuspensionOwner,
        shared_resume: SharedResumeSnapshot,
    },
    /// A native park or cancellation was uncertain. CALLS and PARENTS retain their owners;
    /// the outer handoff quarantines this admission until an exact reconciliation path exists.
    Retained {
        child: nt_component_suspension::ExternalAdmissionKey,
    },
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

/// An ordinary hosted syscall retained while the root runs an independent service pass.
/// This is neither a provider completion nor a Receive child admission.
#[derive(Clone, Copy)]
pub(crate) struct RootMaintenanceYield {
    pub route: nt_component_suspension::peer_registry::PeerRoute,
    pub dispatch: nt_component_suspension::LaneDispatchIdentity,
    pub reply: u64,
    pub owner: nt_component_suspension::SuspensionOwner,
    pub captured_pass: u64,
}

#[derive(Clone, Copy)]
pub(crate) struct SuspendedPumpSnapshot {
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

#[derive(Clone, Copy)]
pub(crate) struct PendingServiceWaitDispatch {
    pub yielded: ServiceWaitYield,
    pub snapshot: SuspendedPumpSnapshot,
}

pub(super) static mut SERVICE_WAIT_PENDING_DISPATCH: Option<PendingServiceWaitDispatch> = None;

pub(crate) unsafe fn take_pending_service_wait_dispatch() -> Option<PendingServiceWaitDispatch> {
    core::ptr::replace(core::ptr::addr_of_mut!(SERVICE_WAIT_PENDING_DISPATCH), None)
}

pub(crate) unsafe fn restore_pending_service_wait_dispatch(
    pending: PendingServiceWaitDispatch,
) -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(SERVICE_WAIT_PENDING_DISPATCH);
    if slot.is_some() { return false; }
    *slot = Some(pending);
    true
}

#[derive(Clone, Copy)]
pub(crate) struct PendingRootMaintenanceDispatch {
    pub yielded: RootMaintenanceYield,
    pub snapshot: SuspendedPumpSnapshot,
}

/// A nested physical parent refused restoration after the pump entered. The snapshot owns the
/// receive-half continuation; `origin` retains the callback stack and original lane return path.
/// The root Reply is attached by the outer handoff before it is parked.
#[derive(Clone, Copy)]
pub(crate) struct PendingNestedRestoreDispatch {
    pub snapshot: SuspendedPumpSnapshot,
    pub origin: NestedRestoreOrigin,
}

#[derive(Clone, Copy)]
pub(crate) struct NestedRestoreOrigin {
    pub nested_user_callback: bool,
    pub outer_callback: Option<(nt_component_suspension::LaneHandle, u64)>,
    pub registered_client: bool,
    pub owner: Option<nt_component_suspension::SuspensionOwner>,
}

pub(super) static mut NESTED_RESTORE_PENDING_DISPATCH: Option<PendingNestedRestoreDispatch> = None;

pub(crate) unsafe fn pending_nested_restore_dispatch_is_some() -> bool {
    (&*core::ptr::addr_of!(NESTED_RESTORE_PENDING_DISPATCH)).is_some()
}

pub(crate) unsafe fn take_pending_nested_restore_dispatch() -> Option<PendingNestedRestoreDispatch> {
    core::ptr::replace(core::ptr::addr_of_mut!(NESTED_RESTORE_PENDING_DISPATCH), None)
}

pub(crate) unsafe fn restore_pending_nested_restore_dispatch(
    pending: PendingNestedRestoreDispatch,
) -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(NESTED_RESTORE_PENDING_DISPATCH);
    if slot.is_some() { return false; }
    *slot = Some(pending);
    true
}

pub(super) static mut ROOT_MAINTENANCE_PENDING_DISPATCH: Option<PendingRootMaintenanceDispatch> = None;

pub(crate) unsafe fn pending_root_maintenance_dispatch_is_some() -> bool {
    (&*core::ptr::addr_of!(ROOT_MAINTENANCE_PENDING_DISPATCH)).is_some()
}

pub(crate) unsafe fn take_pending_root_maintenance_dispatch() -> Option<PendingRootMaintenanceDispatch> {
    core::ptr::replace(core::ptr::addr_of_mut!(ROOT_MAINTENANCE_PENDING_DISPATCH), None)
}

pub(crate) unsafe fn restore_pending_root_maintenance_dispatch(
    pending: PendingRootMaintenanceDispatch,
) -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(ROOT_MAINTENANCE_PENDING_DISPATCH);
    if slot.is_some() { return false; }
    *slot = Some(pending);
    true
}

#[derive(Clone, Copy)]
pub(crate) struct PendingReceiveDispatch {
    pub yielded: ReceiveYield,
    pub snapshot: SuspendedPumpSnapshot,
}

#[derive(Clone, Copy)]
pub(crate) struct PendingRootIngressDispatch {
    pub yielded: RootIngressYield,
    pub snapshot: SuspendedPumpSnapshot,
}

pub(super) static mut ROOT_INGRESS_PENDING_DISPATCH: Option<PendingRootIngressDispatch> = None;

pub(crate) unsafe fn pending_root_ingress_dispatch_is_some() -> bool {
    (&*core::ptr::addr_of!(ROOT_INGRESS_PENDING_DISPATCH)).is_some()
}

pub(crate) unsafe fn pending_root_ingress_dispatch_identity() -> Option<(
    Win32kClientContext, nt_user_callback::DispatchContext,
)> {
    let pending = (&*core::ptr::addr_of!(ROOT_INGRESS_PENDING_DISPATCH)).as_ref()?;
    Some((pending.snapshot.client, pending.snapshot.dispatch))
}

/// Observe a selectable root child without moving its saved pump or physical parent. Retained
/// and uncertain yields do not expose a selector; the later take rechecks both identities.
pub(crate) unsafe fn pending_root_ingress_selector() -> Option<(
    crate::spawn_hosts::shared_ingress::owner::runtime::nested::NestedRestoreTicket,
    nt_component_suspension::ExternalAdmissionKey,
)> {
    let pending = (&*core::ptr::addr_of!(ROOT_INGRESS_PENDING_DISPATCH)).as_ref()?;
    let RootIngressYield::ParkedUnbound { ticket, child, .. } = pending.yielded else {
        return None;
    };
    if !crate::spawn_hosts::shared_ingress::owner::runtime
        ::prepared_root_ingress_child_is_current(child)
        || crate::spawn_hosts::shared_ingress::owner::runtime::nested
            ::parked_unbound_root_parent(ticket, child).is_none()
    {
        return None;
    }
    Some((ticket, child))
}

/// The slot and the physical parent travel together across the serialized outer handoff.
/// This bundle is intentionally move-only even though the saved pump snapshot is copyable.
pub(crate) struct TakenRootIngressDispatch {
    pub(crate) pending: PendingRootIngressDispatch,
    pub(crate) parent: crate::spawn_hosts::shared_ingress::owner::runtime::nested::ParkedParentHandle,
}

/// Claim only the exact prepared child and parked physical parent. A retained/uncertain yield
/// never grants a parent handle, and any failed check leaves the pending slot untouched.
pub(crate) unsafe fn take_pending_root_ingress_dispatch(
    ticket: crate::spawn_hosts::shared_ingress::owner::runtime::nested::NestedRestoreTicket,
    child: nt_component_suspension::ExternalAdmissionKey,
) -> Option<TakenRootIngressDispatch> {
    let slot = &mut *core::ptr::addr_of_mut!(ROOT_INGRESS_PENDING_DISPATCH);
    let pending = slot.as_ref()?;
    let RootIngressYield::ParkedUnbound {
        ticket: pending_ticket, child: pending_child, ..
    } = pending.yielded else { return None };
    if pending_ticket != ticket || pending_child != child
        || !crate::spawn_hosts::shared_ingress::owner::runtime
            ::prepared_root_ingress_child_is_current(child)
    {
        return None;
    }
    let parent = crate::spawn_hosts::shared_ingress::owner::runtime::nested
        ::parked_unbound_root_parent(ticket, child)?;
    let pending = core::ptr::replace(slot, None)?;
    Some(TakenRootIngressDispatch { pending, parent })
}

/// A pre-effect refusal must return both the saved pump and its move-only parent selector.
/// If identity or the destination slot changed, the caller retains the complete bundle.
pub(crate) unsafe fn restore_pending_root_ingress_dispatch(
    taken: TakenRootIngressDispatch,
) -> Result<(), TakenRootIngressDispatch> {
    let RootIngressYield::ParkedUnbound { ticket, child, .. } = taken.pending.yielded
    else { return Err(taken) };
    if taken.parent.ticket() != ticket
        || !crate::spawn_hosts::shared_ingress::owner::runtime
            ::prepared_root_ingress_child_is_current(child)
        || crate::spawn_hosts::shared_ingress::owner::runtime::nested
            ::parked_unbound_root_parent(ticket, child).is_none()
    {
        return Err(taken);
    }
    let slot = &mut *core::ptr::addr_of_mut!(ROOT_INGRESS_PENDING_DISPATCH);
    if slot.is_some() { return Err(taken) }
    *slot = Some(taken.pending);
    Ok(())
}

pub(super) static mut RECEIVE_PENDING_DISPATCH: Option<PendingReceiveDispatch> = None;

/// Dispatch-owned cells in the one physical win32k shared page. Global SSDT, SAS, font and
/// handle-table publications deliberately stay outside this snapshot.
#[derive(Clone, Copy)]
pub(crate) struct SharedResumeSnapshot {
    header: nt_user_callback::CallbackHeader,
    // Nested callbacks reuse this physical frame. Retain its dispatch-owned bytes along with
    // the header; the header alone cannot reconstruct an in-flight callback request or reply.
    payload: Option<[u8; nt_user_callback::CALLBACK_PAYLOAD_MAX]>,
    published: Win32kPublishedContext,
    request: [u64; SHARED_RESUME_REQUEST_OFFSETS.len()],
}

impl SharedResumeSnapshot {
    pub(crate) fn lease_snapshot(
        &self, client: Win32kClientContext,
    ) -> Option<nt_user_callback::SharedPageSnapshot> {
        Some(nt_user_callback::SharedPageSnapshot {
            header: self.header,
            callback_payload: self.payload?,
            publication: self.callback_publication(),
            request_owner: shared_page_client_identity(client),
            request_ssn: self.request[0],
        })
    }

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

    /// The exact page the authority parked.
    pub(crate) fn from_lease_snapshot(page: nt_user_callback::SharedPageSnapshot) -> Self {
        Self {
            payload: Some(page.callback_payload),
            ..Self::from_callback_publication(page.header, page.publication)
        }
    }

    /// A callback frame retains its request and publication but not the payload it was
    /// published with. When the parked page is that same publication, restore it whole, so the
    /// restore is the exact page and the reply is then written over it by its owner.
    pub(crate) fn with_parked_payload(
        self, parked: Option<nt_user_callback::SharedPageSnapshot>,
    ) -> Self {
        match parked {
            Some(page) if self.payload.is_none()
                && page.publication == self.callback_publication()
                && page.header.matches_dispatch_identity(
                    self.header.dispatch_id, self.header.client_pi,
                    self.header.client_tid, self.header.client_badge,
                ) => Self::from_lease_snapshot(page),
            _ => self,
        }
    }

    pub(crate) fn from_callback_publication(
        header: nt_user_callback::CallbackHeader,
        publication: nt_user_callback::SharedCallbackPublication,
    ) -> Self {
        let context = publication.context();
        Self {
            header,
            // This constructor is used by callback reply publication, which copies the result
            // into the frame after restoring the request/context cells below.
            payload: None,
            request: *publication.request(),
            published: Win32kPublishedContext {
                pid: context[0], tid: context[1],
                eprocess: context[2], ethread: context[3],
                w32process: context[4], w32thread: context[5],
            },
        }
    }
}

pub(crate) fn shared_page_client_identity(
    client: Win32kClientContext,
) -> nt_user_callback::SharedPageClientIdentity {
    nt_user_callback::SharedPageClientIdentity {
        pi: client.pi, pid: client.pid, generation: client.generation,
        tid: client.tid, badge: client.badge, tcb: client.tcb,
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

unsafe fn read_shared_resume_request() -> [u64; SHARED_RESUME_REQUEST_OFFSETS.len()] {
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    let mut request = [0u64; SHARED_RESUME_REQUEST_OFFSETS.len()];
    for (value, offset) in request.iter_mut().zip(SHARED_RESUME_REQUEST_OFFSETS) {
        *value = core::ptr::read_volatile((sh + offset) as *const u64);
    }
    request
}

unsafe fn read_shared_callback_payload() -> [u8; nt_user_callback::CALLBACK_PAYLOAD_MAX] {
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *const nt_user_callback::CallbackFrame;
    let mut payload = [0u8; nt_user_callback::CALLBACK_PAYLOAD_MAX];
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte = core::ptr::read_volatile(core::ptr::addr_of!((*frame).payload[index]));
    }
    payload
}

unsafe fn shared_callback_payload_matches(
    expected: &[u8; nt_user_callback::CALLBACK_PAYLOAD_MAX],
) -> bool {
    let frame = (win32k_subsystem::WIN32K_SHARED_VADDR + win32k_subsystem::SH_USER_CALLBACK)
        as *const nt_user_callback::CallbackFrame;
    expected.iter().enumerate().all(|(index, byte)|
        core::ptr::read_volatile(core::ptr::addr_of!((*frame).payload[index])) == *byte)
}

/// Capture the physical shared page only while it still belongs to this exact dispatch.
/// A displaced or concurrently changing publication is uncertain, so its caller must retain
/// the pending owner rather than reconstructing its request from retained identity fields.
pub(crate) unsafe fn try_capture_exact_shared_resume_snapshot(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> Option<SharedResumeSnapshot> {
    if !win32k_client_context_is_admitted(client)
        || client.token_user_sid_len as usize > client.token_user_sid.len()
    {
        return None;
    }
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    let frame = (sh + win32k_subsystem::SH_USER_CALLBACK)
        as *const nt_user_callback::CallbackFrame;
    let header_before = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    if !header_before.matches_dispatch_identity(
        dispatch.dispatch_id, client.pi, client.tid, client.badge,
    ) {
        return None;
    }
    let request = read_shared_resume_request();
    let published = published_win32k_context();
    let payload = read_shared_callback_payload();
    let confirm_request = read_shared_resume_request();
    let confirm_published = published_win32k_context();
    let payload_stable = shared_callback_payload_matches(&payload);
    let header_after = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    if header_before != header_after || request != confirm_request
        || !payload_stable
        || [published.pid, published.tid, published.eprocess, published.ethread,
            published.w32process, published.w32thread]
            != [confirm_published.pid, confirm_published.tid,
                confirm_published.eprocess, confirm_published.ethread,
                confirm_published.w32process, confirm_published.w32thread]
    {
        return None;
    }
    let owner = shared_request_owner::RequestOwner {
        ssn: dispatch.ssn,
        pid: client.pid,
        pi: client.pi as u64,
        tid: client.tid,
        generation: client.generation,
        token_auth: client.token_authentication_id,
        token_sid_len: client.token_user_sid_len as u64,
        token_sid_ptr: win32k_subsystem::WIN32K_TOKEN_USER_SID_VADDR,
    };
    if !shared_request_owner::matches(&request, owner) {
        return None;
    }
    let snapshot = SharedResumeSnapshot {
        header: header_before, payload: Some(payload), published, request,
    };
    let page = snapshot.lease_snapshot(client)?;
    if !page.matches(nt_user_callback::SharedPageLeaseIdentity {
        dispatch,
        client: page.request_owner,
    }) {
        return None;
    }
    Some(snapshot)
}

/// #419: every return of a pump entered under the shared page settles that hold once, here,
/// before any pending owner is built from the result: a suspension parks the exact page, a
/// return frees it, and a refused or uncertain return keeps the page with its owner.
pub(crate) unsafe fn settle_pump_page(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
    pump: &crate::spawn_hosts::PumpResult,
    site: &[u8],
) {
    use nt_user_callback::SharedPagePumpSettlement as Settlement;
    let settlement = if pump.provider_wait_capture_refusal.is_some() || pump.refused_before_entry {
        Settlement::Retained
    } else if pump.callback_suspended {
        // Parked at the callback rendezvous (`park_callback_suspended_page`), before the root
        // lifted the client context out of the page.
        return;
    } else if pump.page_yielded() {
        Settlement::Yielded(try_capture_exact_shared_resume_snapshot(dispatch, client)
            .and_then(|snapshot| snapshot.lease_snapshot(client)))
    } else if pump.completed {
        Settlement::Completed
    } else {
        Settlement::Retained
    };
    crate::win32k_shared_page_authority::audit_settle(
        nt_user_callback::SharedPageLeaseIdentity { dispatch, client: shared_page_client_identity(client) },
        settlement,
        site,
    );
}

#[track_caller]
pub(crate) unsafe fn capture_shared_resume_snapshot(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> SharedResumeSnapshot {
    let sh = win32k_subsystem::WIN32K_SHARED_VADDR;
    let frame = (sh + win32k_subsystem::SH_USER_CALLBACK)
        as *const nt_user_callback::CallbackFrame;
    let header = core::ptr::read_volatile(core::ptr::addr_of!((*frame).header));
    if !header.matches_dispatch_identity(dispatch.dispatch_id, client.pi, client.tid, client.badge) {
        let caller = core::panic::Location::caller();
        print_str(b"[win32k-shared-capture-site] ");
        print_str(caller.file().as_bytes());
        print_str(b":");
        print_u64(caller.line() as u64);
        print_str(b" active-dispatch=");
        print_u64(core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH)).dispatch_id);
        print_str(b"\n");
        print_str(b"[win32k-shared-header-mismatch] expected dispatch/pi/tid/badge=");
        print_u64(dispatch.dispatch_id); print_str(b"/"); print_u64(client.pi as u64);
        print_str(b"/"); print_u64(client.tid); print_str(b"/"); print_u64(client.badge);
        print_str(b" actual dispatch/pi/tid/badge/state=");
        print_u64(header.dispatch_id); print_str(b"/"); print_u64(header.client_pi as u64);
        print_str(b"/"); print_u64(header.client_tid); print_str(b"/");
        print_u64(header.client_badge); print_str(b"/"); print_u64(header.state as u64);
        print_str(b" magic/version/kind=0x"); print_hex_u64(header.magic as u64);
        print_str(b"/"); print_u64(header.version as u64);
        print_str(b"/"); print_u64(header.kind as u64);
        print_str(b" request ssn/pi/tid=");
        print_u64(core::ptr::read_volatile((sh + win32k_subsystem::SH_REQ_SSN) as *const u64));
        print_str(b"/");
        print_u64(core::ptr::read_volatile((sh + win32k_subsystem::SH_REQ_CLIENT_PI) as *const u64));
        print_str(b"/");
        print_u64(core::ptr::read_volatile((sh + win32k_subsystem::SH_REQ_THREAD_ID) as *const u64));
        print_str(b"\n");
    }
    assert!(header.matches_dispatch_identity(
        dispatch.dispatch_id, client.pi, client.tid, client.badge,
    ), "yielded win32k shared callback belongs to another dispatch");
    let mut request = read_shared_resume_request();
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
    SharedResumeSnapshot {
        header, payload: Some(read_shared_callback_payload()),
        published: published_win32k_context(), request,
    }
}

/// The effect on the physical request and callback page. A rejected identity has not
/// written the page; an applied restore carries the exact bytes that were published.
/// If a future native write can refuse after its first store, it must return Uncertain
/// and retain the page owner rather than allowing another writer to enter.
#[derive(Clone, Copy)]
#[allow(dead_code)] // The current volatile write sequence has no fallible step after its first store.
pub(crate) enum SharedResumeRestoreEffect {
    NoPageWrite,
    Applied(SharedResumeSnapshot),
    Uncertain,
}

pub(crate) unsafe fn restore_shared_resume_snapshot_effect(
    snapshot: SharedResumeSnapshot,
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> SharedResumeRestoreEffect {
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
        return SharedResumeRestoreEffect::NoPageWrite;
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
    if let Some(payload) = snapshot.payload {
        for (index, byte) in payload.iter().enumerate() {
            core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).payload[index]), *byte);
        }
    }
    core::ptr::write_volatile(core::ptr::addr_of_mut!((*frame).header), snapshot.header);
    SharedResumeRestoreEffect::Applied(snapshot)
}

/// Keep existing callers' completion behavior while the native page authority is
/// integrated. Only a full, acknowledged publication counts as restored.
pub(crate) unsafe fn restore_shared_resume_snapshot(
    snapshot: SharedResumeSnapshot,
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> bool {
    matches!(
        restore_shared_resume_snapshot_effect(snapshot, dispatch, client),
        SharedResumeRestoreEffect::Applied(_)
    )
}

/// Select the exact client window before restoring its retained shared publication.
/// Return both effects so callers that diagnose selection separately keep that evidence.
pub(crate) unsafe fn select_and_restore_shared_resume_snapshot(
    snapshot: SharedResumeSnapshot,
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) -> (bool, bool) {
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch, client: shared_page_client_identity(client),
    };
    // #419: the parked dispatch takes the page back before restoring its publication.
    let parked = crate::win32k_shared_page_authority::audit_reacquire(
        identity, snapshot.lease_snapshot(client), b"resume");
    if parked.is_err() && crate::win32k_shared_page_authority::ENFORCING {
        // Another dispatch holds the page, or this one never parked: nothing is written and
        // the caller retains its pending owner.
        return (false, false);
    }
    let snapshot = snapshot.with_parked_payload(parked.ok());
    if !super::select_win32k_client_window(client) {
        crate::win32k_shared_page_authority::audit_restored(identity, None, b"resume-select");
        return (false, false);
    }
    let restored = match restore_shared_resume_snapshot_effect(snapshot, dispatch, client) {
        SharedResumeRestoreEffect::Applied(page) => {
            crate::win32k_shared_page_authority::audit_restored(
                identity, page.lease_snapshot(client), b"resume");
            true
        }
        SharedResumeRestoreEffect::NoPageWrite | SharedResumeRestoreEffect::Uncertain => {
            crate::win32k_shared_page_authority::audit_restored(identity, None, b"resume");
            false
        }
    };
    (true, restored)
}

/// A user callback suspends its dispatch: park the exact page at the rendezvous, while it still
/// carries the client context the callback frame recorded.
pub(crate) unsafe fn park_callback_suspended_page(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
) {
    crate::win32k_shared_page_authority::audit_park(
        nt_user_callback::SharedPageLeaseIdentity { dispatch, client: shared_page_client_identity(client) },
        try_capture_exact_shared_resume_snapshot(dispatch, client)
            .and_then(|snapshot| snapshot.lease_snapshot(client)),
        b"callback-suspend",
    );
}

/// A cancelled or dead-client callback is answered with a failure reply. Before that header
/// write, its dispatch takes back and restores the exact page it parked at the callback.
/// False refuses the reply: the page is not this dispatch's to write.
pub(crate) unsafe fn reacquire_parked_callback_page(
    dispatch: nt_user_callback::DispatchContext,
    client: Win32kClientContext,
    site: &[u8],
) -> bool {
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch, client: shared_page_client_identity(client),
    };
    let Ok(parked) = crate::win32k_shared_page_authority::audit_reacquire(identity, None, site)
    else { return !crate::win32k_shared_page_authority::ENFORCING };
    let applied = match restore_shared_resume_snapshot_effect(
        SharedResumeSnapshot::from_lease_snapshot(parked), dispatch, client,
    ) {
        SharedResumeRestoreEffect::Applied(page) => page.lease_snapshot(client),
        SharedResumeRestoreEffect::NoPageWrite | SharedResumeRestoreEffect::Uncertain => None,
    };
    crate::win32k_shared_page_authority::audit_restored(identity, applied, site);
    // The page is this dispatch's again (applied), or pinned with it (refused restore).
    true
}

/// The dispatcher's singleton publication for one entered kernel job. `previous` is the
/// publication this job displaced at entry; the job may lend the page only when that is empty.
#[derive(Clone, Copy)]
pub(crate) struct KernelJobPublication {
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub previous: nt_user_callback::DispatchContext,
}

/// Lend the singleton page while this job's own service Call is parked on a source terminal.
/// The exact full page is copied first; a refusal changes neither the page nor the dispatch.
pub(crate) unsafe fn park_kernel_job_publication(
    job: KernelJobPublication,
) -> Option<SharedResumeSnapshot> {
    let current = core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH));
    if job.dispatch.dispatch_id == 0 || current != job.dispatch || job.previous.dispatch_id != 0 {
        return None;
    }
    let page = try_capture_exact_shared_resume_snapshot(job.dispatch, job.client)?;
    crate::win32k_shared_page_authority::audit_park(
        nt_user_callback::SharedPageLeaseIdentity {
            dispatch: job.dispatch, client: shared_page_client_identity(job.client),
        },
        page.lease_snapshot(job.client),
        b"kernel-job-lend",
    );
    core::ptr::write(core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH), job.previous);
    Some(page)
}

/// Return the lent page to its parked job before that job's receive half continues.
pub(crate) unsafe fn restore_kernel_job_publication(
    job: KernelJobPublication,
    page: SharedResumeSnapshot,
) -> bool {
    if core::ptr::read(core::ptr::addr_of!(USER_CALLBACK_CURRENT_DISPATCH)) != job.previous {
        return false;
    }
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch: job.dispatch, client: shared_page_client_identity(job.client),
    };
    if crate::win32k_shared_page_authority::audit_reacquire(
        identity, page.lease_snapshot(job.client), b"kernel-job-lend",
    ).is_err() && crate::win32k_shared_page_authority::ENFORCING {
        return false;
    }
    let SharedResumeRestoreEffect::Applied(applied) =
        restore_shared_resume_snapshot_effect(page, job.dispatch, job.client)
    else {
        crate::win32k_shared_page_authority::audit_restored(identity, None, b"kernel-job-lend");
        return false;
    };
    crate::win32k_shared_page_authority::audit_restored(
        identity, applied.lease_snapshot(job.client), b"kernel-job-lend");
    core::ptr::write(core::ptr::addr_of_mut!(USER_CALLBACK_CURRENT_DISPATCH), job.dispatch);
    true
}

pub(crate) unsafe fn take_pending_receive_dispatch() -> Option<PendingReceiveDispatch> {
    core::ptr::replace(core::ptr::addr_of_mut!(RECEIVE_PENDING_DISPATCH), None)
}

pub(crate) unsafe fn restore_pending_receive_dispatch(pending: PendingReceiveDispatch) -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(RECEIVE_PENDING_DISPATCH);
    if slot.is_some() { return false; }
    *slot = Some(pending);
    true
}

pub(super) static PROVIDER_WAIT_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);
pub(super) static LPC_WAIT_LAST_PUMP_SUSPENDED: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy)]
pub(crate) struct PendingProviderWaitDispatch {
    pub request: nt_provider_wait::ProviderWaitRequest,
    pub dispatch: nt_user_callback::DispatchContext,
    pub client: Win32kClientContext,
    pub shared_resume: Option<SharedResumeSnapshot>,
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
    pub shared_resume: Option<SharedResumeSnapshot>,
    pub nested_user_callback: bool,
    pub arg_snapshot_len: u32,
    pub arg_snapshot: [u8; COMPLETED_ARG_SNAPSHOT_BYTES],
}

pub(super) static mut LPC_WAIT_PENDING_DISPATCH: Option<PendingLpcWaitDispatch> = None;

#[derive(Clone, Copy)]
pub(crate) enum ProviderWaitPumpCompletion {
    NestedSourceDeferred,
    Completed(CompletedWin32kDispatch),
    Reparked(PendingProviderWaitDispatch),
    LpcReparked(PendingLpcWaitDispatch),
    ReceiveReparked(PendingReceiveDispatch),
    ServiceReparked(PendingServiceWaitDispatch),
    UserCallbackSuspended,
    CaptureRefused(PendingProviderWaitDispatch, crate::spawn_hosts::PumpResult, crate::spawn_hosts::PumpChannel),
    RetainedFailure(PendingProviderWaitDispatch, i32),
    Failed(i32),
}

pub(crate) enum LpcWaitPumpCompletion {
    Completed(CompletedWin32kDispatch),
    ProviderReparked(PendingProviderWaitDispatch),
    Reparked(PendingLpcWaitDispatch),
    ReceiveReparked(PendingReceiveDispatch),
    ServiceReparked(PendingServiceWaitDispatch),
    UserCallbackSuspended,
    CaptureRefused(PendingLpcWaitDispatch, crate::spawn_hosts::PumpResult, crate::spawn_hosts::PumpChannel),
    RetainedFailure(PendingLpcWaitDispatch, i32),
    Failed(i32),
}

/// What the returned pump left for its handoff, named by the dispatch that published it.
pub(crate) unsafe fn pending_yield_observation(
    current_dispatch: Option<u64>,
    callback_suspended: bool,
) -> nt_user_host::yield_handoff::HandoffObservation {
    use nt_user_host::yield_handoff::{HandoffObservation, YieldKind};
    let mut observation = HandoffObservation::new(current_dispatch, callback_suspended);
    if let Some(pending) = &*core::ptr::addr_of!(RECEIVE_PENDING_DISPATCH) {
        observation = observation.with(YieldKind::Receive, pending.snapshot.dispatch.dispatch_id);
    }
    if let Some(pending) = &*core::ptr::addr_of!(SERVICE_WAIT_PENDING_DISPATCH) {
        observation =
            observation.with(YieldKind::ServiceWait, pending.snapshot.dispatch.dispatch_id);
    }
    if PROVIDER_WAIT_LAST_PUMP_SUSPENDED.load(Ordering::Acquire) != 0 {
        if let Some(pending) = &*core::ptr::addr_of!(PROVIDER_WAIT_PENDING_DISPATCH) {
            observation = observation.with(YieldKind::ProviderWait, pending.dispatch.dispatch_id);
        }
    }
    if LPC_WAIT_LAST_PUMP_SUSPENDED.load(Ordering::Acquire) != 0 {
        if let Some(pending) = &*core::ptr::addr_of!(LPC_WAIT_PENDING_DISPATCH) {
            observation = observation.with(YieldKind::LpcWait, pending.dispatch.dispatch_id);
        }
    }
    observation
}

/// Take a record out of the pending set without admitting it, naming the client it carried.
/// Its lane keeps the Call and Reply it yielded with; nothing here resumes or answers them.
pub(crate) unsafe fn fence_pending_yield(
    kind: nt_user_host::yield_handoff::YieldKind,
) -> Option<Win32kClientContext> {
    use nt_user_host::yield_handoff::YieldKind;
    match kind {
        YieldKind::Receive => take_pending_receive_dispatch().map(|pending| pending.snapshot.client),
        YieldKind::ServiceWait => {
            take_pending_service_wait_dispatch().map(|pending| pending.snapshot.client)
        }
        YieldKind::ProviderWait => take_pending_provider_wait_dispatch().map(|pending| pending.client),
        YieldKind::LpcWait => take_pending_lpc_wait_dispatch().map(|pending| pending.client),
    }
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

pub(crate) unsafe fn restore_pending_provider_wait_dispatch(
    pending: PendingProviderWaitDispatch,
) -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(PROVIDER_WAIT_PENDING_DISPATCH);
    if slot.is_some() { return false; }
    *slot = Some(pending);
    PROVIDER_WAIT_LAST_PUMP_SUSPENDED.store(1, Ordering::Release);
    true
}

pub(crate) unsafe fn take_pending_lpc_wait_dispatch() -> Option<PendingLpcWaitDispatch> {
    if LPC_WAIT_LAST_PUMP_SUSPENDED.swap(0, Ordering::AcqRel) == 0 {
        return None;
    }
    core::ptr::replace(core::ptr::addr_of_mut!(LPC_WAIT_PENDING_DISPATCH), None)
}

pub(crate) unsafe fn restore_pending_lpc_wait_dispatch(pending: PendingLpcWaitDispatch) -> bool {
    let slot = &mut *core::ptr::addr_of_mut!(LPC_WAIT_PENDING_DISPATCH);
    if slot.is_some() { return false; }
    *slot = Some(pending);
    LPC_WAIT_LAST_PUMP_SUSPENDED.store(1, Ordering::Release);
    true
}

pub(super) unsafe fn capture_provider_wait_repark(
    prior: PendingProviderWaitDispatch,
    request: nt_provider_wait::ProviderWaitRequest,
) -> PendingProviderWaitDispatch {
    PendingProviderWaitDispatch {
        request,
        dispatch: prior.dispatch,
        client: prior.client,
        shared_resume: try_capture_exact_shared_resume_snapshot(prior.dispatch, prior.client),
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
        shared_resume: try_capture_exact_shared_resume_snapshot(dispatch, client),
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
