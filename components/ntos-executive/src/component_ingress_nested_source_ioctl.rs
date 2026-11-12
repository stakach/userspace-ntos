//! Exact source terminal child of a retained physical component parent.

use super::*;
use crate::{win32k_glue, win32k_subsystem};

enum QuarantinedSourcePreflight {
    Selection(crate::driver_launch::NestedIoctlSelection),
    Checkpoint(
        NestedPreEntryCheckpoint<crate::driver_launch::NestedIoctlKey>,
        crate::driver_launch::NestedIoctlSelection,
    ),
    Source(SourceIoctlParent),
}

// A preflight requeue refusal has no physical Parent row yet. Keep the exact move-only
// selection and checkpoint in this one-slot quarantine while the Resuming frame fences the page.
static mut QUARANTINED_PREFLIGHT: Option<QuarantinedSourcePreflight> = None;

unsafe fn quarantine_preflight(owner: QuarantinedSourcePreflight, stage: &[u8]) {
    trace_source_ioctl_preflight(stage);
    if (&*core::ptr::addr_of!(QUARANTINED_PREFLIGHT)).is_none() {
        core::ptr::write(core::ptr::addr_of_mut!(QUARANTINED_PREFLIGHT), Some(owner));
    } else {
        // The global page is already fenced. Never release a second uncertain selection.
        core::mem::forget(owner);
    }
}

fn trace_source_ioctl_preflight(stage: &[u8]) {
    crate::print_str(b"[nested-source-preflight-retained] stage=");
    crate::print_str(stage);
    crate::print_str(b"\n");
}

pub(crate) unsafe fn requeue_no_effect_source_ioctl(
    mut source: SourceIoctlParent,
) -> Result<(), (Error, SourceIoctlParent)> {
    // The source Work still owns its Reply and transport; the preselection has no native
    // effect and is revalidated from that same Work on the next attempt.
    source.checkpoint.requeue_no_effect_parent(lanes())
        .map_err(|_| (Error::Admission, source))
}

pub(crate) unsafe fn quarantine_refused_source_ioctl(source: SourceIoctlParent) {
    quarantine_preflight(QuarantinedSourcePreflight::Source(source), b"no-effect-requeue-refused");
}

/// Called only after the provider's full retained page and argument bank were restored, and
/// before its pump enters. The Work preselection is moved into the physical Parent row first.
pub(crate) unsafe fn park_resuming_source_ioctl(
    dispatch_context: nt_user_callback::DispatchContext,
    client: win32k_glue::Win32kClientContext,
) -> SourceIoctlPark {
    if (&*core::ptr::addr_of!(QUARANTINED_PREFLIGHT)).is_some() {
        return SourceIoctlPark::Retained;
    }
    let Some(lane) = lanes().running() else {
        trace_source_ioctl_preflight(b"no-running-lane");
        return SourceIoctlPark::Retained;
    };
    let Some(route) = lanes().peer_route(lane).ok().flatten() else {
        trace_source_ioctl_preflight(b"no-exact-route");
        return SourceIoctlPark::Retained;
    };
    let Ok(dispatch) = dispatch(route) else {
        trace_source_ioctl_preflight(b"no-exact-dispatch");
        return SourceIoctlPark::Retained;
    };
    let Ok(reply) = current_reply(route) else {
        trace_source_ioctl_preflight(b"no-exact-reply");
        return SourceIoctlPark::Retained;
    };
    let Some(selection) = crate::driver_launch::select_nested_win32k_source_ioctl_terminal(
        route, dispatch, reply,
    ) else { return SourceIoctlPark::NoChild };
    let Some(frame) = lanes().top(lane).ok().flatten() else {
        quarantine_preflight(QuarantinedSourcePreflight::Selection(selection), b"no-resuming-frame");
        return SourceIoctlPark::Retained;
    };
    if frame.owner.dispatch_id != dispatch_context.dispatch_id {
        quarantine_preflight(QuarantinedSourcePreflight::Selection(selection), b"wrong-resuming-owner");
        return SourceIoctlPark::Retained;
    }
    let Ok(mut checkpoint) = NestedPreEntryCheckpoint::from_resuming(
        lanes(), route, dispatch, reply, frame.key, frame.owner, selection.key(),
    ) else {
        quarantine_preflight(QuarantinedSourcePreflight::Selection(selection), b"checkpoint-rejected");
        return SourceIoctlPark::Retained;
    };
    let Some(shared_resume) = win32k_glue::try_capture_exact_shared_resume_snapshot(
        dispatch_context, client,
    ) else {
        if checkpoint.requeue_no_effect_parent(lanes()).is_err() {
            quarantine_preflight(
                QuarantinedSourcePreflight::Checkpoint(checkpoint, selection),
                b"capture-requeue-refused",
            );
            return SourceIoctlPark::Retained;
        }
        return SourceIoctlPark::RequeuedNoEffect;
    };
    let Some(page) = shared_resume.lease_snapshot(client) else {
        if checkpoint.requeue_no_effect_parent(lanes()).is_err() {
            quarantine_preflight(
                QuarantinedSourcePreflight::Checkpoint(checkpoint, selection),
                b"page-requeue-refused",
            );
            return SourceIoctlPark::Retained;
        }
        return SourceIoctlPark::RequeuedNoEffect;
    };
    let identity = nt_user_callback::SharedPageLeaseIdentity {
        dispatch: dispatch_context,
        client: win32k_glue::shared_page_client_identity(client),
    };
    let mut shared_leases = nt_user_callback::SharedPageLeaseStack::<2>::new();
    if shared_leases.begin(identity).is_err() || shared_leases.displace(identity, page).is_err() {
        if checkpoint.requeue_no_effect_parent(lanes()).is_err() {
            quarantine_preflight(
                QuarantinedSourcePreflight::Checkpoint(checkpoint, selection),
                b"lease-requeue-refused",
            );
            return SourceIoctlPark::Retained;
        }
        return SourceIoctlPark::RequeuedNoEffect;
    }
    let source = SourceIoctlParent {
        key: selection.key(), checkpoint, selection: Some(selection), shared_resume,
        dispatch: dispatch_context, client, shared_leases, child_dispatch: None,
    };
    match park_current_attempt(None, Some(source)) {
        ParkAttemptOutcome::Parked(handle) => SourceIoctlPark::Parked(handle),
        ParkAttemptOutcome::NoRunningLane(Some(source))
            | ParkAttemptOutcome::RefusedNoEffect(_, Some(source)) =>
            SourceIoctlPark::RefusedNoEffect(source),
        _ => SourceIoctlPark::Retained,
    }
}

/// A parked source parent lifts the generic busy fence only for its exact selected terminal.
/// Every other Win32k request still waits for the parent page and Reply to be restored.
pub(crate) unsafe fn source_ioctl_child_blocks_fresh_dispatch(
    request_kind: u64, packet: u64, length: u64,
) -> bool {
    if (&*core::ptr::addr_of!(QUARANTINED_PREFLIGHT)).is_some() { return true; }
    let rows = &*core::ptr::addr_of!(PARENTS);
    let Some(source) = rows.iter().flatten().find_map(|parent|
        parent.source_ioctl.as_ref().map(|source| (parent, source))) else {
        return false;
    };
    if source.0.phase != ParentPhase::Parked
        || request_kind != win32k_subsystem::WIN32K_REQUEST_SOURCE_IOCTL_TERMINAL
        || !crate::driver_launch::selected_nested_terminal_dispatch_matches(
            source.1.key, packet, length,
        )
    {
        return true;
    }
    false
}

pub(crate) unsafe fn source_ioctl_parent_retained() -> bool {
    (&*core::ptr::addr_of!(QUARANTINED_PREFLIGHT)).is_some()
        || (&*core::ptr::addr_of!(PARENTS)).iter().flatten()
        .any(|parent| parent.source_ioctl.is_some())
}

pub(crate) unsafe fn source_ioctl_parent_ready() -> bool {
    (&*core::ptr::addr_of!(PARENTS)).iter().flatten().any(|parent| {
        let Some(source) = parent.source_ioctl.as_ref() else { return false };
        if !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending) {
            return false;
        }
        matches!(source.checkpoint.phase(),
            NestedPreEntryPhase::ChildAcknowledged | NestedPreEntryPhase::Restoring
                | NestedPreEntryPhase::ParentActive)
            || crate::driver_launch::selected_nested_terminal_ready(source.key)
    })
}

/// Bind a fresh source dispatch before its first page write. A different packet cannot enter
/// merely because the physical parent is parked.
pub(crate) unsafe fn register_selected_source_ioctl_dispatch(
    dispatch_id: u64, packet: u64, length: u64,
) -> bool {
    if (&*core::ptr::addr_of!(QUARANTINED_PREFLIGHT)).is_some() { return false; }
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let Some(parent) = rows.iter_mut().flatten()
        .find(|parent| parent.source_ioctl.is_some()) else { return true };
    if parent.phase != ParentPhase::Parked || dispatch_id == 0 {
        return false;
    }
    let source = parent.source_ioctl.as_mut().expect("selected source parent");
    if !crate::driver_launch::selected_nested_terminal_dispatch_matches(
        source.key, packet, length,
    ) || source.child_dispatch.is_some_and(|active| active != dispatch_id) {
        return false;
    }
    source.child_dispatch = Some(dispatch_id);
    true
}

pub(crate) unsafe fn finish_selected_source_ioctl_dispatch(dispatch_id: u64) {
    if let Some(source) = (&mut *core::ptr::addr_of_mut!(PARENTS)).iter_mut().flatten()
        .filter_map(|parent| parent.source_ioctl.as_mut())
        .find(|source| source.child_dispatch == Some(dispatch_id))
    {
        source.child_dispatch = None;
    }
}

/// A direct provider resume also writes the singleton page, so it obeys the child fence.
pub(crate) unsafe fn source_ioctl_parent_blocks_provider_resume(dispatch_id: u64) -> bool {
    (&*core::ptr::addr_of!(QUARANTINED_PREFLIGHT)).is_some()
        || (&*core::ptr::addr_of!(PARENTS)).iter().flatten()
        .filter_map(|parent| parent.source_ioctl.as_ref().map(|source| (parent, source)))
        .any(|(parent, source)| parent.phase != ParentPhase::Parked
            || source.child_dispatch != Some(dispatch_id))
}

/// One serialized step of the exact retained source Work. An ACK by itself is not settlement.
pub(crate) unsafe fn redrive_selected_source_ioctl_terminal(
    handle: &ParkedParentHandle, handler: *mut crate::ExecNtHandler,
) -> Result<bool, Error> {
    use crate::driver_launch::NestedIoctlTerminalStep as Step;
    let (selection, key) = {
        let parent = (&mut *core::ptr::addr_of_mut!(PARENTS))
            .get_mut(handle.index).and_then(Option::as_mut).ok_or(Error::Admission)?;
        if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked
            || !parent.physical.held() { return Err(Error::Admission); }
        let source = parent.source_ioctl.as_mut().ok_or(Error::Admission)?;
        let selection = source.selection.take().ok_or(Error::Admission)?;
        let key = source.key;
        if selection.key() != key {
            source.selection = Some(selection);
            return Err(Error::Admission);
        }
        if source.checkpoint.phase() == NestedPreEntryPhase::Parked {
            let selection = source.checkpoint.reserve_child(key, selection)
                .map_err(|(_, selection)| {
                    source.selection = Some(selection);
                    Error::Admission
                })?;
            source.selection = Some(selection);
        } else {
            source.selection = Some(selection);
        }
        if !matches!(source.checkpoint.phase(),
            NestedPreEntryPhase::ChildReserved | NestedPreEntryPhase::ChildActive)
        { return Err(Error::Admission); }
        (source.selection.take().ok_or(Error::Admission)?, key)
    };
    // No PARENTS reference crosses this native call. Nested dispatch reads the retained row.
    let (selection, step) = crate::driver_launch::redrive_selected_win32k_source_ioctl_terminal(
        handler, selection,
    );
    let Some(parent) = (&mut *core::ptr::addr_of_mut!(PARENTS))
        .get_mut(handle.index).and_then(Option::as_mut) else {
        core::mem::forget(selection);
        return Err(Error::Admission);
    };
    if !row_matches(handle, parent) || parent.phase != ParentPhase::Parked {
        core::mem::forget(selection);
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    let source = parent.source_ioctl.as_mut().ok_or(Error::Admission)?;
    if selection.key() != source.key {
        core::mem::forget(selection);
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    source.selection = Some(selection);
    match step {
        Step::PreEntryRetained => {
            if source.checkpoint.phase() == NestedPreEntryPhase::ChildReserved {
                source.checkpoint.child_no_effect(key).map_err(|_| Error::Admission)?;
            }
            Ok(false)
        }
        Step::ReturnedNotReady | Step::ReturnedAwaitingAck | Step::PacketAckRetained => {
            if source.checkpoint.phase() == NestedPreEntryPhase::ChildReserved {
                source.checkpoint.child_started(key).map_err(|_| Error::Admission)?;
            }
            Ok(false)
        }
        Step::Settled(receipt) => {
            if source.checkpoint.phase() == NestedPreEntryPhase::ChildReserved {
                source.checkpoint.child_started(key).map_err(|_| Error::Admission)?;
            }
            source.checkpoint.acknowledge_child(receipt)
                .map_err(|_| Error::Admission)?;
            Ok(true)
        }
        Step::Indeterminate => {
            let _ = source.checkpoint.child_uncertain(lanes(), key);
            parent.phase = ParentPhase::Quarantined;
            Err(Error::Admission)
        }
    }
}

/// Restore the full parent page, canonical Reply scope and physical execution hold. The
/// original provider completion becomes selectable again only after every stage acknowledges.
pub(crate) unsafe fn restore_settled_source_ioctl_parent(
    handle: &mut Option<ParkedParentHandle>,
) -> Result<(), Error> {
    let ticket = handle.as_ref().ok_or(Error::Admission)?.ticket();
    let rows = &mut *core::ptr::addr_of_mut!(PARENTS);
    let parent = rows.get_mut(ticket.index).and_then(Option::as_mut)
        .ok_or(Error::Admission)?;
    if !ticket_matches(ticket, parent)
        || !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending)
        || parent.source_ioctl.as_ref().is_none_or(|source|
            !matches!(source.checkpoint.phase(),
                NestedPreEntryPhase::ChildAcknowledged | NestedPreEntryPhase::Restoring
                    | NestedPreEntryPhase::ParentActive))
    {
        return Err(Error::Admission);
    }
    parent.phase = ParentPhase::RestorePending;
    let _message = crate::ipc_message::SavedMessageBuffer::capture();
    if parent.physical.restore_step()? == RestoreStep::Canonical {
        let scope = parent.scope.as_mut().ok_or(Error::Admission)?;
        let source = parent.source_ioctl.as_mut().ok_or(Error::Admission)?;
        if source.checkpoint.phase() == NestedPreEntryPhase::ChildAcknowledged {
            source.checkpoint.begin_restore(lanes(), scope)
                .map_err(|_| Error::Admission)?;
        }
        if source.checkpoint.phase() == NestedPreEntryPhase::Restoring {
            let identity = nt_user_callback::SharedPageLeaseIdentity {
                dispatch: source.dispatch,
                client: win32k_glue::shared_page_client_identity(source.client),
            };
            let page = source.shared_resume.lease_snapshot(source.client)
                .ok_or(Error::Admission)?;
            match win32k_glue::select_win32k_client_window_effect(source.client) {
                nt_user_host::client_alias_window::WindowSelectionEffect::Applied => {}
                nt_user_host::client_alias_window::WindowSelectionEffect::RefusedNoEffect =>
                    return Err(Error::Admission),
                nt_user_host::client_alias_window::WindowSelectionEffect::Uncertain => {
                    let _ = source.checkpoint.finish_restore(
                        lanes(), nt_component_suspension::NestedPreEntryRestoreEffect::Uncertain,
                    );
                    parent.phase = ParentPhase::Quarantined;
                    return Err(Error::Admission);
                }
            }
            match win32k_glue::restore_shared_resume_snapshot_effect(
                source.shared_resume, source.dispatch, source.client,
            ) {
                win32k_glue::SharedResumeRestoreEffect::NoPageWrite => {
                    source.checkpoint.finish_restore(
                        lanes(), nt_component_suspension::NestedPreEntryRestoreEffect::NoEffect,
                    ).map_err(|_| Error::Admission)?;
                    return Err(Error::Admission);
                }
                win32k_glue::SharedResumeRestoreEffect::Uncertain => {
                    let _ = source.checkpoint.finish_restore(
                        lanes(), nt_component_suspension::NestedPreEntryRestoreEffect::Uncertain,
                    );
                    parent.phase = ParentPhase::Quarantined;
                    return Err(Error::Admission);
                }
                win32k_glue::SharedResumeRestoreEffect::Applied(_) => {}
            }
            if source.shared_leases.acknowledge_restore(
                identity, nt_user_callback::SharedPageRestoreEffect::Applied(page),
            ).is_err() || source.shared_leases.finish(identity, Some(page)).is_err() {
                parent.phase = ParentPhase::Quarantined;
                return Err(Error::Admission);
            }
            if source.checkpoint.restore_applied(
                lanes(), scope, RestoredSourceIoctlPage(scope.identity()),
            ).is_err() {
                parent.phase = ParentPhase::Quarantined;
                return Err(Error::Admission);
            }
        }
        if source.checkpoint.phase() != NestedPreEntryPhase::ParentActive {
            parent.phase = ParentPhase::Quarantined;
            return Err(Error::Admission);
        }
        let owner = owner();
        owner.receiver.as_mut().expect("ready receiver")
            .resume_nested_execution(
                scope, lanes(), owner.peers.as_ref().expect("ready peers"),
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
            ).map_err(|_| Error::Admission)?;
        parent.physical.canonical_restored()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Projection {
        parent.physical.restore_projection()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Release {
        parent.physical.release()?;
    }
    if parent.physical.restore_step()? == RestoreStep::Finalize {
        parent.physical.projection_restored()?;
    }
    if parent.physical.restore_step()? != RestoreStep::Done {
        return Err(Error::Admission);
    }
    if parent.source_ioctl.as_mut().ok_or(Error::Admission)?
        .checkpoint.requeue_unentered_parent(lanes()).is_err() {
        parent.phase = ParentPhase::Quarantined;
        return Err(Error::Admission);
    }
    rows[ticket.index] = None;
    *handle = None;
    Ok(())
}

/// Outer service redrive. The parent row remains the unique owner across every no-effect step;
/// an uncertain terminal or restore stays quarantined and is never selected again.
pub(crate) unsafe fn drain_source_ioctl_parent(
    handler: *mut crate::ExecNtHandler,
) -> bool {
    let selected = (&*core::ptr::addr_of!(PARENTS)).iter().enumerate()
        .find_map(|(index, row)| {
            let parent = row.as_ref()?;
            if parent.source_ioctl.is_none()
                || !matches!(parent.phase, ParentPhase::Parked | ParentPhase::RestorePending)
            { return None; }
            let identity = parent.scope.as_ref()?.identity();
            Some(ParkedParentHandle { index, generation: parent.generation, identity })
        });
    let Some(handle) = selected else { return false };
    let ready_to_restore = (&*core::ptr::addr_of!(PARENTS))[handle.index]
        .as_ref().and_then(|parent| parent.source_ioctl.as_ref())
        .is_some_and(|source| matches!(source.checkpoint.phase(),
            NestedPreEntryPhase::ChildAcknowledged | NestedPreEntryPhase::Restoring
                | NestedPreEntryPhase::ParentActive));
    if !ready_to_restore {
        match redrive_selected_source_ioctl_terminal(&handle, handler) {
            Ok(false) => return false,
            Ok(true) => {},
            Err(_) => return false,
        }
    }
    let mut handle = Some(handle);
    restore_settled_source_ioctl_parent(&mut handle).is_ok()
}
