//! Publish accepted File work before service post-actions can retire its caller.

use super::*;
use crate::spawn_hosts::shared_ingress::owner::runtime;

/// A selected queued READ has one of three ownership outcomes. The published variants retain
/// the File row and original child Reply; neither authorizes parent restoration yet.
#[allow(dead_code)]
#[must_use]
pub(super) enum SelectedFileTransfer {
    RefusedNoEffect(SelectedFileTransferError),
    PublishedCallerRefused(SelectedFileTransferRetained),
    ReadyForReplyPark(SelectedFileTransferReady),
}

#[allow(dead_code)]
pub(super) enum SelectedFileTransferError {
    UnsupportedRecord,
    UnqueuedIrp,
    MissingReservation,
    MissingBusySource,
    BusySource(nt_io_manager::inline_file_retirement::InlineFileRetirementError),
    BusyMismatch,
    EventMismatch,
    WrongReply,
    ReplyParkUnavailable,
    Caller(crate::pending_file_caller::SelectedFileCallerError),
    FileOwner(nt_io_manager::PendingFileIoParkError),
}

#[allow(dead_code)]
pub(super) enum SelectedFileTransferRetainedReason {
    BusySource(nt_io_manager::inline_file_retirement::InlineFileRetirementError),
    Caller(crate::pending_file_caller::SelectedFileCallerError),
}

#[allow(dead_code)]
#[must_use = "retain the published File row, caller claim, and child Reply for reconciliation"]
pub(super) struct SelectedFileTransferRetained {
    pub identity: nt_io_manager::PendingFileIoIdentity,
    pub caller: crate::pending_file_caller::SelectedFileCallerPublication,
    pub reply_park: root_reply_park::RootReplyPark,
    pub busy_source: Option<nt_io_manager::inline_file_retirement::InlineFileRetirementIdentity>,
    pub reason: SelectedFileTransferRetainedReason,
}

#[allow(dead_code)]
#[must_use = "park the exact child Reply before acknowledging RootIngress"]
pub(super) struct SelectedFileTransferReady {
    pub identity: nt_io_manager::PendingFileIoIdentity,
    pub reply_park: root_reply_park::RootReplyPark,
}

/// Publish only a selected synchronous hosted READ after its queued IRP and exact File claim
/// exist. All refusal checks precede the first File-row effect; after that effect, every owner
/// remains in the exact row or returned stage until caller publication and Reply park settle.
#[allow(dead_code)]
pub(super) unsafe fn publish_selected_queued_read(
    nt_handler: &mut ExecNtHandler,
    child_reply: u64,
    native_call_transport: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> SelectedFileTransfer {
    use SelectedFileTransfer as Outcome;
    use SelectedFileTransferError as Refusal;
    let Some(mut pending) = nt_handler.pending_file_io_transfer else {
        return Outcome::RefusedNoEffect(Refusal::UnsupportedRecord);
    };
    if pending.major != nt_io_abi::major::IRP_MJ_READ
        || !matches!(pending.operation, nt_io_manager::PendingFileIoOperation::Transfer)
        || !matches!(pending.route, nt_io_manager::PendingFileRoute::Hosted(_))
        || !nt_handler.pending_file_io_wait
        || pending.reply_cap != 0
        || pending.reply_required
    {
        return Outcome::RefusedNoEffect(Refusal::UnsupportedRecord);
    }
    let nt_io_manager::PendingFileRoute::Hosted(file_id) = pending.route else {
        return Outcome::RefusedNoEffect(Refusal::UnsupportedRecord);
    };
    if !driver_launch::queued_hosted_file_read_matches_exact(
        nt_io_manager::IrpId(pending.irp_id),
        file_id,
        pending.tid,
    ) {
        return Outcome::RefusedNoEffect(Refusal::UnqueuedIrp);
    }
    let Some(reservation) = nt_handler.pending_file_io_reservation else {
        return Outcome::RefusedNoEffect(Refusal::MissingReservation);
    };
    let Some(active) = nt_handler.current_synchronous_file else {
        return Outcome::RefusedNoEffect(Refusal::MissingBusySource);
    };
    let owner = match inline_file_retirement::try_active_owner(active) {
        Ok(owner) => owner,
        Err(error) => return Outcome::RefusedNoEffect(Refusal::BusySource(error)),
    };
    if pending.busy.is_some()
        || pending.tid != owner.tid
        || !matches!(pending.route, nt_io_manager::PendingFileRoute::Hosted(file)
            if owner.key == nt_io_manager::FileIoWaitKey::Hosted(file))
    {
        return Outcome::RefusedNoEffect(Refusal::BusyMismatch);
    }
    pending.busy = Some(nt_io_manager::PendingFileBusy::new(owner));
    if pending.transfer_event.is_some()
        || nt_handler.current_file_transfer_event.is_some_and(|event| {
            pending.event_obj_idx != u64::MAX && pending.event_obj_idx != event.native_identity
        })
    {
        return Outcome::RefusedNoEffect(Refusal::EventMismatch);
    }
    // The handler retains the Event lease until the File table accepts this copied observation.
    pending.transfer_event = nt_handler.current_file_transfer_event;
    if child_reply == 0
        || REPLY_MAIN_SLOT.load(Ordering::Relaxed) != child_reply
        || !runtime::owns_ingress_reply(child_reply)
    {
        return Outcome::RefusedNoEffect(Refusal::WrongReply);
    }
    let Some(reply_park) = root_reply_park::RootReplyPark::prepare() else {
        return Outcome::RefusedNoEffect(Refusal::ReplyParkUnavailable);
    };
    pending.reply_cap = child_reply;
    pending.reply_required = true;
    pending.native_call_transport = native_call_transport;
    pending.resume_ip = resume_ip;
    pending.resume_sp = sp;
    pending.resume_flags = flags;
    let caller = match crate::pending_file_caller::prepare_selected_publication(reservation, pending) {
        Ok(claim) => claim,
        Err(error) => return Outcome::RefusedNoEffect(Refusal::Caller(error)),
    };
    let identity = reservation.identity();
    if let Err(error) = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO)).park_reserved(reservation, pending) {
        return Outcome::RefusedNoEffect(Refusal::FileOwner(error));
    }
    // The accepted row now owns the IRP, Event lease, Busy, and Reply. Clear the handler copies
    // before any subsequent checked operation can refuse.
    nt_handler.pending_file_io_transfer = None;
    nt_handler.pending_file_io_reservation = None;
    nt_handler.current_file_transfer_event = None;
    nt_handler.current_synchronous_file = None;
    thread_wait_state_park_badge_waiting(nt_handler, pending.badge);
    super::mounted_read_lifetime_trace::parked(nt_handler, identity, pending);
    if let Err(error) = inline_file_retirement::try_transfer_to_pending(active) {
        return Outcome::PublishedCallerRefused(SelectedFileTransferRetained {
            identity,
            caller,
            reply_park,
            busy_source: Some(active),
            reason: SelectedFileTransferRetainedReason::BusySource(error),
        });
    }
    match crate::pending_file_caller::try_publish_selected(caller) {
        Ok(_) => Outcome::ReadyForReplyPark(SelectedFileTransferReady { identity, reply_park }),
        Err((error, caller)) => Outcome::PublishedCallerRefused(SelectedFileTransferRetained {
            identity,
            caller,
            reply_park,
            busy_source: None,
            reason: SelectedFileTransferRetainedReason::Caller(error),
        }),
    }
}

pub(super) struct PublishedFileIo {
    identity: nt_io_manager::PendingFileIoIdentity,
    irp_id: u64,
    badge: u64,
    pub tid: u64,
    pub wait_for_completion: bool,
}

impl PublishedFileIo {
    /// Capture only the exact published mounted CREATE while this outer caller still owns its
    /// parked Reply. Periodic census reads the resulting atomics without borrowing the manager.
    pub(super) unsafe fn trace_parked_mounted_create(&self) {
        super::mounted_create_owner_trace::park_exact(self.identity, self.irp_id);
    }

    pub(super) unsafe fn still_waiting(&self) -> bool {
        self.wait_for_completion
            && thread_wait_state_badge_parked(self.badge)
            && (&*core::ptr::addr_of!(PENDING_FILE_IO))
                .get_exact(self.identity)
                .is_some_and(|pending| {
                    pending.irp_id == self.irp_id
                        && pending.tid == self.tid
                        && pending.badge == self.badge
                        && !pending.consumer_abandoned
                        && pending.reply_required
                        && pending.reply_cap != 0
                })
    }
}

#[must_use = "finish the handoff to release its transfer event and settle terminating File ownership"]
pub(super) struct EventLocalFileHandoff {
    published: Option<PublishedFileIo>,
    inline_retirement_needs_redrive: bool,
    terminating: bool,
}

impl EventLocalFileHandoff {
    pub(super) fn inline_retirement_needs_redrive(&self) -> bool {
        self.inline_retirement_needs_redrive
    }
}

pub(super) unsafe fn before_post_action(
    nt_handler: &mut ExecNtHandler,
    action: ExecPostAction,
    native_call_transport: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> EventLocalFileHandoff {
    // NtContinue does not dispatch File I/O. Its context/reply replacement must not cross an
    // unrelated staged File operation, even when the context application is later refused.
    if matches!(action, ExecPostAction::ContinueCurrentThread { .. }) {
        assert!(nt_handler.pending_file_io_transfer.is_none());
        assert!(nt_handler.current_synchronous_file.is_none());
    }
    let terminating = matches!(
        action,
        ExecPostAction::TerminateCurrentThread { .. }
            | ExecPostAction::TerminateProcess {
                drop_reply: true,
                ..
            }
            | ExecPostAction::CriticalTermination { .. }
    );
    let published = if let Some(mut pending) = nt_handler.pending_file_io_transfer {
        if let Some(identity) = nt_handler.current_synchronous_file {
            let owner = inline_file_retirement::active_owner(identity);
            assert_eq!(
                match pending.route {
                    nt_io_manager::PendingFileRoute::Hosted(file) => {
                        Some(nt_io_manager::FileIoWaitKey::Hosted(file))
                    }
                    nt_io_manager::PendingFileRoute::Local(nt_io_manager::LocalFileObject::Overlay(file)) => {
                        Some(nt_io_manager::FileIoWaitKey::LocalOverlay(file))
                    }
                    nt_io_manager::PendingFileRoute::Local(_) => None,
                },
                Some(owner.key)
            );
            assert_eq!(pending.tid, owner.tid);
            assert!(pending.busy.is_none());
            pending.busy = Some(nt_io_manager::PendingFileBusy::new(owner));
        }
        let reservation = nt_handler
            .pending_file_io_reservation
            .expect("accepted File IRP has no pre-dispatch reservation");
        let wait_for_completion = nt_handler.pending_file_io_wait && !terminating;
        // The source remains in the handler until publication succeeds. Continuing synchronous
        // calls attach their reply in this same commit, never exposing an unarmed delivery row.
        let identity = reservation.identity();
        let local_terminal = pending.owned_terminal_result().is_some()
            || pending.operation.is_owned_mode_uncommitted();
        if let Some(event) = nt_handler.current_file_transfer_event.take() {
            assert!(pending.transfer_event.is_none());
            assert!(pending.event_obj_idx == u64::MAX || pending.event_obj_idx == event.native_identity);
            pending.transfer_event = Some(event);
        }
        pending_file_io_transfer(
            pending,
            wait_for_completion,
            reservation,
            native_call_transport,
            resume_ip,
            sp,
            flags,
        );
        nt_handler.pending_file_io_transfer = None;
        nt_handler.pending_file_io_reservation = None;
        if local_terminal {
            FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
        }
        if let Some(identity) = nt_handler.current_synchronous_file.take() {
            inline_file_retirement::transfer_to_pending(identity);
        }
        if wait_for_completion {
            // Publish Waiting before any reentrant completion can make this thread Ready.
            thread_wait_state_park_badge_waiting(nt_handler, pending.badge);
        }
        super::pending_pipe_read_trace::parked(
            nt_handler, identity, pending, wait_for_completion,
        );
        super::mounted_read_lifetime_trace::parked(nt_handler, identity, pending);
        Some(PublishedFileIo {
            identity,
            irp_id: pending.irp_id,
            badge: pending.badge,
            tid: pending.tid,
            wait_for_completion,
        })
    } else {
        if let Some(reservation) = nt_handler.pending_file_io_reservation.take() {
            assert!(
                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO)).cancel_reservation(reservation),
                "unused File reservation became stale"
            );
            crate::pending_file_caller::cancel_reserved(reservation);
        }
        None
    };

    let inline_retirement_needs_redrive = if let Some(identity) = nt_handler.current_synchronous_file.take() {
        // No accepted pending IRP exists: inline completion (including dispatch refusal) has
        // already settled the operation. Retire its existing Busy/reference before any exit.
        inline_file_retirement::retire(identity);
        true
    } else {
        false
    };
    EventLocalFileHandoff { published, inline_retirement_needs_redrive, terminating }
}

pub(super) unsafe fn finish_after_inline_retirement(
    nt_handler: &mut ExecNtHandler,
    handoff: EventLocalFileHandoff,
) -> Option<PublishedFileIo> {
    nt_handler.release_current_transfer_event();
    if let Some(owner) = handoff.published.as_ref().filter(|_| handoff.terminating) {
        // The current main Reply was never transferred. Post-action teardown deletes it; the
        // published File owner instead retains real cancellation/completion and Busy retirement.
        // CREATE deliberately continues through the existing specialized unpublished-handle path.
        nt_handler.abandon_new_file_io_exact(owner.identity, owner.irp_id);
    }
    handoff.published
}
