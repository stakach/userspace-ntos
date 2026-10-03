//! Publish accepted File work before service post-actions can retire its caller.

use super::*;

pub(super) struct PublishedFileIo {
    identity: nt_io_manager::PendingFileIoIdentity,
    irp_id: u64,
    badge: u64,
    pub tid: u64,
    pub wait_for_completion: bool,
}

impl PublishedFileIo {
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

pub(super) unsafe fn before_post_action(
    nt_handler: &mut ExecNtHandler,
    action: ExecPostAction,
    native_call_transport: bool,
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> Option<PublishedFileIo> {
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
            || matches!(pending.operation, nt_io_manager::PendingFileIoOperation::OwnedModePrecommit(_));
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

    if let Some(identity) = nt_handler.current_synchronous_file.take() {
        // No accepted pending IRP exists: inline completion (including dispatch refusal) has
        // already settled the operation. Retire its existing Busy/reference before any exit.
        inline_file_retirement::retire(identity);
        inline_file_retirement::redrive(nt_handler);
    }
    nt_handler.release_current_transfer_event();
    if let Some(owner) = published.as_ref().filter(|_| terminating) {
        // The current main Reply was never transferred. Post-action teardown deletes it; the
        // published File owner instead retains real cancellation/completion and Busy retirement.
        // CREATE deliberately continues through the existing specialized unpublished-handle path.
        nt_handler.abandon_new_file_io_exact(owner.identity, owner.irp_id);
    }
    published
}
