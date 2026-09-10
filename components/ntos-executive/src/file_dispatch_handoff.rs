//! Publish accepted File work before service post-actions can retire its caller.

use super::*;

pub(super) struct PublishedFileIo {
    slot: usize,
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
                .get(self.slot)
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
    resume_ip: u64,
    sp: u64,
    flags: u64,
) -> Option<PublishedFileIo> {
    // NtContinue does not dispatch File I/O. Its context/reply replacement must not cross an
    // unrelated staged File operation, even when the context application is later refused.
    if matches!(action, ExecPostAction::ContinueCurrentThread { .. }) {
        assert!(nt_handler.pending_file_io_transfer.is_none());
        assert_eq!(nt_handler.current_synchronous_file_lock, 0);
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
        let file_id = nt_handler.current_synchronous_file_lock;
        if file_id != 0 {
            assert_eq!(pending.route.hosted_file_id(), Some(file_id));
            assert_eq!(pending.tid, nt_handler.current_tid);
            assert!(pending.busy.is_none());
            pending.busy = Some(nt_io_manager::PendingFileBusy::new(
                nt_io_manager::FileIoBusyOwner {
                    key: nt_io_manager::FileIoWaitKey::Hosted(file_id),
                    tid: pending.tid,
                    mode: nt_handler
                        .file_completion
                        .io_mode(file_id)
                        .expect("accepted File handoff lost its captured mode"),
                },
            ));
        }
        let reservation = nt_handler
            .pending_file_io_reservation
            .expect("accepted File IRP has no pre-dispatch reservation");
        let wait_for_completion = nt_handler.pending_file_io_wait && !terminating;
        // The source remains in the handler until publication succeeds. Continuing synchronous
        // calls attach their reply in this same commit, never exposing an unarmed delivery row.
        let slot = pending_file_io_transfer(
            pending,
            wait_for_completion,
            reservation,
            resume_ip,
            sp,
            flags,
        );
        nt_handler.pending_file_io_transfer = None;
        nt_handler.pending_file_io_reservation = None;
        nt_handler.current_synchronous_file_lock = 0;
        if wait_for_completion {
            // Publish Waiting before any reentrant completion can make this thread Ready.
            thread_wait_state_park_badge_waiting(nt_handler, pending.badge);
        }
        Some(PublishedFileIo {
            slot,
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
        }
        None
    };

    if nt_handler.current_synchronous_file_lock != 0 {
        // No accepted pending IRP exists: inline completion (including dispatch refusal) has
        // already settled the operation. Retire its existing Busy/reference before any exit.
        let file_id = core::mem::replace(&mut nt_handler.current_synchronous_file_lock, 0);
        synchronous_file_release_and_wake(nt_handler, file_id, nt_handler.current_tid);
        nt_handler.release_file_reference(file_id);
    }
    if let Some(owner) = published.as_ref().filter(|_| terminating) {
        // The current main Reply was never transferred. Post-action teardown deletes it; the
        // published File owner instead retains real cancellation/completion and Busy retirement.
        // CREATE deliberately continues through the existing specialized unpublished-handle path.
        nt_handler.abandon_new_file_io_exact(owner.slot, owner.irp_id);
    }
    published
}
