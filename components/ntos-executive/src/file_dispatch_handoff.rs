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
        let reservation = if let Some(primary) = nt_handler.pending_basic_primary_reservation.take() {
            PendingFileTransferClaim::Basic(primary)
        } else {
            PendingFileTransferClaim::Ordinary(nt_handler.pending_file_io_reservation
                .expect("accepted File IRP has no pre-dispatch reservation"))
        };
        // The caller is inside IoCallDriver until the driver returns (#427): a kept or queued
        // dispatch parks even an asynchronous caller, which only a STATUS_PENDING return frees.
        let in_flight = matches!(pending.route, nt_io_manager::PendingFileRoute::Hosted(_))
            && driver_launch::hosted_dispatch_progress(pending.irp_id)
                == Some(nt_hosted_runtime::DispatchProgress::InFlight);
        let wait_for_completion =
            nt_hosted_runtime::parks_file_caller(nt_handler.pending_file_io_wait, in_flight)
                && !terminating;
        let async_in_flight = in_flight && !nt_handler.pending_file_io_wait && !terminating;
        // The source remains in the handler until publication succeeds. Continuing synchronous
        // calls attach their reply in this same commit, never exposing an unarmed delivery row.
        let local_terminal = pending.owned_terminal_result().is_some()
            || pending.operation.is_owned_work_uncommitted();
        if let Some(event) = nt_handler.current_file_transfer_event.take() {
            assert!(pending.transfer_event.is_none());
            assert!(pending.event_obj_idx == u64::MAX || pending.event_obj_idx == event.native_identity);
            pending.transfer_event = Some(event);
        }
        let identity = pending_file_io_transfer(
            pending,
            wait_for_completion,
            reservation,
            nt_handler.pending_basic_prepared_transfer.take(),
            nt_handler.pending_basic_sidecar_reservation.take(),
            nt_handler.pending_basic_reply_reservation.take(),
            native_call_transport,
            resume_ip,
            sp,
            flags,
        );
        let published_pending = (&*core::ptr::addr_of!(PENDING_FILE_IO))
            .get_exact(identity)
            .expect("published File handoff lost its exact owner");
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
            thread_wait_state_park_badge_waiting(nt_handler, published_pending.badge);
        }
        if async_in_flight {
            hold_async_in_flight(identity, published_pending.irp_id);
        }
        super::pending_pipe_read_trace::parked(
            nt_handler, identity, published_pending, wait_for_completion,
        );
        super::mounted_read_lifetime_trace::parked(nt_handler, identity, published_pending);
        super::mounted_installer_file_trace::parked(nt_handler, identity, published_pending);
        Some(PublishedFileIo {
            identity,
            irp_id: published_pending.irp_id,
            badge: published_pending.badge,
            tid: published_pending.tid,
            wait_for_completion,
        })
    } else {
        assert!(nt_handler.pending_basic_prepared_transfer.is_none(),
            "unpublished Basic File owner lost its delivery row");
        if let Some(reply) = nt_handler.pending_basic_reply_reservation.take() {
            assert!(reply.cancel_no_effects(),
                "unused Basic Reply replacement lost its no-effect lease");
        }
        if let Some(sidecar) = nt_handler.pending_basic_sidecar_reservation.take() {
            assert!((&mut *core::ptr::addr_of_mut!(PENDING_BASIC_PREPARED))
                .cancel_admission(sidecar));
        }
        if let Some(primary) = nt_handler.pending_basic_primary_reservation.take() {
            let identity = primary.identity();
            assert!((&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                .cancel_basic_primary(primary));
            crate::pending_file_caller::cancel_reserved_identity(identity);
        }
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

/// Asynchronous callers parked only because their dispatch was still in flight (#427).
static mut ASYNC_IN_FLIGHT: nt_hosted_runtime::InFlightCallers<nt_io_manager::PendingFileIoIdentity> =
    nt_hosted_runtime::InFlightCallers::new();

/// `[inflight-caller]` stages (#427): held, released with STATUS_PENDING, released to its
/// completion's ordinary delivery, and a reply that could not be sent yet.
const INFLIGHT_STAGES: [&[u8]; 4] =
    [b"held", b"released-pending", b"released-completion", b"reply-retry"];
static INFLIGHT_COUNTS: [AtomicU64; 4] =
    [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];

/// Bounded evidence of an asynchronous caller held while its dispatch was in flight: each
/// stage's first sightings and then powers of two, totals in the census; a retry always prints.
fn trace_inflight_caller(stage: usize, identity: nt_io_manager::PendingFileIoIdentity, irp_id: u64) {
    let n = INFLIGHT_COUNTS[stage].fetch_add(1, Ordering::Relaxed) + 1;
    if stage != 3 && n > 16 && !n.is_power_of_two() { return; }
    print_str(b"[inflight-caller] stage=");
    print_str(INFLIGHT_STAGES[stage]);
    print_str(b" n="); print_u64(n);
    print_str(b" slot/generation/irp="); print_u64(identity.slot() as u64); print_str(b"/");
    print_u64(identity.generation()); print_str(b"/"); print_hex_u64(irp_id);
    print_str(b"\n");
}

/// Census totals of held and released asynchronous in-flight callers (#427).
pub(super) fn print_inflight_caller_census() {
    let counts: [u64; 4] = core::array::from_fn(|stage| INFLIGHT_COUNTS[stage].load(Ordering::Relaxed));
    if counts.iter().all(|count| *count == 0) { return; }
    print_str(b"[inflight-caller-census] held/released-pending/released-completion/reply-retry=");
    for (index, count) in counts.iter().enumerate() {
        if index != 0 { print_str(b"/"); }
        print_u64(*count);
    }
    print_str(b"\n");
}

fn hold_async_in_flight(identity: nt_io_manager::PendingFileIoIdentity, irp_id: u64) {
    trace_inflight_caller(0, identity, irp_id);
    let _durable = crate::allocator::enter_durable();
    unsafe { (*core::ptr::addr_of_mut!(ASYNC_IN_FLIGHT)).hold(identity, irp_id) };
}

/// The hosted dispatch of `irp_id` returned to its File owner, pending or completed.
pub(super) fn dispatch_returned(irp_id: u64) {
    let callers = unsafe { &mut *core::ptr::addr_of_mut!(ASYNC_IN_FLIGHT) };
    if callers.held() != 0 && callers.dispatch_returned(irp_id) {
        FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
    }
}

/// Release each held asynchronous caller whose driver has returned. A STATUS_PENDING return
/// replies STATUS_PENDING now and leaves the row to deliver the completion through the IOSB,
/// Event, APC or IOCP; a completed IRP is replied with its own status by ordinary delivery.
/// Only callers readied by a return are visited; with none ready this does nothing.
pub(super) unsafe fn release_returned_async_callers(nt_handler: &mut ExecNtHandler) -> usize {
    let callers = &mut *core::ptr::addr_of_mut!(ASYNC_IN_FLIGHT);
    if !callers.any_ready() { return 0; }
    let _durable = crate::allocator::enter_durable();
    let mut released = 0;
    for (identity, irp_id) in callers.take_ready() {
        let Some(pending) = (&*core::ptr::addr_of!(PENDING_FILE_IO)).get_exact(identity)
            .filter(|pending| pending.irp_id == irp_id)
        else { continue };
        let progress = driver_launch::hosted_dispatch_progress(irp_id)
            .unwrap_or(nt_hosted_runtime::DispatchProgress::Completed);
        match nt_hosted_runtime::in_flight_caller_reply(false, progress) {
            // Returned but not yet settled: the settling transition readies it again.
            nt_hosted_runtime::InFlightReply::Hold => callers.hold(identity, irp_id),
            nt_hosted_runtime::InFlightReply::Completion => trace_inflight_caller(2, identity, irp_id),
            nt_hosted_runtime::InFlightReply::Pending => {
                let slot = identity.slot();
                let Some(Some(cap)) = (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .claim_reply_cap_exact(slot, irp_id)
                else { continue };
                if !reply_parked_syscall(cap, nt_status::NtStatus::PENDING.raw() as u32 as u64) {
                    (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                        .restore_reply_cap_exact(slot, irp_id, cap)
                        .expect("in-flight File reply lost its exact capability owner");
                    callers.retry(identity, irp_id);
                    trace_inflight_caller(3, identity, irp_id);
                    FILE_IO_DELIVERY_RETRY_PENDING.store(true, Ordering::Release);
                    continue;
                }
                (&mut *core::ptr::addr_of_mut!(PENDING_FILE_IO))
                    .mark_reply_published_exact(slot, irp_id)
                    .expect("in-flight File reply publication owner disappeared");
                release_reply_pool_cap(cap);
                thread_wait_state_clear_badge_ready(nt_handler, pending.badge);
                trace_inflight_caller(1, identity, irp_id);
                released += 1;
            }
        }
    }
    released
}
