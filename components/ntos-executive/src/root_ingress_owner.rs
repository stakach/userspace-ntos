//! Durable, move-only handoff of one selected root Call and its held nested parent.
//!
//! This row is dormant until lane admission and original root Reply parking can be completed
//! together. Its numeric root Reply is only a captured selector: the later admission must
//! revalidate REPLY_MAIN_SLOT, exact pool identity and physical binding before any effect.

use super::*;
use nt_user_host::root_ingress_handoff::{
    RootIngressHandoffKey, RootIngressHandoffReservation, RootIngressHandoffTable,
    RootIngressHandoffTicket,
};
use nt_component_suspension::{ReplyBindingObservation, RootReplyIdentity, RootReplySlotState};

/// An observed original root Reply, authenticated again immediately before any park effect.
#[allow(dead_code)]
pub(crate) struct RootReplyAuthority {
    reply: u64,
    identity: RootReplyIdentity,
    binding: nt_user_host::thread_binding::ThreadBinding<HostedThreadRole>,
}

#[allow(dead_code)]
pub(crate) enum Bundle {
    Unbound {
        taken: win32k_glue::TakenRootIngressDispatch,
        authority: RootReplyAuthority,
        child_snapshot: crate::spawn_hosts::shared_ingress::owner::runtime::PendingSnapshot,
    },
    UnwindPrepared(UnwindRootIngress),
    RestoredProof(RestoredRouteProof),
    RestoredCancelled(RestoredRouteOwner),
    BoundUnadmitted(BoundRootIngress),
    AdmittedUnparked(AdmittedRootIngress),
    Parked(AdmittedRootIngress),
}

#[allow(dead_code)]
pub(crate) struct BoundRootIngress {
    pending: win32k_glue::PendingRootIngressDispatch,
    authority: RootReplyAuthority,
    child_snapshot: crate::spawn_hosts::shared_ingress::owner::runtime::PendingSnapshot,
    admission: nt_component_suspension::ExternalAdmissionKey,
    parent: nt_component_suspension::NestedExecutionIdentity,
}

#[allow(dead_code)]
pub(crate) struct UnwindRootIngress {
    pending: win32k_glue::PendingRootIngressDispatch,
    authority: RootReplyAuthority,
    child_snapshot: crate::spawn_hosts::shared_ingress::owner::runtime::PendingSnapshot,
    admission: nt_component_suspension::ExternalAdmissionKey,
    parent: Option<crate::spawn_hosts::shared_ingress::owner::runtime::nested::ParkedParentHandle>,
    restore_entered: bool,
}

#[allow(dead_code)]
pub(crate) struct RestoredRouteOwner {
    pending: win32k_glue::PendingRootIngressDispatch,
    authority: RootReplyAuthority,
    child_snapshot: crate::spawn_hosts::shared_ingress::owner::runtime::PendingSnapshot,
    admission: nt_component_suspension::ExternalAdmissionKey,
    parent: nt_component_suspension::NestedExecutionIdentity,
}

#[allow(dead_code)]
pub(crate) struct RestoredRouteProof {
    owner: RestoredRouteOwner,
    proof: crate::spawn_hosts::shared_ingress::owner::runtime::nested::RestoredBeforeChildProof,
}

#[allow(dead_code)]
pub(crate) struct AdmittedRootIngress {
    bound: BoundRootIngress,
    key: nt_component_suspension::SuspensionKey,
    sequence: u64,
    owner: nt_component_suspension::SuspensionOwner,
}

static mut OWNERS: RootIngressHandoffTable<Bundle> = RootIngressHandoffTable::new();

/// Capture before taking the selected pending slot. The child's Reply is separate from this
/// delivered parent's Reply; a numeric match without pool generation and TCB binding is refused.
#[allow(dead_code)]
pub(crate) unsafe fn capture_root_reply_authority(reply: u64) -> Option<RootReplyAuthority> {
    if reply == 0 || REPLY_MAIN_SLOT.load(Ordering::Relaxed) != reply { return None; }
    let identity = wait_reply_pool_ref().find_cap(reply)?;
    if wait_reply_pool_ref().state(identity).ok() != Some(RootReplySlotState::Used) {
        return None;
    }
    let binding = crate::spawn_hosts::shared_ingress::owner::runtime
        ::parkable_hosted_reply_binding(reply)?;
    if crate::spawn_hosts::query_component_reply_binding(binding.tcb, reply)
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        return None;
    }
    Some(RootReplyAuthority { reply, identity, binding })
}

/// A fresh observation must still identify the same pool incarnation and hosted caller.
#[allow(dead_code)]
pub(crate) unsafe fn root_reply_authority_is_live(authority: &RootReplyAuthority) -> bool {
    capture_root_reply_authority(authority.reply).is_some_and(|current| {
        current.identity == authority.identity && current.binding == authority.binding
    })
}

fn same_child_snapshot(
    left: crate::spawn_hosts::shared_ingress::owner::runtime::PendingSnapshot,
    right: crate::spawn_hosts::shared_ingress::owner::runtime::PendingSnapshot,
) -> bool {
    left.binding == right.binding && left.reply == right.reply
        && left.executor == right.executor
        && left.admission_sequence == right.admission_sequence
        && left.info == right.info && left.registers == right.registers
}

#[allow(dead_code)]
pub(crate) unsafe fn reserve_capacity() -> Option<RootIngressHandoffReservation> {
    let _durable = allocator::enter_durable();
    (&mut *core::ptr::addr_of_mut!(OWNERS)).reserve().ok()
}

#[allow(dead_code)]
pub(crate) unsafe fn cancel_reservation(reservation: RootIngressHandoffReservation) -> bool {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).cancel_reservation(reservation)
}

/// Check the pending copy against its move-only physical parent before storing either. The
/// supplied root Reply is not authenticated here; this is durable storage, not lane admission.
/// Refusal returns the complete bundle, and the reservation remains available for cancellation.
#[allow(dead_code)]
pub(crate) unsafe fn retain(
    reservation: RootIngressHandoffReservation,
    taken: win32k_glue::TakenRootIngressDispatch,
    authority: RootReplyAuthority,
) -> Result<RootIngressHandoffTicket, (win32k_glue::TakenRootIngressDispatch, RootReplyAuthority)> {
    let win32k_glue::RootIngressYield::ParkedUnbound { ticket, child, owner, .. } = taken.pending.yielded
    else { return Err((taken, authority)) };
    let parent_identity = taken.parent.identity();
    let snapshot = taken.pending.snapshot;
    if ticket != taken.parent.ticket()
        || parent_identity.dispatch().lane() != snapshot.dispatch.lane
        || snapshot.callback_token.is_some()
        || snapshot.pump.reply_cap == 0
        || owner.dispatch_id != snapshot.dispatch.dispatch_id
        || !crate::spawn_hosts::shared_ingress::owner::runtime::nested
            ::undelivered_root_parent_candidate(&taken.parent, child)
        || !crate::spawn_hosts::shared_ingress::owner::runtime
            ::prepared_root_ingress_child_is_current(child)
        || child.reply() == authority.reply
        || !root_reply_authority_is_live(&authority)
    {
        return Err((taken, authority));
    }
    let Some(key) = RootIngressHandoffKey::new(parent_identity, child, authority.reply) else {
        return Err((taken, authority));
    };
    let Some(child_snapshot) = crate::spawn_hosts::shared_ingress::owner::runtime
        ::prepared_root_ingress_snapshot(child) else {
        return Err((taken, authority));
    };
    (&mut *core::ptr::addr_of_mut!(OWNERS))
        .retain(reservation, key, Bundle::Unbound { taken, authority, child_snapshot })
        .map_err(|(_, bundle)| match bundle {
            Bundle::Unbound { taken, authority, .. } => (taken, authority),
            Bundle::UnwindPrepared(_) | Bundle::RestoredProof(_)
                | Bundle::RestoredCancelled(_) | Bundle::BoundUnadmitted(_)
                | Bundle::AdmittedUnparked(_) | Bundle::Parked(_) =>
                unreachable!("fresh retention is unbound"),
        })
}

/// Memory-only one-shot bind. A refused bind returns the complete parent to this exact row;
/// after a positive bind CALLS owns the parent and this row retains the saved pump and Reply
/// authority for lane admission. No provider call or Reply park is allowed inside this step.
#[allow(dead_code)]
pub(crate) unsafe fn bind_prepared(
    ticket: RootIngressHandoffTicket,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime::Error;
    let result = (&mut *core::ptr::addr_of_mut!(OWNERS)).transition_held(ticket, |bundle| {
        let Bundle::Unbound { taken, authority, child_snapshot } = bundle else {
            return Err((Error::Admission, bundle));
        };
        let win32k_glue::TakenRootIngressDispatch { pending, parent } = taken;
        let win32k_glue::RootIngressYield::ParkedUnbound { child, .. } = pending.yielded else {
            return Err((Error::Admission, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent }, authority, child_snapshot,
            }));
        };
        if ticket.key().parent() != parent.identity()
            || ticket.key().child() != child
            || ticket.key().root_reply() != authority.reply
            || !root_reply_authority_is_live(&authority)
        {
            return Err((Error::Admission, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent }, authority, child_snapshot,
            }));
        }
        let parent_identity = parent.identity();
        let Some(snapshot) = crate::spawn_hosts::shared_ingress::owner::runtime
            ::prepared_root_ingress_snapshot(child) else {
            return Err((Error::Admission, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent }, authority, child_snapshot,
            }));
        };
        if !same_child_snapshot(snapshot, child_snapshot) {
            return Err((Error::Admission, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent }, authority,
                child_snapshot,
            }));
        }
        match crate::spawn_hosts::shared_ingress::owner::runtime::bind_root_ingress_pass(
            snapshot, parent, dispatch,
        ) {
            Ok(()) => Ok(Bundle::BoundUnadmitted(BoundRootIngress {
                pending, authority, child_snapshot, admission: child, parent: parent_identity,
            })),
            Err((error, parent)) => Err((error, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent }, authority, child_snapshot,
            })),
        }
    });
    result.map_err(|error| match error {
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::StaleTicket => Error::Admission,
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::Refused(error) => error,
    })
}

/// Observational route gate for the exact still-undelivered child. The runtime service table
/// is supplied by the serialized outer dispatcher, so no SSN or process identity is copied
/// into this owner. Unsupported and changed routes leave both retained owners untouched.
#[allow(dead_code)]
pub(crate) unsafe fn preflight_selected_read(
    ticket: RootIngressHandoffTicket,
    handler: &crate::ExecNtHandler,
    table: &nt_syscall::NativeServiceTable,
) -> crate::exec_handler::RootIngressReadPreflight {
    use crate::exec_handler::RootIngressReadPreflight;
    let Some(Bundle::Unbound { taken, authority, .. }) =
        (&*core::ptr::addr_of!(OWNERS)).get(ticket)
    else { return RootIngressReadPreflight::Changed };
    let win32k_glue::RootIngressYield::ParkedUnbound { child, .. } = taken.pending.yielded
    else { return RootIngressReadPreflight::Changed };
    if ticket.key().child() != child
        || ticket.key().parent() != taken.parent.identity()
        || ticket.key().root_reply() != authority.reply
        || !root_reply_authority_is_live(authority)
        || !crate::spawn_hosts::shared_ingress::owner::runtime::nested
            ::undelivered_root_parent_candidate(&taken.parent, child)
    {
        return RootIngressReadPreflight::Changed;
    }
    let request = match crate::spawn_hosts::shared_ingress::owner::runtime
        ::selected_root_read_request(child, table)
    {
        crate::spawn_hosts::shared_ingress::owner::runtime::SelectedRootReadRequestOutcome
            ::Accepted(request) => request,
        crate::spawn_hosts::shared_ingress::owner::runtime::SelectedRootReadRequestOutcome
            ::Unsupported => return RootIngressReadPreflight::Unsupported,
        crate::spawn_hosts::shared_ingress::owner::runtime::SelectedRootReadRequestOutcome
            ::Changed => return RootIngressReadPreflight::Changed,
    };
    match handler.root_ingress_read_preflight(request.binding, request.handle, None) {
        RootIngressReadPreflight::Accepted(observed)
            if observed.mode == nt_io_completion::FileIoMode::Asynchronous => {
                RootIngressReadPreflight::Unsupported
            }
        outcome => outcome,
    }
}

/// Seal a refused, still-undelivered child before any physical parent restore. A CALLS-side
/// preflight refusal may have sealed the pass already; retrying this exact handoff is harmless.
#[allow(dead_code)]
pub(crate) unsafe fn begin_route_refusal_unwind(
    ticket: RootIngressHandoffTicket,
    handler: &crate::ExecNtHandler,
    table: &nt_syscall::NativeServiceTable,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::exec_handler::RootIngressReadPreflight;
    use crate::spawn_hosts::shared_ingress::owner::runtime::{self, Error};
    if matches!(preflight_selected_read(ticket, handler, table), RootIngressReadPreflight::Accepted(_)) {
        return Err(Error::Admission);
    }
    let result = (&mut *core::ptr::addr_of_mut!(OWNERS)).transition_held(ticket, |bundle| {
        let Bundle::Unbound { taken, authority, child_snapshot } = bundle else {
            return Err((Error::Admission, bundle));
        };
        let win32k_glue::TakenRootIngressDispatch { pending, parent } = taken;
        let win32k_glue::RootIngressYield::ParkedUnbound { child, .. } = pending.yielded else {
            return Err((Error::Admission, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent },
                authority, child_snapshot,
            }));
        };
        if ticket.key().child() != child || ticket.key().parent() != parent.identity()
            || ticket.key().root_reply() != authority.reply
            || child_snapshot.reply != child.reply()
            || child_snapshot.executor != child.executor()
            || child_snapshot.admission_sequence != child.admission_sequence()
            || !root_reply_authority_is_live(&authority)
        {
            return Err((Error::Admission, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent },
                authority, child_snapshot,
            }));
        }
        match runtime::begin_undelivered_root_unwind(child_snapshot, &parent) {
            Ok(()) => Ok(Bundle::UnwindPrepared(UnwindRootIngress {
                pending, authority, child_snapshot, admission: child,
                parent: Some(parent), restore_entered: false,
            })),
            Err(error) => Err((error, Bundle::Unbound {
                taken: win32k_glue::TakenRootIngressDispatch { pending, parent },
                authority, child_snapshot,
            })),
        }
    });
    result.map_err(|error| match error {
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::StaleTicket => Error::Admission,
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::Refused(error) => error,
    })
}

/// PARENTS retains the exact scope and one-shot token on every physical refusal. An uncertain
/// effect is never replayed: only a positive RestorePending ticket permits a later attempt.
#[allow(dead_code)]
pub(crate) unsafe fn restore_route_refusal_parent(
    ticket: RootIngressHandoffTicket,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime::{nested, Error};
    let result = (&mut *core::ptr::addr_of_mut!(OWNERS)).transition_held(ticket, |bundle| {
        let Bundle::UnwindPrepared(mut unwind) = bundle else {
            return Err((Error::Admission, bundle));
        };
        let Some(parent) = unwind.parent.as_ref() else {
            return Err((Error::Admission, Bundle::UnwindPrepared(unwind)));
        };
        if ticket.key().child() != unwind.admission
            || ticket.key().parent() != parent.identity()
            || ticket.key().root_reply() != unwind.authority.reply
            || (unwind.restore_entered
                && !nested::pending_undelivered_root_ticket(parent.ticket())
                && !nested::parked_undelivered_root_ticket(parent.ticket()))
        {
            return Err((Error::Admission, Bundle::UnwindPrepared(unwind)));
        }
        let expected_parent = parent.identity();
        unwind.restore_entered = true;
        match nested::restore_undelivered_root(&mut unwind.parent) {
            Ok(proof) => Ok(Bundle::RestoredProof(RestoredRouteProof {
                owner: RestoredRouteOwner {
                    pending: unwind.pending, authority: unwind.authority,
                    child_snapshot: unwind.child_snapshot, admission: unwind.admission,
                    parent: expected_parent,
                },
                proof,
            })),
            Err(error) => Err((error, Bundle::UnwindPrepared(unwind))),
        }
    });
    result.map_err(|error| match error {
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::StaleTicket => Error::Admission,
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::Refused(error) => error,
    })
}

/// Only the positive move-only restore receipt can cancel the prepared child pass. A refusal
/// returns that receipt to this row, and the original child Call stays in CALLS.
#[allow(dead_code)]
pub(crate) unsafe fn cancel_route_refusal_child(
    ticket: RootIngressHandoffTicket,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime::{self, Error};
    let result = (&mut *core::ptr::addr_of_mut!(OWNERS)).transition_held(ticket, |bundle| {
        let Bundle::RestoredProof(restored) = bundle else {
            return Err((Error::Admission, bundle));
        };
        let RestoredRouteProof { owner, proof } = restored;
        if ticket.key().child() != owner.admission
            || ticket.key().parent() != owner.parent
            || ticket.key().root_reply() != owner.authority.reply
            || proof.admission_key() != owner.admission
            || proof.parent() != owner.parent
            || proof.child() != owner.child_snapshot.binding
        {
            return Err((Error::Admission, Bundle::RestoredProof(RestoredRouteProof { owner, proof })));
        }
        match runtime::cancel_restored_undelivered_root_pass(owner.child_snapshot, proof) {
            Ok(()) => Ok(Bundle::RestoredCancelled(owner)),
            Err((error, proof)) => Err((error,
                Bundle::RestoredProof(RestoredRouteProof { owner, proof }))),
        }
    });
    result.map_err(|error| match error {
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::StaleTicket => Error::Admission,
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::Refused(error) => error,
    })
}

/// One ticket advances the exact retained route refusal. After any refusal the caller may
/// invoke this again; the row chooses the next stage and never replays an uncertain restore.
#[allow(dead_code)]
pub(crate) unsafe fn unwind_unbound_route_refusal(
    ticket: RootIngressHandoffTicket,
    handler: &crate::ExecNtHandler,
    table: &nt_syscall::NativeServiceTable,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime::Error;
    if matches!((&*core::ptr::addr_of!(OWNERS)).get(ticket), Some(Bundle::Unbound { .. })) {
        begin_route_refusal_unwind(ticket, handler, table)?;
    }
    if matches!((&*core::ptr::addr_of!(OWNERS)).get(ticket), Some(Bundle::UnwindPrepared(_))) {
        restore_route_refusal_parent(ticket)?;
    }
    if matches!((&*core::ptr::addr_of!(OWNERS)).get(ticket), Some(Bundle::RestoredProof(_))) {
        cancel_route_refusal_child(ticket)?;
    }
    if matches!((&*core::ptr::addr_of!(OWNERS)).get(ticket), Some(Bundle::RestoredCancelled(_))) {
        Ok(())
    } else {
        Err(Error::Admission)
    }
}

/// Admit the exact bound child once. A pure lane refusal returns its continuation before any
/// frame mutation; BoundUnadmitted remains durable for a ticket-only retry after the old pending
/// slot has been cleared. Successful admission records the exact frame before Reply effects.
#[allow(dead_code)]
pub(crate) unsafe fn admit_bound_root_ingress(
    ticket: RootIngressHandoffTicket,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime::{self, Error};
    let result = (&mut *core::ptr::addr_of_mut!(OWNERS)).transition_held(ticket, |bundle| {
        let Bundle::BoundUnadmitted(bound) = bundle else {
            return Err((Error::Admission, bundle));
        };
        let win32k_glue::RootIngressYield::ParkedUnbound { child, owner, .. } = bound.pending.yielded
        else { return Err((Error::Admission, Bundle::BoundUnadmitted(bound))) };
        if ticket.key().child() != child || ticket.key().parent() != bound.parent
            || ticket.key().root_reply() != bound.authority.reply
            || bound.admission != child
            || owner.dispatch_id != bound.pending.snapshot.dispatch.dispatch_id
            || !root_reply_authority_is_live(&bound.authority)
        {
            return Err((Error::Admission, Bundle::BoundUnadmitted(bound)));
        }
        let key = nt_component_suspension::SuspensionKey::root_ingress(child.admission_sequence());
        let sequence = crate::next_dispatcher_wait_sequence();
        let continuation = ComponentNativeContinuation::RootIngress(ticket);
        let admitted = runtime::with_bound_root_ingress_scope(child, bound.parent, |scope| {
            let lanes = &mut *core::ptr::addr_of_mut!(COMPONENT_SUSPENSIONS);
            Ok(lanes.admit_root_ingress_owned(
                scope, key, sequence, owner, child, continuation,
            ))
        });
        match admitted {
            Ok(Ok(())) => Ok(Bundle::AdmittedUnparked(AdmittedRootIngress {
                bound, key, sequence, owner,
            })),
            Ok(Err((_, ComponentNativeContinuation::RootIngress(returned))))
                if returned == ticket => Err((Error::Admission, Bundle::BoundUnadmitted(bound))),
            Ok(Err(_)) | Err(_) => Err((Error::Admission, Bundle::BoundUnadmitted(bound))),
        }
    });
    result.map_err(|error| match error {
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::StaleTicket => Error::Admission,
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::Refused(error) => error,
    })
}

/// A refusal retains the admitted frame and retries only this original root Reply park. The
/// positive native commit is followed by an infallible in-row Parked transition in this turn.
#[allow(dead_code)]
pub(crate) unsafe fn park_admitted_root_reply(
    ticket: RootIngressHandoffTicket,
) -> Result<(), crate::spawn_hosts::shared_ingress::owner::runtime::Error> {
    use crate::spawn_hosts::shared_ingress::owner::runtime::Error;
    let result = (&mut *core::ptr::addr_of_mut!(OWNERS)).transition_held(ticket, |bundle| {
        let Bundle::AdmittedUnparked(admitted) = bundle else {
            return Err((Error::Admission, bundle));
        };
        let bound = &admitted.bound;
        if crate::spawn_hosts::shared_ingress::owner::runtime
            ::with_bound_root_ingress_scope(bound.admission, bound.parent, |_| Ok(())).is_err()
        {
            return Err((Error::Admission, Bundle::AdmittedUnparked(admitted)));
        }
        let lane = bound.parent.dispatch().lane();
        let frame_is_exact = (&*core::ptr::addr_of!(COMPONENT_SUSPENSIONS))
            .top(lane).ok().flatten().is_some_and(|frame| {
                frame.key == admitted.key
                    && frame.admission_sequence == admitted.sequence
                    && frame.owner == admitted.owner
                    && matches!(frame.phase, nt_component_suspension::SuspensionPhase::Waiting)
                    && matches!(frame.continuation,
                        ComponentNativeContinuation::RootIngress(retained) if retained == ticket)
            });
        if !frame_is_exact || ticket.key().child() != bound.admission
            || ticket.key().parent() != bound.parent
            || ticket.key().root_reply() != bound.authority.reply
            || !root_reply_authority_is_live(&bound.authority)
        {
            return Err((Error::Admission, Bundle::AdmittedUnparked(admitted)));
        }
        let Some(park) = super::root_reply_park::RootReplyPark
            ::prepare_exact_hosted(bound.authority.reply) else {
            return Err((Error::Reply, Bundle::AdmittedUnparked(admitted)));
        };
        if !root_reply_authority_is_live(&bound.authority) {
            return Err((Error::Reply, Bundle::AdmittedUnparked(admitted)));
        }
        match park.try_commit() {
            Ok(()) => Ok(Bundle::Parked(admitted)),
            Err(_) => Err((Error::Reply, Bundle::AdmittedUnparked(admitted))),
        }
    });
    result.map_err(|error| match error {
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::StaleTicket => Error::Admission,
        nt_user_host::root_ingress_handoff::RootIngressTransitionError::Refused(error) => error,
    })
}

/// The exact ticket may lend its bundle to a later lane transfer. A refused transfer must
/// return the same bundle to this row; neither operation changes a physical Reply.
#[allow(dead_code)]
pub(crate) unsafe fn take(ticket: RootIngressHandoffTicket) -> Option<Bundle> {
    let owners = &mut *core::ptr::addr_of_mut!(OWNERS);
    if !matches!(owners.get(ticket), Some(Bundle::Parked(_))) { return None; }
    owners.take(ticket)
}

#[allow(dead_code)]
pub(crate) unsafe fn restore(
    ticket: RootIngressHandoffTicket,
    taken: Bundle,
) -> Result<(), Bundle> {
    (&mut *core::ptr::addr_of_mut!(OWNERS)).restore(ticket, taken)
}
