//! Hosted-user Calls retain independent thread identity beside component dispatch ownership.

use super::*;
use core::sync::atomic::Ordering;
use nt_component_suspension::{ExternalAdmissionKey, ExternalIngress, ReplyBindingObservation};
type Binding = nt_user_host::thread_binding::ThreadBinding<crate::HostedThreadRole>;

struct ReceiveSettlement {
    barrier: nt_user_host::receive_child_barrier::ReceiveChildBarrier<crate::HostedThreadRole>,
    observation: crate::win32k_glue::ReceiveFaultCapture,
    provider_tcb: u64,
    provider_pml4: u64,
    // Copied at admission for diagnostics only; the barrier owns restoration authority.
    trace_owner: nt_component_suspension::SuspensionOwner,
    parent: Option<super::nested::ParkedParentHandle>,
    transferred: bool,
    rejected: Option<nt_component_suspension::ExternalSettlement>,
}

/// Prepared before the physical hold, then bound to its exact retained parent after parking.
/// This owner has no delivery or restore authority until the event checkpoint is installed.
struct RootIngressOwner {
    pass: nt_user_host::root_ingress_pass::RootIngressPass<crate::HostedThreadRole>,
    parent: Option<super::nested::ParkedParentHandle>,
    /// The exact unbound physical parent, retained through pre-effect refusal and cancellation.
    undelivered_parent: Option<nt_component_suspension::NestedExecutionIdentity>,
    /// Sealed before parent unwind; moves into PARENTS before any restore effect.
    undelivered: Option<nt_user_host::root_ingress_pass::UndeliveredRootIngress<crate::HostedThreadRole>>,
    /// Only a positive physical restore receipt clears the provider-selection exclusion.
    restored: Option<nt_user_host::root_ingress_pass::RootIngressRestored<crate::HostedThreadRole>>,
    /// A positive Free receipt that could not be consumed by the pre-restore pass. The later
    /// result owner may take it only under the same physical child and admission.
    unconsumed_settlement: Option<nt_component_suspension::ExternalSettlement>,
}

/// Single-use outer-loop delivery. The parent row already retains the sealed settlement permit.
pub(crate) struct ReceiveSettlementBoundary {
    pub(crate) parent: Option<super::nested::ParkedParentHandle>,
}

#[derive(Clone, Copy)]
pub(crate) struct ReceiveChildObservation {
    pub observation: crate::win32k_glue::ReceiveFaultCapture,
    pub parent: nt_component_suspension::NestedExecutionIdentity,
    pub child: nt_component_suspension::ExternalAdmissionKey,
    pub provider_tcb: u64,
    pub provider_pml4: u64,
    pub trace_owner: nt_component_suspension::SuspensionOwner,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Completion {
    Acknowledged,
    Cancelled,
    Restarted,
}

struct HostedCall {
    binding: Binding,
    call: Option<ExternalIngress<ReceivedMessage>>,
    delivered: bool,
    recycled: Option<ComponentIngress<ReceivedMessage>>,
    completion: Option<Completion>,
    released: bool,
    receive_settlement: Option<ReceiveSettlement>,
    root_ingress: Option<RootIngressOwner>,
}
static mut CALLS: Vec<Option<HostedCall>> = Vec::new();

#[derive(Clone, Copy, Debug)]
pub(crate) struct PendingSnapshot {
    pub binding: Binding,
    pub reply: u64,
    pub executor: u64,
    pub admission_sequence: u64,
    pub info: u64,
    pub registers: [u64; 4],
}

pub(super) unsafe fn oldest_pending_snapshot() -> Option<PendingSnapshot> {
    let rows = &*core::ptr::addr_of!(CALLS);
    let index = nt_component_suspension::oldest_receive_external_ingress(
        rows.iter().enumerate().filter_map(|(index, row)| {
            let row = row.as_ref()?;
            row.call
                .as_ref()
                .map(|call| (index, call, nt_component_suspension::ExternalReceiveState {
                    delivered: row.delivered,
                    released: row.released,
                    settlement_prepared: row.receive_settlement.is_some(),
                }))
        }),
    )?;
    let row = rows[index].as_ref()?;
    let call = row.call.as_ref()?;
    let message = call.message();
    Some(PendingSnapshot {
        binding: row.binding,
        reply: call.reply(),
        executor: call.executor(),
        admission_sequence: call.admission_sequence(),
        info: message.info(),
        registers: message.registers(),
    })
}

/// Read-only gate state for a retained hosted Call at a periodic boot census.
#[derive(Clone, Copy, Debug)]
pub(crate) struct DeliveryGateSnapshot {
    pub journal_owned: bool,
    pub receive_child_pending: bool,
    pub oldest_can_park: Option<bool>,
    pub oldest_settlement_prepared: Option<bool>,
    pub pending_calls: usize,
}

pub(crate) unsafe fn delivery_gate_snapshot() -> DeliveryGateSnapshot {
    let rows = &*core::ptr::addr_of!(CALLS);
    let oldest = oldest_pending_snapshot();
    let oldest_row = oldest.and_then(|snapshot| {
        rows.iter().flatten().find(|row| {
            row.binding == snapshot.binding
                && row.call.as_ref().is_some_and(|call| {
                    call.reply() == snapshot.reply
                        && call.admission_sequence() == snapshot.admission_sequence
                })
        })
    });
    DeliveryGateSnapshot {
        journal_owned: crate::writable_fs::registry_journal::owns_volume(),
        receive_child_pending: receive_child_pending(),
        oldest_can_park: oldest_row.and_then(|row| row.call.as_ref().map(ExternalIngress::can_park)),
        oldest_settlement_prepared: oldest_row.map(|row| row.receive_settlement.is_some()),
        pending_calls: rows.iter().flatten().filter(|row| {
            !row.delivered && !row.released && row.completion.is_none()
        }).count(),
    }
}
struct Cancellation {
    binding: Binding,
    reply: u64,
}
static mut CANCELLATIONS: Vec<Cancellation> = Vec::new();

pub(crate) unsafe fn hosted_cancellation_proven(badge: u64, reply: u64) -> bool {
    let Some(binding) = crate::service_sec_image::hosted_ingress_binding(badge) else {
        return false;
    };
    (&*core::ptr::addr_of!(CANCELLATIONS))
        .iter()
        .any(|cancelled| cancelled.binding == binding && cancelled.reply == reply)
}

pub(crate) unsafe fn hosted_can_resume(tcb: u64) -> bool {
    let stopped_call = (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .any(|row| {
            row.binding.tcb == tcb
                && row.call.as_ref().is_some_and(ExternalIngress::stop_started)
        });
    let cancelled = (&*core::ptr::addr_of!(CANCELLATIONS)).iter().any(|row| {
        row.binding.tcb == tcb
            && crate::service_sec_image::hosted_ingress_binding(row.binding.badge)
                == Some(row.binding)
    });
    !stopped_call && !cancelled
}

pub(super) unsafe fn retain(
    owner: &mut NativeSharedIngress,
    lanes: &ComponentLanes,
    badge: u64,
    probe: u64,
) -> Result<(), Error> {
    let binding =
        crate::service_sec_image::hosted_ingress_binding(badge).ok_or(Error::PhysicalIdentity)?;
    let records = &mut *core::ptr::addr_of_mut!(CALLS);
    let index = if let Some(index) = records.iter().position(Option::is_none) {
        index
    } else {
        let _durable = crate::allocator::enter_durable();
        records.try_reserve(1).map_err(|_| Error::Capacity)?;
        records.push(None);
        records.len() - 1
    };
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let call = owner
        .replacements
        .as_mut()
        .expect("ready pool")
        .retain_external(
            owner.receiver.as_mut().expect("ready receiver"),
            lanes,
            binding.tcb,
            |reply| crate::spawn_hosts::query_component_reply_binding(probe, reply),
            |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
        )
        .map_err(|_| Error::Retain)?;
    crate::registry_mutation_work::trace_next_hosted_call(
        binding, call.reply(), call.message().info(), call.message().registers()[0],
    );
    records[index] = Some(HostedCall {
        binding,
        call: Some(call),
        delivered: false,
        recycled: None,
        completion: None,
        released: false,
        receive_settlement: None,
        root_ingress: None,
    });
    Ok(())
}

pub(crate) unsafe fn take_hosted_with(
    import: impl FnOnce(u64, &ReceivedMessage) -> bool,
) -> Result<Option<(u64, ReceivedMessage)>, Error> {
    recycle_completed()?;
    if crate::writable_fs::registry_journal::owns_volume() {
        return Ok(None);
    }
    let pending_receive = receive_child_pending();
    let Some(index) = nt_component_suspension::oldest_external_ingress(
        (&*core::ptr::addr_of!(CALLS))
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                let row = row.as_ref()?;
                if row.delivered || row.released || row.completion.is_some() {
                    return None;
                }
                if row.root_ingress.is_some() {
                    return None;
                }
                let call = row.call.as_ref().filter(|call| call.can_park())?;
                if pending_receive {
                    let receive = row.receive_settlement.as_ref()?;
                    if receive.transferred
                        || receive.parent.is_none()
                        || receive.barrier.admission_key() != call.admission_key()
                    {
                        return None;
                    }
                } else if row.receive_settlement.is_some() {
                    return None;
                }
                Some((index, call))
            }),
    ) else {
        return Ok(None);
    };
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))[index]
        .as_mut()
        .ok_or(Error::Retain)?;
    let call = row.call.as_ref().ok_or(Error::Retain)?;
    if crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding) {
        return Err(Error::PhysicalIdentity);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if crate::spawn_hosts::query_component_reply_binding(row.binding.tcb, call.reply())
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        return Err(Error::Reply);
    }
    let message = call.message().clone();
    let reply = call.reply();
    if !import(reply, &message) {
        return Err(Error::Retain);
    }
    row.delivered = true;
    Ok(Some((reply, message)))
}

/// Import only the selected ordinary root child after its dependent route is authenticated.
/// The callback may affect the root Reply pool, so this one attempt is sealed in the move-only
/// pass before entry. A false or uncertain callback retains CALLS and the physical parent.
/// The callback must not reenter CALLS or invoke a provider while this row is borrowed.
pub(crate) unsafe fn take_selected_root_hosted_with(
    snapshot: PendingSnapshot,
    admission: ExternalAdmissionKey,
    parent_identity: nt_component_suspension::NestedExecutionIdentity,
    import: impl FnOnce(u64, &ReceivedMessage) -> bool,
) -> Result<(u64, ReceivedMessage), Error> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == snapshot.binding
            && row.call.as_ref().is_some_and(|call| {
                call.reply() == snapshot.reply
                    && call.admission_sequence() == snapshot.admission_sequence
            }))
        .ok_or(Error::Admission)?;
    let call = row.call.as_ref().ok_or(Error::Admission)?;
    let root = row.root_ingress.as_mut().ok_or(Error::Admission)?;
    let parent = root.parent.as_ref().ok_or(Error::Admission)?;
    if row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some() || root.restored.is_some()
        || root.undelivered_parent.is_some() || root.undelivered.is_some()
        || row.binding.tcb != snapshot.executor
        || call.admission_key() != admission
        || call.reply() != admission.reply()
        || call.executor() != admission.executor()
        || call.message().badge() != row.binding.badge
        || call.message().info() != snapshot.info
        || call.message().registers() != snapshot.registers
        || call.message().message_len().is_none()
        || !call.can_park()
        || root.pass.child() != row.binding
        || root.pass.admission_key() != admission
        || parent.identity() != parent_identity
        || !super::nested::root_ingress_parent_is_held(parent, admission)
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        return Err(Error::Admission);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if crate::spawn_hosts::query_component_reply_binding(row.binding.tcb, call.reply())
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        return Err(Error::Reply);
    }
    let message = call.message().clone();
    let reply = call.reply();
    root.pass.begin_import(row.binding, call).map_err(|_| Error::Admission)?;
    if !import(reply, &message) {
        return Err(Error::Retain);
    }
    root.pass.deliver(row.binding, call).map_err(|_| Error::Admission)?;
    row.delivered = true;
    Ok((reply, message))
}

/// Seal one selected child's park attempt before the caller enters RootReplyPark::try_commit.
/// A refusal after this point retains the exact Call and pass. Only its certified no-effect
/// receipt may reopen the pass for a fresh attempt.
pub(crate) unsafe fn begin_root_ingress_reply_park(
    snapshot: PendingSnapshot,
    admission: ExternalAdmissionKey,
    parent_identity: nt_component_suspension::NestedExecutionIdentity,
) -> Result<nt_user_host::root_ingress_pass::RootIngressParkAttempt<crate::HostedThreadRole>, Error> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == snapshot.binding
            && row.call.as_ref().is_some_and(|call| {
                call.reply() == snapshot.reply
                    && call.admission_sequence() == snapshot.admission_sequence
            }))
        .ok_or(Error::Admission)?;
    let call = row.call.as_ref().ok_or(Error::Admission)?;
    let root = row.root_ingress.as_mut().ok_or(Error::Admission)?;
    let parent = root.parent.as_ref().ok_or(Error::Admission)?;
    if !row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some() || root.restored.is_some()
        || root.unconsumed_settlement.is_some()
        || root.undelivered.is_some() || root.undelivered_parent.is_some()
        || row.binding.tcb != snapshot.executor
        || call.admission_key() != admission
        || call.message().badge() != row.binding.badge
        || call.message().info() != snapshot.info
        || call.message().registers() != snapshot.registers
        || root.pass.child() != row.binding
        || root.pass.admission_key() != admission
        || parent.identity() != parent_identity
        || !super::nested::root_ingress_parent_is_held(parent, admission)
        || !call.can_park()
        || crate::REPLY_MAIN_SLOT.load(Ordering::Relaxed) != call.reply()
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        return Err(Error::Admission);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if crate::spawn_hosts::query_component_reply_binding(row.binding.tcb, call.reply())
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        return Err(Error::Reply);
    }
    root.pass.begin_park(row.binding, call).map_err(|_| Error::Admission)
}

/// Record only a positive physical RootReplyPark::try_commit result for the sealed child.
///
/// # Safety
/// The caller must have just observed `Ok(())` from the one native park attempt for this
/// exact child. The retained Reply remains in CALLS; this receipt does not settle it.
pub(crate) unsafe fn acknowledge_root_ingress_reply_park(
    snapshot: PendingSnapshot,
    admission: ExternalAdmissionKey,
    parent_identity: nt_component_suspension::NestedExecutionIdentity,
    committed: nt_user_host::root_ingress_pass::RootReplyParkCommitted<crate::HostedThreadRole>,
) -> Result<(), (Error, nt_user_host::root_ingress_pass::RootReplyParkCommitted<crate::HostedThreadRole>)> {
    macro_rules! refuse { ($error:expr) => { return Err(($error, committed)) }; }
    let Some(row) = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == snapshot.binding
            && row.call.as_ref().is_some_and(|call| {
                call.reply() == snapshot.reply
                    && call.admission_sequence() == snapshot.admission_sequence
            })) else { refuse!(Error::Admission) };
    let Some(call) = row.call.as_ref() else { refuse!(Error::Admission) };
    let Some(root) = row.root_ingress.as_mut() else { refuse!(Error::Admission) };
    let Some(parent) = root.parent.as_ref() else { refuse!(Error::Admission) };
    if !row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some() || root.restored.is_some()
        || root.unconsumed_settlement.is_some()
        || row.binding.tcb != snapshot.executor
        || call.admission_key() != admission
        || call.message().badge() != row.binding.badge
        || call.message().info() != snapshot.info
        || call.message().registers() != snapshot.registers
        || root.pass.child() != row.binding
        || root.pass.admission_key() != admission
        || parent.identity() != parent_identity
        || !super::nested::root_ingress_parent_is_held(parent, admission)
        || !call.can_park()
        || crate::REPLY_MAIN_SLOT.load(Ordering::Relaxed) != 0
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        refuse!(Error::Admission);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if crate::spawn_hosts::query_component_reply_binding(row.binding.tcb, call.reply())
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        refuse!(Error::Reply);
    }
    root.pass.acknowledge_park(row.binding, call, committed)
        .map_err(|(_, committed)| (Error::Admission, committed))
}

/// Consume only the native pre-effect refusal for this exact selected child. A failed physical
/// identity check returns the receipt unchanged and leaves the pass sealed.
pub(crate) unsafe fn abort_root_ingress_reply_park(
    snapshot: PendingSnapshot,
    admission: ExternalAdmissionKey,
    parent_identity: nt_component_suspension::NestedExecutionIdentity,
    no_effect: nt_user_host::root_ingress_pass::RootReplyParkNoEffect<crate::HostedThreadRole>,
) -> Result<(), (Error, nt_user_host::root_ingress_pass::RootReplyParkNoEffect<crate::HostedThreadRole>)> {
    macro_rules! refuse { ($error:expr) => { return Err(($error, no_effect)) }; }
    let Some(row) = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == snapshot.binding
            && row.call.as_ref().is_some_and(|call| {
                call.reply() == snapshot.reply
                    && call.admission_sequence() == snapshot.admission_sequence
            })) else { refuse!(Error::Admission) };
    let Some(call) = row.call.as_ref() else { refuse!(Error::Admission) };
    let Some(root) = row.root_ingress.as_mut() else { refuse!(Error::Admission) };
    let Some(parent) = root.parent.as_ref() else { refuse!(Error::Admission) };
    if !row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some() || root.restored.is_some()
        || root.unconsumed_settlement.is_some()
        || row.binding.tcb != snapshot.executor
        || call.admission_key() != admission
        || call.message().badge() != row.binding.badge
        || call.message().info() != snapshot.info
        || call.message().registers() != snapshot.registers
        || root.pass.child() != row.binding
        || root.pass.admission_key() != admission
        || parent.identity() != parent_identity
        || !super::nested::root_ingress_parent_is_held(parent, admission)
        || !call.can_park()
        || crate::REPLY_MAIN_SLOT.load(Ordering::Relaxed) != call.reply()
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        refuse!(Error::Admission);
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    if crate::spawn_hosts::query_component_reply_binding(row.binding.tcb, call.reply())
        != Ok(ReplyBindingObservation::BoundToTarget)
    {
        refuse!(Error::Reply);
    }
    root.pass.abort_park_before_effect(row.binding, call, no_effect)
        .map_err(|(_, no_effect)| (Error::Admission, no_effect))
}

/// Return an unexecuted root delivery to its existing physical ingress owner. No syscall has
/// been admitted yet, so replay restores the original full message rather than captured argv.
pub(crate) unsafe fn defer_hosted_delivery(reply: u64, badge: u64) -> Result<(), Error> {
    if crate::REPLY_MAIN_SLOT.load(Ordering::Relaxed) != reply {
        return Err(Error::PhysicalIdentity);
    }
    let index = (&*core::ptr::addr_of!(CALLS))
        .iter()
        .position(|entry| {
            entry.as_ref().is_some_and(|row| {
                row.binding.badge == badge
                    && row.delivered
                    && row.completion.is_none()
                    && !row.released
                    && row
                        .call
                        .as_ref()
                        .is_some_and(|call| call.reply() == reply && call.can_park())
            })
        })
        .ok_or(Error::Retain)?;
    let binding = (&*core::ptr::addr_of!(CALLS))[index]
        .as_ref()
        .unwrap()
        .binding;
    // A Receive child can become selected while root redrives an already delivered,
    // unrelated Call. Return that untouched Call to its exact ingress owner first.
    if !crate::writable_fs::registry_journal::owns_volume()
        && (!receive_child_pending() || receive_child_is_current(binding, reply))
    {
        return Err(Error::PhysicalIdentity);
    }
    if crate::service_sec_image::hosted_ingress_binding(badge) != Some(binding) {
        return Err(Error::PhysicalIdentity);
    }
    {
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        if crate::spawn_hosts::query_component_reply_binding(binding.tcb, reply)
            != Ok(ReplyBindingObservation::BoundToTarget)
        {
            return Err(Error::Reply);
        }
    }
    let pool_index = crate::wait_reply_pool_find_cap(reply).ok_or(Error::Reply)?;
    let park = crate::root_reply_park::RootReplyPark::prepare().ok_or(Error::Retain)?;
    // This is a memory-only ownership transfer. The ingress owner keeps the capability and its
    // exact caller; only the root semantic pool record is removed, never the physical Reply.
    park.try_commit().map_err(|_| Error::Retain)?;
    // The root selector is now clear. Publish the exact ingress row as retained before
    // removing its pool record, so even a refused clear cannot lose the physical Call.
    (&mut *core::ptr::addr_of_mut!(CALLS))[index]
        .as_mut()
        .unwrap()
        .delivered = false;
    if !crate::wait_reply_pool_clear_cap(pool_index) {
        return Err(Error::Reply);
    }
    Ok(())
}

pub(crate) unsafe fn owns_hosted_reply(reply: u64) -> bool {
    (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .any(|row| {
            row.call.as_ref().is_some_and(|call| call.reply() == reply)
                || row
                    .recycled
                    .as_ref()
                    .is_some_and(|call| call.reply() == reply)
        })
}

pub(crate) unsafe fn can_park_hosted_reply(reply: u64) -> bool {
    (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .any(|row| {
            row.delivered
                && row.completion.is_none()
                && !row.released
                && crate::service_sec_image::hosted_ingress_binding(row.binding.badge)
                    == Some(row.binding)
                && row
                    .call
                    .as_ref()
                    .is_some_and(|call| call.reply() == reply && call.can_park())
        })
}

/// Only a known, mutation-free kernel rejection may become an ordinary NT failure Reply.
/// Any ownership/query uncertainty retains the entered restart and stops the caller's adapter.
pub(crate) unsafe fn restart_hosted(
    reply: u64,
    tcb: u64,
    context: &nt_thread_start::amd64_context::LegacyContextRestore,
) -> Result<Result<(), u64>, Error> {
    use nt_component_suspension::ExternalRestartObservation;
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|row| row.call.as_ref().is_some_and(|call| call.reply() == reply))
        .ok_or(Error::Reply)?;
    if !row.delivered
        || row.binding.tcb != tcb
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        return Err(Error::PhysicalIdentity);
    }
    let call = row.call.as_mut().expect("retained context restart");
    if !call.is_restarted() {
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        match call
            .restart_owned(
                |tcb, reply| {
                    crate::spawn_hosts::query_component_reply_binding(tcb, reply)
                        .map_err(|_| u64::MAX)
                },
                |tcb| match crate::thread_context::continue_thread(tcb, context) {
                    Ok(()) => ExternalRestartObservation::Acknowledged,
                    Err(status) => ExternalRestartObservation::Rejected(status),
                },
            )
            .map_err(|_| Error::Reply)?
        {
            ExternalRestartObservation::Acknowledged => {}
            ExternalRestartObservation::Rejected(status) => return Ok(Err(status)),
            ExternalRestartObservation::Indeterminate => return Err(Error::Reply),
        }
    }
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let (ready, _message) = owner()
        .receiver
        .as_mut()
        .expect("ready receiver")
        .finish_restarted_external(&mut row.call, |tcb, reply| {
            crate::spawn_hosts::query_component_reply_binding(tcb, reply)
        })
        .map_err(|_| Error::Reply)?;
    row.recycled = Some(ready);
    row.completion = Some(Completion::Restarted);
    Ok(Ok(()))
}

/// Reject a wrong selected child before Reply send or checked Free can consume its physical
/// authority. Ordinary hosted Calls have no RootIngress owner and keep their existing path.
unsafe fn preflight_root_ingress_settlement(row: &HostedCall) -> Result<(), Error> {
    let Some(root) = row.root_ingress.as_ref() else { return Ok(()) };
    let call = row.call.as_ref().ok_or(Error::Admission)?;
    let admission = call.admission_key();
    if !row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some() || root.unconsumed_settlement.is_some()
        || call.reply() != admission.reply() || call.executor() != row.binding.tcb
        || call.message().badge() != row.binding.badge
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        return Err(Error::Admission);
    }
    let (parent_identity, disposition) = root.pass
        .settlement_disposition(row.binding, admission)
        .map_err(|_| Error::Admission)?;
    if let Some(restored) = root.restored.as_ref() {
        if root.parent.is_some()
            || disposition != nt_user_host::root_ingress_pass::RootIngressSettlementDisposition::RetainForResult
            || !restored.parked_child()
            || restored.child() != row.binding
            || restored.admission_key() != admission
            || restored.parent() != parent_identity
        {
            return Err(Error::Admission);
        }
    } else {
        let parent = root.parent.as_ref().ok_or(Error::Admission)?;
        if parent.identity() != parent_identity
            || !super::nested::root_ingress_parent_is_held(parent, admission)
        {
            return Err(Error::Admission);
        }
    }
    Ok(())
}

pub(crate) unsafe fn reply_hosted(reply: u64, info: u64, words: [u64; 4]) -> Result<(), Error> {
    let records = &mut *core::ptr::addr_of_mut!(CALLS);
    let index = records
        .iter()
        .position(|row| {
            row.as_ref().is_some_and(|row| {
                row.call.as_ref().is_some_and(|call| call.reply() == reply)
                    || row
                        .recycled
                        .as_ref()
                        .is_some_and(|call| call.reply() == reply)
            })
        })
        .ok_or(Error::Reply)?;
    let row = records[index].as_mut().expect("retained hosted Call");
    if let Some(completion) = row.completion {
        if completion != Completion::Acknowledged {
            return Err(Error::Reply);
        }
        if row.root_ingress.as_ref().is_some_and(|root| {
            root.parent.is_some() && root.unconsumed_settlement.is_some()
        }) {
            return Err(Error::Retain);
        }
        return Ok(());
    }
    if !row.delivered
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        return Err(Error::PhysicalIdentity);
    }
    preflight_root_ingress_settlement(row)?;
    if !row
        .call
        .as_ref()
        .expect("retained hosted Call")
        .is_acknowledged()
    {
        let saved = crate::ipc_message::SavedMessageBuffer::capture();
        let observation = row
            .call
            .as_mut()
            .expect("retained hosted Call")
            .reply_owned(
                |tcb, reply| crate::spawn_hosts::query_component_reply_binding(tcb, reply),
                |reply| {
                    // A wide reply's buffer must survive the binding-query IPC before this effect.
                    drop(saved);
                    if crate::reply_on(reply, info, words[0], words[1], words[2], words[3]) == 0 {
                        IngressReplyObservation::Acknowledged
                    } else {
                        IngressReplyObservation::Indeterminate
                    }
                },
            )
            .map_err(|_| Error::Reply)?;
        if observation != IngressReplyObservation::Acknowledged {
            return Err(Error::Reply);
        }
    }
    finish_acknowledged(row)
}

/// Reconcile only a Reply whose send already has a positive acknowledgement. This never sends
/// again, so an indeterminate send remains distinct from a failed post-send Free observation.
pub(crate) unsafe fn finish_acknowledged_hosted_reply(reply: u64) -> Result<bool, Error> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .flatten()
        .find(|row| {
            row.call.as_ref().is_some_and(|call| call.reply() == reply)
                || row
                    .recycled
                    .as_ref()
                    .is_some_and(|call| call.reply() == reply)
        })
        .ok_or(Error::Reply)?;
    if row.completion == Some(Completion::Acknowledged) {
        if row.root_ingress.as_ref().is_some_and(|root| {
            root.parent.is_some() && root.unconsumed_settlement.is_some()
        }) {
            return Ok(false);
        }
        return Ok(true);
    }
    if row.completion.is_some() {
        return Ok(false);
    }
    if !row
        .call
        .as_ref()
        .is_some_and(ExternalIngress::is_acknowledged)
    {
        return Ok(false);
    }
    finish_acknowledged(row)?;
    Ok(true)
}

unsafe fn finish_acknowledged(row: &mut HostedCall) -> Result<(), Error> {
    preflight_root_ingress_settlement(row)?;
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let owner = owner();
    let (ready, _message, settlement) = owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .finish_external_with_settlement(&mut row.call, |tcb, reply| {
            crate::spawn_hosts::query_component_reply_binding(tcb, reply)
        })
        .map_err(|_| Error::Reply)?;
    row.recycled = Some(ready);
    row.completion = Some(Completion::Acknowledged);
    if row.root_ingress.is_some() {
        settle_root_ingress(row, settlement)?;
    } else {
        settle_receive(row, settlement)?;
    }
    let trace = row.receive_settlement.as_ref().and_then(|receive| {
        receive
            .parent
            .as_ref()
            .map(|parent| {
                (
                    parent.identity(),
                    receive.barrier.admission_key(),
                    receive.trace_owner,
                )
            })
    });
    if let Some((parent, child, trace_owner)) = trace {
        crate::win32k_glue::trace_receive_phase(b"child-ack-free", parent, child, trace_owner);
    }
    Ok(())
}

fn settle_receive(
    row: &mut HostedCall,
    settlement: nt_component_suspension::ExternalSettlement,
) -> Result<(), Error> {
    let Some(receive) = row.receive_settlement.as_mut() else {
        return Ok(());
    };
    match receive.barrier.accept_settlement(row.binding, settlement) {
        Ok(()) => Ok(()),
        Err((_, settlement)) => {
            receive.rejected = Some(settlement);
            Err(Error::Admission)
        }
    }
}

fn settle_root_ingress(
    row: &mut HostedCall,
    settlement: nt_component_suspension::ExternalSettlement,
) -> Result<(), Error> {
    let root = row.root_ingress.as_mut().ok_or(Error::Admission)?;
    // finish_acknowledged excludes a second receipt before the irreversible Free. This
    // private helper has no other caller, so the slot remains available for this receipt.
    if settlement.admission_key() != root.pass.admission_key()
        || root.pass.child() != row.binding
    {
        root.unconsumed_settlement = Some(settlement);
        return Err(Error::Admission);
    }
    match root.pass.settlement_disposition(row.binding, settlement.admission_key()) {
        Ok((_, nt_user_host::root_ingress_pass::RootIngressSettlementDisposition::Checkpoint)) => {
            match root.pass.acknowledge_settlement(row.binding, settlement) {
                Ok(()) => Ok(()),
                Err((_, settlement)) => {
                    root.unconsumed_settlement = Some(settlement);
                    Err(Error::Admission)
                }
            }
        }
        Ok((_, nt_user_host::root_ingress_pass::RootIngressSettlementDisposition::RetainForResult)) => {
            root.unconsumed_settlement = Some(settlement);
            Ok(())
        }
        Err(_) => {
            root.unconsumed_settlement = Some(settlement);
            Err(Error::Admission)
        }
    }
}

/// Transfer a post-restoration Free receipt to the exact later result owner. This does not
/// recreate the parent checkpoint or authorize another Reply send.
pub(crate) unsafe fn take_root_ingress_settlement(
    binding: Binding,
    admission: ExternalAdmissionKey,
) -> Option<nt_component_suspension::ExternalSettlement> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == binding
            && row.root_ingress.as_ref().is_some_and(|root| {
                root.pass.admission_key() == admission
            }))?;
    let root = row.root_ingress.as_mut()?;
    if root.restored.as_ref().is_none_or(|restored| {
        restored.child() != binding || restored.admission_key() != admission
            || !restored.parked_child()
    }) || row.completion != Some(Completion::Acknowledged)
        || row.recycled.as_ref().is_none_or(|ready| ready.reply() != admission.reply())
        || root.unconsumed_settlement.as_ref().is_none_or(|settlement| {
            settlement.admission_key() != admission
        })
    {
        return None;
    }
    root.unconsumed_settlement.take()
}

fn receive_settlement_consumed(row: &HostedCall) -> bool {
    row.receive_settlement.as_ref().is_none_or(|receive| {
        receive.transferred && receive.parent.is_none() && receive.rejected.is_none()
    })
}

pub(crate) unsafe fn prepare_receive_settlement(
    snapshot: PendingSnapshot,
    observation: crate::win32k_glue::ReceiveFaultCapture,
    provider_tcb: u64,
    provider_pml4: u64,
    trace_owner: nt_component_suspension::SuspensionOwner,
) -> Result<nt_component_suspension::ExternalAdmissionKey, Error> {
    if root_ingress_pending() {
        return Err(Error::Admission);
    }
    let oldest = oldest_pending_snapshot().ok_or(Error::Admission)?;
    if oldest.binding != snapshot.binding
        || oldest.reply != snapshot.reply
        || oldest.admission_sequence != snapshot.admission_sequence
    {
        return Err(Error::Admission);
    }
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .flatten()
        .find(|row| {
            row.binding == snapshot.binding
                && row.call.as_ref().is_some_and(|call| {
                    call.reply() == snapshot.reply
                        && call.admission_sequence() == snapshot.admission_sequence
                })
        })
        .ok_or(Error::Admission)?;
    if row.receive_settlement.is_some() || row.root_ingress.is_some()
        || row.delivered || row.released {
        return Err(Error::Admission);
    }
    let barrier = nt_user_host::receive_child_barrier::ReceiveChildBarrier::prepare(
        row.call.as_ref().ok_or(Error::Admission)?,
        row.binding,
    )
    .map_err(|_| Error::Admission)?;
    let admission = barrier.admission_key();
    row.receive_settlement = Some(ReceiveSettlement {
        barrier,
        observation,
        provider_tcb,
        provider_pml4,
        trace_owner,
        parent: None,
        transferred: false,
        rejected: None,
    });
    Ok(admission)
}

/// Prepare the oldest exact hosted Call for one ordinary root event. This is memory-only and
/// precedes the parent's physical park; the child Reply remains in its original CALLS row.
pub(crate) unsafe fn prepare_root_ingress_pass(
    snapshot: PendingSnapshot,
) -> Result<nt_component_suspension::ExternalAdmissionKey, Error> {
    if receive_child_pending() || root_ingress_pending() {
        return Err(Error::Admission);
    }
    let oldest = oldest_pending_snapshot().ok_or(Error::Admission)?;
    if oldest.binding != snapshot.binding
        || oldest.reply != snapshot.reply
        || oldest.admission_sequence != snapshot.admission_sequence
        || oldest.info != snapshot.info
        || oldest.registers != snapshot.registers
        || (snapshot.info >> 12) != nt_syscall_abi::NT_NATIVE_SYSCALL_LABEL
    {
        return Err(Error::Admission);
    }
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .flatten()
        .find(|row| {
            row.binding == snapshot.binding
                && row.call.as_ref().is_some_and(|call| {
                    call.reply() == snapshot.reply
                        && call.admission_sequence() == snapshot.admission_sequence
                })
        })
        .ok_or(Error::Admission)?;
    if row.receive_settlement.is_some() || row.root_ingress.is_some()
        || row.delivered || row.released || row.completion.is_some()
    {
        return Err(Error::Admission);
    }
    let call = row.call.as_ref().ok_or(Error::Admission)?;
    if call.message().info() != snapshot.info
        || call.message().registers() != snapshot.registers
    {
        return Err(Error::Admission);
    }
    let pass = nt_user_host::root_ingress_pass::RootIngressPass::prepare(call, row.binding)
        .map_err(|_| Error::Admission)?;
    let admission = pass.admission_key();
    row.root_ingress = Some(RootIngressOwner {
        pass, parent: None, undelivered_parent: None, undelivered: None, restored: None,
        unconsumed_settlement: None,
    });
    Ok(admission)
}

/// Discard only an unbound root preparation after nested ownership proves that its park attempt
/// made no physical change (or fully acknowledged the abort). A wrong snapshot returns the
/// move-only proof to its caller; an uncertain attempt cannot create this proof.
pub(crate) unsafe fn cancel_unbound_root_ingress_pass(
    snapshot: PendingSnapshot,
    admission: nt_component_suspension::ExternalAdmissionKey,
    proof: super::nested::NoEffectParkProof,
) -> Result<(), (Error, super::nested::NoEffectParkProof)> {
    if proof.admission_key() != admission {
        return Err((Error::Admission, proof));
    }
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .flatten()
        .find(|row| {
            row.binding == snapshot.binding
                && row.call.as_ref().is_some_and(|call| {
                    call.reply() == snapshot.reply
                        && call.admission_sequence() == snapshot.admission_sequence
                })
        });
    let Some(row) = row else { return Err((Error::Admission, proof)); };
    let exact = row.call.as_ref().is_some_and(|call| {
        call.admission_key() == admission
            && call.message().info() == snapshot.info
            && call.message().registers() == snapshot.registers
            && call.can_park()
    });
    if !exact || row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some()
        || row.root_ingress.as_ref().is_none_or(|root| {
            root.parent.is_some() || root.undelivered_parent.is_some()
                || root.undelivered.is_some() || root.restored.is_some()
                || root.pass.admission_key() != admission
        })
    {
        return Err((Error::Admission, proof));
    }
    row.root_ingress = None;
    Ok(())
}

/// Seal the exact untouched child Call and transfer its one-shot unwind owner into the physical
/// parent row. A pre-effect parent refusal retains the token in CALLS for this same retry.
pub(crate) unsafe fn begin_undelivered_root_unwind(
    snapshot: PendingSnapshot,
    parent: &super::nested::ParkedParentHandle,
) -> Result<(), Error> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == snapshot.binding
            && row.call.as_ref().is_some_and(|call| {
                call.reply() == snapshot.reply
                    && call.admission_sequence() == snapshot.admission_sequence
            }))
        .ok_or(Error::Admission)?;
    let call = row.call.as_ref().ok_or(Error::Admission)?;
    if row.delivered || row.released || row.completion.is_some()
        || row.receive_settlement.is_some()
        || call.executor() != snapshot.executor
        || call.message().info() != snapshot.info
        || call.message().registers() != snapshot.registers
        || !call.can_park()
    {
        return Err(Error::Admission);
    }
    let root = row.root_ingress.as_mut().ok_or(Error::Admission)?;
    if root.parent.is_some() || root.restored.is_some()
        || root.pass.admission_key() != call.admission_key()
        || root.pass.child() != row.binding
        || root.undelivered_parent.is_some_and(|identity| identity != parent.identity())
        || !super::nested::undelivered_root_parent_candidate(parent, call.admission_key())
    {
        return Err(Error::Admission);
    }
    root.undelivered_parent = Some(parent.identity());
    if root.undelivered.is_none() {
        root.undelivered = Some(root.pass.begin_undelivered_unwind(row.binding, call)
            .map_err(|_| Error::Admission)?);
    }
    if !root.pass.is_undelivered_unwind(root.undelivered.as_ref().ok_or(Error::Admission)?) {
        return Err(Error::Admission);
    }
    super::nested::begin_undelivered_root_unwind(parent, &mut root.undelivered)
}

/// Cancel only after a positive physical parent restore produced this move-only receipt.
/// Every refusal returns the receipt to its caller; the original Call remains retained.
pub(crate) unsafe fn cancel_restored_undelivered_root_pass(
    snapshot: PendingSnapshot,
    proof: super::nested::RestoredBeforeChildProof,
) -> Result<(), (Error, super::nested::RestoredBeforeChildProof)> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == snapshot.binding
            && row.call.as_ref().is_some_and(|call| {
                call.reply() == snapshot.reply
                    && call.admission_sequence() == snapshot.admission_sequence
            }));
    let Some(row) = row else { return Err((Error::Admission, proof)) };
    let exact = row.call.as_ref().is_some_and(|call| {
        call.admission_key() == proof.admission_key()
            && call.executor() == snapshot.executor
            && call.message().info() == snapshot.info
            && call.message().registers() == snapshot.registers
            && call.can_park()
    });
    if !exact || proof.child() != snapshot.binding || row.delivered || row.released
        || row.completion.is_some() || row.receive_settlement.is_some()
        || row.root_ingress.as_ref().is_none_or(|root| {
            root.parent.is_some() || root.restored.is_some()
                || root.undelivered_parent != Some(proof.parent())
                || root.undelivered.is_some()
                || root.pass.child() != row.binding
                || !root.pass.is_undelivered_unwind(proof.token())
        })
    {
        return Err((Error::Admission, proof));
    }
    row.root_ingress = None;
    Ok(())
}

/// Transfer the exact physical parent handle to the prepared child row after park acknowledges.
/// On refusal, return the handle to the caller; the PARENTS row retains its physical hold.
pub(crate) unsafe fn bind_root_ingress_pass(
    snapshot: PendingSnapshot,
    parent: super::nested::ParkedParentHandle,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), (Error, super::nested::ParkedParentHandle)> {
    let result = (|| {
        let row = (&mut *core::ptr::addr_of_mut!(CALLS))
            .iter_mut()
            .flatten()
            .find(|row| {
                row.binding == snapshot.binding
                    && row.call.as_ref().is_some_and(|call| {
                        call.reply() == snapshot.reply
                            && call.admission_sequence() == snapshot.admission_sequence
                    })
            })
            .ok_or(Error::Admission)?;
        if row.delivered || row.released || row.completion.is_some()
            || row.receive_settlement.is_some()
        {
            return Err(Error::Admission);
        }
        let root = row.root_ingress.as_mut().ok_or(Error::Admission)?;
        if root.parent.is_some() || root.undelivered_parent.is_some()
            || root.undelivered.is_some() || root.restored.is_some()
            || root.pass.admission_key()
                != row.call.as_ref().ok_or(Error::Admission)?.admission_key()
            || row.call.as_ref().ok_or(Error::Admission)?.message().info() != snapshot.info
            || row.call.as_ref().ok_or(Error::Admission)?.message().registers()
                != snapshot.registers
        {
            return Err(Error::Admission);
        }
        super::nested::bind_root_ingress_child(&parent, &mut root.pass, dispatch)
    })();
    if let Err(error) = result {
        return Err((error, parent));
    }
    let root = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .flatten()
        .find(|row| {
            row.binding == snapshot.binding
                && row.call.as_ref().is_some_and(|call| {
                    call.reply() == snapshot.reply
                        && call.admission_sequence() == snapshot.admission_sequence
                })
        })
        .and_then(|row| row.root_ingress.as_mut())
        .expect("validated root ingress child retained");
    root.parent = Some(parent);
    Ok(())
}

unsafe fn root_ingress_pending() -> bool {
    (&*core::ptr::addr_of!(CALLS)).iter().flatten()
        .any(|row| row.root_ingress.is_some())
}

/// Memory-only admission check for a pending outer RootIngress handoff. A numeric Reply or
/// admission sequence alone cannot select a different CALLS row after slot reuse.
pub(crate) unsafe fn prepared_root_ingress_child_is_current(
    admission: ExternalAdmissionKey,
) -> bool {
    (&*core::ptr::addr_of!(CALLS)).iter().flatten().any(|row| {
        let Some(root) = row.root_ingress.as_ref() else { return false };
        let Some(call) = row.call.as_ref() else { return false };
        !row.delivered && !row.released && row.completion.is_none()
            && row.receive_settlement.is_none()
            && root.parent.is_none() && root.undelivered_parent.is_none()
            && root.undelivered.is_none() && root.restored.is_none()
            && root.pass.child() == row.binding
            && root.pass.admission_key() == admission
            && call.admission_key() == admission
            && call.reply() == admission.reply()
            && call.executor() == admission.executor()
            && call.can_park()
            && crate::service_sec_image::hosted_ingress_binding(row.binding.badge)
                == Some(row.binding)
    })
}

fn root_child_admission_current(row: &HostedCall, admission: ExternalAdmissionKey) -> bool {
    match row.call.as_ref() {
        Some(call) => call.admission_key() == admission,
        None => row.completion.is_some() && row.recycled.as_ref().is_some_and(|ready| {
            ready.reply() == admission.reply()
        }),
    }
}

/// Consume only the exact positive native parent-restoration receipt. An async child result may
/// remain in this CALLS row, but it no longer excludes unrelated provider progress afterward.
pub(crate) unsafe fn accept_root_ingress_parent_restored(
    restored: nt_user_host::root_ingress_pass::RootIngressRestored<crate::HostedThreadRole>,
) -> Result<(), (Error, nt_user_host::root_ingress_pass::RootIngressRestored<crate::HostedThreadRole>)> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten()
        .find(|row| row.binding == restored.child()
            && row.root_ingress.as_ref().is_some_and(|root| {
                root.pass.admission_key() == restored.admission_key()
            }));
    let Some(row) = row else { return Err((Error::Admission, restored)) };
    let child_current = root_child_admission_current(row, restored.admission_key());
    let Some(root) = row.root_ingress.as_mut() else {
        return Err((Error::Admission, restored));
    };
    if root.restored.is_some()
        || root.pass.child() != row.binding
        || root.pass.admission_key() != restored.admission_key()
        || !child_current
        || root.parent.as_ref().is_none_or(|parent| parent.identity() != restored.parent())
    {
        return Err((Error::Admission, restored));
    }
    root.restored = Some(restored);
    root.parent = None;
    Ok(())
}

/// A prepared or bound root child excludes all unrelated provider selection until its exact
/// physical parent is restored. Inconsistent retained ownership also excludes selection.
pub(crate) unsafe fn root_ingress_parent_blocks_provider_resume() -> bool {
    for row in (&*core::ptr::addr_of!(CALLS)).iter().flatten() {
        let Some(root) = row.root_ingress.as_ref() else { continue };
        if root.pass.child() != row.binding
            || !root_child_admission_current(row, root.pass.admission_key())
        {
            return true;
        }
        if let Some(restored) = root.restored.as_ref() {
            if root.parent.is_some()
                || restored.child() != row.binding
                || restored.admission_key() != root.pass.admission_key()
            {
                return true;
            }
            continue;
        }
        let Some(parent) = root.parent.as_ref() else { return true };
        if !super::nested::root_ingress_parent_is_held(parent, root.pass.admission_key()) {
            return true;
        }
        return true;
    }
    false
}

pub(crate) unsafe fn receive_child_pending() -> bool {
    (&*core::ptr::addr_of!(CALLS)).iter().flatten().any(|row| {
        row.receive_settlement
            .as_ref()
            .is_some_and(|receive| !receive.transferred)
    })
}

pub(crate) unsafe fn receive_child_is_current(binding: Binding, reply: u64) -> bool {
    (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .any(|row| {
            row.binding == binding
                && row.delivered
                && row.call.as_ref().is_some_and(|call| call.reply() == reply)
                && row
                    .receive_settlement
                    .as_ref()
                    .is_some_and(|receive| !receive.transferred)
        })
}

pub(crate) unsafe fn receive_child_observation(
    binding: Binding,
    reply: u64,
) -> Option<ReceiveChildObservation> {
    (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .find_map(|row| {
            if row.binding != binding
                || !row.delivered
                || !row.call.as_ref().is_some_and(|call| call.reply() == reply)
            {
                return None;
            }
            row.receive_settlement
                .as_ref()
                .filter(|receive| !receive.transferred)
                .and_then(|receive| {
                    Some(ReceiveChildObservation {
                        observation: receive.observation,
                        parent: receive.parent.as_ref()?.identity(),
                        child: receive.barrier.admission_key(),
                        provider_tcb: receive.provider_tcb,
                        provider_pml4: receive.provider_pml4,
                        trace_owner: receive.trace_owner,
                    })
                })
        })
}

pub(crate) unsafe fn receive_child_delivery_allowed(reply: u64) -> bool {
    !receive_child_pending()
        || (&*core::ptr::addr_of!(CALLS))
            .iter()
            .filter_map(Option::as_ref)
            .any(|row| {
                !row.delivered
                    && row.call.as_ref().is_some_and(|call| call.reply() == reply)
                    && row
                        .receive_settlement
                        .as_ref()
                        .is_some_and(|receive| !receive.transferred)
            })
}

/// The actual child owns the parent ticket until the sealed outer-boundary transfer.
pub(crate) unsafe fn with_bound_receive_scope<T>(
    identity: nt_component_suspension::NestedExecutionIdentity,
    use_scope: impl FnOnce(&nt_component_suspension::NestedExecutionScope) -> Result<T, Error>,
) -> Result<T, Error> {
    let parent = (&*core::ptr::addr_of!(CALLS))
        .iter()
        .flatten()
        .filter_map(|row| row.receive_settlement.as_ref()?.parent.as_ref())
        .find(|parent| parent.identity() == identity)
        .ok_or(Error::Admission)?;
    super::nested::with_receive_scope(parent, use_scope)
}

pub(crate) unsafe fn bind_receive_settlement(
    snapshot: PendingSnapshot,
    parent: super::nested::ParkedParentHandle,
    dispatch: nt_component_suspension::LaneDispatchIdentity,
) -> Result<(), (Error, super::nested::ParkedParentHandle)> {
    let result = (|| {
        let row = (&mut *core::ptr::addr_of_mut!(CALLS))
            .iter_mut()
            .flatten()
            .find(|row| {
                row.binding == snapshot.binding
                    && row.call.as_ref().is_some_and(|call| {
                        call.reply() == snapshot.reply
                            && call.admission_sequence() == snapshot.admission_sequence
                    })
            })
            .ok_or(Error::Admission)?;
        let receive = row.receive_settlement.as_mut().ok_or(Error::Admission)?;
        if receive.parent.is_some() || receive.transferred || row.delivered {
            return Err(Error::Admission);
        }
        super::nested::bind_receive_child(&parent, &mut receive.barrier, dispatch)?;
        Ok(())
    })();
    if let Err(error) = result {
        return Err((error, parent));
    }
    let receive = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .flatten()
        .find(|row| {
            row.binding == snapshot.binding
                && row.call.as_ref().is_some_and(|call| {
                    call.reply() == snapshot.reply
                        && call.admission_sequence() == snapshot.admission_sequence
                })
        })
        .and_then(|row| row.receive_settlement.as_mut())
        .expect("validated child retained");
    receive.parent = Some(parent);
    Ok(())
}

pub(crate) unsafe fn take_outer_boundary() -> Result<Option<ReceiveSettlementBoundary>, Error> {
    for row in (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut().flatten() {
        let Some(receive) = row.receive_settlement.as_mut() else {
            continue;
        };
        if receive.transferred || row.completion != Some(Completion::Acknowledged) {
            continue;
        }
        if receive.rejected.is_some() {
            return Err(Error::Admission);
        }
        let parent = receive.parent.as_ref().ok_or(Error::Admission)?;
        super::nested::consume_receive_settlement(parent, &mut receive.barrier)?;
        receive.transferred = true;
        return Ok(Some(ReceiveSettlementBoundary {
            parent: receive.parent.take(),
        }));
    }
    Ok(None)
}

/// Stop one retained physical Call. The semantic process layout may already be retired, so
/// authenticate its immutable admission key against the Reply still bound to the exact TCB.
/// A refused query leaves the Call intact; an uncertain native Stop remains entered in the Call.
unsafe fn stop_retained_hosted_call(
    reply: u64,
    tcb: u64,
    invoke: impl FnOnce() -> u64,
) -> Result<(), Error> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|row| row.call.as_ref().is_some_and(|call| call.reply() == reply))
        .ok_or(Error::Reply)?;
    let call = row.call.as_ref().ok_or(Error::Reply)?;
    let admission = call.admission_key();
    if row.binding.tcb != tcb
        || admission.executor() != tcb
        || admission.reply() != reply
        || admission.admission_sequence() == 0
    {
        return Err(Error::PhysicalIdentity);
    }
    {
        let _saved = crate::ipc_message::SavedMessageBuffer::capture();
        if crate::spawn_hosts::query_component_reply_binding(tcb, reply)
            != Ok(ReplyBindingObservation::BoundToTarget)
        {
            return Err(Error::Reply);
        }
    }
    row.call
        .as_mut()
        .ok_or(Error::Reply)?
        .stop_owned(|executor| {
            if executor != tcb {
                return Err(u64::MAX);
            }
            let status = invoke();
            if status == 0 { Ok(()) } else { Err(status) }
        })
        .map_err(|_| Error::Retirement)
}

pub(crate) unsafe fn stop_hosted_caller(
    tcb: u64,
    invoke: impl FnOnce() -> u64,
) -> Option<Result<(), Error>> {
    let reply = (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .find(|row| row.binding.tcb == tcb && row.call.is_some())
        .and_then(|row| row.call.as_ref().map(ExternalIngress::reply));
    let Some(reply) = reply else {
        return (&*core::ptr::addr_of!(CANCELLATIONS))
            .iter()
            .any(|cancelled| {
                cancelled.binding.tcb == tcb
                    && crate::service_sec_image::hosted_ingress_binding(cancelled.binding.badge)
                        == Some(cancelled.binding)
            })
            .then_some(Ok(()));
    };
    Some(stop_retained_hosted_call(reply, tcb, invoke))
}

/// Containment stops the exact retained sender before cancelling its Call, without destroying
/// or retyping a shared Reply. An uncertain Stop remains recorded and cannot be retried.
pub(crate) unsafe fn stop_and_cancel_hosted(reply: u64) -> Result<(), Error> {
    if hosted_reply_cancelled(reply) {
        return Ok(());
    }
    let binding = (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .find(|row| row.call.as_ref().is_some_and(|call| call.reply() == reply))
        .map(|row| row.binding)
        .ok_or(Error::Reply)?;
    stop_retained_hosted_call(reply, binding.tcb, || crate::tcb_suspend_raw_r(binding.tcb))?;
    cancel_hosted(reply)
}

pub(crate) unsafe fn cancel_hosted(reply: u64) -> Result<(), Error> {
    let records = &mut *core::ptr::addr_of_mut!(CALLS);
    let index = records
        .iter()
        .position(|row| {
            row.as_ref().is_some_and(|row| {
                row.call.as_ref().is_some_and(|call| call.reply() == reply)
                    || row
                        .recycled
                        .as_ref()
                        .is_some_and(|call| call.reply() == reply)
            })
        })
        .ok_or(Error::Reply)?;
    let row = records[index].as_mut().expect("retained external Call");
    if let Some(completion) = row.completion {
        if completion != Completion::Cancelled {
            return Err(Error::Retirement);
        }
        return Ok(());
    }
    let owner = owner();
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let cancellations = &mut *core::ptr::addr_of_mut!(CANCELLATIONS);
    {
        let _durable = crate::allocator::enter_durable();
        cancellations.try_reserve(1).map_err(|_| Error::Capacity)?;
    }
    let (ready, _cancelled) = owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .finish_cancelled_external(&mut row.call, |tcb, reply| {
            crate::spawn_hosts::query_component_reply_binding(tcb, reply)
        })
        .map_err(|_| Error::Retirement)?;
    cancellations.push(Cancellation {
        binding: row.binding,
        reply,
    });
    row.recycled = Some(ready);
    row.completion = Some(Completion::Cancelled);
    // Queued Calls were never handed to a legacy semantic owner.
    row.released = !row.delivered;
    Ok(())
}

/// Inspect the current retained cancellation, never a historical numeric-capability match.
pub(crate) unsafe fn hosted_reply_cancelled(reply: u64) -> bool {
    (&*core::ptr::addr_of!(CALLS))
        .iter()
        .filter_map(Option::as_ref)
        .any(|row| {
            row.completion == Some(Completion::Cancelled)
                && row
                    .recycled
                    .as_ref()
                    .is_some_and(|ready| ready.reply() == reply)
        })
}

/// Memory-only semantic retirement. A later receive checkpoint performs native Free queries.
pub(crate) unsafe fn release_hosted_reply(reply: u64) -> Result<(), Error> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|row| {
            row.recycled
                .as_ref()
                .is_some_and(|ready| ready.reply() == reply)
        })
        .ok_or(Error::Reply)?;
    if row.call.is_some() || row.completion.is_none() {
        return Err(Error::Reply);
    }
    row.released = true;
    Ok(())
}

pub(crate) unsafe fn cancel_hosted_caller(tcb: u64) -> Result<(), Error> {
    loop {
        let next = (&*core::ptr::addr_of!(CALLS))
            .iter()
            .filter_map(Option::as_ref)
            .find(|row| row.binding.tcb == tcb && row.call.is_some());
        let Some(row) = next else {
            return Ok(());
        };
        cancel_hosted(row.call.as_ref().expect("selected retained Call").reply())?;
    }
}

/// Retry only the pool transfer. Neither the native Reply nor Stop effect is replayed.
pub(super) unsafe fn recycle_completed() -> Result<(), Error> {
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let owner = owner();
    for record in (&mut *core::ptr::addr_of_mut!(CALLS)).iter_mut() {
        let Some(row) = record.as_mut() else {
            continue;
        };
        if !row.released || !receive_settlement_consumed(row) || row.root_ingress.is_some() {
            continue;
        }
        let Some(ready) = row.recycled.as_ref() else {
            continue;
        };
        let reply = ready.reply();
        let _ = crate::REPLY_MAIN_SLOT.compare_exchange(
            reply,
            0,
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
        );
        if let Some(index) = crate::wait_reply_pool_find_cap(reply) {
            if !crate::wait_reply_pool_clear_cap(index) {
                return Err(Error::Reply);
            }
        }
        owner
            .replacements
            .as_mut()
            .expect("ready pool")
            .insert_pending(
                &mut row.recycled,
                owner.receiver.as_ref().expect("ready receiver"),
                lanes(),
                // The stopped hosted TCB may already be retired; the root TCB is a stable probe.
                |reply| crate::spawn_hosts::query_component_reply_binding(1, reply),
            )
            .map_err(|_| Error::Reply)?;
        *record = None;
    }
    Ok(())
}
