//! Hosted-user Calls retain independent thread identity beside component dispatch ownership.

use super::*;
use core::sync::atomic::Ordering;
use nt_component_suspension::{ExternalIngress, ReplyBindingObservation};
type Binding = nt_user_host::thread_binding::ThreadBinding<crate::HostedThreadRole>;

struct ReceiveSettlement {
    barrier: nt_user_host::receive_child_barrier::ReceiveChildBarrier<crate::HostedThreadRole>,
    observation: crate::exec_handler::private_residency::ResidentReadFaultCapture,
    provider_tcb: u64,
    provider_pml4: u64,
    // Copied at admission for diagnostics only; the barrier owns restoration authority.
    trace_owner: nt_component_suspension::SuspensionOwner,
    parent: Option<super::nested::ParkedParentHandle>,
    transferred: bool,
    rejected: Option<nt_component_suspension::ExternalSettlement>,
}

/// Single-use outer-loop delivery. The parent row already retains the sealed settlement permit.
pub(crate) struct ReceiveSettlementBoundary {
    pub(crate) parent: Option<super::nested::ParkedParentHandle>,
}

#[derive(Clone, Copy)]
pub(crate) struct ReceiveChildObservation {
    pub resident: crate::exec_handler::private_residency::ResidentReadFaultCapture,
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
    let index = nt_component_suspension::oldest_external_ingress(
        rows.iter().enumerate().filter_map(|(index, row)| {
            let row = row.as_ref()?;
            if row.delivered {
                return None;
            }
            row.call.as_ref().map(|call| (index, call))
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
                && crate::service_sec_image::hosted_ingress_binding(row.binding.badge)
                    == Some(row.binding)
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
    records[index] = Some(HostedCall {
        binding,
        call: Some(call),
        delivered: false,
        recycled: None,
        completion: None,
        released: false,
        receive_settlement: None,
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
    let Some(index) = nt_component_suspension::oldest_external_ingress(
        (&*core::ptr::addr_of!(CALLS))
            .iter()
            .enumerate()
            .filter_map(|(index, row)| {
                let row = row.as_ref()?;
                if row.delivered {
                    return None;
                }
                row.call.as_ref().map(|call| (index, call))
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

/// Return an unexecuted root delivery to its existing physical ingress owner. No syscall has
/// been admitted yet, so replay restores the original full message rather than captured argv.
pub(crate) unsafe fn defer_hosted_delivery(reply: u64, badge: u64) -> Result<(), Error> {
    if !crate::writable_fs::registry_journal::owns_volume()
        || crate::REPLY_MAIN_SLOT.load(Ordering::Relaxed) != reply
    {
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
    park.commit();
    crate::wait_reply_pool_clear_cap(pool_index);
    (&mut *core::ptr::addr_of_mut!(CALLS))[index]
        .as_mut()
        .unwrap()
        .delivered = false;
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
        return Ok(());
    }
    if !row.delivered
        || crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding)
    {
        return Err(Error::PhysicalIdentity);
    }
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
    settle_receive(row, settlement)?;
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

fn receive_settlement_consumed(row: &HostedCall) -> bool {
    row.receive_settlement.as_ref().is_none_or(|receive| {
        receive.transferred && receive.parent.is_none() && receive.rejected.is_none()
    })
}

pub(crate) unsafe fn prepare_receive_settlement(
    snapshot: PendingSnapshot,
    observation: crate::exec_handler::private_residency::ResidentReadFaultCapture,
    provider_tcb: u64,
    provider_pml4: u64,
    trace_owner: nt_component_suspension::SuspensionOwner,
) -> Result<nt_component_suspension::ExternalAdmissionKey, Error> {
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
    if row.receive_settlement.is_some() || row.delivered || row.released {
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
                        resident: receive.observation,
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

pub(crate) unsafe fn stop_hosted_caller(
    tcb: u64,
    invoke: impl FnOnce() -> u64,
) -> Option<Result<(), Error>> {
    let row = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|row| row.binding.tcb == tcb && row.call.is_some());
    let Some(row) = row else {
        return (&*core::ptr::addr_of!(CANCELLATIONS))
            .iter()
            .any(|cancelled| {
                cancelled.binding.tcb == tcb
                    && crate::service_sec_image::hosted_ingress_binding(cancelled.binding.badge)
                        == Some(cancelled.binding)
            })
            .then_some(Ok(()));
    };
    if crate::service_sec_image::hosted_ingress_binding(row.binding.badge) != Some(row.binding) {
        return Some(Err(Error::PhysicalIdentity));
    }
    let result = row
        .call
        .as_mut()
        .expect("retained external Call")
        .stop_owned(|executor| {
            if executor != tcb {
                return Err(u64::MAX);
            }
            let status = invoke();
            if status == 0 {
                Ok(())
            } else {
                Err(status)
            }
        });
    Some(result.map_err(|_| Error::Retirement))
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
    if crate::service_sec_image::hosted_ingress_binding(binding.badge) != Some(binding) {
        return Err(Error::PhysicalIdentity);
    }
    stop_hosted_caller(binding.tcb, || crate::tcb_suspend_raw_r(binding.tcb))
        .ok_or(Error::PhysicalIdentity)??;
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
        if !row.released || !receive_settlement_consumed(row) {
            continue;
        }
        let Some(ready) = row.recycled.as_ref() else {
            continue;
        };
        let reply = ready.reply();
        if let Some(index) = crate::wait_reply_pool_find_cap(reply) {
            crate::wait_reply_pool_clear_cap(index);
        }
        let _ = crate::REPLY_MAIN_SLOT.compare_exchange(
            reply,
            0,
            core::sync::atomic::Ordering::Relaxed,
            core::sync::atomic::Ordering::Relaxed,
        );
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
