//! Hosted-user Calls retain independent thread identity beside component dispatch ownership.

use super::*;
use nt_component_suspension::{ExternalIngress, ReplyBindingObservation};
type Binding = nt_user_host::thread_binding::ThreadBinding<crate::HostedThreadRole>;

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
}
static mut CALLS: Vec<Option<HostedCall>> = Vec::new();
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
    });
    Ok(())
}

pub(crate) unsafe fn take_hosted_with(
    import: impl FnOnce(u64, &ReceivedMessage) -> bool,
) -> Result<Option<(u64, ReceivedMessage)>, Error> {
    recycle_completed()?;
    let Some(row) = (&mut *core::ptr::addr_of_mut!(CALLS))
        .iter_mut()
        .filter_map(Option::as_mut)
        .find(|row| !row.delivered && row.call.is_some())
    else {
        return Ok(None);
    };
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
    let _saved = crate::ipc_message::SavedMessageBuffer::capture();
    let owner = owner();
    let (ready, _message) = owner
        .receiver
        .as_mut()
        .expect("ready receiver")
        .finish_external(&mut row.call, |tcb, reply| {
            crate::spawn_hosts::query_component_reply_binding(tcb, reply)
        })
        .map_err(|_| Error::Reply)?;
    row.recycled = Some(ready);
    row.completion = Some(Completion::Acknowledged);
    Ok(())
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
        if !row.released {
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
